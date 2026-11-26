package storageupload

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"time"

	"vnbui/agent/internal/models"
)

// FinalizeBinding is immutable, non-secret evidence. It grants authority only
// for the original VMB; no child resource or finalizer mutation is authorized.
type FinalizeBinding struct {
	Protocol            string                 `json:"protocol"`
	ReservationID       string                 `json:"reservation_id"`
	AttemptID           string                 `json:"attempt_id"`
	PlanSHA256          string                 `json:"plan_sha256"`
	ReceiptSHA256       string                 `json:"receipt_sha256"`
	AcceptanceID        string                 `json:"acceptance_id"`
	Namespace           string                 `json:"namespace"`
	VMUID               string                 `json:"vm_uid"`
	VMIUID              *string                `json:"vmi_uid"`
	TrackerName         string                 `json:"tracker_name"`
	TrackerUID          string                 `json:"tracker_uid"`
	VMBName             string                 `json:"vmb_name"`
	VMBUID              string                 `json:"vmb_uid"`
	Checkpoint          string                 `json:"checkpoint"`
	Parent              *models.StorageParent  `json:"parent"`
	Volumes             []models.StorageVolume `json:"volumes"`
	StartedAt           string                 `json:"started_at"`
	GuestConsistency    string                 `json:"guest_consistency"`
	GuestEvidenceSource string                 `json:"guest_evidence_source"`
}
type CheckpointProof struct {
	IntentID                string `json:"intent_id"`
	Checkpoint              string `json:"checkpoint"`
	TrackerResourceVersion  string `json:"tracker_resource_version"`
	TerminalResourceVersion string `json:"terminal_resource_version"`
	CheckpointCreationTime  string `json:"checkpoint_creation_time"`
	VMBAbsent               bool   `json:"vmb_absent"`
	GuestConsistency        string `json:"guest_consistency"`
}
type FinalizeState struct {
	Binding                 FinalizeBinding  `json:"binding"`
	IntentID                string           `json:"intent_id"`
	DeleteResourceVersion   string           `json:"delete_resource_version"`
	DeleteRefused           bool             `json:"delete_refused"`
	TerminalResourceVersion string           `json:"terminal_resource_version"`
	Proof                   *CheckpointProof `json:"proof"`
	Reported                bool             `json:"reported"`
}

func consistency(s string) bool {
	return s == "quiesced" || s == "crash-consistent" || s == "failed" || s == "unknown"
}
func finalizeBinding(s *State, guest string) FinalizeBinding {
	r, n := &s.Request, s.Native
	return FinalizeBinding{r.Protocol, r.ReservationID, r.Plan.AttemptID, r.PlanSHA256, s.Acceptance.ReceiptSHA256, s.Acceptance.AcceptanceID, r.Plan.Source.Namespace, r.Plan.Source.VMUID, r.Plan.Source.VMIUID, n.Objects[0].Name, n.Objects[0].UID, n.Objects[1].Name, n.Objects[1].UID, s.Export.Checkpoint, r.Plan.Parent, r.Plan.Source.Volumes, s.Utility.StartedAt, guest, "kubevirt/VMB.status.conditions"}
}
func validFinalize(s *State) bool {
	f := s.Finalize
	if f == nil {
		return true
	}
	if s.Phase != "accepted" || s.Acceptance == nil || s.Native == nil || !validNative(s.Native, &s.Request) || s.Utility == nil || s.Export == nil || len(s.Maps) == 0 || !consistency(f.Binding.GuestConsistency) {
		return false
	}
	if !reflect.DeepEqual(f.Binding, finalizeBinding(s, f.Binding.GuestConsistency)) {
		return false
	}
	for _, value := range []string{f.IntentID, f.DeleteResourceVersion, f.TerminalResourceVersion} {
		if value != "" && !nativeID(value) {
			return false
		}
	}
	if f.IntentID == "" && (f.DeleteResourceVersion != "" || f.TerminalResourceVersion != "" || f.Proof != nil || f.Reported) {
		return false
	}
	if f.TerminalResourceVersion != "" && f.DeleteResourceVersion == "" {
		return false
	}
	if f.DeleteRefused && (f.DeleteResourceVersion == "" || f.TerminalResourceVersion != "" || f.Proof != nil || f.Reported) {
		return false
	}
	if p := f.Proof; p != nil {
		if f.TerminalResourceVersion == "" || p.IntentID != f.IntentID || p.Checkpoint != f.Binding.Checkpoint || p.TerminalResourceVersion != f.TerminalResourceVersion || !p.VMBAbsent || p.CheckpointCreationTime != f.Binding.StartedAt || p.GuestConsistency != f.Binding.GuestConsistency || !nativeID(p.TrackerResourceVersion) {
			return false
		}
	}
	return !f.Reported || f.Proof != nil
}
func (j *Journal) PrepareFinalize(guest string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned || j.state.Phase != "accepted" || j.state.Acceptance == nil || j.state.Native == nil || j.state.Utility == nil || j.state.Export == nil || !consistency(guest) {
		return ErrHeld
	}
	b := finalizeBinding(&j.state, guest)
	if j.state.Finalize != nil {
		if !reflect.DeepEqual(b, j.state.Finalize.Binding) {
			return ErrHeld
		}
		return j.save()
	}
	j.state.Finalize = &FinalizeState{Binding: b}
	return j.save()
}
func (j *Journal) RecordDeleteIntent(rv string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	f := j.state.Finalize
	if j.poisoned || f == nil || f.DeleteRefused || f.IntentID == "" || f.Proof != nil || f.TerminalResourceVersion != "" || !nativeID(rv) {
		return ErrHeld
	}
	f.DeleteResourceVersion = rv
	return j.save()
}
func (j *Journal) RecordDeleteRefusal() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	f := j.state.Finalize
	if j.poisoned || f == nil || f.DeleteResourceVersion == "" || f.TerminalResourceVersion != "" || f.Proof != nil {
		return ErrHeld
	}
	f.DeleteRefused = true
	return j.save()
}
func (j *Journal) RecordTerminal(rv string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	f := j.state.Finalize
	if j.poisoned || f == nil || f.DeleteRefused || f.IntentID == "" || f.DeleteResourceVersion == "" || !nativeID(rv) {
		return ErrHeld
	}
	if f.TerminalResourceVersion != "" && f.TerminalResourceVersion != rv {
		return ErrHeld
	}
	f.TerminalResourceVersion = rv
	return j.save()
}
func (j *Journal) RecordCheckpoint(rv string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	f := j.state.Finalize
	if j.poisoned || f == nil || f.DeleteRefused || f.IntentID == "" || f.TerminalResourceVersion == "" || !nativeID(rv) {
		return ErrHeld
	}
	p := &CheckpointProof{f.IntentID, f.Binding.Checkpoint, rv, f.TerminalResourceVersion, f.Binding.StartedAt, true, f.Binding.GuestConsistency}
	if f.Proof != nil && !reflect.DeepEqual(f.Proof, p) {
		return ErrHeld
	}
	f.Proof = p
	return j.save()
}

// FinalizeControl never performs a provider/Kubernetes operation. Both request
// and reply are bounded; uncertainty retains the identical durable request.
func (j *Journal) FinalizeControl(ctx context.Context, base string, client *http.Client, credential func(context.Context) (string, error), report bool) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	f := j.state.Finalize
	if j.poisoned || f == nil || f.DeleteRefused || !validFinalize(&j.state) || client == nil || credential == nil {
		return ErrHeld
	}
	if report && (f.Proof == nil || f.IntentID == "") {
		return ErrHeld
	}
	if report && f.Reported {
		return j.save()
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return ErrHeld
	}
	if t, ok := client.Transport.(*http.Transport); ok && t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify {
		return ErrHeld
	}
	var value any = f.Binding
	path := "finalize-intent"
	if report {
		value = f.Proof
		path = "checkpoint-proof"
	}
	body, err := models.StorageCanonical(value)
	if err != nil || len(body) > 65536 || j.save() != nil {
		return ErrHeld
	}
	key, err := credential(ctx)
	if err != nil || key == "" {
		return ErrHeld
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/agents/backups/"+j.state.Request.BackupID+"/"+path, bytes.NewReader(body))
	if err != nil {
		return ErrHeld
	}
	req.Header.Set("X-Agent-Key", key)
	req.Header.Set("Content-Type", "application/json")
	bounded := *client
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := bounded.Do(req)
	if err != nil {
		return ErrHeld
	}
	defer resp.Body.Close()
	expectedStatus := http.StatusOK
	if report {
		expectedStatus = http.StatusAccepted
	}
	if resp.StatusCode != expectedStatus || resp.Header.Get("Cache-Control") != "no-store" {
		return ErrHeld
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(data) > 65536 {
		return ErrHeld
	}
	if report {
		var ack struct {
			IntentID  string `json:"intent_id"`
			Status    string `json:"status"`
			Completed bool   `json:"completed"`
		}
		// Keep replaying the durable proof until the backend has published the
		// generation and committed completion, including after a lost reply.
		if models.DecodeStorageValue(data, &ack, 65536) != nil || ack.IntentID != f.IntentID || ack.Status != "completed" || !ack.Completed {
			return ErrHeld
		}
		f.Reported = true
	} else {
		var ack struct {
			IntentID string          `json:"intent_id"`
			Binding  FinalizeBinding `json:"binding"`
		}
		if models.DecodeStorageValue(data, &ack, 65536) != nil || !nativeID(ack.IntentID) || !reflect.DeepEqual(ack.Binding, f.Binding) || (f.IntentID != "" && f.IntentID != ack.IntentID) {
			return ErrHeld
		}
		f.IntentID = ack.IntentID
	}
	return j.save()
}
