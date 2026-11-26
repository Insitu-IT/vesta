package storageupload

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"time"
	"vnbui/agent/internal/models"
)

const CompensationReason = "original_native_identity_lost"

// ImmutableCompensationVersions rejects the mutable S3 null version as well as
// absent IDs. IfMatch alone is not a qualified deletion capability.
func ImmutableCompensationVersions(s *State) bool {
	if s.Receipt == nil || len(s.Receipt.Objects) == 0 {
		return false
	}
	for _, object := range s.Receipt.Objects {
		if object.VersionID == nil || *object.VersionID == "" || *object.VersionID == "null" {
			return false
		}
	}
	return true
}

// HoldUnversionedCompensation preserves a positively failed native attempt
// without creating abort authority or sending a provider request.
func (j *Journal) HoldUnversionedCompensation() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned || j.state.Phase != "accepted" || j.state.Finalize != nil || ImmutableCompensationVersions(&j.state) {
		return ErrHeld
	}
	j.state.Phase = "held"
	return j.save()
}

// CompensationState is an irreversible receipt-bound abort. S3 absence never
// proves native cleanup or permits releasing backend capacity.
type CompensationState struct {
	AbortID       string `json:"abort_id"`
	ReceiptSHA256 string `json:"receipt_sha256"`
	AcceptanceID  string `json:"acceptance_id"`
	Reason        string `json:"reason"`
	S3Absent      bool   `json:"s3_absent"`
}

func validCompensation(s *State) bool {
	c := s.Compensation
	if c == nil {
		return s.Phase != "compensating"
	}
	if s.Request.Plan.Provider != "kubevirt" || s.Request.Plan.CapabilityProfile != "db-rooted-consumer-verified/1" || s.Finalize != nil || s.Acceptance == nil || !ImmutableCompensationVersions(s) || s.Native == nil || !validNative(s.Native, &s.Request) {
		return false
	}
	if c.AbortID != "abort:"+s.Request.ReservationID || c.ReceiptSHA256 != s.Acceptance.ReceiptSHA256 || c.AcceptanceID != s.Acceptance.AcceptanceID || c.Reason != CompensationReason || (s.Phase != "compensating" && s.Phase != "held") || (c.S3Absent && s.Phase != "held") {
		return false
	}
	for _, o := range s.Native.Objects {
		if o.Phase != "observed" {
			return false
		}
	}
	for _, o := range s.Objects {
		if o.Phase != "complete" || o.Receipt == nil {
			return false
		}
	}
	return true
}

// BeginCompensation follows a positive original-native identity loss observation.
// A timeout or generic ErrHeld must never invoke it.
func (j *Journal) BeginCompensation() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned {
		return ErrHeld
	}
	if j.state.Compensation != nil {
		return j.save()
	}
	if j.state.Phase != "accepted" || j.state.Acceptance == nil || j.state.Finalize != nil || !ImmutableCompensationVersions(&j.state) {
		return ErrHeld
	}
	a := j.state.Acceptance
	j.state.Compensation = &CompensationState{AbortID: "abort:" + j.state.Request.ReservationID, ReceiptSHA256: a.ReceiptSHA256, AcceptanceID: a.AcceptanceID, Reason: CompensationReason}
	j.state.Phase = "compensating"
	return j.save()
}

// Compensate sends only durable abort identity; deletion authority stays backend-owned.
func (j *Journal) Compensate(ctx context.Context, base string, client *http.Client, credential func(context.Context) (string, error)) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned || j.state.Compensation == nil || !validCompensation(&j.state) || credential == nil {
		return ErrHeld
	}
	if j.state.Compensation.S3Absent {
		return j.save()
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return ErrHeld
	}
	bounded, err := boundedClient(client)
	if err != nil {
		return ErrHeld
	}
	r, c := &j.state.Request, j.state.Compensation
	body, err := models.StorageCanonical(map[string]any{
		"schema": 1, "binding": map[string]any{"reservation_id": r.ReservationID, "attempt_id": r.Plan.AttemptID, "plan_sha256": r.PlanSHA256, "key_ref": r.Plan.Encryption.KeyRef},
		"artifact_key": "", "operation": "compensate_pre_finalize",
		"args": map[string]any{"abort_id": c.AbortID, "receipt_sha256": c.ReceiptSHA256, "acceptance_id": c.AcceptanceID, "reason": c.Reason},
	})
	if err != nil || j.save() != nil {
		return ErrHeld
	}
	key, err := credential(ctx)
	if err != nil || key == "" {
		return ErrHeld
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/agents/backups/"+r.BackupID+"/storage-control", bytes.NewReader(body))
	if err != nil {
		return ErrHeld
	}
	req.Header.Set("X-Agent-Key", key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := bounded.Do(req)
	if err != nil {
		return ErrHeld
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		return ErrHeld
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(data) > 4096 {
		return ErrHeld
	}
	var reply struct {
		Schema          int    `json:"schema"`
		IntentID        string `json:"intent_id"`
		S3Absent        *bool  `json:"s3_absent"`
		CleanupRequired bool   `json:"cleanup_required"`
		CapacityState   string `json:"capacity_state"`
	}
	if models.DecodeStorageValue(data, &reply, 4096) != nil || reply.Schema != 1 || reply.IntentID != c.AbortID || reply.S3Absent == nil || !reply.CleanupRequired || reply.CapacityState != "reserved" {
		return ErrHeld
	}
	if *reply.S3Absent {
		c.S3Absent = true
		j.state.Phase = "held"
	}
	return j.save()
}
