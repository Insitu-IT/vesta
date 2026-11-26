//go:build linux

package storageupload

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
)

type ClosedNativeAdmission struct {
	IntentSHA256 string                  `json:"intent_sha256"`
	Inventory    models.NativeFileSet    `json:"inventory"`
	PushResult   models.NativePushResult `json:"push_result"`
	ClosedJob    struct {
		JobID        string `json:"job_id"`
		AttemptID    string `json:"attempt_id"`
		InvocationID string `json:"invocation_id"`
		ExitCode     int    `json:"exit_code"` // Reserved zero for sealed, observed OS exit for exited.
		State        string `json:"state"`
	} `json:"closed_job"`
}

// UploadClosedNative connects authenticated inventory admission, durable whole
// plan delivery, exclusive local journal, finite provider control and prepared
// acceptance. The caller must supply closed-job evidence, never a path-only
// retry. It does not launch a native job, report completion or delete local data.
func UploadClosedNative(ctx context.Context, journalRoot, tree, org, agent, base string, admission []byte, backend, provider *http.Client, agentKey func(context.Context) (string, error)) (*models.StorageAcceptance, error) {
	var closed ClosedNativeAdmission
	if models.DecodeStorageValue(admission, &closed, models.MaxStorageRequestBytes) != nil || nativefileset.Validate(closed.Inventory) != nil || !validHash(closed.IntentSHA256) || closed.PushResult.Manifest.Schema != "libvirt-push-qcow2/1" ||
		closed.ClosedJob.JobID != closed.Inventory.JobID || closed.ClosedJob.AttemptID != closed.Inventory.AttemptID || (closed.ClosedJob.State != "exited" && closed.ClosedJob.State != "sealed") || closed.ClosedJob.ExitCode != 0 {
		return nil, ErrHeld
	}
	inventoryBytes, err := models.StorageCanonical(closed.Inventory)
	if err != nil {
		return nil, ErrHeld
	}
	inventoryHash := digest(inventoryBytes)
	bound := func(r models.NativeTransactionRequest) bool {
		return r.OrgID == org && r.AgentID == agent && r.BackupID == closed.Inventory.BackupID && r.ReservationID == closed.Inventory.AttemptID && reflect.DeepEqual(r.Plan.Source.Inventory, closed.Inventory)
	}
	var j *FileSetJournal
	_, err = os.Lstat(filepath.Join(journalRoot, closed.Inventory.AttemptID))
	if err == nil {
		j, err = openFileSet(journalRoot, closed.Inventory.AttemptID, bound)
	} else if os.IsNotExist(err) {
		if nativefileset.CheckTree(tree, closed.Inventory) != nil {
			return nil, ErrHeld
		}
		response, e := nativeControl(ctx, base, backend, agentKey, closed.Inventory.BackupID, "native-inventory", admission)
		if e != nil {
			return nil, e
		}
		var accepted struct {
			Accepted        bool   `json:"accepted"`
			InventorySHA256 string `json:"inventory_sha256"`
			AttemptID       string `json:"attempt_id"`
			Completed       bool   `json:"completed"`
		}
		if models.DecodeStorageValue(response, &accepted, 4096) != nil || !accepted.Accepted || accepted.Completed || accepted.InventorySHA256 != inventoryHash || accepted.AttemptID != closed.Inventory.AttemptID {
			return nil, ErrHeld
		}
		binding, _ := json.Marshal(map[string]string{"attempt_id": closed.Inventory.AttemptID, "inventory_sha256": inventoryHash})
		request, e := nativeControl(ctx, base, backend, agentKey, closed.Inventory.BackupID, "native-transaction", binding)
		if e != nil {
			return nil, e
		}
		r, e := nativefileset.DecodeTransaction(request)
		if e != nil || !bound(*r) {
			return nil, ErrHeld
		}
		j, err = CreateFileSet(journalRoot, request)
	} else {
		return nil, ErrHeld
	}
	if err != nil {
		return nil, ErrHeld
	}
	defer j.Close()
	if j.state.Phase == "held" {
		return nil, ErrHeld
	}
	if j.state.Phase == "uploading" {
		request, e := json.Marshal(j.state.Request)
		if e != nil {
			return nil, ErrHeld
		}
		storage, e := NewNativeControlledS3(request, base, backend, provider, agentKey)
		if e != nil {
			return nil, e
		}
		defer storage.Close()
		key, e := storage.ResolveKey(ctx)
		if e != nil {
			return nil, e
		}
		defer clear(key)
		if e = j.UploadClosedTree(ctx, storage, tree, key); e != nil {
			return nil, e
		}
	}
	return j.Submit(ctx, base, backend, agentKey)
}

func nativeControl(ctx context.Context, base string, client *http.Client, agentKey func(context.Context) (string, error), backup, operation string, body []byte) ([]byte, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || agentKey == nil || len(body) > models.MaxStorageRequestBytes {
		return nil, ErrHeld
	}
	bounded, err := boundedClient(client)
	if err != nil {
		return nil, err
	}
	key, err := agentKey(ctx)
	if err != nil || key == "" {
		return nil, ErrHeld
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/agents/backups/"+backup+"/"+operation, bytes.NewReader(body))
	if err != nil {
		return nil, ErrHeld
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Key", key)
	response, err := bounded.Do(req)
	if err != nil {
		return nil, ErrHeld
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Cache-Control") != "no-store" {
		return nil, ErrHeld
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, models.MaxStorageRequestBytes+1))
	if err != nil || len(data) > models.MaxStorageRequestBytes {
		return nil, ErrHeld
	}
	return data, nil
}

// RequestNativeRetirementProof is a read-only authenticated callback. The
// backend returns only a previously committed owner-reviewed release.
func RequestNativeRetirementProof(ctx context.Context, base, backup string, body []byte, client *http.Client, key func(context.Context) (string, error)) ([]byte, error) {
	return nativeControl(ctx, base, client, key, backup, "storage-retirement", body)
}

// PublishClosedNative repeats only the exact accepted receipt identity. A
// successful response means the backend committed its unique S3 generation and
// atomic catalog/capacity transition; the agent cannot infer that from upload.
func PublishClosedNative(ctx context.Context, base, backup string, accepted *models.StorageAcceptance, client *http.Client, agentKey func(context.Context) (string, error)) error {
	if accepted == nil || !accepted.Accepted {
		return ErrHeld
	}
	body, err := json.Marshal(map[string]string{"reservation_id": accepted.ReservationID, "receipt_sha256": accepted.ReceiptSHA256, "acceptance_id": accepted.AcceptanceID})
	if err != nil {
		return ErrHeld
	}
	response, err := nativeControl(ctx, base, client, agentKey, backup, "native-publication", body)
	if err != nil {
		return err
	}
	var result struct {
		ReservationID string `json:"reservation_id"`
		Status        string `json:"status"`
		Completed     bool   `json:"completed"`
	}
	if models.DecodeStorageValue(response, &result, 4096) != nil || result.ReservationID != accepted.ReservationID || result.Status != "completed" || !result.Completed {
		return ErrHeld
	}
	return nil
}

// AdmitNativeProducer checks original live authority after queueing/restart,
// before a new local attempt directory or any VM-changing producer operation.
func AdmitNativeProducer(ctx context.Context, base, backup, attempt, intentSHA256, producerRequestSHA256 string, client *http.Client, agentKey func(context.Context) (string, error)) error {
	body, err := json.Marshal(map[string]string{"attempt_id": attempt, "intent_sha256": intentSHA256, "producer_request_sha256": producerRequestSHA256})
	if err != nil {
		return ErrHeld
	}
	response, err := nativeControl(ctx, base, client, agentKey, backup, "native-admission", body)
	if err != nil {
		return err
	}
	var result struct {
		AttemptID             string `json:"attempt_id"`
		IntentSHA256          string `json:"intent_sha256"`
		ProducerRequestSHA256 string `json:"producer_request_sha256"`
		Admitted              bool   `json:"admitted"`
	}
	if models.DecodeStorageValue(response, &result, 4096) != nil || result.AttemptID != attempt || result.IntentSHA256 != intentSHA256 || result.ProducerRequestSHA256 != producerRequestSHA256 || !result.Admitted {
		return ErrHeld
	}
	return nil
}

// SettleNativeNoEffect reports the exact original helper refusal, never a new
// admission. The backend owns capacity release and identical-response replay.
func SettleNativeNoEffect(ctx context.Context, base, backup string, binding map[string]string, client *http.Client, agentKey func(context.Context) (string, error)) error {
	body, err := json.Marshal(binding)
	if err != nil || len(body) > 256<<10 {
		return ErrHeld
	}
	response, err := nativeControl(ctx, base, client, agentKey, backup, "native-no-effect", body)
	if err != nil {
		return err
	}
	var refusal struct {
		AttemptID string `json:"attempt_id"`
	}
	if json.Unmarshal([]byte(binding["refusal_canonical"]), &refusal) != nil || refusal.AttemptID == "" {
		return ErrHeld
	}
	var result struct {
		Settled       bool   `json:"settled"`
		AttemptID     string `json:"attempt_id"`
		IntentSHA256  string `json:"intent_sha256"`
		RefusalSHA256 string `json:"refusal_sha256"`
		CapacityID    string `json:"capacity_id"`
	}
	if models.DecodeStorageValue(response, &result, 4096) != nil || !result.Settled || result.AttemptID != refusal.AttemptID ||
		result.IntentSHA256 != binding["intent_sha256"] || result.RefusalSHA256 != binding["refusal_sha256"] || result.CapacityID == "" {
		return ErrHeld
	}
	return nil
}

// SettleNativeClosedFailure acknowledges termination, never successful data or
// no-effect. Lost acknowledgements replay only the original certificate.
func SettleNativeClosedFailure(ctx context.Context, base, backup string, binding map[string]string, client *http.Client, agentKey func(context.Context) (string, error)) error {
	body, err := json.Marshal(binding)
	if err != nil || len(body) > models.MaxStorageRequestBytes {
		return ErrHeld
	}
	response, err := nativeControl(ctx, base, client, agentKey, backup, "native-closed-failure", body)
	if err != nil {
		return err
	}
	var closure struct {
		AttemptID string `json:"attempt_id"`
	}
	if json.Unmarshal([]byte(binding["closure_canonical"]), &closure) != nil || closure.AttemptID == "" {
		return ErrHeld
	}
	var result struct {
		Settled       bool   `json:"settled"`
		AttemptID     string `json:"attempt_id"`
		IntentSHA256  string `json:"intent_sha256"`
		ClosureSHA256 string `json:"closure_sha256"`
		CapacityID    string `json:"capacity_id"`
	}
	if models.DecodeStorageValue(response, &result, 4096) != nil || !result.Settled || result.AttemptID != closure.AttemptID ||
		result.IntentSHA256 != binding["intent_sha256"] || result.ClosureSHA256 != binding["closure_sha256"] || result.CapacityID == "" {
		return ErrHeld
	}
	return nil
}
