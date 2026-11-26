//go:build linux

package backup

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/operationbudget"
)

type nativeQueueRecord struct {
	Schema       int                      `json:"schema"`
	IntentSHA256 string                   `json:"intent_sha256"`
	Budget       operationbudget.Progress `json:"budget"`
}

// Queue expiry is observable even while a producer or upload ahead is blocked.
// It grants no new effect authority. Reconciliation can still consume existing
// positive closure evidence when this original item reaches the worker.
func (r *nativeRunner) expireQueue(_ time.Time) {
	r.expireQueueWithClock(time.Now)
}

func (r *nativeRunner) expireQueueWithClock(clock func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, work := range r.queue {
		if work.queueExpired {
			continue
		}
		reason := "operation_budget_missing_or_invalid"
		if work.queueBudget != nil {
			// The wake timestamp can predate admission while we wait for r.mu.
			reason = work.queueBudget.Exhausted(clock())
		}
		if reason == "" {
			continue
		}
		work.queueExpired = true
		r.progress(work, models.TaskStatusCleanupRequired, reason+"; original attempt retained")
	}
}

func readNativeQueueBudget(root string, request *NativeJobRequest) (*operationbudget.Progress, error) {
	b, err := readNativeFile(filepath.Join(root, "queue-budgets", request.Intent.AttemptID+".json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrNativeUncertain
	}
	if _, err := models.DecodeStorageControlJSONBounded(b, 4096); err != nil {
		return nil, ErrNativeUncertain
	}
	var record nativeQueueRecord
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&record) != nil || d.Decode(new(any)) != io.EOF || record.Schema != 1 || record.IntentSHA256 != request.IntentSHA256 || !record.Budget.Valid() || record.Budget.Stage != "queued" {
		return nil, ErrNativeUncertain
	}
	return &record.Budget, nil
}
