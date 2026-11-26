//go:build linux

package backup

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/resources"
)

func TestNativeQueueDeadlineSurvivesRestartAndPolicyChange(t *testing.T) {
	for _, age := range []time.Duration{-2 * time.Hour, time.Hour} {
		t.Run(age.String(), func(t *testing.T) {
			e, body, request := nativeRunnerFixture(t)
			first := nativeReady(t, e)
			if err := e.StartNativeJob(context.Background(), body); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(first.root, "queue-budgets", request.Intent.AttemptID+".json")
			data, err := readNativeFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var record nativeQueueRecord
			if err := json.Unmarshal(data, &record); err != nil {
				t.Fatal(err)
			}
			// Model elapsed wall time without sleeping or touching the immutable request.
			record.Budget.StartedAt = time.Now().Add(age).UTC()
			record.Budget.LastProgressAt = record.Budget.StartedAt
			data, _ = json.Marshal(record)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			first.cancel()
			if err := first.lock.Close(); err != nil {
				t.Fatal(err)
			}
			e.cfg.OperationBudget = e.cfg.SafetyPolicy()
			e.cfg.OperationBudget.TimeCoefficient = 99
			reopened := NewExecutor(e.cfg, resources.New(1, 1))
			r := nativeReady(t, reopened)
			defer r.cancel()
			defer r.lock.Close()
			work := r.work[request.Intent.BackupID]
			if work.queueBudget == nil || !work.queueBudget.StartedAt.Equal(record.Budget.StartedAt) || work.queueBudget.Budget != record.Budget.Budget {
				t.Fatal("queue policy or start changed on restart")
			}
			admissions, effects := 0, 0
			r.admit = func(context.Context, string, string, string, string, string, *http.Client, func(context.Context) (string, error)) error {
				admissions++
				return nil
			}
			r.produce = func(context.Context, NativePushRequest) (*NativePushResult, error) {
				effects++
				return nil, ErrNativeUncertain
			}
			r.process(work)
			if admissions != 0 || effects != 0 || reopened.GetProgress(request.Intent.BackupID).Status != models.TaskStatusCleanupRequired {
				t.Fatal("expired queue reached producer authority", admissions, effects)
			}
			after, _ := readNativeFile(path)
			if string(after) != string(data) {
				t.Fatal("queue budget rewritten")
			}
		})
	}

}

func TestNativeQueueExpiryDoesNotWaitForProducerLock(t *testing.T) {
	e, body, request := nativeRunnerFixture(t)
	r := nativeReady(t, e)
	defer r.cancel()
	defer r.lock.Close()
	if err := e.StartNativeJob(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	work := r.work[request.Intent.BackupID]
	r.transactionMu.Lock()
	r.expireQueueWithClock(func() time.Time { return work.queueBudget.Deadline() })
	r.transactionMu.Unlock()
	if progress := e.GetProgress(request.Intent.BackupID); progress.Status != models.TaskStatusCleanupRequired {
		t.Fatal("expired queue still pending", progress)
	}
	if events := e.NativeHoldEvents(); len(events) != 1 || events[0]["attempt_id"] != request.Intent.AttemptID {
		t.Fatal("queue exhaustion not observable", events)
	}
	if err := e.StartNativeJob(context.Background(), body); !errors.Is(err, ErrNativeUncertain) {
		t.Fatal("redelivery renewed exhausted queued work", err)
	}
	if _, err := os.Lstat(r.attemptPath(request.Intent.AttemptID)); !os.IsNotExist(err) {
		t.Fatal("queue observer created producer files", err)
	}
}

func TestNativeQueueExpiryUsesLockedDecisionClock(t *testing.T) {
	for _, regression := range []bool{false, true} {
		t.Run(map[bool]string{false: "stale_tick", true: "clock_regression"}[regression], func(t *testing.T) {
			e, body, request := nativeRunnerFixture(t)
			r := nativeReady(t, e)
			defer r.cancel()
			defer r.lock.Close()
			if err := e.StartNativeJob(context.Background(), body); err != nil {
				t.Fatal(err)
			}
			work := r.work[request.Intent.BackupID]
			before := *work.queueBudget
			stale := before.StartedAt.Add(-time.Second)
			if regression {
				r.expireQueueWithClock(func() time.Time {
					if r.mu.TryLock() {
						r.mu.Unlock()
						t.Fatal("decision clock sampled outside queue lock")
					}
					return stale
				})
			} else {
				// Hold the mutation lock across a timer wake predating admission.
				r.mu.Lock()
				started, done := make(chan struct{}), make(chan struct{})
				go func() { close(started); r.expireQueue(stale); close(done) }()
				<-started
				r.mu.Unlock()
				<-done
			}
			if work.queueExpired != regression || *work.queueBudget != before {
				t.Fatal("stale wake expired admission or decision renewed original budget")
			}
			if regression {
				p := e.GetProgress(request.Intent.BackupID)
				if p.Status != models.TaskStatusCleanupRequired || p.CurrentOperation == nil || *p.CurrentOperation != "invalid_budget_or_clock; original attempt retained" {
					t.Fatal("clock regression lost its diagnostic", p)
				}
			}
			if _, err := os.Lstat(r.attemptPath(request.Intent.AttemptID)); !os.IsNotExist(err) {
				t.Fatal("queue observer created producer files", err)
			}
		})
	}
}
