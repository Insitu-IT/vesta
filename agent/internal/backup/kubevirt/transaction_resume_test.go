//go:build kubevirt

package kubevirt

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestTransactionExactRedeliveryWakesOnlyResumableHeldWork(t *testing.T) {
	for _, damaged := range []bool{false, true} {
		t.Run(map[bool]string{false: "resumable", true: "uncertain-journal"}[damaged], func(t *testing.T) {
			e, body, request := runnerFixture(t)
			r, err := newTransactionRunner(context.Background(), e)
			if err != nil {
				t.Fatal(err)
			}
			defer r.cancel()
			defer r.lock.Close()
			e.storageRunner = r
			if err := e.StartStorageTransaction(context.Background(), body); err != nil {
				t.Fatal(err)
			}
			work := r.work[request.BackupID]
			r.queue = nil // Model a stopped observer, without any provider effect.
			work.finished, work.held = true, true
			if damaged {
				if err := os.WriteFile(filepath.Join(r.root, request.ReservationID, "transaction.json"), []byte("uncertain"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err = e.StartStorageTransaction(context.Background(), body)
			if damaged {
				if err == nil || len(r.queue) != 0 || !work.held {
					t.Fatal("uncertain journal was reset or requeued")
				}
				return
			}
			if err != nil || len(r.queue) != 1 || r.queue[0] != work || work.held || work.finished {
				t.Fatal("exact resumable attempt not requeued", err)
			}
			if err := e.StartStorageTransaction(context.Background(), body); err != nil || len(r.queue) != 1 {
				t.Fatal("duplicate resume enqueued twice", err)
			}
		})
	}
}
