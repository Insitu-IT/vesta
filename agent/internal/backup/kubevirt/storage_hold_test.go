//go:build kubevirt

package kubevirt

import (
	"fmt"
	"reflect"
	"testing"
)

func TestStorageHoldEventsExactRepeatableAndPaginated(t *testing.T) {
	e, _, request := runnerFixture(t)
	r := &transactionRunner{work: make(map[string]*transactionWork)}
	e.storageRunner = r
	for index := 0; index < 70; index++ {
		copy := *request
		copy.BackupID = fmt.Sprintf("backup-%03d", index)
		r.work[copy.BackupID] = &transactionWork{request: &copy, finished: true, held: true}
	}
	seen := map[string]bool{}
	for page := 0; page < 2; page++ {
		events := e.StorageHoldEvents()
		if len(events) != 64 {
			t.Fatal("unbounded or incomplete page", len(events))
		}
		for _, event := range events {
			id := event["backup_id"].(string)
			want := map[string]interface{}{
				"type": "storage_transaction_held", "schema": 1, "backup_id": id,
				"reservation_id": request.ReservationID, "plan_sha256": request.PlanSHA256,
				"reason": "storage_transaction_retained",
			}
			if !reflect.DeepEqual(event, want) {
				t.Fatal("unexpected report", event)
			}
			seen[id] = true
		}
	}
	if len(seen) != 70 {
		t.Fatal("holds starved", len(seen))
	}
	for _, work := range r.work {
		work.held = false
	}
	if len(e.StorageHoldEvents()) != 0 {
		t.Fatal("completed/resumed work reported held")
	}
}
