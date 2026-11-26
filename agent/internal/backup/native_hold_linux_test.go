//go:build linux

package backup

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func TestNativeHoldEventsRepeatExactIdentityWithoutProviderDetails(t *testing.T) {
	e, _, request := nativeRunnerFixture(t)
	work := &nativeWork{request: request, finished: true, held: true, uploadHeld: true}
	e.nativeRunner = &nativeRunner{work: map[string]*nativeWork{request.Intent.BackupID: work}}
	expected := []map[string]interface{}{{
		"type": "native_attempt_held", "schema": 1,
		"backup_id": request.Intent.BackupID, "attempt_id": request.Intent.AttemptID,
		"intent_sha256": request.IntentSHA256, "reason": "native_upload_held",
	}}
	for index := 0; index < 3; index++ {
		got := e.NativeHoldEvents()
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("hold snapshot: %#v", got)
		}
		got[0]["reason"] = "caller mutation"
	}
	work.uploadHeld = false
	if e.NativeHoldEvents()[0]["reason"] != "native_attempt_retained" {
		t.Fatal("producer hold unavailable")
	}
	work.held = false
	if len(e.NativeHoldEvents()) != 0 {
		t.Fatal("completed/resumed attempt reported held")
	}
	delete(e.nativeRunner.work, request.Intent.BackupID)
	if len(e.NativeHoldEvents()) != 0 {
		t.Fatal("retired attempt reported held")
	}
	e.nativeRunner = nil
	if len(e.NativeHoldEvents()) != 0 {
		t.Fatal("inactive native runner reported hold")
	}
}

func TestNativeHoldEventsBoundedPaginationAndConcurrentSnapshots(t *testing.T) {
	e, _, request := nativeRunnerFixture(t)
	r := &nativeRunner{work: map[string]*nativeWork{}}
	e.nativeRunner = r
	for index := 0; index < 130; index++ {
		copy := *request
		copy.Intent.BackupID = fmt.Sprintf("backup-%03d", index)
		r.work[copy.Intent.BackupID] = &nativeWork{request: &copy, finished: true, held: true}
	}
	seen := map[string]bool{}
	for index := 0; index < 3; index++ {
		events := e.NativeHoldEvents()
		if len(events) != 64 {
			t.Fatal("unbounded/incomplete snapshot", len(events))
		}
		for _, event := range events {
			seen[event["backup_id"].(string)] = true
		}
	}
	if len(seen) != 130 {
		t.Fatal("holds starved beyond first snapshot", len(seen))
	}
	var group sync.WaitGroup
	for index := 0; index < 4; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for round := 0; round < 20; round++ {
				e.NativeHoldEvents()
			}
		}()
	}
	group.Wait()
}
