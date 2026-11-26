package storageupload

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vnbui/agent/internal/models"
)

func TestRetirementOfSettledCompensationPreservesAcceptedReceipts(t *testing.T) {
	j, root, body := finalizeJournalVersioned(t, true)
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	before, _ := j.Snapshot()
	if err := j.BeginCompensation(); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		response, _ := models.StorageCanonical(map[string]any{"schema": 1, "intent_id": "abort:" + before.Request.ReservationID, "s3_absent": true, "cleanup_required": true, "capacity_state": "reserved"})
		return &http.Response{StatusCode: 200, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(bytes.NewReader(response))}, nil
	})}
	if err := j.Compensate(context.Background(), "https://backend.test", client, func(context.Context) (string, error) { return "current-agent", nil }); err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	journalPath := filepath.Join(root, before.Request.ReservationID, "transaction.json")
	original, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := HeldJournalSHA256(root, body)
	if err != nil || hash != digest(original) {
		t.Fatal("settled compensation cannot obtain its reviewed journal binding", err)
	}
	proof := RetirementProof{Schema: 1, OrgID: before.Request.OrgID, BackupID: before.Request.BackupID,
		ReservationID: before.Request.ReservationID, AttemptID: before.Request.Plan.AttemptID, PlanSHA256: before.Request.PlanSHA256,
		OperationID: "11111111-1111-4111-8111-111111111111", CapacityID: "22222222-2222-4222-8222-222222222222",
		JournalSHA256: hash, ReleaseSHA256: strings.Repeat("a", 64)}
	for i := 0; i < 2; i++ {
		if err := Retire(root, body, proof); err != nil {
			t.Fatal("exact compensated retirement failed", err)
		}
		requests, err := RecoverRequests(root)
		if err != nil || len(requests) != 0 {
			t.Fatal("retired compensation requeued after restart", err)
		}
	}
	after, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("retirement rewrote accepted receipt or abort evidence", err)
	}
}

func TestRetirementStillRefusesAcceptedOrUnsettledCompensation(t *testing.T) {
	for _, aborted := range []bool{false, true} {
		j, root, body := finalizeJournalVersioned(t, true)
		if aborted && j.BeginCompensation() != nil {
			t.Fatal("abort")
		}
		// A held presentation alone is not positive S3 cleanup evidence.
		j.state.Phase = "held"
		if err := j.save(); err != nil {
			t.Fatal(err)
		}
		_ = j.Close()
		if _, err := HeldJournalSHA256(root, body); err == nil {
			t.Fatal("accepted or unsettled attempt acquired retirement binding")
		}
	}
}

func heldRetirementFixture(t *testing.T) (string, []byte, RetirementProof) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	request := request(t, false)
	r, err := models.DecodeStorageTransaction(request)
	if err != nil {
		t.Fatal(err)
	}
	j, err := Create(root, request)
	if err != nil {
		t.Fatal(err)
	}
	j.state.Phase = "held"
	if err = j.save(); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err := os.ReadFile(filepath.Join(root, r.ReservationID, "transaction.json"))
	if err != nil {
		t.Fatal(err)
	}
	proof := RetirementProof{
		Schema: 1, OrgID: r.OrgID, BackupID: r.BackupID,
		ReservationID: r.ReservationID, AttemptID: r.Plan.AttemptID,
		PlanSHA256:    r.PlanSHA256,
		OperationID:   "11111111-1111-4111-8111-111111111111",
		CapacityID:    "22222222-2222-4222-8222-222222222222",
		JournalSHA256: digest(journal),
		ReleaseSHA256: strings.Repeat("a", 64),
	}
	return root, request, proof
}

func TestRetirementTombstonePreservesJournalAndSkipsRecovery(t *testing.T) {
	root, request, proof := heldRetirementFixture(t)
	if actual, err := HeldJournalSHA256(root, request); err != nil || actual != proof.JournalSHA256 {
		t.Fatal("held journal digest was not bound", err)
	}
	journal := filepath.Join(root, proof.ReservationID, "transaction.json")
	before, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err = Retire(root, request, proof); err != nil {
		t.Fatal(err)
	}
	if _, err := HeldJournalSHA256(root, request); err == nil {
		t.Fatal("retired journal was offered for a new review")
	}
	if err = Retire(root, request, proof); err != nil {
		t.Fatal("exact review should be idempotent", err)
	}
	locked, err := lock(filepath.Join(root, proof.ReservationID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = recoveredRequest(locked, proof.ReservationID); err != nil {
		t.Fatal("original journal invalid", err)
	}
	if ok, _, err := retired(locked); err != nil || !ok {
		t.Fatal("retirement record invalid", ok, err)
	}
	_ = locked.Close()
	after, err := os.ReadFile(journal)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("retirement changed original held custody", err)
	}
	requests, err := RecoverRequests(root)
	if err != nil || len(requests) != 0 {
		t.Fatal("retired attempt was requeued", err)
	}
	if j, err := Create(root, request); err == nil {
		_ = j.Close()
		t.Fatal("old reservation was recreated")
	}
	changed := proof
	changed.OperationID = "33333333-3333-4333-8333-333333333333"
	if err := Retire(root, request, changed); err == nil {
		t.Fatal("different review replaced the tombstone")
	}
}

func TestRetirementRefusesUnheldAndWrongProof(t *testing.T) {
	root, request, proof := heldRetirementFixture(t)
	for _, mutate := range []func(*RetirementProof){
		func(p *RetirementProof) { p.BackupID = "wrong" },
		func(p *RetirementProof) { p.ReleaseSHA256 = "bad" },
		func(p *RetirementProof) { p.JournalSHA256 = strings.Repeat("b", 64) },
		func(p *RetirementProof) { p.OperationID = "AAAAAAAA-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
	} {
		wrong := proof
		mutate(&wrong)
		if err := Retire(root, request, wrong); err == nil {
			t.Fatal("unbound review retired held attempt")
		}
	}
	if _, err := os.Lstat(filepath.Join(root, proof.ReservationID, retirementFile)); !os.IsNotExist(err) {
		t.Fatal("refused review wrote a retirement record", err)
	}
	activeRoot := t.TempDir()
	j, err := Create(activeRoot, request)
	if err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	if err := Retire(activeRoot, request, proof); err == nil {
		t.Fatal("unheld attempt retired")
	}
}

func TestRetirementCorruptionFailsClosed(t *testing.T) {
	for _, variant := range []string{"record", "journal", "permission"} {
		t.Run(variant, func(t *testing.T) {
			root, request, proof := heldRetirementFixture(t)
			if err := Retire(root, request, proof); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, proof.ReservationID, retirementFile)
			switch variant {
			case "record":
				if err := os.WriteFile(path, []byte(`{"sha256":"bad"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "journal":
				journal := filepath.Join(root, proof.ReservationID, "transaction.json")
				if err := os.WriteFile(journal, []byte("broken"), 0600); err != nil {
					t.Fatal(err)
				}
			case "permission":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := RecoverRequests(root); err == nil {
				t.Fatal("corrupt retirement silently skipped")
			}
		})
	}
}
