//go:build linux

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

	"vnbui/agent/internal/nativefileset"
)

func TestNativeAcceptedUploadCanUseSeparatelyReviewedRetirement(t *testing.T) {
	body, tree := nativeRequest(t, true)
	root := t.TempDir()
	j, err := CreateFileSet(root, body)
	if err != nil {
		t.Fatal(err)
	}
	r := j.state.Request
	if err := j.UploadClosedTree(context.Background(), nativeStore(r), tree, bytes.Repeat([]byte{9}, 32)); err != nil {
		t.Fatal(err)
	}
	response := nativeAck(t, j)
	client := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(response))}, nil
	})}
	if _, err := j.Submit(context.Background(), "https://backend.test", client, func(context.Context) (string, error) { return "registered-agent", nil }); err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	path := filepath.Join(root, r.ReservationID, "transaction.json")
	before, _ := os.ReadFile(path)
	p, err := NativeHeldJournalIdentity(root, r.ReservationID, r.OrgID, r.AgentID, r.BackupID)
	if err != nil {
		t.Fatal("closed accepted upload is not reviewable", err)
	}
	p.OperationID, p.CapacityID, p.ReleaseSHA256 = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", strings.Repeat("a", 64)
	for i := 0; i < 2; i++ {
		if err := RetireNativeFileSet(root, r.ReservationID, p); err != nil {
			t.Fatal(err)
		}
		ok, got, err := NativeFileSetRetired(root, r.ReservationID, r.OrgID, r.AgentID, r.BackupID)
		if err != nil || !ok || got != p {
			t.Fatal("accepted native retirement did not survive restart", err)
		}
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("retirement discarded accepted native evidence")
	}
}

func nativeRetirementFixture(t *testing.T) (string, RetirementProof) {
	t.Helper()
	body, _ := nativeRequest(t, true)
	r, err := nativefileset.DecodeTransaction(body)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	j, err := CreateFileSet(root, body)
	if err != nil {
		t.Fatal(err)
	}
	j.state.Phase = "held"
	if err := j.save(); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := NativeHeldJournalIdentity(root, r.ReservationID, r.OrgID, r.AgentID, r.BackupID)
	if err != nil {
		t.Fatal(err)
	}
	p.OperationID = "11111111-1111-4111-8111-111111111111"
	p.CapacityID = "22222222-2222-4222-8222-222222222222"
	p.ReleaseSHA256 = strings.Repeat("a", 64)
	return root, p
}

func TestNativeRetirementPreservesOriginalJournal(t *testing.T) {
	root, proof := nativeRetirementFixture(t)
	path := filepath.Join(root, proof.AttemptID, "transaction.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := RetireNativeFileSet(root, proof.AttemptID, proof); err != nil {
			t.Fatal(err)
		}
	}
	j, err := nativeRetirementJournal(root, proof.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	agent := j.state.Request.AgentID
	_ = j.Close()
	ok, got, err := NativeFileSetRetired(root, proof.AttemptID, proof.OrgID, agent, proof.BackupID)
	if err != nil || !ok || got != proof {
		t.Fatal("restart lost retirement", ok, err)
	}
	if _, err := NativeHeldJournalIdentity(root, proof.AttemptID, proof.OrgID, agent, proof.BackupID); err == nil {
		t.Fatal("retired journal offered for review again")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("original journal changed", err)
	}
	if _, _, err := NativeFileSetRetired(root, proof.AttemptID, proof.OrgID, "foreign-agent", proof.BackupID); err == nil {
		t.Fatal("foreign agent adopted tombstone")
	}
}

func TestNativeRetirementRefusesWrongProofAndCorruption(t *testing.T) {
	root, proof := nativeRetirementFixture(t)
	for _, mutate := range []func(*RetirementProof){
		func(p *RetirementProof) { p.BackupID = "foreign" },
		func(p *RetirementProof) { p.JournalSHA256 = strings.Repeat("b", 64) },
		func(p *RetirementProof) { p.OperationID = "invalid" },
	} {
		wrong := proof
		mutate(&wrong)
		if err := RetireNativeFileSet(root, proof.AttemptID, wrong); err == nil {
			t.Fatal("unbound retirement accepted")
		}
	}
	if err := RetireNativeFileSet(root, proof.AttemptID, proof); err != nil {
		t.Fatal(err)
	}
	j, err := nativeRetirementJournal(root, proof.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	agent := j.state.Request.AgentID
	_ = j.Close()
	if err := os.Chmod(filepath.Join(root, proof.AttemptID, retirementFile), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NativeFileSetRetired(root, proof.AttemptID, proof.OrgID, agent, proof.BackupID); err == nil {
		t.Fatal("unsafe tombstone accepted")
	}
}

func TestNativeRetirementRefusesActiveUpload(t *testing.T) {
	body, _ := nativeRequest(t, false)
	r, err := nativefileset.DecodeTransaction(body)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	j, err := CreateFileSet(root, body)
	if err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	if _, err := NativeHeldJournalIdentity(root, r.ReservationID, r.OrgID, r.AgentID, r.BackupID); err == nil {
		t.Fatal("active upload offered for retirement")
	}
}
