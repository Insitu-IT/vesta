package storageupload

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"testing"

	"vnbui/agent/internal/models"
)

func TestCompensationDurableRetryReopenAndNativeHold(t *testing.T) {
	j, root, body := finalizeJournalVersioned(t, true)
	before, _ := j.Snapshot()
	if err := j.BeginCompensation(); err != nil {
		t.Fatal(err)
	}
	if j.PrepareFinalize("unknown") == nil {
		t.Fatal("abort reopened finalize")
	}
	_ = j.Close()
	var err error
	j, err = Open(root, body)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	var sent [][]byte
	absent := false
	client := &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(req.Body)
		sent = append(sent, raw)
		wire, decodeErr := models.DecodeStorageControlJSON(raw)
		if decodeErr != nil || wire["operation"] != "compensate_pre_finalize" || wire["artifact_key"] != "" {
			t.Fatal("body")
		}
		s, _ := j.read()
		if !bytes.Contains(s, []byte("compensating")) {
			t.Fatal("send before durable abort")
		}
		response, _ := models.StorageCanonical(map[string]any{"schema": 1, "intent_id": "abort:" + before.Request.ReservationID, "s3_absent": absent, "cleanup_required": true, "capacity_state": "reserved"})
		return &http.Response{StatusCode: 200, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(bytes.NewReader(response))}, nil
	})}
	credential := func(context.Context) (string, error) { return "current-agent-key", nil }
	if j.Compensate(context.Background(), "https://backend.test", client, credential) != nil {
		t.Fatal("denied response")
	}
	s, _ := j.Snapshot()
	if s.Phase != "compensating" || s.Compensation.S3Absent {
		t.Fatal("denial settled")
	}
	absent = true
	if j.Compensate(context.Background(), "https://backend.test", client, credential) != nil {
		t.Fatal("retry")
	}
	s, _ = j.Snapshot()
	if s.Phase != "held" || !s.Compensation.S3Absent || !reflect.DeepEqual(s.Receipt, before.Receipt) || !reflect.DeepEqual(s.Native, before.Native) || s.Finalize != nil {
		t.Fatal("native/receipt custody drift")
	}
	if len(sent) != 2 || !bytes.Equal(sent[0], sent[1]) {
		t.Fatal("retry changed intent")
	}
	if j.Compensate(context.Background(), "https://backend.test", client, credential) != nil || len(sent) != 2 {
		t.Fatal("settled repeat performed IO")
	}
}

func TestCompensationFailedDurabilityNeverAuthorizesSend(t *testing.T) {
	j, root, body := finalizeJournalVersioned(t, true)
	j.syncFile = func(*os.File) error { return errors.New("fsync failed") }
	if j.BeginCompensation() == nil {
		t.Fatal("failed fsync accepted")
	}
	calls := 0
	client := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected") })}
	if j.Compensate(context.Background(), "https://backend.test", client, func(context.Context) (string, error) { return "key", nil }) == nil || calls != 0 {
		t.Fatal("failed durability authorized IO")
	}
	_ = j.Close()
	reopened, err := Open(root, body)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	s, _ := reopened.Snapshot()
	if s.Compensation != nil || s.Phase != "accepted" {
		t.Fatal("uncommitted abort survived")
	}
}

func TestCompensationRefusesFinalizeAndIncompleteReceipt(t *testing.T) {
	j, _, _ := finalizeJournalVersioned(t, true)
	defer j.Close()
	if j.PrepareFinalize("unknown") != nil || j.BeginCompensation() == nil {
		t.Fatal("finalize admitted abort")
	}
	other, _, _, _ := exportJournal(t)
	defer other.Close()
	if other.BeginCompensation() == nil {
		t.Fatal("incomplete receipt admitted abort")
	}
}

func TestCompensationRejectsMutableNullVersionsWithoutIO(t *testing.T) {
	for _, version := range []*string{nil, ptrVersion(""), ptrVersion("null")} {
		s := &State{Receipt: &models.StorageReceipt{Objects: []models.StorageObjectReceipt{{VersionID: version}}}}
		if ImmutableCompensationVersions(s) {
			t.Fatal("mutable version qualified")
		}
	}
	j, _, _ := finalizeJournal(t)
	defer j.Close()
	if j.BeginCompensation() == nil {
		t.Fatal("unversioned abort admitted")
	}
	s, err := j.Snapshot()
	if err != nil || s.Compensation != nil || s.Phase != "accepted" {
		t.Fatal("rejected abort changed durable custody")
	}
	if j.HoldUnversionedCompensation() != nil {
		t.Fatal("unversioned hold failed")
	}
	s, _ = j.Snapshot()
	if s.Phase != "held" || s.Compensation != nil {
		t.Fatal("unversioned hold acquired cleanup authority")
	}
}

func ptrVersion(s string) *string { return &s }
