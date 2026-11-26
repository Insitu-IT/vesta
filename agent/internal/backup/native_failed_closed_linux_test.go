//go:build linux

package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"vnbui/agent/internal/models"
)

func nativeClosedFailureFixture(t *testing.T) (NativePushRequest, NativePushResult, nativeClosedFailure) {
	t.Helper()
	request, result := nativeCaptureFixture(t)
	return request, result, writeNativeClosedFailureFixture(t, request)
}

func writeNativeClosedFailureFixture(t *testing.T, request NativePushRequest) nativeClosedFailure {
	t.Helper()
	hash := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	canonical, _ := models.StorageCanonical(request)
	requestSHA := hash(canonical)
	info, err := os.Stat(filepath.Join(request.OutputPath, "data", "vda.qcow2"))
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	artifact := nativeFailureArtifact{Path: "vda.qcow2", Device: uint64(st.Dev), Inode: st.Ino, Size: st.Size, MtimeNS: st.Mtim.Nano(), CtimeNS: st.Ctim.Nano()}
	ack := nativeBeginReturned{Schema: "libvirt-begin-returned/1", RequestSHA256: requestSHA, JobIDs: []string{"backup-vda-node"}, Targets: map[string][]uint64{"vda": {artifact.Device, artifact.Inode}}}
	ackBody, _ := models.StorageCanonical(ack)
	proof := nativeClosedFailure{Schema: "libvirt-closed-failure/1", RequestSHA256: requestSHA, BackupID: request.BackupID, AttemptID: request.AttemptID, DomainUUID: request.DomainUUID,
		InvocationID: strings.Repeat("b", 32), BeginAckSHA256: hash(ackBody), JobIDs: ack.JobIDs, Artifacts: []nativeFailureArtifact{artifact}}
	for _, state := range []string{"created", "running", "aborting", "concluded", "null"} {
		proof.TerminalEvents = append(proof.TerminalEvents, nativeFailureEvent{ID: "backup-vda-node", Status: state})
	}
	proofBody, _ := models.StorageCanonical(proof)
	begin, _ := models.StorageCanonical(map[string]string{"schema": "libvirt-begin-intent/1", "request_sha256": requestSHA})
	for name, body := range map[string][]byte{"intent.json": canonical, "begin-intent.json": begin, "begin-returned.json": ackBody, "uncertain.json": []byte(`{"reason":"checkpoint interference","state":"uncertain"}`), "producer-closed-failure.json": proofBody} {
		if err := writeNativeFile(filepath.Join(request.OutputPath, name), body); err != nil {
			t.Fatal(err)
		}
	}
	return proof
}

func TestNativeClosedFailureLostAckAndRestartNeverRelaunch(t *testing.T) {
	e, body, job := nativeRunnerFixture(t)
	r := nativeReady(t, e)
	i := job.Intent
	produced, settled := 0, 0
	r.produce = func(_ context.Context, request NativePushRequest) (*NativePushResult, error) {
		produced++
		sealedNativeResult(t, request) // Fixture data only, no successful seal.
		writeNativeClosedFailureFixture(t, request)
		return nil, ErrNativeUncertain
	}
	var original map[string]string
	r.settleClosed = func(_ context.Context, _ string, backup string, binding map[string]string, _ *http.Client, _ func(context.Context) (string, error)) error {
		settled++
		if backup != i.BackupID || binding["intent_sha256"] != job.IntentSHA256 || binding["closure_sha256"] == "" {
			t.Fatal("changed settlement owner")
		}
		if original == nil {
			original = binding
			return errors.New("lost settlement acknowledgement")
		}
		if !reflect.DeepEqual(original, binding) {
			t.Fatal("changed closure on replay")
		}
		return nil
	}
	r.upload = func(context.Context, string, string, string, string, string, []byte, *http.Client, *http.Client, func(context.Context) (string, error)) (*models.StorageAcceptance, error) {
		t.Fatal("partial output uploaded")
		return nil, ErrNativeUncertain
	}
	if err := e.StartNativeJob(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	work := r.work[i.BackupID]
	r.process(work)
	if produced != 1 || settled != 2 || !work.finished || work.held || e.GetProgress(i.BackupID).Status != models.TaskStatusFailed {
		t.Fatal("closure not settled", produced, settled)
	}
	if _, err := os.Stat(filepath.Join(r.root, "attempts", i.AttemptID, "data", "vda.qcow2")); err != nil {
		t.Fatal("partial files removed", err)
	}
	r.cancel()
	r.lock.Close()
	restarted := nativeReady(t, e)
	defer restarted.lock.Close()
	defer restarted.cancel()
	restarted.produce = func(context.Context, NativePushRequest) (*NativePushResult, error) {
		t.Fatal("producer replay")
		return nil, ErrNativeUncertain
	}
	restarted.admit = func(context.Context, string, string, string, string, string, *http.Client, func(context.Context) (string, error)) error {
		t.Fatal("authority readmission")
		return ErrNativeUncertain
	}
	restarted.settleClosed = r.settleClosed
	if len(restarted.queue) != 1 {
		t.Fatal("original request missing")
	}
	if err := restarted.nativeResumeAdmissible(restarted.queue[0]); err != nil {
		t.Fatal("closure resume refused", err)
	}
	restarted.process(restarted.queue[0])
	if produced != 1 || settled != 3 || restarted.queue[0].held {
		t.Fatal("restart changed custody")
	}
}

func TestNativeClosedFailureRetainsOriginalOutputWithoutSuccess(t *testing.T) {
	request, result, _ := nativeClosedFailureFixture(t)
	upload := filepath.Join(t.TempDir(), "absent")
	for n := 0; n < 2; n++ {
		proof, err := readNativeClosedFailure(request.OutputPath, upload, request)
		if err != nil || proof == nil {
			t.Fatal("positive closure refused", err)
		}
	}
	if _, err := readNativeSeal(request.OutputPath, upload, request); err != nil {
		t.Fatal("absent seal is not a successful seal", err)
	}
	if _, err := CaptureNativePush(request, result, strings.Repeat("a", 64), strings.Repeat("b", 32)); err == nil {
		t.Fatal("negative closure admitted partial data")
	}
	if _, err := os.Stat(filepath.Join(request.OutputPath, "data", "vda.qcow2")); err != nil {
		t.Fatal("negative closure removed output", err)
	}
}

func TestNativeClosedFailureRefusesGapsReplacementAndContradictions(t *testing.T) {
	for _, fault := range []string{"request", "ack", "begin", "uncertain", "events", "reuse", "artifact", "replace", "hardlink", "symlink", "admission", "published", "seal", "refusal", "upload"} {
		t.Run(fault, func(t *testing.T) {
			request, _, proof := nativeClosedFailureFixture(t)
			path := request.OutputPath
			upload := filepath.Join(t.TempDir(), "upload")
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			rewrite := false
			switch fault {
			case "request":
				request.TimeoutSeconds++
			case "ack":
				must(os.WriteFile(filepath.Join(path, "begin-returned.json"), []byte(`{}`), 0600))
			case "begin":
				must(os.Remove(filepath.Join(path, "begin-intent.json")))
			case "uncertain":
				must(os.Remove(filepath.Join(path, "uncertain.json")))
			case "events":
				proof.TerminalEvents = proof.TerminalEvents[1:]
				rewrite = true
			case "reuse":
				proof.TerminalEvents = append(proof.TerminalEvents, nativeFailureEvent{ID: proof.JobIDs[0], Status: "created"})
				rewrite = true
			case "artifact":
				proof.Artifacts[0].Inode++
				rewrite = true
			case "replace":
				file := filepath.Join(path, "data", "vda.qcow2")
				body, err := os.ReadFile(file)
				must(err)
				must(os.Rename(file, filepath.Join(t.TempDir(), "retained")))
				must(os.WriteFile(file, body, 0600))
			case "hardlink":
				must(os.Link(filepath.Join(path, "data", "vda.qcow2"), filepath.Join(t.TempDir(), "alias")))
			case "symlink":
				file := filepath.Join(path, "data", "vda.qcow2")
				other := filepath.Join(t.TempDir(), "retained")
				must(os.Rename(file, other))
				must(os.Symlink(other, file))
			case "upload":
				must(os.Mkdir(upload, 0700))
			default:
				names := map[string]string{"admission": "admission.json", "published": "published.json", "seal": "producer-sealed.json", "refusal": "prebegin-refusal.json"}
				must(os.WriteFile(filepath.Join(path, names[fault]), []byte(`{}`), 0600))
			}
			if rewrite {
				body, err := models.StorageCanonical(proof)
				must(err)
				must(os.WriteFile(filepath.Join(path, "producer-closed-failure.json"), body, 0600))
			}
			if _, err := readNativeClosedFailure(path, upload, request); err == nil {
				t.Fatal("ambiguous closure accepted")
			}
		})
	}
}

func TestNativeFailureEventsRequireEachPinnedSingleTerminalCycle(t *testing.T) {
	jobs := []string{"a", "b"}
	events := []nativeFailureEvent{}
	for _, id := range jobs {
		for _, state := range []string{"created", "running", "concluded", "null"} {
			events = append(events, nativeFailureEvent{ID: id, Status: state})
		}
	}
	if !validNativeFailureEvents(jobs, events) {
		t.Fatal("terminal failed writers refused")
	}
	for _, bad := range [][]nativeFailureEvent{events[1:], events[:len(events)-1], append(append([]nativeFailureEvent{}, events...), nativeFailureEvent{ID: "a", Status: "created"}), append(append([]nativeFailureEvent{}, events...), nativeFailureEvent{ID: "foreign", Status: "null"})} {
		if validNativeFailureEvents(jobs, bad) {
			t.Fatal("incomplete/replaced/foreign cycle accepted")
		}
	}
}
