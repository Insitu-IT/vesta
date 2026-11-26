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
	"testing"
	"time"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativestaging"
)

// Mock inspection tests only routing/replay; they do not qualify kernel fences.
func TestNativeFencedFailureLostAckRestartNeverReexecutesProducer(t *testing.T) {
	e, body, job := nativeRunnerFixture(t)
	r := nativeReady(t, e)
	root := t.TempDir()
	r.staging = &nativestaging.Profile{Root: filepath.Join(root, "staging")}
	receipts := filepath.Join(root, "fence-receipts")
	if err := os.Mkdir(receipts, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(receipts, job.Intent.AttemptID+".json"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	request := nativeProducerRequest(job, r.attemptPath(job.Intent.AttemptID))
	original, _ := models.StorageCanonical(request)
	digest := sha256.Sum256(original)
	proof := nativeFencedFailure{Schema: "libvirt-failed-output-fence/1", RequestSHA256: hex.EncodeToString(digest[:]),
		TargetBindingSHA256: "binding", Directory: []uint64{10, 1}, DataDirectory: []uint64{10, 2}, Artifacts: []nativeFencedArtifact{}}
	encoded, _ := models.StorageCanonical(proof)
	old := nativeFenceHelper
	nativeFenceHelper = "import json, sys\nMAX_JSON=4194304\ndef require(value, message):\n    assert value, message\ndef canonical(value):\n    return json.dumps(value).encode()\ndef read_fence_receipt(root, request):\n    return json.loads(" + "'" + string(encoded) + "'" + ")\n"
	t.Cleanup(func() { nativeFenceHelper = old })
	produced, admitted, settled := 0, 0, 0
	r.produce = func(context.Context, NativePushRequest) (*NativePushResult, error) {
		produced++
		return nil, ErrNativeUncertain
	}
	r.admit = func(context.Context, string, string, string, string, string, *http.Client, func(context.Context) (string, error)) error {
		admitted++
		return ErrNativeUncertain
	}
	var binding map[string]string
	r.settleFenced = func(_ context.Context, _ string, _ string, value map[string]string, _ *http.Client, _ func(context.Context) (string, error)) error {
		settled++
		if binding == nil {
			binding = value
			return errors.New("lost acknowledgement")
		}
		if !reflect.DeepEqual(binding, value) {
			t.Fatal("replay changed original proof")
		}
		return nil
	}
	if err := writeNativeFile(filepath.Join(r.root, "requests", job.Intent.AttemptID+".json"), body); err != nil {
		t.Fatal(err)
	}
	work := &nativeWork{request: job, body: body}
	r.process(work)
	if produced != 0 || admitted != 0 || settled != 2 || !work.finished || work.held {
		t.Fatal("fenced failure not settled without effects")
	}
	r.cancel()
	r.lock.Close()
	restarted := nativeReady(t, e)
	defer restarted.cancel()
	defer restarted.lock.Close()
	restarted.staging = r.staging
	restarted.produce, restarted.admit, restarted.settleFenced = r.produce, r.admit, r.settleFenced
	if len(restarted.queue) != 1 {
		t.Fatal("original request lost")
	}
	if err := restarted.nativeResumeAdmissible(restarted.queue[0]); err != nil {
		t.Fatal(err)
	}
	restarted.process(restarted.queue[0])
	if produced != 0 || admitted != 0 || settled != 3 || restarted.queue[0].held {
		t.Fatal("restart reexecuted effects or changed proof")
	}
}

func TestNativeFenceInspectionEntryRejectsPrivilegedDispatch(t *testing.T) {
	for _, action := range []string{"fence", "allocate", "backup", "restore"} {
		var result any
		if err := runNativeHelperSource(context.Background(), nativeFenceHelper+nativeFenceInspectEntry, action, map[string]any{}, &result); err == nil {
			t.Fatal("privileged helper action accepted", action)
		}
	}
}

func TestNativeFencedFailureCallbackUnavailableRetainsCustody(t *testing.T) {
	e, body, job := nativeRunnerFixture(t)
	r := nativeReady(t, e)
	defer r.cancel()
	defer r.lock.Close()
	r.settleFenced = func(context.Context, string, string, map[string]string, *http.Client, func(context.Context) (string, error)) error {
		return errors.New("backend unavailable")
	}
	work := &nativeWork{request: job, body: body}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	r.finishFencedFailure(ctx, work, &nativeFencedFailure{Schema: "fixture"})
	if !work.held || !work.finished || e.GetProgress(job.Intent.BackupID).Status != models.TaskStatusCleanupRequired {
		t.Fatal("unacknowledged failure lost custody")
	}
}
