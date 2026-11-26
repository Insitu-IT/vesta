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

	"vnbui/agent/internal/models"
)

func writeNativeRefusalFixture(t *testing.T, request NativePushRequest) {
	t.Helper()
	if err := os.MkdirAll(request.OutputPath, 0711); err != nil {
		t.Fatal(err)
	}
	body, err := models.StorageCanonical(request)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeNativeFile(filepath.Join(request.OutputPath, "intent.json"), body); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(body)
	proof := nativePreBeginRefusal{Schema: "libvirt-prebegin-refusal/1", RequestSHA256: hex.EncodeToString(h[:]), BackupID: request.BackupID, AttemptID: request.AttemptID, DomainUUID: request.DomainUUID, Reason: "another hypervisor job is active"}
	body, err = models.StorageCanonical(proof)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeNativeFile(filepath.Join(request.OutputPath, "prebegin-refusal.json"), body); err != nil {
		t.Fatal(err)
	}
}

func TestNativePrebeginSettlementLostAckAndRestartNeverRelaunch(t *testing.T) {
	e, body, job := nativeRunnerFixture(t)
	r := nativeReady(t, e)
	i := job.Intent
	produced, settled := 0, 0
	r.produce = func(_ context.Context, request NativePushRequest) (*NativePushResult, error) {
		produced++
		writeNativeRefusalFixture(t, request)
		return nil, ErrNativeUncertain
	}
	var original map[string]string
	r.settle = func(_ context.Context, _ string, backup string, binding map[string]string, _ *http.Client, _ func(context.Context) (string, error)) error {
		settled++
		if backup != i.BackupID || binding["intent_sha256"] != job.IntentSHA256 {
			t.Fatal("changed settlement owner")
		}
		if original == nil {
			original = binding
			return errors.New("lost settlement acknowledgement")
		}
		if !reflect.DeepEqual(original, binding) {
			t.Fatal("settlement retry changed evidence")
		}
		return nil
	}
	if err := e.StartNativeJob(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	work := r.work[i.BackupID]
	r.process(work)
	if produced != 1 || settled != 2 || !work.finished || work.held || e.GetProgress(i.BackupID).Status != models.TaskStatusFailed {
		t.Fatal("refusal not settled exactly", produced, settled)
	}
	r.cancel()
	r.lock.Close()
	restarted := nativeReady(t, e)
	defer restarted.lock.Close()
	defer restarted.cancel()
	restarted.produce = func(context.Context, NativePushRequest) (*NativePushResult, error) {
		t.Fatal("restarted producer")
		return nil, ErrNativeUncertain
	}
	restarted.admit = func(context.Context, string, string, string, string, string, *http.Client, func(context.Context) (string, error)) error {
		t.Fatal("negative settlement re-admitted authority")
		return ErrNativeUncertain
	}
	restarted.settle = r.settle
	if len(restarted.queue) != 1 {
		t.Fatal("original request missing on restart")
	}
	restarted.process(restarted.queue[0])
	if produced != 1 || settled != 3 || restarted.queue[0].held {
		t.Fatal("restart changed refusal custody")
	}
}

func TestNativeNoEffectRejectsContradictoryCustody(t *testing.T) {
	for _, contradiction := range []string{"begin-intent.json", "producer-sealed.json", "admission.json", "data/manifest.json", "upload"} {
		t.Run(contradiction, func(t *testing.T) {
			_, _, job := nativeRunnerFixture(t)
			i := job.Intent
			path := filepath.Join(t.TempDir(), "attempt")
			request := NativePushRequest{Schema: NativePushFormat, URI: "qemu:///system", BackupID: i.BackupID, AttemptID: i.AttemptID, DomainUUID: i.Source.DomainUUID, Disks: i.Source.Disks, Exclusions: i.Source.Exclusions, OutputPath: path, TimeoutSeconds: 86400}
			writeNativeRefusalFixture(t, request)
			upload := filepath.Join(t.TempDir(), "upload")
			if proof, err := readNativeNoEffect(path, upload, request); err != nil || proof == nil {
				t.Fatal("valid proof refused", err)
			}
			target := filepath.Join(path, contradiction)
			if contradiction == "upload" {
				target = upload
			}
			if err := os.MkdirAll(filepath.Dir(target), 0711); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte("uncertain"), 0600); err != nil {
				t.Fatal(err)
			}
			if proof, err := readNativeNoEffect(path, upload, request); err == nil || proof != nil {
				t.Fatal("contradictory evidence settled")
			}
		})
	}
}
