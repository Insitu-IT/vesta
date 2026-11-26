//go:build linux

package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeRestartRetainsProducerFilesWithoutClosedAdmission(t *testing.T) {
	for _, manifestDurable := range []bool{false, true} {
		t.Run(map[bool]string{false: "after-begin", true: "after-manifest"}[manifestDurable], func(t *testing.T) {
			e, body, original := nativeRunnerFixture(t)
			r := nativeReady(t, e)
			if err := e.StartNativeJob(context.Background(), body); err != nil {
				t.Fatal(err)
			}
			i := original.Intent
			path := filepath.Join(r.root, "attempts", i.AttemptID)
			request := NativePushRequest{Schema: NativePushFormat, URI: "qemu:///system", BackupID: i.BackupID,
				AttemptID: i.AttemptID, DomainUUID: i.Source.DomainUUID, Disks: i.Source.Disks,
				Exclusions: i.Source.Exclusions, OutputPath: path, TimeoutSeconds: 60}
			files := []string{"intent.json", "data/vda.qcow2"}
			if manifestDurable {
				sealedNativeResult(t, request) // Producer manifest is not an upload admission.
				files = append(files, "data/manifest.json", "data/checkpoint.xml", "data/domain.xml")
			} else {
				if err := os.MkdirAll(NativePushTree(path), 0711); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(NativePushTree(path), "vda.qcow2"), []byte("partial producer output"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			intent, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(path, "intent.json"), intent, 0600); err != nil {
				t.Fatal(err)
			}
			before := make(map[string][]byte)
			for _, name := range files {
				before[name], err = os.ReadFile(filepath.Join(path, name))
				if err != nil {
					t.Fatal(err)
				}
			}
			r.cancel()
			if err = r.lock.Close(); err != nil {
				t.Fatal(err)
			}
			// Reconstruct the runner from its durable request, not an in-memory hold.
			restarted := nativeReady(t, e)
			defer restarted.cancel()
			defer restarted.lock.Close()
			if len(restarted.queue) != 1 {
				t.Fatal("original durable request was not recovered")
			}
			work := restarted.queue[0]
			restarted.queue = nil
			restarted.produce = func(context.Context, NativePushRequest) (*NativePushResult, error) {
				t.Fatal("restart relaunched a producer with existing custody")
				return nil, ErrNativeUncertain
			}
			restarted.process(work)
			if !work.finished || !work.held || len(restarted.queue) != 0 {
				t.Fatal("producer uncertainty was not held")
			}
			if err = e.StartNativeJob(context.Background(), body); err == nil || len(restarted.queue) != 0 {
				t.Fatal("exact retry bypassed missing closed admission")
			}
			for name, originalBody := range before {
				after, readErr := os.ReadFile(filepath.Join(path, name))
				if readErr != nil || !bytes.Equal(after, originalBody) {
					t.Fatalf("restart changed retained producer file %s: %v", name, readErr)
				}
			}
			if _, err = os.Stat(filepath.Join(path, "admission.json")); !os.IsNotExist(err) {
				t.Fatal("restart synthesized a closed admission", err)
			}
		})
	}
}

func TestNativeExactResumeRequiresDurableClosedAdmission(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unsealed", true: "closed"}[closed], func(t *testing.T) {
			e, body, original := nativeRunnerFixture(t)
			r := nativeReady(t, e)
			defer r.cancel()
			defer r.lock.Close()
			if err := e.StartNativeJob(context.Background(), body); err != nil {
				t.Fatal(err)
			}
			i := original.Intent
			path := filepath.Join(r.root, "attempts", i.AttemptID)
			if closed {
				request := NativePushRequest{Schema: NativePushFormat, URI: "qemu:///system", BackupID: i.BackupID,
					AttemptID: i.AttemptID, DomainUUID: i.Source.DomainUUID, Disks: i.Source.Disks,
					Exclusions: i.Source.Exclusions, OutputPath: path, TimeoutSeconds: 60}
				result := sealedNativeResult(t, request)
				if _, err := CaptureNativePush(request, *result, original.IntentSHA256, strings.Repeat("a", 32)); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(path, 0711); err != nil {
				t.Fatal(err)
			}
			work := r.work[i.BackupID]
			r.queue = nil
			work.finished, work.held = true, true
			err := e.StartNativeJob(context.Background(), body)
			if !closed {
				if err == nil || len(r.queue) != 0 || !work.held {
					t.Fatal("native pre-admission uncertainty relaunched a producer")
				}
				return
			}
			if err != nil || len(r.queue) != 1 || r.queue[0] != work || work.held {
				t.Fatal("closed original native attempt not resumed", err)
			}
			if err := e.StartNativeJob(context.Background(), body); err != nil || len(r.queue) != 1 {
				t.Fatal("native resume enqueued twice", err)
			}
		})
	}
}
