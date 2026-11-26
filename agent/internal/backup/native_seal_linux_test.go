//go:build linux

package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

func writeNativeSealFixture(t *testing.T, request NativePushRequest, result NativePushResult) nativeProducerSeal {
	t.Helper()
	canonical, _ := models.StorageCanonical(request)
	digest := sha256.Sum256(canonical)
	seal := nativeProducerSeal{Schema: "libvirt-producer-seal/1", RequestSHA256: hex.EncodeToString(digest[:]), InvocationID: strings.Repeat("b", 32), Result: result}
	for name, body := range map[string][]byte{"intent.json": canonical, "begin-intent.json": nil} {
		if name == "begin-intent.json" {
			body, _ = models.StorageCanonical(map[string]string{"schema": "libvirt-begin-intent/1", "request_sha256": seal.RequestSHA256})
		}
		if err := writeNativeFile(filepath.Join(request.OutputPath, name), body); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(NativePushTree(request.OutputPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		path := filepath.Join(NativePushTree(request.OutputPath), entry.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		st := info.Sys().(*syscall.Stat_t)
		hash := sha256.Sum256(body)
		seal.Artifacts = append(seal.Artifacts, nativeSealedArtifact{Path: entry.Name(), Device: uint64(st.Dev), Inode: st.Ino, Size: st.Size, MtimeNS: st.Mtim.Nano(), CtimeNS: st.Ctim.Nano(), SHA256: hex.EncodeToString(hash[:])})
	}
	body, _ := models.StorageCanonical(seal)
	if err := writeNativeFile(filepath.Join(request.OutputPath, "producer-sealed.json"), body); err != nil {
		t.Fatal(err)
	}
	return seal
}

func TestNativePositiveSealRecoversExactCaptureWithoutProducer(t *testing.T) {
	request, result := nativeCaptureFixture(t)
	writeNativeSealFixture(t, request, result)
	seal, err := readNativeSeal(request.OutputPath, filepath.Join(t.TempDir(), "absent-upload"), request)
	if err != nil || seal == nil {
		t.Fatal("positive seal refused", err)
	}
	body, err := captureNativeSeal(request, seal, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal("positive seal capture failed", err)
	}
	var closed storageupload.ClosedNativeAdmission
	if json.Unmarshal(body, &closed) != nil || closed.ClosedJob.State != "sealed" || closed.ClosedJob.InvocationID != seal.InvocationID {
		t.Fatal("recovered seal invented process-exit custody")
	}
	if _, err := captureNativeSeal(request, seal, strings.Repeat("a", 64)); err == nil {
		t.Fatal("recovery replaced original admission")
	}
}

func TestNativeSealRejectsAmbiguousOrReplacedCustody(t *testing.T) {
	for _, fault := range []string{"request", "parent", "manifest", "replace-identical", "changed-bytes", "hardlink", "symlink", "missing", "extra", "seal", "begin", "refusal", "uncertain", "upload"} {
		t.Run(fault, func(t *testing.T) {
			request, result := nativeCaptureFixture(t)
			writeNativeSealFixture(t, request, result)
			path := request.OutputPath
			payload := filepath.Join(NativePushTree(path), "vda.qcow2")
			upload := filepath.Join(t.TempDir(), "upload")
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch fault {
			case "request":
				request.TimeoutSeconds++
			case "parent":
				request.Parent = &result
			case "manifest":
				must(os.WriteFile(filepath.Join(NativePushTree(path), "manifest.json"), []byte("{}"), 0600))
			case "replace-identical":
				original, err := os.ReadFile(payload)
				must(err)
				must(os.Rename(payload, filepath.Join(t.TempDir(), "retained")))
				must(os.WriteFile(payload, original, 0600))
			case "changed-bytes":
				must(os.WriteFile(payload, []byte("wrong producer payload!"), 0600))
			case "hardlink":
				must(os.Link(payload, filepath.Join(t.TempDir(), "alias")))
			case "symlink":
				target := filepath.Join(t.TempDir(), "original")
				must(os.Rename(payload, target))
				must(os.Symlink(target, payload))
			case "missing":
				must(os.Rename(payload, filepath.Join(t.TempDir(), "retained")))
			case "extra":
				must(os.WriteFile(filepath.Join(NativePushTree(path), "foreign"), []byte("retain"), 0600))
			case "seal":
				must(os.WriteFile(filepath.Join(path, "producer-sealed.json"), []byte("{}"), 0600))
			case "begin":
				must(os.WriteFile(filepath.Join(path, "begin-intent.json"), []byte("{}"), 0600))
			case "refusal":
				must(os.WriteFile(filepath.Join(path, "prebegin-refusal.json"), []byte("{}"), 0600))
			case "uncertain":
				must(os.WriteFile(filepath.Join(path, "uncertain.json"), []byte("{}"), 0600))
			case "upload":
				must(os.Mkdir(upload, 0700))
			}
			if _, err := readNativeSeal(path, upload, request); err == nil {
				t.Fatal("ambiguous closure was recovered")
			}
			if _, err := os.Stat(filepath.Join(path, "admission.json")); !os.IsNotExist(err) {
				t.Fatal("refused closure manufactured admission")
			}
		})
	}
}

func TestNativeSealRecoversRestartAndLostHelperResponse(t *testing.T) {
	for _, restart := range []bool{true, false} {
		t.Run(map[bool]string{true: "restart", false: "lost-response"}[restart], func(t *testing.T) {
			e, body, original := nativeRunnerFixture(t)
			r := nativeReady(t, e)
			if err := e.StartNativeJob(context.Background(), body); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(r.root, "attempts", original.Intent.AttemptID)
			request := nativeProducerRequest(original, path)
			if restart {
				result := sealedNativeResult(t, request)
				writeNativeSealFixture(t, request, *result)
				r.cancel()
				if err := r.lock.Close(); err != nil {
					t.Fatal(err)
				}
				r = nativeReady(t, e)
				r.produce = func(context.Context, NativePushRequest) (*NativePushResult, error) {
					t.Fatal("relaunched sealed producer")
					return nil, ErrNativeUncertain
				}
			} else {
				r.produce = func(_ context.Context, p NativePushRequest) (*NativePushResult, error) {
					result := sealedNativeResult(t, p)
					writeNativeSealFixture(t, p, *result)
					return nil, ErrNativeUncertain
				}
			}
			defer r.cancel()
			defer r.lock.Close()
			work := r.work[original.Intent.BackupID]
			r.queue = nil
			if restart {
				work.finished, work.held = true, true
				if err := e.StartNativeJob(context.Background(), body); err != nil {
					t.Fatal("seal exact resume refused", err)
				}
				if err := e.StartNativeJob(context.Background(), body); err != nil || len(r.queue) != 1 {
					t.Fatal("duplicate seal resume", err)
				}
				r.queue = nil
			}
			uploads := 0
			r.upload = func(_ context.Context, _, _, _, _, _ string, admission []byte, _, _ *http.Client, _ func(context.Context) (string, error)) (*models.StorageAcceptance, error) {
				var closed storageupload.ClosedNativeAdmission
				if json.Unmarshal(admission, &closed) != nil || closed.ClosedJob.State != "sealed" {
					t.Fatal("seal custody not retained")
				}
				uploads++
				return nil, storageupload.ErrHeld // Keep files for exact custody assertions.
			}
			r.process(work)
			if uploads != 1 || !work.held {
				t.Fatal("sealed attempt did not reach original upload once")
			}
			if _, err := os.Stat(filepath.Join(path, "admission.json")); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(path, "data", "vda.qcow2")); err != nil {
				t.Fatal("held upload lost payload", err)
			}
		})
	}
}

func TestNativeAtomicAdmissionNeverReplacesPartialCustody(t *testing.T) {
	request, result := nativeCaptureFixture(t)
	path := filepath.Join(request.OutputPath, "admission.json")
	if err := os.WriteFile(path, []byte("partial existing custody"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureNativePush(request, result, strings.Repeat("a", 64), strings.Repeat("b", 32)); err == nil {
		t.Fatal("overwrote existing admission")
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "partial existing custody" {
		t.Fatal("changed existing custody")
	}
}

func TestNativeAdmissionCrashRetainedPrivateAliasResumesClosedCustody(t *testing.T) {
	request, result := nativeCaptureFixture(t)
	body, err := CaptureNativePush(request, result, strings.Repeat("a", 64), strings.Repeat("b", 32))
	if err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(request.OutputPath, "admission.json")
	alias := filepath.Join(request.OutputPath, ".admission-crash.tmp")
	// Model death after Link + directory fsync, before unlinking the owned temp.
	if err := os.Link(final, alias); err != nil {
		t.Fatal(err)
	}
	if err := syncNativeDirectory(request.OutputPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(final)
	if err != nil || info.Sys().(*syscall.Stat_t).Nlink != 2 {
		t.Fatal("crash alias not constructed", err)
	}
	saved, err := readNativeFile(final)
	if err != nil || !bytes.Equal(saved, body) {
		t.Fatal("closed immutable admission could not be read", err)
	}
	if err := storageupload.CanResumeClosedNative(t.TempDir(), NativePushTree(request.OutputPath), "org", "agent", saved); err != nil {
		t.Fatal("private crash alias blocked closed upload resume", err)
	}
	if _, err := os.Stat(alias); err != nil {
		t.Fatal("resume unexpectedly deleted alias", err)
	}
}

func TestNativeSealHashesPayloadRatherThanTrustingMatchingStat(t *testing.T) {
	request, result := nativeCaptureFixture(t)
	result.Manifest.Disks[0].SHA256 = strings.Repeat("a", 64)
	manifest, _ := models.StorageCanonical(result.Manifest)
	hash := sha256.Sum256(manifest)
	result.ManifestSHA256 = hex.EncodeToString(hash[:])
	if err := os.WriteFile(filepath.Join(NativePushTree(request.OutputPath), "manifest.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	seal := writeNativeSealFixture(t, request, result)
	for index := range seal.Artifacts {
		if seal.Artifacts[index].Path == "vda.qcow2" {
			seal.Artifacts[index].SHA256 = result.Manifest.Disks[0].SHA256
		}
	}
	body, _ := models.StorageCanonical(seal)
	if err := os.WriteFile(filepath.Join(request.OutputPath, "producer-sealed.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readNativeSeal(request.OutputPath, filepath.Join(t.TempDir(), "upload"), request); err == nil {
		t.Fatal("matching artifact stat and manifest bypassed actual payload digest")
	}
}

func TestNativeSealNeverRepairsExistingCorruptAdmission(t *testing.T) {
	e, body, original := nativeRunnerFixture(t)
	r := nativeReady(t, e)
	defer r.cancel()
	defer r.lock.Close()
	if err := e.StartNativeJob(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(r.root, "attempts", original.Intent.AttemptID)
	request := nativeProducerRequest(original, path)
	result := sealedNativeResult(t, request)
	writeNativeSealFixture(t, request, *result)
	admission := filepath.Join(path, "admission.json")
	if err := os.WriteFile(admission, []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	r.produce = func(context.Context, NativePushRequest) (*NativePushResult, error) {
		t.Fatal("replayed producer")
		return nil, ErrNativeUncertain
	}
	r.upload = func(context.Context, string, string, string, string, string, []byte, *http.Client, *http.Client, func(context.Context) (string, error)) (*models.StorageAcceptance, error) {
		t.Fatal("uploaded corrupt custody")
		return nil, storageupload.ErrHeld
	}
	work := r.work[original.Intent.BackupID]
	r.queue = nil
	r.process(work)
	retained, err := os.ReadFile(admission)
	if err != nil || string(retained) != "partial" || !work.held {
		t.Fatal("recovery overwrote corrupt custody", err)
	}
}
