//go:build linux

package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/storageupload"
)

func nativeRunnerFixture(t *testing.T) (*Executor, []byte, *NativeJobRequest) {
	t.Helper()
	actor := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	i := NativeJobIntent{Schema: 1, OrgID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ActorID: &actor, BackupID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", AgentID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", AttemptID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", Producer: NativePushFormat}
	i.JobID = "vnbui-native-" + i.AttemptID
	i.Checkpoint = "vnbui-" + i.AttemptID
	i.Target = NativeJobTarget{Endpoint: "https://fixture.invalid", Bucket: "backups", Region: "test", CapabilityProfile: "db-rooted-consumer-verified/1"}
	i.Encryption = models.StorageEncryption{Format: "none"}
	i.Source = NativeJobSource{VMID: "ffffffff-ffff-4fff-8fff-ffffffffffff", DomainUUID: "11111111-1111-4111-8111-111111111111", AgentID: i.AgentID, Disks: []NativeSourceDisk{{Target: "vda", Source: "/vm/vda.qcow2", Bus: "virtio", Format: "qcow2"}}, Exclusions: []string{}, BackupType: "full"}
	body, _ := models.StorageCanonical(i)
	hash := sha256.Sum256(body)
	r := &NativeJobRequest{Protocol: "vnbui-native-job/1", Intent: i, IntentSHA256: hex.EncodeToString(hash[:])}
	body, _ = json.Marshal(r)
	cfg := &config.Config{AgentID: i.AgentID, AgentAPIKey: "agent-fixture", OrchestratorAPIKey: "control-fixture", EnableAPIKeyValidation: true, OrchestratorVerifySSL: true, OrchestratorURL: "https://orchestrator.example", LibvirtURI: "qemu:///system", BackupStoragePath: t.TempDir()}
	return NewExecutor(cfg, resources.New(1, 1)), body, r
}

func nativeReady(t *testing.T, e *Executor) *nativeRunner {
	t.Helper()
	r, err := newNativeRunner(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	r.retry = time.Millisecond
	r.admit = func(context.Context, string, string, string, string, string, *http.Client, func(context.Context) (string, error)) error {
		return nil
	}
	e.nativeRunner = r
	return r
}

func TestNativeJobOrganizationAuthorityHasNoHumanActor(t *testing.T) {
	_, _, request := nativeRunnerFixture(t)
	request.Intent.ActorID = nil
	canonical, _ := models.StorageCanonical(request.Intent)
	hash := sha256.Sum256(canonical)
	request.IntentSHA256 = hex.EncodeToString(hash[:])
	body, _ := json.Marshal(request)
	decoded, err := DecodeNativeJob(body)
	if err != nil || decoded.Intent.ActorID != nil {
		t.Fatal("organization native intent rejected", err)
	}
	// Changing the principal never preserves the committed request digest.
	actor := "other"
	request.Intent.ActorID = &actor
	body, _ = json.Marshal(request)
	if _, err := DecodeNativeJob(body); err == nil {
		t.Fatal("changed actor retained original intent")
	}
}

func nativeWait(t *testing.T, e *Executor, backup string, want models.TaskStatus) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		p := e.GetProgress(backup)
		if p != nil && p.Status == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("native runner did not reach", want)
}

func sealedNativeResult(t *testing.T, request NativePushRequest) *NativePushResult {
	t.Helper()
	if err := os.Mkdir(request.OutputPath, 0711); err != nil {
		t.Fatal(err)
	}
	tree := NativePushTree(request.OutputPath)
	if err := os.Mkdir(tree, 0711); err != nil {
		t.Fatal(err)
	}
	digest := func(value string) string { h := sha256.Sum256([]byte(value)); return hex.EncodeToString(h[:]) }
	m := NativePushManifest{Schema: NativePushFormat, BackupID: request.BackupID, AttemptID: request.AttemptID, DomainUUID: request.DomainUUID, Checkpoint: "vnbui-" + request.AttemptID, CheckpointSHA256: digest("checkpoint"), DomainXMLSHA256: digest("domain"), Source: request.Disks, Exclusions: request.Exclusions, Disks: []NativePushDisk{{Target: "vda", File: "vda.qcow2", SizeBytes: 4, VirtualSize: 1048576, SHA256: digest("disk")}}}
	canonical, _ := models.StorageCanonical(m)
	for file, body := range map[string][]byte{"domain.xml": []byte("domain"), "checkpoint.xml": []byte("checkpoint"), "manifest.json": canonical, "vda.qcow2": []byte("disk")} {
		if err := os.WriteFile(filepath.Join(tree, file), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	h := sha256.Sum256(canonical)
	return &NativePushResult{Manifest: m, ManifestSHA256: hex.EncodeToString(h[:])}
}

func TestNativeRunnerPersistsThenCapturesUploadsPublishesAndRecovers(t *testing.T) {
	e, body, request := nativeRunnerFixture(t)
	var produced, uploaded, published, events atomic.Int32
	e.SetEventCallback(func(map[string]interface{}) { events.Add(1) })
	configure := func(r *nativeRunner) {
		r.produce = func(ctx context.Context, p NativePushRequest) (*NativePushResult, error) {
			produced.Add(1)
			if _, err := readNativeFile(filepath.Join(r.root, "requests", p.AttemptID+".json")); err != nil {
				t.Error("effect preceded durable intent")
			}
			return sealedNativeResult(t, p), nil
		}
		r.upload = func(ctx context.Context, journal, tree, org, agent, base string, admission []byte, b, s *http.Client, key func(context.Context) (string, error)) (*models.StorageAcceptance, error) {
			uploaded.Add(1)
			var closed storageupload.ClosedNativeAdmission
			if models.DecodeStorageValue(admission, &closed, models.MaxStorageRequestBytes) != nil || closed.IntentSHA256 != request.IntentSHA256 {
				t.Error("capture did not cross strict admission")
			}
			return &models.StorageAcceptance{Accepted: true, ReservationID: request.Intent.AttemptID,
				ReceiptSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				AcceptanceID:  "accepted-fixture"}, nil
		}
		r.publish = func(context.Context, string, string, *models.StorageAcceptance, *http.Client, func(context.Context) (string, error)) error {
			published.Add(1)
			return nil
		}
	}
	r := nativeReady(t, e)
	configure(r)
	go r.run()
	if err := e.StartNativeJob(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	nativeWait(t, e, request.Intent.BackupID, models.TaskStatusCompleted)
	if err := e.StartNativeJob(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	if err := e.CloseStorageTransactions(); err != nil {
		t.Fatal(err)
	}
	if produced.Load() != 1 || uploaded.Load() != 1 || published.Load() != 1 || events.Load() != 0 {
		t.Fatal("wrong connected lifecycle", produced.Load(), uploaded.Load(), published.Load(), events.Load())
	}
	path := filepath.Join(r.root, "attempts", request.Intent.AttemptID)
	if _, err := os.Stat(NativePushTree(path)); !os.IsNotExist(err) {
		t.Fatal("published native producer files were retained", err)
	}
	if _, err := readNativeFile(nativePublishedPath(path)); err != nil {
		t.Fatal("published native marker was not durable", err)
	}
	second := NewExecutor(e.cfg, resources.New(1, 1))
	r = nativeReady(t, second)
	configure(r)
	go r.run()
	nativeWait(t, second, request.Intent.BackupID, models.TaskStatusCompleted)
	if err := second.CloseStorageTransactions(); err != nil {
		t.Fatal(err)
	}
	if produced.Load() != 1 || uploaded.Load() != 1 || published.Load() != 1 {
		t.Fatal("restart repeated a durably published native attempt")
	}
}

func TestNativeRunnerUncertainProducerNeverRelaunches(t *testing.T) {
	e, body, request := nativeRunnerFixture(t)
	r := nativeReady(t, e)
	if err := e.StartNativeJob(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(r.root, "attempts", request.Intent.AttemptID), 0711); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	r.produce = func(context.Context, NativePushRequest) (*NativePushResult, error) {
		calls.Add(1)
		return nil, ErrNativeUncertain
	}
	go r.run()
	nativeWait(t, e, request.Intent.BackupID, models.TaskStatusCleanupRequired)
	if err := e.CloseStorageTransactions(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("interrupted producer was relaunched")
	}
}

func TestNativeRunnerHeldUploadStopsRetryingAndRetainsCapture(t *testing.T) {
	e, body, request := nativeRunnerFixture(t)
	r := nativeReady(t, e)
	var produced, uploaded, published atomic.Int32
	r.produce = func(_ context.Context, p NativePushRequest) (*NativePushResult, error) {
		produced.Add(1)
		return sealedNativeResult(t, p), nil
	}
	r.upload = func(context.Context, string, string, string, string, string, []byte, *http.Client, *http.Client, func(context.Context) (string, error)) (*models.StorageAcceptance, error) {
		uploaded.Add(1)
		return nil, errors.Join(errors.New("upload cannot resume"), storageupload.ErrHeld)
	}
	r.publish = func(context.Context, string, string, *models.StorageAcceptance, *http.Client, func(context.Context) (string, error)) error {
		published.Add(1)
		return nil
	}
	go r.run()
	if err := e.StartNativeJob(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	nativeWait(t, e, request.Intent.BackupID, models.TaskStatusCleanupRequired)
	// An identical delivery cannot restart a held in-process attempt.
	if observations := e.NativeHoldEvents(); len(observations) != 1 || observations[0]["attempt_id"] != request.Intent.AttemptID || observations[0]["reason"] != "native_upload_held" {
		t.Fatal("held upload not visible with exact identity", observations)
	}
	if err := e.StartNativeJob(context.Background(), body); !errors.Is(err, ErrNativeUncertain) {
		t.Fatal("held upload replay was not refused", err)
	}
	if err := e.CloseStorageTransactions(); err != nil {
		t.Fatal(err)
	}
	if produced.Load() != 1 || uploaded.Load() != 1 || published.Load() != 0 {
		t.Fatal("held upload retried or published", produced.Load(), uploaded.Load(), published.Load())
	}
	path := filepath.Join(r.root, "attempts", request.Intent.AttemptID)
	for _, name := range []string{"admission.json", "data/manifest.json", "data/vda.qcow2"} {
		if _, err := os.Stat(filepath.Join(path, name)); err != nil {
			t.Fatal("held capture lost", name, err)
		}
	}
	if _, err := os.Stat(nativePublishedPath(path)); !os.IsNotExist(err) {
		t.Fatal("held upload acquired publication marker", err)
	}
}

func TestNativeRunnerRestartRetainsPostBeginAttempt(t *testing.T) {
	e, body, request := nativeRunnerFixture(t)
	first := nativeReady(t, e)
	if err := e.StartNativeJob(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	// Model abrupt helper loss after backupBegin: its durable intent, checkpoint
	// and still-possibly-writable output exist, but no closed admission does.
	path := filepath.Join(first.root, "attempts", request.Intent.AttemptID)
	if err := os.Mkdir(path, 0711); err != nil {
		t.Fatal(err)
	}
	producer := NativePushRequest{Schema: NativePushFormat, URI: "qemu:///system", BackupID: request.Intent.BackupID, AttemptID: request.Intent.AttemptID, DomainUUID: request.Intent.Source.DomainUUID, Disks: request.Intent.Source.Disks, Exclusions: request.Intent.Source.Exclusions, OutputPath: path, TimeoutSeconds: 120}
	intent, err := json.Marshal(producer)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeNativeFile(filepath.Join(path, "intent.json"), intent); err != nil {
		t.Fatal(err)
	}
	tree := NativePushTree(path)
	if err := os.Mkdir(tree, 0711); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(tree, "vda.qcow2")
	if err := os.WriteFile(partial, []byte("still possibly writable"), 0600); err != nil {
		t.Fatal(err)
	}
	first.cancel()
	if err := first.lock.Close(); err != nil {
		t.Fatal(err)
	}

	second := NewExecutor(e.cfg, resources.New(1, 1))
	r := nativeReady(t, second)
	var admissions, effects, uploads, publications atomic.Int32
	r.admit = func(context.Context, string, string, string, string, string, *http.Client, func(context.Context) (string, error)) error {
		admissions.Add(1)
		return nil
	}
	r.produce = func(context.Context, NativePushRequest) (*NativePushResult, error) {
		effects.Add(1)
		return nil, ErrNativeUncertain
	}
	r.upload = func(context.Context, string, string, string, string, string, []byte, *http.Client, *http.Client, func(context.Context) (string, error)) (*models.StorageAcceptance, error) {
		uploads.Add(1)
		return nil, ErrNativeUncertain
	}
	r.publish = func(context.Context, string, string, *models.StorageAcceptance, *http.Client, func(context.Context) (string, error)) error {
		publications.Add(1)
		return ErrNativeUncertain
	}
	go r.run()
	nativeWait(t, second, request.Intent.BackupID, models.TaskStatusCleanupRequired)
	if observations := second.NativeHoldEvents(); len(observations) != 1 || observations[0]["attempt_id"] != request.Intent.AttemptID || observations[0]["intent_sha256"] != request.IntentSHA256 {
		t.Fatal("restart lost exact hold observation", observations)
	}
	if err := second.StartNativeJob(context.Background(), body); !errors.Is(err, ErrNativeUncertain) {
		t.Fatal("held attempt was resumable without closed admission", err)
	}
	if err := second.CloseStorageTransactions(); err != nil {
		t.Fatal(err)
	}
	if admissions.Load() != 0 || effects.Load() != 0 || uploads.Load() != 0 || publications.Load() != 0 {
		t.Fatal("post-begin restart repeated an effect", admissions.Load(), effects.Load(), uploads.Load(), publications.Load())
	}
	retained, err := os.ReadFile(partial)
	if err != nil || string(retained) != "still possibly writable" {
		t.Fatal("uncertain output changed", err)
	}
	if _, err := readNativeFile(filepath.Join(path, "intent.json")); err != nil {
		t.Fatal("durable producer intent lost", err)
	}
	if _, err := os.Lstat(filepath.Join(tree, "manifest.json")); !os.IsNotExist(err) {
		t.Fatal("partial attempt gained a manifest", err)
	}
}

func TestNativeRunnerRestartRetainsPostManifestAttempt(t *testing.T) {
	e, body, request := nativeRunnerFixture(t)
	first := nativeReady(t, e)
	if err := e.StartNativeJob(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(first.root, "attempts", request.Intent.AttemptID)
	producer := NativePushRequest{Schema: NativePushFormat, URI: "qemu:///system", BackupID: request.Intent.BackupID, AttemptID: request.Intent.AttemptID, DomainUUID: request.Intent.Source.DomainUUID, Disks: request.Intent.Source.Disks, Exclusions: request.Intent.Source.Exclusions, OutputPath: path, TimeoutSeconds: 120}
	// Model helper loss after durable manifest closure but before the agent
	// records admission.json; a manifest alone does not authorize recovery.
	sealed := sealedNativeResult(t, producer)
	intent, err := json.Marshal(producer)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeNativeFile(filepath.Join(path, "intent.json"), intent); err != nil {
		t.Fatal(err)
	}
	first.cancel()
	if err := first.lock.Close(); err != nil {
		t.Fatal(err)
	}

	second := NewExecutor(e.cfg, resources.New(1, 1))
	r := nativeReady(t, second)
	var admissions, effects, uploads, publications atomic.Int32
	r.admit = func(context.Context, string, string, string, string, string, *http.Client, func(context.Context) (string, error)) error {
		admissions.Add(1)
		return nil
	}
	r.produce = func(context.Context, NativePushRequest) (*NativePushResult, error) {
		effects.Add(1)
		return nil, ErrNativeUncertain
	}
	r.upload = func(context.Context, string, string, string, string, string, []byte, *http.Client, *http.Client, func(context.Context) (string, error)) (*models.StorageAcceptance, error) {
		uploads.Add(1)
		return nil, ErrNativeUncertain
	}
	r.publish = func(context.Context, string, string, *models.StorageAcceptance, *http.Client, func(context.Context) (string, error)) error {
		publications.Add(1)
		return ErrNativeUncertain
	}
	go r.run()
	nativeWait(t, second, request.Intent.BackupID, models.TaskStatusCleanupRequired)
	if err := second.StartNativeJob(context.Background(), body); !errors.Is(err, ErrNativeUncertain) {
		t.Fatal("sealed but unadmitted attempt was resumable", err)
	}
	if err := second.CloseStorageTransactions(); err != nil {
		t.Fatal(err)
	}
	if admissions.Load() != 0 || effects.Load() != 0 || uploads.Load() != 0 || publications.Load() != 0 {
		t.Fatal("post-manifest restart repeated an effect", admissions.Load(), effects.Load(), uploads.Load(), publications.Load())
	}
	manifest, err := os.ReadFile(filepath.Join(NativePushTree(path), "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(manifest)
	if hex.EncodeToString(hash[:]) != sealed.ManifestSHA256 {
		t.Fatal("sealed but unadmitted manifest changed")
	}
	if _, err := os.Stat(filepath.Join(NativePushTree(path), "vda.qcow2")); err != nil {
		t.Fatal("sealed but unadmitted payload was removed", err)
	}
	if _, err := os.Lstat(filepath.Join(path, "admission.json")); !os.IsNotExist(err) {
		t.Fatal("post-manifest recovery fabricated closed admission", err)
	}
}

func TestNativeRunnerReadmitsRecoveredIntentBeforeProducer(t *testing.T) {
	e, body, request := nativeRunnerFixture(t)
	r := nativeReady(t, e)
	if err := e.StartNativeJob(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	// End the old process before its queue starts, retaining only durable intent.
	r.cancel()
	if err := r.lock.Close(); err != nil {
		t.Fatal(err)
	}
	second := NewExecutor(e.cfg, resources.New(1, 1))
	r = nativeReady(t, second)
	var admissions, effects atomic.Int32
	r.admit = func(context.Context, string, string, string, string, string, *http.Client, func(context.Context) (string, error)) error {
		admissions.Add(1)
		return storageupload.ErrHeld
	}
	r.produce = func(context.Context, NativePushRequest) (*NativePushResult, error) {
		effects.Add(1)
		return nil, ErrNativeUncertain
	}
	go r.run()
	nativeWait(t, second, request.Intent.BackupID, models.TaskStatusCleanupRequired)
	if err := second.CloseStorageTransactions(); err != nil {
		t.Fatal(err)
	}
	if admissions.Load() != 1 || effects.Load() != 0 {
		t.Fatal("recovered intent skipped authority readmission")
	}
	if _, err := os.Lstat(filepath.Join(r.root, "attempts", request.Intent.AttemptID)); !os.IsNotExist(err) {
		t.Fatal("refused admission created a producer attempt")
	}
}

func TestNativeRunnerRejectsChangedIntentAndInsecureTransport(t *testing.T) {
	e, body, request := nativeRunnerFixture(t)
	if _, err := DecodeNativeJob(body); err != nil {
		t.Fatal(err)
	}
	request.Intent.Source.Disks[0].Source = "/other"
	changed, _ := json.Marshal(request)
	if _, err := DecodeNativeJob(changed); err == nil {
		t.Fatal("changed intent reused digest")
	}
	e.cfg.OrchestratorVerifySSL = false
	if _, err := newNativeRunner(context.Background(), e); err == nil {
		t.Fatal("TLS verification disabled")
	}
	if _, err := e.StartUpload(request.Intent.BackupID, "/tmp"); err == nil {
		t.Fatal("native path-only upload admitted")
	}
}
