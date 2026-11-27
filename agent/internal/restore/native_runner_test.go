package restore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/encryption"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
	"vnbui/agent/internal/nativerestore"
	"vnbui/agent/internal/operationbudget"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/restoreinput"
)

func nativeHash(body []byte) string { h := sha256.Sum256(body); return hex.EncodeToString(h[:]) }

func TestQueuedNativeRestoreReportsExhaustionBeforeWorkerVisitsIt(t *testing.T) {
	budget, err := operationbudget.DefaultPolicy().Begin(1, 8<<20, 24*time.Hour, time.Now().Add(-10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	s := &nativeRestoreState{Budget: budget, Phase: "prepared", Progress: models.RestoreProgress{RestoreID: "queued", Status: models.TaskStatusRunning}}
	s.Request.RestoreID = "queued"
	r := &nativeRestoreRunner{root: t.TempDir(), states: map[string]*nativeRestoreState{"queued": s}}
	if err := r.write(s); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(r.root, "queued.json")
	before, _ := os.ReadFile(path)
	// No worker loop runs: model another opaque worker occupying it indefinitely.
	for range 2 {
		p := r.progress("queued")
		if p.Status != models.TaskStatusCleanupRequired || p.ErrorMessage == nil || !strings.Contains(*p.ErrorMessage, "admission_wait_exhausted") {
			t.Fatal("expired queue remained running", p)
		}
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) || s.Progress.Status != models.TaskStatusRunning {
		t.Fatal("negative observation rewrote worker custody")
	}
}

func nativeRuntimeFixture(t *testing.T, endpoint string, historical bool) (models.NativeRestoreRequest, map[string][]byte) {
	t.Helper()
	r := models.NativeTransactionRequest{Protocol: models.StorageProtocol, OrgID: "66666666-6666-4666-8666-666666666666", AgentID: "44444444-4444-4444-8444-444444444444", BackupID: "22222222-2222-4222-8222-222222222222", ReservationID: "33333333-3333-4333-8333-333333333333"}
	p := &r.Plan
	p.Provider = "libvirt"
	p.AttemptID = r.ReservationID
	p.CapabilityProfile = "db-rooted-consumer-verified/1"
	p.BackupType = "full"
	p.CredentialRef = "installation/storage.s3"
	p.ChecksumPolicy = "sha256-parts-receipt-v2"
	p.Exclusions = []string{}
	p.Encryption = models.StorageEncryption{Format: "none"}
	p.Target = models.StorageTarget{Endpoint: endpoint, Bucket: "native-test", Region: "us-east-1"}
	if historical {
		p.Target.Region = ""
	}
	inv := models.NativeFileSet{Format: models.NativeFileSetFormat, DomainUUID: "11111111-1111-4111-8111-111111111111", BackupID: r.BackupID, AttemptID: r.ReservationID, JobID: "vnbui-native-" + r.ReservationID, Checkpoint: "vnbui-" + r.ReservationID, Disks: []models.NativeDisk{{ID: "vda", Target: "vda", Bus: "virtio"}}}
	plains := map[string][]byte{"domain.xml": []byte("<domain>captured</domain>"), "checkpoint.xml": []byte("<domaincheckpoint/>"), "vda.qcow2": []byte("native")}
	var key []byte
	if historical {
		key = bytes.Repeat([]byte{0x42}, 32)
		ref := "kek:55555555-5555-4555-8555-555555555555:2222222222222222"
		p.Encryption = models.StorageEncryption{Format: "vnbu1-aes256gcm-chunk5242880", KeyRef: &ref}
		plains["domain.xml"] = []byte(fmt.Sprintf(`<domain type="kvm"><name>captured</name><uuid>%s</uuid><devices><interface type="network"><mac address="52:54:00:00:00:0a"/><source network="source-network"/></interface></devices></domain>`, inv.DomainUUID))
	}
	m := models.NativePushManifest{Schema: backup.NativePushFormat, BackupID: r.BackupID, AttemptID: r.ReservationID, DomainUUID: inv.DomainUUID, Checkpoint: inv.Checkpoint, DomainXMLSHA256: nativeHash(plains["domain.xml"]), CheckpointSHA256: nativeHash(plains["checkpoint.xml"]), Source: []models.NativeSourceDisk{{Target: "vda", Source: "/source/disk", Bus: "virtio", Format: "qcow2"}}, Exclusions: []string{}, Disks: []models.NativePushDisk{{Target: "vda", File: "vda.qcow2", SizeBytes: 6, VirtualSize: 6, SHA256: nativeHash(plains["vda.qcow2"])}}}
	canonical, _ := models.StorageCanonical(m)
	plains["manifest.json"] = canonical
	for i, entry := range []struct{ name, role string }{{"domain.xml", "domain_config"}, {"checkpoint.xml", "checkpoint"}, {"manifest.json", "backup_metadata"}, {"vda.qcow2", "disk_payload"}} {
		f := models.NativeFile{MemberBackupID: r.BackupID, MemberCheckpoint: inv.Checkpoint, Path: entry.name, Role: entry.role, Device: 1, Inode: uint64(i + 1), Size: int64(len(plains[entry.name])), MtimeNS: 1, CtimeNS: 1}
		if entry.role == "disk_payload" {
			name := "vda"
			f.DiskID = &name
		}
		f.ArtifactID = nativefileset.ArtifactID(inv, f)
		inv.Files = append(inv.Files, f)
	}
	body, _ := models.StorageCanonical(inv)
	p.Source = models.NativeStorageSource{Representation: models.NativeFileSetFormat, AgentID: r.AgentID, VMID: "55555555-5555-4555-8555-555555555555", Inventory: inv, InventorySHA256: nativeHash(body)}
	var err error
	p.Artifacts, err = nativefileset.BuildArtifacts(p.Source, r.OrgID, r.BackupID, r.ReservationID, p.Encryption)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = models.StorageCanonical(*p)
	r.PlanSHA256 = nativeHash(body)
	receipt := models.NativeStorageReceipt{Protocol: r.Protocol, Schema: 2, Representation: models.NativeFileSetFormat, BackupID: r.BackupID, ReservationID: r.ReservationID, Endpoint: endpoint, Bucket: p.Target.Bucket}
	objects := map[string][]byte{}
	for _, a := range p.Artifacts {
		var plain []byte
		for _, f := range inv.Files {
			if f.ArtifactID == a.ArtifactID {
				plain = plains[f.Path]
			}
		}
		stored := plain
		if historical {
			var sealed bytes.Buffer
			if err := encryption.EncryptStreamChunked(bytes.NewReader(plain), &sealed, key, 5<<20); err != nil {
				t.Fatal(err)
			}
			stored = sealed.Bytes()
		}
		objects["/"+p.Target.Bucket+"/"+a.Key] = stored
		receipt.Objects = append(receipt.Objects, models.NativeStorageObjectReceipt{ArtifactID: a.ArtifactID, DiskID: a.DiskID, Role: a.Role, Key: a.Key, ETag: `"exact"`, PlaintextBytes: int64(len(plain)), CiphertextBytes: int64(len(stored)), PlaintextSHA256: nativeHash(plain), CiphertextSHA256: nativeHash(stored)})
	}
	bundle := nativerestore.Bundle{Schema: nativerestore.BundleSchema, Members: []nativerestore.Member{{Request: r, Receipt: receipt, PushResult: models.NativePushResult{Manifest: m, ManifestSHA256: nativeHash(canonical)}}}}
	req := models.NativeRestoreRequest{Schema: models.NativeRestoreSchema, OrgID: r.OrgID, AgentID: r.AgentID, RestoreID: "99999999-9999-4999-8999-999999999999", Target: models.NativeRestoreTarget{VMName: "fresh-native", VMUUID: "88888888-8888-4888-8888-888888888888", Disks: []string{"vda"}, DropExcludedDisks: []string{}, Networks: []models.NativeRestoreNetwork{}}, Bundle: nativerestore.MarshalBundle(bundle), S3: models.KubeVirtRestoreS3{Endpoint: endpoint, Bucket: p.Target.Bucket, Region: p.Target.Region, AccessKey: "read", SecretKey: "private-secret"}, Keys: map[string]string{}}
	if historical {
		req.RecoveryOrigin = &models.RestoreOrigin{OrgID: req.OrgID, AgentID: req.AgentID}
		req.OrgID = "33333333-3333-4333-8333-333333333333"
		req.AgentID = "77777777-7777-4777-8777-777777777777"
		req.Target.Networks = []models.NativeRestoreNetwork{{SourceMAC: "52:54:00:00:00:0a", Network: "fresh-network"}}
		req.Keys[r.BackupID] = base64.StdEncoding.EncodeToString(key)
		req.S3.Region = "us-east-1"
	}
	if _, _, err := nativerestore.ValidatePlan(&req, true); err != nil {
		t.Fatal(err)
	}
	return req, objects
}

func TestNativeRuntimeHTTPSObjectsDurableAcceptanceCompletionAndRestart(t *testing.T) {
	for _, historical := range []bool{false, true} {
		name := "catalog"
		if historical {
			name = "verified-s3-recovery"
		}
		t.Run(name, func(t *testing.T) { nativeRuntimeHTTPSObjects(t, historical) })
	}
}

func nativeRuntimeHTTPSObjects(t *testing.T, historical bool) {
	var objects map[string][]byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := objects[r.URL.Path]
		if !ok || r.Method != "GET" || r.Header.Get("If-Match") != `"exact"` ||
			!strings.Contains(r.Header.Get("Authorization"), "/us-east-1/s3/aws4_request,") {
			http.Error(w, "scope", 412)
			return
		}
		w.Header().Set("ETag", `"exact"`)
		w.Header().Set("Last-Modified", "Thu, 01 Oct 2026 00:00:00 GMT")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	}))
	defer server.Close()
	req, store := nativeRuntimeFixture(t, server.URL, historical)
	objects = store
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	ca := filepath.Join(root, "ca.pem")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	open, closeSource, err := restoreinput.S3RestoreSourceConfig(restoreinput.S3Configuration{Endpoint: server.URL, Bucket: req.S3.Bucket, Region: req.S3.Region, AccessKey: req.S3.AccessKey, SecretKey: req.S3.SecretKey, CAFile: ca}, req.RecoveryOrigin)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSource()
	bundle, _, _ := nativerestore.ValidatePlan(&req, true)
	var keys nativerestore.KeyResolver
	if historical {
		keys = func(_ context.Context, member nativerestore.Member) ([]byte, error) {
			return base64.StdEncoding.DecodeString(req.Keys[member.Request.BackupID])
		}
	}
	if _, err = nativerestore.ReadDomainXML(context.Background(), bundle, open, keys); err != nil {
		t.Fatal("TLS source", err)
	}
	cfg := &config.Config{AgentID: req.AgentID, KeyFilePath: filepath.Join(root, "agent.key"), NativeRestoreRoot: filepath.Join(root, "images"), NativeRestoreCAFile: ca, LibvirtURI: "qemu:///system", OrchestratorVerifySSL: true, EnableAPIKeyValidation: true, OrchestratorAPIKey: "authenticated"}
	// The shipped systemd UMask=0027 turns MkdirAll(0711) into 0710.
	// Model that existing root without changing the process-global test umask.
	if err := os.Mkdir(cfg.NativeRestoreRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg.NativeRestoreRoot, 0710); err != nil {
		t.Fatal(err)
	}
	executor := NewExecutor(cfg, resources.New(1, 1))
	r := executor.fresh
	gate := make(chan struct{})
	r.reconstruct = func(ctx context.Context, members []backup.NativeRestoreMember, output string) ([]backup.NativeRestoredDisk, error) {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if len(members) != 1 {
			return nil, fmt.Errorf("wrong members")
		}
		data, err := os.ReadFile(filepath.Join(members[0].Directory, "vda.qcow2"))
		if err != nil || string(data) != "native" {
			return nil, fmt.Errorf("inputs not verified")
		}
		if err = os.Mkdir(output, 0700); err != nil {
			return nil, err
		}
		path := filepath.Join(output, "vda.raw")
		if err = os.WriteFile(path, data, 0600); err != nil {
			return nil, err
		}
		return []backup.NativeRestoredDisk{{Target: "vda", Path: path, SizeBytes: 6, SHA256: nativeHash(data)}}, nil
	}
	defines := 0
	r.define = func(_ context.Context, request nativerestore.DefinitionRequest) (map[string]interface{}, error) {
		defines++
		if !request.AllowCreate || request.Target.VMUUID != req.Target.VMUUID {
			return nil, fmt.Errorf("wrong definition intent")
		}
		if historical && (len(request.Target.Networks) != 1 ||
			request.Target.Networks[0].Network != "fresh-network" ||
			!strings.Contains(string(request.DomainXML), request.Target.Networks[0].SourceMAC)) {
			return nil, fmt.Errorf("lost verified source interface mapping")
		}
		return map[string]interface{}{"vm_name": req.Target.VMName, "vm_uuid": req.Target.VMUUID, "state": "shutoff", "disks": request.Disks, "plan_sha256": request.PlanSHA256}, nil
	}
	if err := executor.StartRestores(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = executor.CloseRestores() }()
	if info, err := os.Stat(cfg.NativeRestoreRoot); err != nil || info.Mode().Perm() != 0711 {
		t.Fatal("QEMU cannot traverse image root under the installed service umask", info, err)
	}
	wrapper := &models.RestoreRequest{RestoreID: req.RestoreID, Native: &req}
	if _, err := executor.StartRestore(wrapper); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(r.root, req.RestoreID+".json")
	if info, err := os.Stat(journal); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("202 before durable private intent", err)
	}
	if _, err := executor.StartRestore(wrapper); err != nil {
		t.Fatal("same request not idempotent", err)
	}
	second := NewExecutor(cfg, resources.New(1, 1))
	if err := second.StartRestores(context.Background()); err == nil {
		_ = second.CloseRestores()
		t.Fatal("two journal writers admitted")
	}
	close(gate)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p := executor.GetProgress(req.RestoreID)
		if p.Status != models.TaskStatusRunning {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if p := executor.GetProgress(req.RestoreID); p.Status != models.TaskStatusCompleted || defines != 1 || executor.ActiveCount() != 0 {
		t.Fatal(p, defines)
	}
	fresh, err := os.ReadFile(filepath.Join(cfg.NativeRestoreRoot, req.RestoreID, "disks", "vda.raw"))
	if err != nil || string(fresh) != "native" {
		t.Fatal("fresh disk readback differs from the authenticated input", err)
	}
	if err := executor.CloseRestores(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(journal)
	if err != nil || strings.Contains(string(body), "private-secret") {
		t.Fatal("completed journal retained read credentials", err)
	}
	reopened := NewExecutor(cfg, resources.New(1, 1))
	if err = reopened.StartRestores(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer reopened.CloseRestores()
	if p := reopened.GetProgress(req.RestoreID); p == nil || p.Status != models.TaskStatusCompleted {
		t.Fatal("durable completion lost", p)
	}
}

func TestNativeRuntimeHoldsInterruptedWritesAndNeverRecreatesDestination(t *testing.T) {
	req, _ := nativeRuntimeFixture(t, "https://s3.example.invalid", false)
	_, digest, _ := nativerestore.ValidatePlan(&req, true)
	for _, phase := range []string{"materializing", "assembling", "defining"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			_ = os.Chmod(root, 0700)
			r := newNativeRestoreRunner(&config.Config{}, resources.New(1, 1))
			r.root = root
			state := &nativeRestoreState{Schema: 1, Request: req, PlanSHA: digest, Token: strings.Repeat("a", 64), Root: root, URI: "qemu:///system", Phase: phase, Progress: models.RestoreProgress{RestoreID: req.RestoreID, Status: models.TaskStatusRunning}}
			destination := filepath.Join(root, req.RestoreID)
			_ = os.Mkdir(destination, 0700)
			sentinel := filepath.Join(destination, "retain")
			_ = os.WriteFile(sentinel, []byte("uncertain writes"), 0600)
			r.reconstruct = func(context.Context, []backup.NativeRestoreMember, string) ([]backup.NativeRestoredDisk, error) {
				t.Fatal("restarted uncertain producer")
				return nil, nil
			}
			r.define = func(context.Context, nativerestore.DefinitionRequest) (map[string]interface{}, error) {
				t.Fatal("defined with missing durable inputs")
				return nil, nil
			}
			if err := r.reconcile(context.Background(), state); err == nil {
				t.Fatal("uncertain phase inferred successful")
			}
			if body, err := os.ReadFile(sentinel); err != nil || string(body) != "uncertain writes" {
				t.Fatal("uncertain destination removed")
			}
			if err := r.write(state); err != nil {
				t.Fatal(err)
			}
			var saved nativeRestoreState
			if err := restoreinput.ReadJSONFile(filepath.Join(root, req.RestoreID+".json"), &saved, 8<<20, true); err != nil || saved.Phase != phase {
				t.Fatal(err)
			}
		})
	}
}
