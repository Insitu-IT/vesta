//go:build linux

package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/storageupload"
)

func TestNativeReviewedRetirementSurvivesRestartWithoutRelaunch(t *testing.T) {
	nativePushDigest := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	e, body, request := nativeRunnerFixture(t)
	r := nativeReady(t, e)
	i := request.Intent
	r.produce = func(_ context.Context, p NativePushRequest) (*NativePushResult, error) {
		return sealedNativeResult(t, p), nil
	}
	r.upload = func(_ context.Context, root, tree, org, agent, base string, admission []byte, b, s *http.Client, key func(context.Context) (string, error)) (*models.StorageAcceptance, error) {
		var closed storageupload.ClosedNativeAdmission
		if err := json.Unmarshal(admission, &closed); err != nil {
			t.Fatal(err)
		}
		inv, _ := models.StorageCanonical(closed.Inventory)
		p := models.NativeStoragePlan{AttemptID: i.AttemptID, CapabilityProfile: i.Target.CapabilityProfile,
			Provider: "libvirt", Source: models.NativeStorageSource{Representation: "libvirt-native-fileset/1",
				AgentID: agent, VMID: i.Source.VMID, InventorySHA256: nativePushDigest(inv), Inventory: closed.Inventory},
			BackupType: "full", Exclusions: []string{}, Target: models.StorageTarget{Endpoint: i.Target.Endpoint, Bucket: i.Target.Bucket, Region: i.Target.Region},
			CredentialRef: "installation/storage.s3", Encryption: i.Encryption, ChecksumPolicy: "sha256-parts-receipt-v2"}
		var err error
		p.Artifacts, err = nativefileset.BuildArtifacts(p.Source, org, i.BackupID, i.AttemptID, p.Encryption)
		if err != nil {
			t.Fatal(err)
		}
		canonical, _ := models.StorageCanonical(p)
		transaction := models.NativeTransactionRequest{Protocol: models.StorageProtocol, OrgID: org, AgentID: agent,
			BackupID: i.BackupID, ReservationID: i.AttemptID, PlanSHA256: nativePushDigest(canonical), Plan: p}
		objects := []any{}
		for _, artifact := range p.Artifacts {
			objects = append(objects, map[string]any{"artifact": artifact, "phase": "planned", "part_size": 8 * 1024 * 1024,
				"upload_id": "", "parts": []any{}, "pending_part": nil, "receipt": nil, "provider": nil, "assurance": ""})
		}
		state := map[string]any{"schema": 6, "request": transaction, "phase": "held", "objects": objects, "receipt": nil, "acceptance": nil}
		canonical, _ = models.StorageCanonical(state)
		disk, _ := json.Marshal(map[string]any{"sha256": nativePushDigest(canonical), "state": state})
		dir := filepath.Join(root, i.AttemptID)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "transaction.json"), disk, 0600); err != nil {
			t.Fatal(err)
		}
		return nil, storageupload.ErrHeld
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/v1/agents/backups/"+i.BackupID+"/storage-retirement" || req.Header.Get("X-Agent-Key") != e.cfg.AgentAPIKey {
			t.Error("unbound proof request")
			http.Error(w, "denied", 403)
			return
		}
		identity, err := storageupload.NativeHeldJournalIdentity(filepath.Join(r.root, "uploads"), i.AttemptID, i.OrgID, i.AgentID, i.BackupID)
		if err != nil {
			t.Error(err)
			http.Error(w, "held", 423)
			return
		}
		var binding map[string]string
		if json.NewDecoder(req.Body).Decode(&binding) != nil || len(binding) != 4 || binding["journal_sha256"] != identity.JournalSHA256 || binding["plan_sha256"] != identity.PlanSHA256 || binding["attempt_id"] != i.AttemptID || binding["reservation_id"] != i.AttemptID {
			t.Error("proof request differs from original journal")
			http.Error(w, "denied", 403)
			return
		}
		identity.OperationID = "11111111-1111-4111-8111-111111111111"
		identity.CapacityID = "22222222-2222-4222-8222-222222222222"
		identity.ReleaseSHA256 = strings.Repeat("a", 64)
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(identity)
	}))
	defer server.Close()
	e.cfg.OrchestratorURL = server.URL
	r.backend = server.Client()
	go r.run()
	if err := e.StartNativeJob(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	nativeWait(t, e, i.BackupID, models.TaskStatusCleanupRequired)
	if err := e.RetireStorageTransaction(context.Background(), i.BackupID, i.AttemptID); err != nil {
		t.Fatal(err)
	}
	if err := e.StartNativeJob(context.Background(), body); err == nil {
		t.Fatal("retired delivery accepted")
	}
	if err := e.CloseStorageTransactions(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(r.root, "attempts", i.AttemptID, "data", "vda.qcow2")); err != nil {
		t.Fatal("retirement deleted captured payload", err)
	}
	second := NewExecutor(e.cfg, resources.New(1, 1))
	r = nativeReady(t, second)
	if len(r.queue) != 0 || len(r.work) != 0 {
		t.Fatal("restart requeued retired native attempt")
	}
	go r.run()
	if err := second.CloseStorageTransactions(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeRetirementRefusesActiveOrNonheldRunnerBeforeCallback(t *testing.T) {
	for _, flags := range [][2]bool{{false, false}, {false, true}, {true, false}} {
		e, body, request := nativeRunnerFixture(t)
		r := nativeReady(t, e)
		r.work[request.Intent.BackupID] = &nativeWork{request: request, body: body, finished: flags[0], held: flags[1]}
		if err := e.RetireStorageTransaction(context.Background(), request.Intent.BackupID, request.Intent.AttemptID); err == nil {
			t.Fatal("nonheld producer acquired retirement authority")
		}
		r.cancel()
		_ = r.lock.Close()
	}
}
