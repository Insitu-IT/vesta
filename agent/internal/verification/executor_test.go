package verification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storagerestore"
)

func hash(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }

func TestJournalReservesFilesystemHeadroom(t *testing.T) {
	root := t.TempDir()
	id := "journal"
	executor := New(Config{Root: root, MinFreeBytes: 1})
	if err := executor.checkSpace(id, 4096); err != nil {
		t.Fatalf("small journal with available space: %v", err)
	}
	executor.cfg.MinFreeBytes = math.MaxInt64
	if err := executor.checkSpace(id, 4096); !errors.Is(err, ErrJournal) {
		t.Fatalf("journal must preserve the configured free-space reserve: %v", err)
	}
}

// This fixture and injected runner exercise lifecycle/custody, not provider I/O.
// Actual byte and producer roundtrips live in the two streaming engine packages.
func requestFixture(t *testing.T, encrypted bool) Request {
	t.Helper()
	body, err := os.ReadFile("../../contracts/storage_semantic_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var source models.StorageTransactionRequest
	if json.Unmarshal(body, &source) != nil {
		t.Fatal("fixture")
	}
	source.Plan.Target.Region = "us-east-1"
	keys := map[string]string{}
	if encrypted {
		ref := "kek:66666666-6666-4666-8666-666666666666:aaaaaaaaaaaaaaaa"
		source.Plan.Encryption = models.StorageEncryption{Format: "vnbu1-aes256gcm-chunk5242880", KeyRef: &ref}
		keys[source.BackupID] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))
		for i := range source.Plan.Artifacts {
			a := &source.Plan.Artifacts[i]
			if a.Role == "volume_payload" {
				a.CiphertextMin = 5
				a.CiphertextMax = 5 + a.PlaintextMax + 32*((a.PlaintextMax+5242880-1)/5242880)
			}
		}
	}
	canonical, _ := models.StorageCanonical(source.Plan)
	source.PlanSHA256 = hash(canonical)
	receipt := models.StorageReceipt{Protocol: models.StorageProtocol, Schema: 2, ReservationID: source.ReservationID, BackupID: source.BackupID, Endpoint: source.Plan.Target.Endpoint, Bucket: source.Plan.Target.Bucket, Objects: []models.StorageObjectReceipt{}}
	for _, a := range source.Plan.Artifacts {
		o := models.StorageObjectReceipt{Key: a.Key, VolumeID: a.VolumeID, Role: a.Role, ETag: `"fixture"`, PlaintextBytes: 3, CiphertextBytes: 3, PlaintextSHA256: hash([]byte("abc")), CiphertextSHA256: hash([]byte("abc"))}
		if encrypted && a.Role == "volume_payload" {
			o.CiphertextBytes = 40
			o.CiphertextSHA256 = hash([]byte("cipher"))
		}
		receipt.Objects = append(receipt.Objects, o)
	}
	bundle, _ := json.Marshal(kubevirtBundle{Schema: "vnbui-kubevirt-restore/1", Members: []storagerestore.Member{{Request: source, Receipt: receipt}}})
	req := Request{Plan: Plan{Schema: Schema, VerificationID: uuid.NewString(), OrgID: source.OrgID, AgentID: source.AgentID, Provider: "kubevirt", AuthoritySHA256: strings.Repeat("a", 64), Bundle: bundle}, S3: models.KubeVirtRestoreS3{Endpoint: source.Plan.Target.Endpoint, Bucket: source.Plan.Target.Bucket, Region: "us-east-1", AccessKey: "read-access", SecretKey: "secret-must-not-persist", SessionToken: "session-must-not-persist"}, Keys: keys}
	if _, _, err := ExpectedResult(req.Plan); err != nil {
		t.Fatal("fixture plan", err)
	}
	if err := validateCredentials(req); err != nil {
		t.Fatal("fixture credentials", err)
	}
	return req
}

func executorFor(t *testing.T, req Request, root string) *Executor {
	t.Helper()
	e := New(Config{Root: root, AgentID: req.Plan.AgentID, Provider: req.Plan.Provider, Timeout: time.Hour})
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func awaitStatus(t *testing.T, e *Executor, req Request, status string) *Progress {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		p := e.Get(req.Plan.VerificationID, req.Plan.OrgID)
		if p != nil && p.Status == status {
			return p
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("did not reach %s: %+v", status, e.Get(req.Plan.VerificationID, req.Plan.OrgID))
	return nil
}

func TestDurableCompletionAndLostACKNeverRepeatReads(t *testing.T) {
	req := requestFixture(t, true)
	root := filepath.Join(t.TempDir(), "journals")
	e := executorFor(t, req, root)
	var calls atomic.Int32
	e.runner = func(context.Context, Request, string) (*storagerestore.VerificationResult, error) {
		calls.Add(1)
		r, _, err := ExpectedResult(req.Plan)
		return r, err
	}
	ack, err := e.Submit(req)
	if err != nil || ack.Status != "pending" || ack.Result != nil {
		t.Fatal(ack, err)
	}
	passed := awaitStatus(t, e, req, "passed")
	if passed.WorkerID != ack.WorkerID || passed.PlanSHA256 != ack.PlanSHA256 || passed.Result == nil {
		t.Fatal(passed)
	}
	passed.Result.Members[0].BackupID = "caller-mutation"
	if e.Get(req.Plan.VerificationID, req.Plan.OrgID).Result.Members[0].BackupID == "caller-mutation" {
		t.Fatal("progress exposes mutable journal")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e2 := executorFor(t, req, root)
	e2.runner = func(context.Context, Request, string) (*storagerestore.VerificationResult, error) {
		calls.Add(1)
		return nil, errors.New("must not read")
	}
	replay, err := e2.Submit(req)
	if err != nil || replay.Status != "passed" || replay.WorkerID != ack.WorkerID || calls.Load() != 1 {
		t.Fatal(replay, err, calls.Load())
	}
	entries, _ := os.ReadDir(root)
	for _, entry := range entries {
		body, _ := os.ReadFile(filepath.Join(root, entry.Name()))
		for _, secret := range []string{req.S3.SecretKey, req.S3.SessionToken, req.Keys[string(replay.Result.Members[0].BackupID)]} {
			if secret != "" && bytes.Contains(body, []byte(secret)) {
				t.Fatal("credential entered journal")
			}
		}
	}
}

func TestRestartRequiresFreshReadmissionOfOriginalPlan(t *testing.T) {
	req := requestFixture(t, false)
	root := filepath.Join(t.TempDir(), "journals")
	e := executorFor(t, req, root)
	started := make(chan struct{})
	e.runner = func(ctx context.Context, _ Request, _ string) (*storagerestore.VerificationResult, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ack, err := e.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if e.Cancel(req.Plan.VerificationID, uuid.NewString(), ack.PlanSHA256) != nil || e.Get(req.Plan.VerificationID, uuid.NewString()) != nil {
		t.Fatal("foreign org accessed operation")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e2 := executorFor(t, req, root)
	var calls atomic.Int32
	e2.runner = func(context.Context, Request, string) (*storagerestore.VerificationResult, error) {
		calls.Add(1)
		r, _, err := ExpectedResult(req.Plan)
		return r, err
	}
	if e2.Get(req.Plan.VerificationID, req.Plan.OrgID).Status != "held" || calls.Load() != 0 {
		t.Fatal("restart resumed without credentials/readmission")
	}
	changed := req
	changed.Plan.AuthoritySHA256 = strings.Repeat("b", 64)
	if _, err := e2.Submit(changed); !errors.Is(err, ErrConflict) {
		t.Fatal("authority replaced", err)
	}
	req.S3.SecretKey = "fresh-read-credential"
	if _, err := e2.Submit(req); err != nil {
		t.Fatal(err)
	}
	passed := awaitStatus(t, e2, req, "passed")
	if passed.WorkerID != ack.WorkerID || passed.PlanSHA256 != ack.PlanSHA256 || calls.Load() != 1 {
		t.Fatal(passed, calls.Load())
	}
}

func TestExpiredOrLegacyVerificationCannotReadAgainAfterRestart(t *testing.T) {
	for _, scenario := range []string{"expired", "missing_legacy_budget", "backward_clock"} {
		t.Run(scenario, func(t *testing.T) {
			req := requestFixture(t, false)
			root := filepath.Join(t.TempDir(), "journals")
			e := executorFor(t, req, root)
			started := make(chan struct{})
			e.runner = func(ctx context.Context, _ Request, _ string) (*storagerestore.VerificationResult, error) {
				close(started)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			ack, err := e.Submit(req)
			if err != nil {
				t.Fatal(err)
			}
			<-started
			if err := e.Close(); err != nil {
				t.Fatal(err)
			}
			state := e.states[req.Plan.VerificationID]
			if scenario == "missing_legacy_budget" {
				state.Budget = nil
			} else {
				state.Budget.StartedAt = time.Now().Add(-2 * time.Hour).UTC()
				if scenario == "backward_clock" {
					state.Budget.StartedAt = time.Now().Add(time.Hour).UTC()
				}
				state.Budget.LastProgressAt = state.Budget.StartedAt
			}
			if err := e.persist(state); err != nil {
				t.Fatal(err)
			}
			e2 := executorFor(t, req, root)
			e2.cfg.BudgetPolicy.TimeCoefficient = 99
			var reads atomic.Int32
			e2.runner = func(context.Context, Request, string) (*storagerestore.VerificationResult, error) {
				reads.Add(1)
				return nil, errors.New("must not read")
			}
			for range 2 {
				replay, err := e2.Submit(req)
				if err != nil || replay.WorkerID != ack.WorkerID || replay.Status != "held" || replay.Message != "operation_budget_exhausted_or_missing" || reads.Load() != 0 {
					t.Fatal("expired operation readmitted", replay, err, reads.Load())
				}
			}
		})
	}
}

func TestConcurrentDuplicateBusyAndCancellation(t *testing.T) {
	req := requestFixture(t, false)
	e := executorFor(t, req, filepath.Join(t.TempDir(), "journals"))
	started := make(chan struct{})
	var calls atomic.Int32
	e.runner = func(ctx context.Context, _ Request, _ string) (*storagerestore.VerificationResult, error) {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if _, err := e.Submit(req); err != nil {
		t.Fatal(err)
	}
	<-started
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.Submit(req); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	other := req
	other.Plan.VerificationID = uuid.NewString()
	if _, err := e.Submit(other); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if e.Get(other.Plan.VerificationID, other.Plan.OrgID) != nil || calls.Load() != 1 {
		t.Fatal("second worker created")
	}
	_, digest, _ := ExpectedResult(req.Plan)
	if e.Cancel(req.Plan.VerificationID, req.Plan.OrgID, strings.Repeat("b", 64)) != nil {
		t.Fatal("wrong plan cancelled original reads")
	}
	if p := e.Cancel(req.Plan.VerificationID, req.Plan.OrgID, digest); p == nil {
		t.Fatal("missing original operation")
	}
	awaitStatus(t, e, req, "held")
}

func TestCancelledIDCannotRestartFromDelayedSubmitOrProcessRestart(t *testing.T) {
	req := requestFixture(t, false)
	root := filepath.Join(t.TempDir(), "journals")
	e := executorFor(t, req, root)
	var calls atomic.Int32
	e.runner = func(ctx context.Context, _ Request, _ string) (*storagerestore.VerificationResult, error) {
		calls.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ack, err := e.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	awaitStatus(t, e, req, "running")
	if e.Cancel(req.Plan.VerificationID, req.Plan.OrgID, ack.PlanSHA256) == nil {
		t.Fatal("cancel")
	}
	awaitStatus(t, e, req, "held")
	if _, err := e.Submit(req); err != nil {
		t.Fatal(err)
	}
	if p := e.Get(req.Plan.VerificationID, req.Plan.OrgID); p.Status != "held" || calls.Load() > 1 {
		t.Fatalf("cancelled ID was restarted: %+v, calls=%d", p, calls.Load())
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e2 := executorFor(t, req, root)
	e2.runner = func(context.Context, Request, string) (*storagerestore.VerificationResult, error) {
		calls.Add(1)
		r, _, err := ExpectedResult(req.Plan)
		return r, err
	}
	if _, err := e2.Submit(req); err != nil {
		t.Fatal(err)
	}
	if p := e2.Get(req.Plan.VerificationID, req.Plan.OrgID); p.Status != "held" || calls.Load() > 1 {
		t.Fatalf("cancel fence lost across restart: %+v, calls=%d", p, calls.Load())
	}
}

func TestFailedCancelFenceWriteCannotReportQuiescence(t *testing.T) {
	req := requestFixture(t, false)
	root := filepath.Join(t.TempDir(), "journals")
	e := executorFor(t, req, root)
	var calls atomic.Int32
	started := make(chan struct{})
	e.runner = func(ctx context.Context, _ Request, _ string) (*storagerestore.VerificationResult, error) {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ack, err := e.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	e.mu.Lock()
	budget := e.cfg.MaxJournalBytes
	e.cfg.MaxJournalBytes = 1
	e.mu.Unlock()
	if p := e.Cancel(req.Plan.VerificationID, req.Plan.OrgID, ack.PlanSHA256); p == nil || p.Status != "running" || p.Message != "cancellation_pending" {
		t.Fatalf("uncommitted cancel fence acknowledged: %+v", p)
	}
	e.wg.Wait()
	if p := e.Get(req.Plan.VerificationID, req.Plan.OrgID); p.Status != "running" || p.Message != "cancellation_pending" || p.Result != nil {
		t.Fatalf("reader exit was mistaken for durable cancellation: %+v", p)
	}
	if _, err := e.Submit(req); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("failed fence allowed another read")
	}
	e.mu.Lock()
	e.cfg.MaxJournalBytes = budget
	e.mu.Unlock()
	if p := e.Cancel(req.Plan.VerificationID, req.Plan.OrgID, ack.PlanSHA256); p.Status != "held" {
		t.Fatalf("durable fence did not release quiescence: %+v", p)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e2 := executorFor(t, req, root)
	if p, err := e2.Submit(req); err != nil || p.Status != "held" {
		t.Fatalf("durable cancel fence lost at restart: %+v %v", p, err)
	}
}

func TestFailedWrongOrPanickedResultCannotBecomePassed(t *testing.T) {
	for _, fault := range []string{"error", "wrong", "nil", "panic"} {
		t.Run(fault, func(t *testing.T) {
			req := requestFixture(t, false)
			e := executorFor(t, req, filepath.Join(t.TempDir(), "journals"))
			e.runner = func(context.Context, Request, string) (*storagerestore.VerificationResult, error) {
				if fault == "error" {
					return nil, errors.New(req.S3.SecretKey)
				}
				if fault == "panic" {
					panic(req.S3.SecretKey)
				}
				if fault == "nil" {
					return nil, nil
				}
				r, _, _ := ExpectedResult(req.Plan)
				r.Members[0].ReceiptSHA256 = strings.Repeat("b", 64)
				return r, nil
			}
			if _, err := e.Submit(req); err != nil {
				t.Fatal(err)
			}
			p := awaitStatus(t, e, req, "failed")
			body, _ := json.Marshal(p)
			if p.Result != nil || bytes.Contains(body, []byte(req.S3.SecretKey)) {
				t.Fatal("failure returned result or secret", p)
			}
		})
	}
}

func TestJournalWriteFailureNeverProducesSuccess(t *testing.T) {
	req := requestFixture(t, false)
	root := filepath.Join(t.TempDir(), "journals")
	e := executorFor(t, req, root)
	started, finish := make(chan struct{}), make(chan struct{})
	e.runner = func(context.Context, Request, string) (*storagerestore.VerificationResult, error) {
		close(started)
		<-finish
		r, _, err := ExpectedResult(req.Plan)
		return r, err
	}
	if _, err := e.Submit(req); err != nil {
		t.Fatal(err)
	}
	<-started
	retained := root + "-retained"
	if err := os.Rename(root, retained); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root, []byte("block atomic commit"), 0600); err != nil {
		t.Fatal(err)
	}
	close(finish)
	p := awaitStatus(t, e, req, "held")
	if p.Result != nil || p.Message != "journal_unavailable" {
		t.Fatal(p)
	}
	var saved journal
	if err := readJournal(filepath.Join(retained, req.Plan.VerificationID+".json"), &saved); err != nil || saved.Status != "running" {
		t.Fatal(saved.Status, err)
	}
}

func TestOriginalJournalLockAndCorruptResultFailClosed(t *testing.T) {
	req := requestFixture(t, false)
	root := filepath.Join(t.TempDir(), "journals")
	e := executorFor(t, req, root)
	e2 := New(e.cfg)
	if !errors.Is(e2.Start(context.Background()), ErrJournal) {
		t.Fatal("second process acquired original journal")
	}
	e.runner = func(context.Context, Request, string) (*storagerestore.VerificationResult, error) {
		r, _, err := ExpectedResult(req.Plan)
		return r, err
	}
	if _, err := e.Submit(req); err != nil {
		t.Fatal(err)
	}
	awaitStatus(t, e, req, "passed")
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, req.Plan.VerificationID+".json")
	var saved journal
	if readJournal(path, &saved) != nil {
		t.Fatal("missing completed journal")
	}
	saved.Result.Members[0].ReceiptSHA256 = strings.Repeat("b", 64)
	body, _ := json.Marshal(saved)
	if os.WriteFile(path, body, 0600) != nil {
		t.Fatal("fixture write")
	}
	if !errors.Is(e2.Start(context.Background()), ErrJournal) {
		t.Fatal("corrupt result accepted")
	}
}

func TestInvalidCredentialsOrOwnershipNeverCreateJournal(t *testing.T) {
	for _, fault := range []string{"org", "agent", "provider", "authority", "endpoint", "bucket", "region", "missing-key", "extra-key"} {
		t.Run(fault, func(t *testing.T) {
			req := requestFixture(t, true)
			e := executorFor(t, req, filepath.Join(t.TempDir(), "journals"))
			switch fault {
			case "org":
				req.Plan.OrgID = uuid.NewString()
			case "agent":
				req.Plan.AgentID = uuid.NewString()
			case "provider":
				req.Plan.Provider = "libvirt"
			case "authority":
				req.Plan.AuthoritySHA256 = "invalid"
			case "endpoint":
				req.S3.Endpoint = "https://foreign.invalid"
			case "bucket":
				req.S3.Bucket = "foreign"
			case "region":
				req.S3.Region = ""
			case "missing-key":
				req.Keys = map[string]string{}
			case "extra-key":
				req.Keys[uuid.NewString()] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
			}
			if _, err := e.Submit(req); !errors.Is(err, ErrPlan) {
				t.Fatal("invalid authority admitted", err)
			}
			entries, _ := os.ReadDir(e.cfg.Root)
			if len(entries) != 1 || entries[0].Name() != ".lock" {
				t.Fatal("refused input persisted", entries)
			}
		})
	}
}

func TestUncleanRunningJournalRequiresReadmissionWithoutSecrets(t *testing.T) {
	req := requestFixture(t, true)
	root := filepath.Join(t.TempDir(), "journals")
	e := executorFor(t, req, root)
	_, digest, _ := ExpectedResult(req.Plan)
	state := &journal{Schema: 1, Plan: req.Plan, PlanSHA256: digest, WorkerID: uuid.NewString(), Status: "running", Message: "reading_exact_artifacts"}
	if err := e.persist(state); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e2 := executorFor(t, req, root)
	if p := e2.Get(req.Plan.VerificationID, req.Plan.OrgID); p == nil || p.Status != "held" || p.WorkerID != state.WorkerID || p.Result != nil {
		t.Fatal(p)
	}
	if e2.active != "" {
		t.Fatal("startup started an unauthorized read")
	}
}

func TestDuplicateJournalFieldsAndWorldReadableRootAreRejected(t *testing.T) {
	req := requestFixture(t, false)
	root := filepath.Join(t.TempDir(), "journals")
	e := executorFor(t, req, root)
	_, digest, _ := ExpectedResult(req.Plan)
	state := &journal{Schema: 1, Plan: req.Plan, PlanSHA256: digest, WorkerID: uuid.NewString(), Status: "running", Message: "reading_exact_artifacts"}
	if err := e.persist(state); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(state)
	body = append([]byte(`{"status":"passed",`), body[1:]...)
	if err := os.WriteFile(filepath.Join(root, req.Plan.VerificationID+".json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := New(e.cfg).Start(context.Background()); !errors.Is(err, ErrJournal) {
		t.Fatal("ambiguous journal accepted", err)
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := New(e.cfg).Start(context.Background()); !errors.Is(err, ErrJournal) {
		t.Fatal("nonprivate journal root accepted", err)
	}
}

func TestConcurrentCloseIsIdempotent(t *testing.T) {
	req := requestFixture(t, false)
	e := executorFor(t, req, filepath.Join(t.TempDir(), "journals"))
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { done <- e.Close() }()
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("close deadlocked")
		}
	}
}

func TestJournalBudgetRefusesBeforeAnyObjectRead(t *testing.T) {
	req := requestFixture(t, false)
	e := New(Config{Root: filepath.Join(t.TempDir(), "journals"), AgentID: req.Plan.AgentID, Provider: req.Plan.Provider, MaxJournalBytes: 1024})
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var calls atomic.Int32
	e.runner = func(context.Context, Request, string) (*storagerestore.VerificationResult, error) {
		calls.Add(1)
		return nil, nil
	}
	if _, err := e.Submit(req); !errors.Is(err, ErrJournal) || calls.Load() != 0 || e.Get(req.Plan.VerificationID, req.Plan.OrgID) != nil {
		t.Fatal("budget exhaustion created worker", err, calls.Load())
	}
	entries, _ := os.ReadDir(e.cfg.Root)
	if len(entries) != 1 || entries[0].Name() != ".lock" {
		t.Fatal("budget exhaustion wrote plan", entries)
	}
}
