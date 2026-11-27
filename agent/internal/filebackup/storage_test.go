package filebackup

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestChangedTargetCannotDiscardOrReuploadUnresolvedArchive(t *testing.T) {
	originalStore := &testStorage{loseAck: true, blockHead: true}
	_, configPath, state, scope := archiveFixture(t, originalStore)
	originalConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	runner := openArchiveRunner(t, configPath, state)
	if _, err := runner.Submit(testID, "documents", &scope); err != nil {
		runner.Close()
		t.Fatal(err)
	}
	j := awaitStorageRetry(t, runner)
	runner.Close()
	archive, err := os.ReadFile(runner.archivePath(testID))
	if err != nil {
		t.Fatal(err)
	}

	var unexpectedCalls atomic.Int32
	changedStore := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		unexpectedCalls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer changedStore.Close()
	var changedConfig configuration
	if err := json.Unmarshal(originalConfig, &changedConfig); err != nil {
		t.Fatal(err)
	}
	changedConfig.S3["endpoint"] = changedStore.URL
	replacement, err := json.Marshal(changedConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, replacement, 0600); err != nil {
		t.Fatal(err)
	}
	makeRetryDue(t, runner, j)
	changed := openArchiveRunner(t, configPath, state)
	held := awaitStorageRetryAfter(t, changed, j.RetryCount)
	changed.Close()

	staged, err := os.ReadFile(changed.archivePath(testID))
	if err != nil || !bytes.Equal(archive, staged) || held.ArchiveSHA != j.ArchiveSHA ||
		held.PutPhase != putPossible || held.Target != j.Target || unexpectedCalls.Load() != 0 {
		t.Fatalf("target drift changed custody or attempted new target; calls=%d, %v", unexpectedCalls.Load(), err)
	}
	if err := os.WriteFile(configPath, originalConfig, 0600); err != nil {
		t.Fatal(err)
	}
	originalStore.mu.Lock()
	originalStore.blockHead = false
	originalStore.mu.Unlock()
	makeRetryDue(t, changed, held)
	restored := openArchiveRunner(t, configPath, state)
	defer restored.Close()
	if result := awaitResult(t, restored); result.Status != "completed" || result.ArchiveSHA != j.ArchiveSHA {
		t.Fatalf("restored target did not reconcile the original archive: %+v", result)
	}
	originalStore.mu.Lock()
	defer originalStore.mu.Unlock()
	if originalStore.writes != 1 {
		t.Fatalf("target drift produced %d PUTs", originalStore.writes)
	}
}

func TestScopedVersionAbsencePermitsConditionalRetryAfterHeadForbidden(t *testing.T) {
	store := &testStorage{absentHeadStatus: http.StatusForbidden}
	var rejected atomic.Bool
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPut && !rejected.Swap(true) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		store.ServeHTTP(w, req)
	})
	source, config, state, scope := archiveFixture(t, wrapped)
	runner := openArchiveRunner(t, config, state)
	if _, err := runner.Submit(testID, "documents", &scope); err != nil {
		runner.Close()
		t.Fatal(err)
	}
	j := awaitStorageRetry(t, runner)
	runner.Close()
	if j.PutPhase != putPossible || j.PutVersion != "" || !rejected.Load() {
		t.Fatalf("first uncommitted upload did not enter reconciliation: %+v", j)
	}
	stage, err := os.ReadFile(runner.archivePath(testID))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(source); err != nil {
		t.Fatal(err)
	}
	makeRetryDue(t, runner, j)
	restarted := openArchiveRunner(t, config, state)
	defer restarted.Close()
	if result := awaitResult(t, restarted); result.Status != "completed" || result.ArchiveSHA != j.ArchiveSHA {
		t.Fatalf("no-object reconciliation did not reuse the stage: %+v", result)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.writes != 1 || store.lists < 2 || !bytes.Equal(store.body, stage) {
		t.Fatalf("unexpected successful writes (%d) or changed staged bytes", store.writes)
	}
}

func makeRetryDue(t *testing.T, runner *Runner, j job) {
	t.Helper()
	j.RetryAt = time.Now().Add(-time.Second)
	if err := runner.save(j); err != nil {
		t.Fatal(err)
	}
}

func TestMissingVersionGrantHoldsStageWithoutSecondPut(t *testing.T) {
	store := &testStorage{absentHeadStatus: http.StatusForbidden}
	var rejected atomic.Int32
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPut {
			rejected.Add(1)
			store.mu.Lock()
			store.blockList = true
			store.mu.Unlock()
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		store.ServeHTTP(w, req)
	})
	_, config, state, scope := archiveFixture(t, wrapped)
	runner := openArchiveRunner(t, config, state)
	if _, err := runner.Submit(testID, "documents", &scope); err != nil {
		runner.Close()
		t.Fatal(err)
	}
	j := awaitStorageRetry(t, runner)
	runner.Close()
	makeRetryDue(t, runner, j)
	restarted := openArchiveRunner(t, config, state)
	defer restarted.Close()
	held := awaitStorageRetryAfter(t, restarted, j.RetryCount)
	if held.PutPhase != putPossible || held.PutVersion != "" || rejected.Load() != 1 {
		t.Fatalf("expected held stage without another PUT: %+v calls=%d", held, rejected.Load())
	}
	if _, err := os.Stat(restarted.archivePath(testID)); err != nil {
		t.Fatal(err)
	}
}

func TestArchiveKeyWithOnlyDeleteMarkerIsNeverReplaced(t *testing.T) {
	store := &testStorage{deleted: true}
	_, config, state, scope := archiveFixture(t, store)
	runner := openArchiveRunner(t, config, state)
	defer runner.Close()
	if _, err := runner.Submit(testID, "documents", &scope); err != nil {
		t.Fatal(err)
	}
	if job := awaitStorageRetry(t, runner); job.PutVersion != "" {
		t.Fatalf("delete marker cannot establish custody: %+v", job)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.lists != 1 || store.writes != 0 || store.gets != 0 {
		t.Fatalf("expected version listing only: %+v", store)
	}
}

func TestRetainedArchiveBeneathDeleteMarkerIsReadByExactVersion(t *testing.T) {
	store := &testStorage{loseAck: true}
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		store.ServeHTTP(w, req)
		if req.Method == http.MethodPut {
			store.mu.Lock()
			store.deleted = true
			store.mu.Unlock()
		}
	})
	_, config, state, scope := archiveFixture(t, wrapped)
	runner := openArchiveRunner(t, config, state)
	defer runner.Close()
	if _, err := runner.Submit(testID, "documents", &scope); err != nil {
		t.Fatal(err)
	}
	result := awaitResult(t, runner)
	if result.Status != "completed" || result.S3Version != "version-1" {
		t.Fatalf("exact retained archive was not reconciled: %+v", result)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.writes != 1 || store.gets != 1 || store.lists != 2 {
		t.Fatalf("expected one write, exact readback, and two scoped listings: %+v", store)
	}
}

func TestVersionGrantCheckedBeforeFirstUpload(t *testing.T) {
	store := &testStorage{blockList: true}
	_, config, state, scope := archiveFixture(t, store)
	runner := openArchiveRunner(t, config, state)
	defer runner.Close()
	if _, err := runner.Submit(testID, "documents", &scope); err != nil {
		t.Fatal(err)
	}
	if job := awaitStorageRetry(t, runner); job.PutPhase != putReady {
		t.Fatalf("unexpected PUT phase without scoped listing: %+v", job)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.lists != 1 || store.writes != 0 {
		t.Fatalf("expected no PUT before readiness check: %+v", store)
	}
}
