package filebackup

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"vnbui/agent/internal/filearchive"
	"vnbui/agent/internal/files3"
)

const testID = "a1686fb4-4c3a-406f-91da-a440b42e7172"

type testStorage struct {
	mu               sync.Mutex
	body             []byte
	sha              string
	writes           int
	heads            int
	gets             int
	loseAck          bool
	blockHead        bool
	exactHead        bool
	wrongRead        bool
	absentHeadStatus int
	blockList        bool
	deleted          bool
	lists            int
}

const testObjectKey = "test/managed-files/documents/" + testID + "/archive.age"

func (s *testStorage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/archive-bucket/" && r.URL.Query().Has("versioning") {
		io.WriteString(w, "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>")
		return
	}
	if r.URL.Path == "/archive-bucket/" && r.URL.Query().Has("versions") {
		s.lists++
		if r.URL.Query().Get("prefix") != testObjectKey {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if s.blockList {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		io.WriteString(w, "<ListVersionsResult><IsTruncated>false</IsTruncated>")
		if s.deleted {
			fmt.Fprintf(w, "<DeleteMarker><Key>%s</Key><VersionId>marker-1</VersionId><IsLatest>true</IsLatest></DeleteMarker>", testObjectKey)
		}
		if s.body != nil {
			fmt.Fprintf(w, "<Version><Key>%s</Key><VersionId>version-1</VersionId><IsLatest>%t</IsLatest><Size>%d</Size></Version>", testObjectKey, !s.deleted, len(s.body))
		}
		io.WriteString(w, "</ListVersionsResult>")
		return
	}
	if r.URL.Path != "/archive-bucket/"+testObjectKey {
		http.Error(w, "unexpected object", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodHead:
		s.heads++
		if s.blockHead {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		exact := r.URL.Query().Get("versionId") == "version-1"
		if s.deleted && !exact {
			w.Header().Set("X-Amz-Delete-Marker", "true")
			w.Header().Set("X-Amz-Version-Id", "marker-1")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if s.body == nil || s.exactHead && !exact {
			status := cmp.Or(s.absentHeadStatus, http.StatusNotFound)
			w.WriteHeader(status)
			return
		}
		s.setHeaders(w)
	case http.MethodGet:
		s.gets++
		if s.body == nil || r.URL.Query().Get("versionId") != "version-1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		s.setHeaders(w)
		body := s.body
		if s.wrongRead {
			body = bytes.Clone(body)
			body[len(body)-1] ^= 1
		}
		_, _ = w.Write(body)
	case http.MethodPut:
		s.writes++
		if r.Header.Get("If-None-Match") != "*" || s.body != nil {
			http.Error(w, "non-conditional write or overwrite attempt", http.StatusPreconditionFailed)
			return
		}
		s.body, _ = io.ReadAll(r.Body)
		sum := sha256.Sum256(s.body)
		s.sha = r.Header.Get("X-Amz-Meta-Vesta-Archive-Sha256")
		if s.sha != hex.EncodeToString(sum[:]) {
			s.body = nil
			http.Error(w, "digest mismatch", http.StatusBadRequest)
			return
		}
		if s.loseAck {
			// The effect has committed, but the client receives a failed response.
			http.Error(w, "simulated acknowledgement loss", http.StatusPreconditionFailed)
			return
		}
		w.Header().Set("ETag", `"stored"`)
		w.Header().Set("X-Amz-Version-Id", "version-1")
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *testStorage) setHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Length", strconv.Itoa(len(s.body)))
	w.Header().Set("Last-Modified", "Fri, 27 Nov 2026 12:00:00 GMT")
	w.Header().Set("ETag", `"stored"`)
	w.Header().Set("X-Amz-Meta-Vesta-Archive-Sha256", s.sha)
	w.Header().Set("X-Amz-Version-Id", "version-1")
}

func archiveFixture(t *testing.T, store http.Handler) (source, cfgPath, statePath string, scope ExpectedStorage) {
	t.Helper()
	dir := t.TempDir()
	source = filepath.Join(dir, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "letter"), []byte("site data"), 0600); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipient := identity.Recipient().String()
	server := httptest.NewTLSServer(store)
	t.Cleanup(server.Close)
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := configuration{
		Sets: []set{{Name: "documents", Root: source, Recipient: recipient}},
		S3: map[string]interface{}{
			"endpoint": server.URL, "bucket": "archive-bucket", "prefix": "test",
			"region": "us-east-1", "access_key": "test-access", "secret_key": "test-secret",
		},
		S3CAFile: caPath,
	}
	cfgPath = filepath.Join(dir, "file-backups.json")
	buf, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, buf, 0600); err != nil {
		t.Fatal(err)
	}
	scope = ExpectedStorage{
		Endpoint: server.URL, Region: "us-east-1", Bucket: "archive-bucket",
		Prefix: "test", RecipientSHA: digest(recipient),
	}
	return source, cfgPath, filepath.Join(dir, "state"), scope
}

func TestManagedFileBackupCustodyAndRestart(t *testing.T) {
	store := &testStorage{loseAck: true}
	source, cfgPath, statePath, wantScope := archiveFixture(t, store)
	runner, err := Open(t.Context(), cfgPath, statePath, "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	func() {
		defer runner.Close()
		if _, err := Open(t.Context(), cfgPath, statePath, "test-agent"); err == nil {
			t.Fatal("second process acquired the same journal")
		}
		if _, err := runner.Submit(testID, "unknown", &wantScope); !errors.Is(err, ErrUnknown) {
			t.Fatalf("undeclared file set: %v", err)
		}
		if _, err := runner.Submit(testID, "documents", &ExpectedStorage{}); !errors.Is(err, ErrScope) {
			t.Fatalf("wrong scope: %v", err)
		}
		if _, err := runner.Submit(testID, "documents", nil); !errors.Is(err, ErrScope) {
			t.Fatalf("absent scope: %v", err)
		}
		wrongEndpoint, wrongRegion := wantScope, wantScope
		wrongEndpoint.Endpoint = "https://different.test"
		wrongRegion.Region = "eu-west-1"
		for _, wrong := range []ExpectedStorage{wrongEndpoint, wrongRegion} {
			if _, err := runner.Submit(testID, "documents", &wrong); !errors.Is(err, ErrScope) {
				t.Fatalf("accepted a different S3 origin or region: %v", err)
			}
		}
		if result, err := runner.Submit(testID, "documents", &wantScope); err != nil || result.Status != "pending" {
			t.Fatalf("submit: %+v %v", result, err)
		}
		if _, err := runner.Submit(testID, "unknown", &wantScope); !errors.Is(err, ErrConflict) {
			t.Fatalf("conflicting file set: %v", err)
		}
		result := awaitResult(t, runner)
		if result.Status != "completed" || result.S3Version != "version-1" || result.S3Path != "s3://archive-bucket/test/managed-files/documents/"+testID+"/archive.age" ||
			result.Files != 1 || result.Bytes != 9 || result.RecipientSHA != wantScope.RecipientSHA ||
			result.Destination == nil || *result.Destination != wantScope {
			t.Fatalf("terminal result: %+v", result)
		}
		// Simulate death after S3 commit and before the final journal record.
		j, err := runner.read(testID)
		if err != nil {
			t.Fatal(err)
		}
		j.Status, j.S3Path, j.S3Version = "running", "", ""
		if err := runner.save(j); err != nil {
			t.Fatal(err)
		}
	}()
	// A new process must recognize the S3 object without collecting again.
	if err := os.RemoveAll(source); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(t.Context(), cfgPath, statePath, "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	result := awaitResult(t, restarted)
	if result.Status != "completed" {
		t.Fatalf("recovered status: %+v", result)
	}
	replayed, err := restarted.Submit(testID, "documents", &wantScope)
	if err != nil || !reflect.DeepEqual(replayed, result) {
		t.Fatalf("idempotent replay: %+v %v", replayed, err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.writes != 1 || result.ArchiveSize != int64(len(store.body)) || result.ArchiveSHA != store.sha {
		t.Fatalf("incorrect S3 effects (%d writes) or custody evidence: %+v", store.writes, result)
	}
	if !bytes.HasPrefix(store.body, []byte("age-encryption.org/v1\n")) || bytes.Contains(store.body, []byte("site data")) {
		t.Fatal("S3 data is not an encrypted age archive")
	}
	if result.ArchiveFormat != filearchive.Format {
		t.Fatalf("unexpected format %q", result.ArchiveFormat)
	}
}

func awaitResult(t *testing.T, runner *Runner) Result {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err := runner.Get(testID)
		if err != nil {
			t.Fatal(err)
		}
		if result.Status == "failed" || result.Status == "completed" {
			return result
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("backup did not reach terminal status")
	return Result{}
}

func TestPossibleUploadRetainsStageAcrossRestart(t *testing.T) {
	for _, lost := range []bool{false, true} {
		name, wantVersion := "acknowledged", "version-1"
		if lost {
			name, wantVersion = "lost-acknowledgement", ""
		}
		t.Run(name, func(t *testing.T) {
			store := &testStorage{loseAck: lost, blockHead: true, exactHead: !lost}
			source, config, state, scope := archiveFixture(t, store)
			runner := openArchiveRunner(t, config, state)
			if _, err := runner.Submit(testID, "documents", &scope); err != nil {
				runner.Close()
				t.Fatal(err)
			}
			j := awaitStorageRetry(t, runner)
			runner.Close()

			if j.PutPhase != putPossible || j.PutVersion != wantVersion || j.ArchiveSHA == "" || j.ArchiveSize <= 0 {
				t.Fatalf("unexpected persisted custody state: %+v", j)
			}
			stage, err := os.ReadFile(runner.archivePath(testID))
			if err != nil || int64(len(stage)) != j.ArchiveSize {
				t.Fatalf("staged encrypted bytes missing: %d, %v", len(stage), err)
			}
			if err := os.RemoveAll(source); err != nil {
				t.Fatal(err)
			}
			store.mu.Lock()
			heads := store.heads
			store.mu.Unlock()

			delayed := openArchiveRunner(t, config, state)
			// The persisted retry time must prevent further S3 traffic immediately
			// after restart, even with no remaining source tree.
			time.Sleep(100 * time.Millisecond)
			delayed.Close()
			store.mu.Lock()
			if store.heads != heads || store.writes != 1 {
				t.Errorf("restart retried before its deadline: %d HEADs, %d PUTs", store.heads, store.writes)
			}
			store.blockHead = false
			store.mu.Unlock()

			// The original capture deadline and the backoff ceiling never
			// turn a possible PUT into a terminal failure.
			j.AcceptedAt = time.Now().Add(-48 * time.Hour)
			j.RetryCount = maxRetryCount
			j.RetryAt = time.Now().Add(-time.Second)
			if err := runner.save(j); err != nil {
				t.Fatal(err)
			}
			restarted := openArchiveRunner(t, config, state)
			defer restarted.Close()
			result := awaitResult(t, restarted)
			if result.Status != "completed" || result.S3Version != "version-1" || result.ArchiveSHA != j.ArchiveSHA {
				t.Fatalf("recovered result: %+v", result)
			}
			store.mu.Lock()
			defer store.mu.Unlock()
			if store.writes != 1 || store.gets != 1 || !bytes.Equal(stage, store.body) {
				t.Fatalf("restart changed storage: %d PUTs, %d GETs", store.writes, store.gets)
			}
		})
	}
}

func TestDeclaredRemoteDigestCannotSubstituteForReadback(t *testing.T) {
	store := &testStorage{loseAck: true, wrongRead: true}
	_, config, state, scope := archiveFixture(t, store)
	runner := openArchiveRunner(t, config, state)
	defer runner.Close()
	if _, err := runner.Submit(testID, "documents", &scope); err != nil {
		t.Fatal(err)
	}
	j := awaitStorageRetry(t, runner)
	public, err := runner.Get(testID)
	if err != nil || public.Status != "running" || public.S3Version != "" ||
		j.PutVersion != "version-1" || j.Status != "running" {
		t.Fatalf("wrong remote ciphertext was accepted: public %+v journal %+v error %v", public, j, err)
	}
	if _, err := os.Stat(runner.archivePath(testID)); err != nil {
		t.Fatalf("stage lost while remote bytes differ: %v", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.writes != 1 || store.gets != 1 {
		t.Fatalf("expected one conditional PUT and one exact GET: %d, %d", store.writes, store.gets)
	}
}

func TestCustodyBackoffAllowsOtherJobs(t *testing.T) {
	future := time.Now().Add(time.Hour)
	runner := Runner{
		queue:   []string{"delayed", "ready"},
		retries: map[string]time.Time{"delayed": future},
	}
	if index, _ := runner.nextJob(); index != 1 {
		t.Fatalf("a delayed custody retry blocked a ready job: index %d", index)
	}
	runner.retries["ready"] = future.Add(time.Second)
	if index, due := runner.nextJob(); index != -1 || !due.Equal(future) {
		t.Fatalf("worker must wait for first retry: index %d due %v", index, due)
	}
}

func openArchiveRunner(t *testing.T, config, state string) *Runner {
	t.Helper()
	runner, err := Open(t.Context(), config, state, "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func awaitStorageRetry(t *testing.T, runner *Runner) job {
	t.Helper()
	return awaitStorageRetryAfter(t, runner, 0)
}

func awaitStorageRetryAfter(t *testing.T, runner *Runner, previous uint8) job {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		j, err := runner.read(testID)
		if err != nil {
			t.Fatal(err)
		}
		if j.terminal() {
			t.Fatalf("job became terminal during an S3 outage: %+v", j)
		}
		if j.RetryCount > previous {
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("pending S3 custody was not journaled")
	return job{}
}
func TestManagedFileStorageCanonicalOrigin(t *testing.T) {
	for _, endpoint := range []string{
		"http://example.test", "https://user@example.test", "https://example.test?secret=value",
		"https://example.test#", "https://example.test?", "https://example.test/other",
		"https://example.test:99999",
	} {
		if _, err := files3.CanonicalOrigin(endpoint); err == nil {
			t.Errorf("accepted unsafe endpoint %q", endpoint)
		}
	}
	got, err := files3.CanonicalOrigin("https://Archive.Test:443/")
	if err != nil || got != "https://archive.test" {
		t.Fatalf("canonical endpoint: %q %v", got, err)
	}
	defaults, err := parseFileStorage(map[string]interface{}{"bucket": "archive-bucket"})
	if err != nil || defaults.Endpoint != "s3.us-east-1.amazonaws.com" || defaults.Region != "us-east-1" {
		t.Fatalf("AWS defaults: %+v %v", defaults, err)
	}
}

func TestStagingCapacityIsBoundedWithoutOverflow(t *testing.T) {
	const available = int64(500 << 20)
	for _, tc := range []struct {
		blocks            uint64
		size, limit, want int64
	}{
		{^uint64(0), 4096, available, available},
		{uint64(1) << 63, 1, available, available},
		{300, 1 << 20, available, 44 << 20},
		{1024, 1 << 20, available, available},
	} {
		got, err := stagingLimit(tc.blocks, tc.size, tc.limit)
		if err != nil || got != tc.want {
			t.Fatalf("stagingLimit(%d, %d, %d): %d %v", tc.blocks, tc.size, tc.limit, got, err)
		}
	}
	for _, size := range []int64{0, -1, 4096} {
		if _, err := stagingLimit(1, size, available); err == nil {
			t.Fatalf("unsafe or full storage accepted, block size %d", size)
		}
	}
}
