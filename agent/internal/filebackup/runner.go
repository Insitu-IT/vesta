package filebackup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/bits"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"golang.org/x/sys/unix"

	"vnbui/agent/internal/filearchive"
)

const maxQueuedJobs = 32

const (
	putReady      = "ready"
	putPossible   = "possible"
	maxRetryCount = 6
)

var (
	ErrInvalid  = errors.New("invalid backup ID or file set name")
	ErrUnknown  = errors.New("file set is not declared on this host")
	ErrConflict = errors.New("backup ID already belongs to another file set")
	ErrScope    = errors.New("managed file backup storage scope differs from the host declaration")
	ErrBusy     = errors.New("file backup queue is full")
)

// Result is the stable observable state of a managed file backup.
type Result struct {
	BackupID      string           `json:"backup_id"`
	FileSet       string           `json:"file_set"`
	Status        string           `json:"status"`
	ArchiveFormat string           `json:"archive_format"`
	S3Path        string           `json:"s3_path,omitempty"`
	S3Version     string           `json:"s3_version_id,omitempty"`
	ArchiveSize   int64            `json:"archive_size_bytes,omitempty"`
	ArchiveSHA    string           `json:"archive_sha256,omitempty"`
	RecipientSHA  string           `json:"recipient_sha256,omitempty"`
	Destination   *ExpectedStorage `json:"storage,omitempty"`
	Files         int64            `json:"files"`
	Directories   int64            `json:"directories"`
	Bytes         int64            `json:"bytes"`
	Error         string           `json:"error,omitempty"`
}

type ExpectedStorage struct {
	Endpoint     string `json:"endpoint"`
	Region       string `json:"region"`
	Bucket       string `json:"bucket"`
	Prefix       string `json:"prefix"`
	RecipientSHA string `json:"recipient_sha256"`
}

func (s ExpectedStorage) fingerprint() string {
	return digest(strings.Join([]string{s.Endpoint, s.Region, s.Bucket, s.Prefix, s.RecipientSHA}, "\x00"))
}

type job struct {
	Result
	Definition string    `json:"definition_sha256"`
	Target     string    `json:"target_sha256"`
	Storage    string    `json:"storage_sha256"`
	AcceptedAt time.Time `json:"accepted_at"`
	PutPhase   string    `json:"put_phase,omitempty"`
	PutVersion string    `json:"put_version,omitempty"`
	RetryAt    time.Time `json:"retry_at,omitzero"`
	RetryCount uint8     `json:"retry_count,omitempty"`
}

func (j job) terminal() bool { return j.Status == "completed" || j.Status == "failed" }

type Runner struct {
	dir      string
	sets     map[string]set
	target   string
	endpoint string
	region   string
	bucket   string
	prefix   string
	maxBytes int64
	client   *minio.Client
	lock     *os.File
	mu       sync.Mutex
	queue    []string
	retries  map[string]time.Time
	wake     chan struct{}
	done     chan struct{}
	cancel   context.CancelFunc
	active   bool
}

func Open(ctx context.Context, configPath, stateDir, agentID string) (*Runner, error) {
	if agentID == "" {
		return nil, errors.New("managed file backups require an enrolled agent ID")
	}
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return nil, errors.New("managed file backup state directory must be a clean absolute path")
	}
	cfg, s3, err := loadConfig(configPath, stateDir)
	if err != nil {
		return nil, err
	}
	client, err := newClient(s3, cfg.S3CAFile)
	if err != nil {
		return nil, fmt.Errorf("initialize file backup S3 client: %w", err)
	}
	stateDir = filepath.Join(stateDir, digest(agentID))
	lock, err := lockJournal(stateDir)
	if err != nil {
		return nil, err
	}
	sets := make(map[string]set, len(cfg.Sets))
	for _, source := range cfg.Sets {
		sets[source.Name] = source
	}
	r := &Runner{
		dir: stateDir, client: client, sets: sets, lock: lock,
		target:   digest(strings.Join([]string{s3.Endpoint, s3.Region, s3.Bucket, s3.Prefix}, "\x00")),
		endpoint: "https://" + s3.Endpoint, region: s3.Region,
		bucket: s3.Bucket, prefix: s3.Prefix, maxBytes: cfg.MaxBytes,
		wake: make(chan struct{}, 1), done: make(chan struct{}), retries: make(map[string]time.Time),
	}
	if err := r.loadQueue(); err != nil {
		lock.Close()
		return nil, err
	}
	ctx, r.cancel = context.WithCancel(ctx)
	go r.run(ctx)
	return r, nil
}

func (r *Runner) Close() {
	r.cancel()
	<-r.done
	r.lock.Close()
}

func (r *Runner) Names() []string {
	names := make([]string, 0, len(r.sets))
	for name := range r.sets {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func (r *Runner) StorageScope() (endpoint, region, bucket, prefix string, recipients map[string]string) {
	recipients = make(map[string]string, len(r.sets))
	for name, source := range r.sets {
		recipients[name] = digest(source.Recipient)
	}
	return r.endpoint, r.region, r.bucket, r.prefix, recipients
}

func (r *Runner) ActiveCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active {
		return 1
	}
	return 0
}

func validID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil && parsed.String() == id
}

// Submit durably admits an attempt before a worker can collect any data.
// Repeated admission reads the existing outcome, including after restart.
func (r *Runner) Submit(id, name string, expected *ExpectedStorage) (Result, error) {
	if !validID(id) || !ValidName(name) {
		return Result{}, ErrInvalid
	}
	if expected == nil {
		return Result{}, ErrScope
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, err := r.read(id)
	if err == nil {
		if existing.FileSet != name {
			return Result{}, ErrConflict
		}
		if existing.Storage != expected.fingerprint() {
			return Result{}, ErrScope
		}
		// A previous admission could have installed the journal record
		// before its final directory sync failed. Reinstate that work.
		if !existing.terminal() && !slices.Contains(r.queue, id) {
			if err := r.syncJournal(); err != nil {
				return Result{}, err
			}
			r.enqueue(id)
		}
		return publicResult(existing), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Result{}, err
	}
	source, ok := r.sets[name]
	if !ok {
		return Result{}, ErrUnknown
	}
	storage := ExpectedStorage{
		Endpoint: r.endpoint, Region: r.region, Bucket: r.bucket, Prefix: r.prefix,
		RecipientSHA: digest(source.Recipient),
	}
	if storage != *expected {
		return Result{}, ErrScope
	}
	if len(r.queue) >= maxQueuedJobs {
		return Result{}, ErrBusy
	}
	j := job{
		Result:     Result{BackupID: id, FileSet: name, Status: "pending", ArchiveFormat: filearchive.Format, Destination: &storage},
		Definition: definition(source), Target: r.target, Storage: storage.fingerprint(), AcceptedAt: time.Now().UTC(),
	}
	if err := r.save(j); err != nil {
		return Result{}, err
	}
	r.enqueue(id)
	return publicResult(j), nil
}

func (r *Runner) enqueue(id string) {
	r.queue = append(r.queue, id)
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *Runner) Get(id string) (Result, error) {
	if !validID(id) {
		return Result{}, ErrInvalid
	}
	j, err := r.read(id)
	return publicResult(j), err
}

func publicResult(j job) Result {
	result := j.Result
	if result.Status == "running" && !j.RetryAt.IsZero() {
		result.Error = "Awaiting S3 confirmation; encrypted archive retained on host"
	}
	if result.Status != "completed" {
		result.ArchiveSHA = ""
		result.RecipientSHA = ""
		result.Destination = nil
		result.ArchiveSize = 0
	}
	return result
}

func (r *Runner) run(ctx context.Context) {
	defer close(r.done)
	for ctx.Err() == nil {
		r.mu.Lock()
		index, due := r.nextJob()
		if index < 0 {
			r.mu.Unlock()
			r.waitForJob(ctx, due)
			continue
		}
		id := r.queue[index]
		r.active = true
		r.mu.Unlock()

		retry, err := r.execute(ctx, id)
		if err != nil && ctx.Err() == nil {
			slog.Error("managed file backup journal unavailable", "backup_id", id, "error", err)
			retry = time.Now().Add(10 * time.Second)
		}
		r.mu.Lock()
		r.active = false
		switch {
		case !retry.IsZero():
			r.retries[id] = retry
		case err == nil:
			r.queue = slices.Delete(r.queue, index, index+1)
			delete(r.retries, id)
		}
		r.mu.Unlock()
	}
}

// nextJob runs with mu held. Pending custody checks do not block other jobs.
func (r *Runner) nextJob() (int, time.Time) {
	now := time.Now()
	var earliest time.Time
	for index, id := range r.queue {
		retry := r.retries[id]
		if !retry.After(now) {
			return index, time.Time{}
		}
		if earliest.IsZero() || retry.Before(earliest) {
			earliest = retry
		}
	}
	return -1, earliest
}

func (r *Runner) waitForJob(ctx context.Context, due time.Time) {
	var retry <-chan time.Time
	if !due.IsZero() {
		timer := time.NewTimer(time.Until(due))
		defer timer.Stop()
		retry = timer.C
	}
	select {
	case <-r.wake:
	case <-retry:
	case <-ctx.Done():
	}
}

func (r *Runner) execute(ctx context.Context, id string) (time.Time, error) {
	j, err := r.read(id)
	if err != nil {
		return time.Time{}, err
	}
	if j.terminal() {
		if err := r.syncJournal(); err != nil {
			return time.Time{}, err
		}
		r.cleanup(id)
		return time.Time{}, nil
	}
	// Old staged journal entries may already have sent a PUT.
	if j.ArchiveSHA != "" && j.PutPhase == "" {
		j.PutPhase = putPossible
	}
	if j.Target != r.target {
		if j.PutPhase == putPossible {
			return r.deferStorage(j, errors.New("S3 destination changed after an archive PUT may have committed"))
		}
		return time.Time{}, r.fail(j, "S3 destination changed after admission", nil)
	}
	deadline := j.AcceptedAt.Add(archiveUploadTimeout)
	if j.PutPhase != putPossible && !time.Now().Before(deadline) {
		return time.Time{}, r.fail(j, "backup deadline reached before an archive PUT", nil)
	}
	if j.Status == "pending" {
		j.Status = "running"
		if err := r.save(j); err != nil {
			return time.Time{}, err
		}
	}
	if j.ArchiveSHA == "" {
		source, found := r.sets[j.FileSet]
		if !found || j.Definition != definition(source) {
			return time.Time{}, r.fail(j, "local file set changed after admission", nil)
		}
		operation, cancel := context.WithDeadline(ctx, deadline)
		err := r.capture(operation, &j, source)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return time.Time{}, ctx.Err()
			}
			return time.Time{}, r.fail(j, "could not create encrypted file archive from the declared root", err)
		}
		j.PutPhase = putReady
		if err := r.save(j); err != nil {
			return time.Time{}, err
		}
	}

	version, err := r.storeArchive(ctx, &j)
	if ctx.Err() != nil {
		return r.deferStorage(j, ctx.Err())
	}
	if err != nil {
		if j.PutPhase == putReady && (errors.Is(err, errStageInvalid) || errors.Is(err, errVersioningDisabled)) {
			return time.Time{}, r.fail(j, "could not place the staged archive in versioned S3 storage", err)
		}
		return r.deferStorage(j, err)
	}
	if j.PutVersion == "" {
		j.PutVersion = version
		if err := r.save(j); err != nil {
			return time.Time{}, err
		}
	}
	if err := r.verifyArchive(ctx, j); err != nil {
		return r.deferStorage(j, err)
	}
	j.Status = "completed"
	j.S3Path = "s3://" + r.bucket + "/" + r.objectKey(j)
	j.S3Version = version
	j.RetryAt = time.Time{}
	j.RetryCount = 0
	if err := r.save(j); err != nil {
		return time.Time{}, err
	}
	r.cleanup(id)
	slog.Info("managed file backup completed", "backup_id", id, "file_set", j.FileSet, "files", j.Files, "bytes", j.Bytes)
	return time.Time{}, nil
}

func (r *Runner) deferStorage(j job, cause error) (time.Time, error) {
	// Delayed retries remain counted against the fixed queue size. Persist
	// the schedule so process restarts cannot spin on an unavailable store.
	delay := min(5*time.Second<<j.RetryCount, 5*time.Minute)
	j.RetryCount = min(j.RetryCount+1, maxRetryCount)
	j.RetryAt = time.Now().UTC().Add(delay)
	if err := r.save(j); err != nil {
		return time.Time{}, err
	}
	slog.Warn("managed file backup awaiting S3 custody confirmation", "backup_id", j.BackupID, "file_set", j.FileSet, "retry_at", j.RetryAt, "error", cause)
	return j.RetryAt, nil
}

func (r *Runner) objectKey(j job) string {
	return path.Join(r.prefix, "managed-files", j.FileSet, j.BackupID, archiveObject)
}

func (r *Runner) archivePath(id string) string { return filepath.Join(r.dir, id+".age") }

func (r *Runner) fail(j job, reason string, cause error) error {
	j.Status, j.Error = "failed", reason
	if err := r.save(j); err != nil {
		return err
	}
	r.cleanup(j.BackupID)
	slog.Warn("managed file backup failed", "backup_id", j.BackupID, "file_set", j.FileSet, "reason", reason, "error", cause)
	return nil
}

func (r *Runner) cleanup(id string) {
	for _, name := range []string{r.archivePath(id), r.archivePath(id) + ".partial"} {
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("could not clean managed file backup stage", "backup_id", id, "error", err)
		}
	}
}

// Staging capacity saturates at the configured archive limit, including on
// large filesystems whose available byte counter exceeds a signed integer.
func stagingLimit(blocks uint64, blockSize, maximum int64) (int64, error) {
	const reserve = 256 << 20
	if blockSize <= 0 || maximum <= 0 {
		return 0, errors.New("invalid archive staging capacity")
	}
	high, bytes := bits.Mul64(blocks, uint64(blockSize))
	if high != 0 || bytes > math.MaxInt64 {
		return maximum, nil
	}
	if bytes <= reserve {
		return 0, errors.New("insufficient free space for encrypted archive staging")
	}
	return min(int64(bytes)-reserve, maximum), nil
}

func (r *Runner) capture(ctx context.Context, j *job, source set) error {
	stage := r.archivePath(j.BackupID) + ".partial"
	if err := os.Remove(stage); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(stage)
	defer f.Close()
	var filesystem unix.Statfs_t
	if err := unix.Statfs(r.dir, &filesystem); err != nil {
		return fmt.Errorf("measure archive staging capacity: %w", err)
	}
	limit, err := stagingLimit(filesystem.Bavail, filesystem.Bsize, r.maxBytes)
	if err != nil {
		return err
	}
	hash := sha256.New()
	dst := &boundedWriter{writer: io.MultiWriter(f, hash), remaining: limit}
	summary, err := filearchive.Write(ctx, dst, source.Root, source.Recipient)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(stage, r.archivePath(j.BackupID)); err != nil {
		return err
	}
	j.Files, j.Directories, j.Bytes = summary.Files, summary.Directories, summary.Bytes
	j.ArchiveSize = limit - dst.remaining
	j.ArchiveSHA = hex.EncodeToString(hash.Sum(nil))
	j.RecipientSHA = digest(source.Recipient)
	return nil
}

type boundedWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, errors.New("encrypted archive exceeds the local staging limit")
	}
	n, err := w.writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}

func definition(s set) string {
	return digest(strings.Join([]string{s.Name, s.Root, s.Recipient}, "\x00"))
}

func digest(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

func lockJournal(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create managed file backup state directory: %w", err)
	}
	info, err := os.Lstat(dir)
	canonical, canonicalErr := filepath.EvalSymlinks(dir)
	if err != nil || canonicalErr != nil || canonical != dir || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("managed file backup state directory must be private and free of symlinks")
	}
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock managed file backup journal: %w", err)
	}
	return f, nil
}
