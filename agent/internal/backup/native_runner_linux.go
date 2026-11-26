//go:build linux

package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativestaging"
	"vnbui/agent/internal/operationbudget"
	"vnbui/agent/internal/storageupload"
)

type NativeJobSource struct {
	VMID           string             `json:"vm_id"`
	DomainUUID     string             `json:"domain_uuid"`
	AgentID        string             `json:"agent_id"`
	Disks          []NativeSourceDisk `json:"disks"`
	Exclusions     []string           `json:"exclusions"`
	BackupType     string             `json:"backup_type"`
	ParentBackupID *string            `json:"parent_backup_id"`
}

type NativeJobTarget struct {
	Endpoint          string `json:"endpoint"`
	Bucket            string `json:"bucket"`
	Region            string `json:"region"`
	Prefix            string `json:"prefix"`
	CapabilityProfile string `json:"capability_profile"`
}

type NativeJobIntent struct {
	Schema     int                      `json:"schema"`
	OrgID      string                   `json:"org_id"`
	ActorID    *string                  `json:"actor_id"`
	BackupID   string                   `json:"backup_id"`
	AgentID    string                   `json:"agent_id"`
	AttemptID  string                   `json:"attempt_id"`
	JobID      string                   `json:"job_id"`
	Checkpoint string                   `json:"checkpoint"`
	Producer   string                   `json:"producer"`
	Parent     *models.StorageParent    `json:"parent"`
	PushParent *NativePushResult        `json:"push_parent"`
	Target     NativeJobTarget          `json:"target"`
	Encryption models.StorageEncryption `json:"encryption"`
	Source     NativeJobSource          `json:"source"`
}

type NativeJobRequest struct {
	Protocol     string          `json:"protocol"`
	Intent       NativeJobIntent `json:"intent"`
	IntentSHA256 string          `json:"intent_sha256"`
}

// DecodeNativeJob accepts only the current attempt-bound push producer. There
// is no command, output path, credential, old checkpoint or fallback producer.
func DecodeNativeJob(body []byte) (*NativeJobRequest, error) {
	var request NativeJobRequest
	if models.DecodeStorageValue(body, &request, models.MaxStorageRequestBytes) != nil {
		return nil, ErrNativeUncertain
	}
	i := &request.Intent
	canonical, err := models.StorageCanonical(i)
	h := sha256.Sum256(canonical)
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if err != nil || request.Protocol != "vnbui-native-job/1" || i.Schema != 1 || i.Producer != NativePushFormat ||
		request.IntentSHA256 != hex.EncodeToString(h[:]) || i.OrgID == "" || (i.ActorID != nil && *i.ActorID == "") || i.AgentID == "" || i.Source.VMID == "" ||
		!uuid.MatchString(i.BackupID) || !uuid.MatchString(i.AttemptID) || !uuid.MatchString(i.Source.DomainUUID) ||
		i.JobID != "vnbui-native-"+i.AttemptID || i.Checkpoint != "vnbui-"+i.AttemptID || i.Source.AgentID != i.AgentID ||
		len(i.Source.Disks) == 0 || len(i.Source.Disks) > 128 || !slices.IsSorted(i.Source.Exclusions) || len(i.Source.Exclusions) >= len(i.Source.Disks) {
		return nil, ErrNativeUncertain
	}
	name := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	target, targetErr := url.Parse(i.Target.Endpoint)
	if targetErr != nil || target.Scheme != "https" || target.Host == "" || target.User != nil || target.Path != "" || target.RawQuery != "" || target.Fragment != "" ||
		i.Target.Bucket == "" || i.Target.Region == "" || i.Target.CapabilityProfile != "db-rooted-consumer-verified/1" ||
		(i.Encryption.Format != "none" && i.Encryption.Format != "vnbu1-aes256gcm-chunk5242880") ||
		(i.Encryption.Format == "none") != (i.Encryption.KeyRef == nil) {
		return nil, ErrNativeUncertain
	}
	if i.Encryption.KeyRef != nil && !regexp.MustCompile(`^kek:[^:]+:[0-9a-f]{16}([0-9a-f]{48})?$`).MatchString(*i.Encryption.KeyRef) {
		return nil, ErrNativeUncertain
	}
	targets := map[string]bool{}
	for index, disk := range i.Source.Disks {
		if !name.MatchString(disk.Target) || !name.MatchString(disk.Bus) || !filepath.IsAbs(disk.Source) || strings.ContainsRune(disk.Source, '\x00') ||
			(disk.Format != "raw" && disk.Format != "qcow2") || (index > 0 && i.Source.Disks[index-1].Target >= disk.Target) {
			return nil, ErrNativeUncertain
		}
		if !slices.Contains(i.Source.Exclusions, disk.Target) && disk.Format != "qcow2" {
			return nil, errors.New("protected native disks require qcow2 persistent checkpoints")
		}
		targets[disk.Target] = true
	}
	for index, disk := range i.Source.Exclusions {
		if !targets[disk] || (index > 0 && i.Source.Exclusions[index-1] == disk) {
			return nil, ErrNativeUncertain
		}
	}
	if i.Source.BackupType == "full" {
		if i.Parent != nil || i.PushParent != nil || i.Source.ParentBackupID != nil {
			return nil, ErrNativeUncertain
		}
	} else if i.Source.BackupType == "incremental" {
		if i.Parent == nil || i.PushParent == nil || i.Parent.BackupID == i.BackupID || i.Parent.TrackerUID != i.Source.DomainUUID ||
			i.PushParent.Manifest.BackupID != i.Parent.BackupID || i.PushParent.Manifest.Checkpoint != i.Parent.Checkpoint ||
			(i.Source.ParentBackupID != nil && *i.Source.ParentBackupID != i.Parent.BackupID) {
			return nil, ErrNativeUncertain
		}
		parent, err := models.StorageCanonical(i.PushParent.Manifest)
		hash := sha256.Sum256(parent)
		if err != nil || i.PushParent.ManifestSHA256 != hex.EncodeToString(hash[:]) {
			return nil, ErrNativeUncertain
		}
	} else {
		return nil, ErrNativeUncertain
	}
	return &request, nil
}

type nativeWork struct {
	request        *NativeJobRequest
	body           []byte
	finished, held bool
	uploadHeld     bool
	queueExpired   bool
	acceptedAt     time.Time
	queueBudget    *operationbudget.Progress
}

type nativeRunner struct {
	executor          *Executor
	root              string
	staging           *nativestaging.Profile
	lock              *os.File
	ctx               context.Context
	cancel            context.CancelFunc
	done              chan struct{}
	wake              chan struct{}
	backend, provider *http.Client
	retry             time.Duration
	mu                sync.Mutex
	transactionMu     sync.Mutex
	closed            bool
	holdCursor        string
	work              map[string]*nativeWork
	queue             []*nativeWork
	produce           func(context.Context, NativePushRequest) (*NativePushResult, error)
	settle            func(context.Context, string, string, map[string]string, *http.Client, func(context.Context) (string, error)) error
	settleClosed      func(context.Context, string, string, map[string]string, *http.Client, func(context.Context) (string, error)) error
	settleFenced      func(context.Context, string, string, map[string]string, *http.Client, func(context.Context) (string, error)) error
	admit             func(context.Context, string, string, string, string, string, *http.Client, func(context.Context) (string, error)) error
	upload            func(context.Context, string, string, string, string, string, []byte, *http.Client, *http.Client, func(context.Context) (string, error)) (*models.StorageAcceptance, error)
	publish           func(context.Context, string, string, *models.StorageAcceptance, *http.Client, func(context.Context) (string, error)) error
}

func (e *Executor) StartStorageTransactions(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.nativeRunner != nil {
		return errors.New("native runner already initialized")
	}
	r, err := newNativeRunner(ctx, e)
	if err != nil {
		return err
	}
	e.nativeRunner = r
	go r.run()
	return nil
}

func newNativeRunner(ctx context.Context, e *Executor) (_ *nativeRunner, err error) {
	if ctx == nil || e.cfg == nil || e.resources == nil || e.cfg.MockVirtnbdbackup || e.cfg.LibvirtURI != "qemu:///system" ||
		!e.cfg.OrchestratorVerifySSL || !e.cfg.EnableAPIKeyValidation || e.cfg.AgentAPIKey == "" || e.cfg.OrchestratorAPIKey == "" || e.cfg.AgentID == "" || !filepath.IsAbs(e.cfg.BackupStoragePath) {
		return nil, errors.New("native push requires local libvirt, durable storage and verified authenticated HTTPS")
	}
	u, err := url.Parse(e.cfg.OrchestratorURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrNativeUncertain
	}
	tlsConfig, err := e.cfg.OutboundTLSConfig()
	if err != nil {
		return nil, err
	}
	root := filepath.Join(e.cfg.BackupStoragePath, "native-transactions")
	if err = os.MkdirAll(root, 0711); err != nil {
		return nil, err
	}
	if resolved, e2 := filepath.EvalSymlinks(root); e2 != nil || resolved != root {
		return nil, ErrNativeUncertain
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0066 != 0 {
		return nil, ErrNativeUncertain
	}
	if err = os.Chmod(root, 0711); err != nil {
		return nil, err
	}
	lock, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = lock.Close()
		}
	}()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errors.New("native journal already owned")
	}
	for name, mode := range map[string]os.FileMode{"requests": 0700, "queue-budgets": 0700, "uploads": 0700, "attempts": 0711} {
		path := filepath.Join(root, name)
		if err = os.MkdirAll(path, mode); err != nil {
			return nil, err
		}
		info, err = os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0066 != 0 {
			return nil, ErrNativeUncertain
		}
		if err = os.Chmod(path, mode); err != nil {
			return nil, err
		}
	}
	if err = syncNativeDirectory(root); err != nil {
		return nil, err
	}
	stage, stageErr := nativestaging.NewProfile(root, e.cfg.NativeStagingRoot, e.cfg.NativeStagingSocket)
	if stageErr != nil {
		return nil, stageErr
	}
	client := func(c *tls.Config) *http.Client {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = c
		t.MaxResponseHeaderBytes = 16 << 10
		t.ResponseHeaderTimeout = 30 * time.Second
		return &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &nativeRunner{executor: e, root: root, lock: lock, ctx: ctx, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1), backend: client(tlsConfig), provider: client(&tls.Config{MinVersion: tls.VersionTLS12}), retry: 2 * time.Second, work: map[string]*nativeWork{}, produce: RunNativePush, settle: storageupload.SettleNativeNoEffect, settleClosed: storageupload.SettleNativeClosedFailure, admit: storageupload.AdmitNativeProducer, upload: storageupload.UploadClosedNative, publish: storageupload.PublishClosedNative}
	r.staging = stage
	entries, err := os.ReadDir(filepath.Join(root, "requests"))
	if err != nil {
		cancel()
		return nil, err
	}
	for _, entry := range entries {
		body, e2 := readNativeFile(filepath.Join(root, "requests", entry.Name()))
		request, e3 := DecodeNativeJob(body)
		if e2 != nil || e3 != nil || entry.Name() != request.Intent.AttemptID+".json" || request.Intent.AgentID != e.cfg.AgentID || r.work[request.Intent.BackupID] != nil {
			cancel()
			return nil, ErrNativeUncertain
		}
		canonical, _ := json.Marshal(request)
		i := request.Intent
		retired, _, retirementErr := storageupload.NativeFileSetRetired(filepath.Join(root, "uploads"), i.AttemptID, i.OrgID, i.AgentID, i.BackupID)
		if retirementErr != nil {
			cancel()
			return nil, retirementErr
		}
		if retired {
			continue
		}
		info, statErr := os.Stat(filepath.Join(root, "requests", entry.Name()))
		if statErr != nil {
			cancel()
			return nil, ErrNativeUncertain
		}
		work := &nativeWork{request: request, body: canonical, acceptedAt: info.ModTime()}
		work.queueBudget, err = readNativeQueueBudget(root, request)
		if err != nil {
			cancel()
			return nil, err
		}
		if work.queueBudget != nil {
			work.acceptedAt = work.queueBudget.StartedAt
		}
		r.work[request.Intent.BackupID] = work
		r.queue = append(r.queue, work)
	}
	return r, nil
}

func (e *Executor) StartNativeJob(ctx context.Context, body []byte) error {
	e.mu.RLock()
	r := e.nativeRunner
	e.mu.RUnlock()
	if r == nil {
		return errors.New("native runner unavailable")
	}
	request, err := DecodeNativeJob(body)
	if err != nil || request.Intent.AgentID != e.cfg.AgentID {
		return ErrNativeUncertain
	}
	canonical, err := json.Marshal(request)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || ctx.Err() != nil || r.ctx.Err() != nil {
		return ErrNativeUncertain
	}
	i := request.Intent
	retired, _, retirementErr := storageupload.NativeFileSetRetired(filepath.Join(r.root, "uploads"), i.AttemptID, i.OrgID, i.AgentID, i.BackupID)
	if retirementErr != nil || retired {
		return ErrNativeUncertain
	}
	if prior := r.work[request.Intent.BackupID]; prior != nil {
		if bytes.Equal(prior.body, canonical) {
			if prior.queueExpired {
				return ErrNativeUncertain
			}
			if prior.finished && prior.held {
				if prior.uploadHeld || len(r.queue) >= 64 || r.nativeResumeAdmissible(prior) != nil {
					return ErrNativeUncertain
				}
				prior.finished, prior.held = false, false
				r.queue = append(r.queue, prior)
				r.progress(prior, models.TaskStatusPending, "resuming exact closed native attempt")
				select {
				case r.wake <- struct{}{}:
				default:
				}
			}
			return nil
		}
		return ErrNativeUncertain
	}
	if len(r.queue) >= 64 {
		return errors.New("native queue at capacity")
	}
	for _, prior := range r.work {
		if prior.request.Intent.AttemptID == request.Intent.AttemptID || ((!prior.finished || prior.held) && prior.request.Intent.Source.DomainUUID == request.Intent.Source.DomainUUID) {
			return ErrNativeUncertain
		}
	}
	queueBudget, err := e.cfg.SafetyPolicy().Begin(0, 8<<20, 24*time.Hour, time.Now())
	if err != nil {
		return err
	}
	if err = writeNativeFile(filepath.Join(r.root, "requests", request.Intent.AttemptID+".json"), canonical); err != nil {
		return err
	}
	queued, err := json.Marshal(nativeQueueRecord{Schema: 1, IntentSHA256: request.IntentSHA256, Budget: *queueBudget})
	if err != nil {
		return err
	}
	if err = writeNativeFile(filepath.Join(r.root, "queue-budgets", request.Intent.AttemptID+".json"), queued); err != nil {
		return err
	}
	work := &nativeWork{request: request, body: canonical, acceptedAt: queueBudget.StartedAt, queueBudget: queueBudget}
	r.work[request.Intent.BackupID] = work
	r.queue = append(r.queue, work)
	r.progress(work, models.TaskStatusPending, "durable native intent accepted")
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return nil
}

func (r *nativeRunner) nativeResumeAdmissible(work *nativeWork) error {
	if proof, err := r.readFencedFailure(r.ctx, work); err != nil {
		return err
	} else if proof != nil {
		return nil // Failed-only settlement, never producer or upload replay.
	}
	i := work.request.Intent
	path := r.attemptPath(i.AttemptID)
	if r.staging != nil {
		body, err := models.StorageCanonical(nativeProducerRequest(work.request, path))
		if err == nil && r.staging.Fresh(body) == nil {
			return nil // Original untouched root-issued slot, never absence or old producer replay.
		}
	}
	proof, proofErr := readNativeClosedFailure(path, filepath.Join(r.root, "uploads", i.AttemptID), nativeProducerRequest(work.request, path))
	if proofErr != nil {
		return proofErr
	}
	if proof != nil {
		return nil // Settlement only; never producer replay or partial upload.
	}
	body, err := readNativeFile(filepath.Join(path, "admission.json"))
	if os.IsNotExist(err) {
		seal, sealErr := readNativeSeal(path, filepath.Join(r.root, "uploads", i.AttemptID), nativeProducerRequest(work.request, path))
		if sealErr == nil && seal != nil {
			return nil // Enqueue capture of positive closure, never producer replay.
		}
		return ErrNativeUncertain
	}
	var closed storageupload.ClosedNativeAdmission
	if err != nil || models.DecodeStorageValue(body, &closed, models.MaxStorageRequestBytes) != nil ||
		closed.IntentSHA256 != work.request.IntentSHA256 || closed.Inventory.BackupID != i.BackupID ||
		closed.Inventory.AttemptID != i.AttemptID || closed.Inventory.DomainUUID != i.Source.DomainUUID ||
		closed.Inventory.Checkpoint != i.Checkpoint {
		return ErrNativeUncertain // Never re-enter a producer to repair missing closure.
	}
	if published, err := readNativePublished(path, work.request, body); err != nil {
		return err
	} else if published {
		return nil // Resume only the exact local reclamation, never upload.
	}
	return storageupload.CanResumeClosedNative(filepath.Join(r.root, "uploads"), NativePushTree(path), i.OrgID, i.AgentID, body)
}

func (r *nativeRunner) run() {
	defer close(r.done)
	queueStopped := make(chan struct{})
	go func() {
		defer close(queueStopped)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			r.expireQueue(time.Now())
			select {
			case <-r.ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() { <-queueStopped }()
	for {
		if r.ctx.Err() != nil {
			return
		}
		r.mu.Lock()
		var work *nativeWork
		if len(r.queue) > 0 {
			work, r.queue = r.queue[0], r.queue[1:]
			work.queueExpired = false
		}
		r.mu.Unlock()
		if work == nil {
			select {
			case <-r.ctx.Done():
				return
			case <-r.wake:
				continue
			}
		}
		r.process(work)
	}
}

func (r *nativeRunner) process(work *nativeWork) {
	r.transactionMu.Lock()
	defer r.transactionMu.Unlock()
	// The original request is O_EXCL and never rewritten. Its acceptance time
	// bounds legacy observation across restart; the fresh producer separately
	// pins a size-derived budget after exact source/blockInfo admission.
	start := work.acceptedAt
	if start.IsZero() {
		info, err := os.Stat(filepath.Join(r.root, "requests", work.request.Intent.AttemptID+".json"))
		if err != nil {
			r.retain(work)
			return
		}
		start = info.ModTime()
	}
	ctx, cancel := context.WithDeadline(r.ctx, start.Add(24*time.Hour))
	defer cancel()
	queueDeadline := start // Missing old policy cannot authorize a new producer.
	if work.queueBudget != nil {
		queueDeadline = work.queueBudget.StartedAt.Add(time.Duration(work.queueBudget.Budget.PreparationSeconds) * time.Second)
	}
	for r.executor.resources.AcquireBackupSlot() != nil {
		if work.queueBudget == nil || work.queueBudget.Exhausted(time.Now()) != "" || !r.wait(ctx) {
			r.retain(work)
			return
		}
	}
	defer r.executor.resources.ReleaseBackupSlot()
	i := work.request.Intent
	credential := func(ctx context.Context) (string, error) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return r.executor.cfg.AgentAPIKey, nil
	}
	path := r.attemptPath(i.AttemptID)
	request := nativeProducerRequest(work.request, path)
	if proof, err := r.readFencedFailure(ctx, work); err != nil {
		r.retain(work)
		return
	} else if proof != nil {
		r.finishFencedFailure(ctx, work, proof)
		return
	}
	closure, closureErr := readNativeClosedFailure(path, filepath.Join(r.root, "uploads", i.AttemptID), request)
	if closureErr != nil {
		r.retain(work)
		return
	}
	if closure != nil {
		r.finishClosedFailure(ctx, work, closure)
		return
	}
	proof, proofErr := readNativeNoEffect(path, filepath.Join(r.root, "uploads", i.AttemptID), request)
	if proofErr != nil {
		r.retain(work)
		return
	}
	if proof != nil {
		r.finishNoEffect(ctx, work, proof)
		return
	}
	admission, err := readNativeFile(filepath.Join(path, "admission.json"))
	if os.IsNotExist(err) {
		seal, sealErr := readNativeSeal(path, filepath.Join(r.root, "uploads", i.AttemptID), request)
		if sealErr != nil {
			r.retain(work)
			return
		}
		if seal != nil {
			admission, err = captureNativeSeal(request, seal, work.request.IntentSHA256)
			if err != nil {
				r.retain(work)
				return
			}
		}
	}
	if err != nil {
		if !os.IsNotExist(err) {
			r.retain(work)
			return
		}
		if work.queueBudget == nil || work.queueBudget.Exhausted(time.Now()) != "" {
			// A slot becoming free does not renew an old queued admission.
			// Positive existing closure/seal recovery above remains separate.
			r.retain(work)
			return
		}
		requestBody, bodyErr := models.StorageCanonical(request)
		if bodyErr != nil {
			r.retain(work)
			return
		}
		if _, inspect := os.Lstat(path); !os.IsNotExist(inspect) {
			if r.staging == nil || r.staging.Fresh(requestBody) != nil {
				r.retain(work)
				return
			}
		}
		producerSHA := sha256.Sum256(requestBody)
		prepareCtx, prepareCancel := context.WithDeadline(ctx, queueDeadline)
		defer prepareCancel()
		if err := r.admit(prepareCtx, r.executor.cfg.OrchestratorURL, i.BackupID, i.AttemptID, work.request.IntentSHA256, hex.EncodeToString(producerSHA[:]), r.backend, credential); err != nil {
			r.retainReason(work, errors.New("native producer authority unavailable; attempt not launched"))
			return
		}
		if r.staging != nil && r.staging.Allocate(prepareCtx, requestBody) != nil {
			r.retainReason(work, errors.New("native staging allocation unavailable; producer not launched"))
			return
		}
		if prepareCtx.Err() != nil {
			r.retain(work)
			return
		}
		prepareCancel()
		r.progress(work, models.TaskStatusRunning, "observing native push producer")
		result, e2 := r.produce(ctx, request)
		if e2 != nil || result == nil {
			closure, closureErr := readNativeClosedFailure(path, filepath.Join(r.root, "uploads", i.AttemptID), request)
			if closureErr != nil {
				r.retain(work)
				return
			}
			if closure != nil {
				r.finishClosedFailure(ctx, work, closure)
				return
			}
			seal, sealErr := readNativeSeal(path, filepath.Join(r.root, "uploads", i.AttemptID), request)
			if sealErr == nil && seal != nil {
				admission, err = captureNativeSeal(request, seal, work.request.IntentSHA256)
				if err != nil {
					r.retain(work)
					return
				}
			} else {
				proof, proofErr := readNativeNoEffect(path, filepath.Join(r.root, "uploads", i.AttemptID), request)
				if proofErr == nil && proof != nil {
					r.finishNoEffect(ctx, work, proof)
					return
				}
				r.retainReason(work, e2)
				return
			}
		} else {
			invocation := make([]byte, 16)
			if _, err = rand.Read(invocation); err != nil {
				r.retain(work)
				return
			}
			admission, err = CaptureNativePush(request, *result, work.request.IntentSHA256, hex.EncodeToString(invocation))
			if err != nil {
				r.retain(work)
				return
			}
		}
	}
	var closed storageupload.ClosedNativeAdmission
	if models.DecodeStorageValue(admission, &closed, models.MaxStorageRequestBytes) != nil ||
		closed.IntentSHA256 != work.request.IntentSHA256 || closed.Inventory.BackupID != i.BackupID ||
		closed.Inventory.AttemptID != i.AttemptID || closed.Inventory.DomainUUID != i.Source.DomainUUID || closed.Inventory.Checkpoint != i.Checkpoint {
		r.retain(work)
		return
	}
	if published, markerErr := readNativePublished(path, work.request, admission); markerErr != nil {
		r.retain(work)
		return
	} else if published {
		if err := reclaimNativeTree(path, closed.Inventory); err != nil {
			r.retainReason(work, err)
			return
		}
		r.complete(work)
		return
	}
	for {
		r.progress(work, models.TaskStatusRunning, "uploading sealed native files and publishing generation")
		accepted, err := r.upload(ctx, filepath.Join(r.root, "uploads"), NativePushTree(path), i.OrgID, i.AgentID, r.executor.cfg.OrchestratorURL, admission, r.backend, r.provider, credential)
		if errors.Is(err, storageupload.ErrHeld) {
			// A held upload is not a transient publication failure. Reopening
			// its journal cannot authorize another provider effect or clear
			// uncertainty; retain custody and expose the operator hold.
			r.retainReason(work, err)
			return
		}
		if err == nil && accepted != nil {
			err = r.publish(ctx, r.executor.cfg.OrchestratorURL, i.BackupID, accepted, r.backend, credential)
			if err == nil {
				if err = r.finishPublished(work, path, admission, closed.Inventory, accepted); err != nil {
					r.retainReason(work, err)
					return
				}
				r.complete(work)
				return
			}
		}
		if !r.wait(ctx) {
			r.retain(work)
			return
		}
	}
}

func (r *nativeRunner) attemptPath(attempt string) string {
	if r.staging != nil {
		return filepath.Join(r.staging.Root, attempt)
	}
	return filepath.Join(r.root, "attempts", attempt)
}

func (r *nativeRunner) complete(work *nativeWork) {
	r.mu.Lock()
	work.finished, work.held = true, false
	r.mu.Unlock()
	r.progress(work, models.TaskStatusCompleted, "native backup published; local producer files reclaimed")
}

func (r *nativeRunner) wait(ctx context.Context) bool {
	timer := time.NewTimer(r.retry)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
func (r *nativeRunner) retain(w *nativeWork) {
	r.retainReason(w, nil)
}

// NativeHoldEvents is a repeatable snapshot, not an execution acknowledgement.
// The durable original requests reconstruct holds after restart. Pagination
// bounds heartbeat size without permanently hiding holds beyond the first page.
func (e *Executor) NativeHoldEvents() []map[string]interface{} {
	e.mu.RLock()
	r := e.nativeRunner
	e.mu.RUnlock()
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0)
	for id, work := range r.work {
		if (work.finished && work.held) || work.queueExpired {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	if len(ids) == 0 {
		return nil
	}
	start := 0
	for index, id := range ids {
		if id > r.holdCursor {
			start = index
			break
		}
	}
	events := make([]map[string]interface{}, 0, min(len(ids), 64))
	for index := 0; index < min(len(ids), 64); index++ {
		id := ids[(start+index)%len(ids)]
		work := r.work[id]
		reason := "native_attempt_retained"
		if work.uploadHeld {
			reason = "native_upload_held"
		}
		events = append(events, map[string]interface{}{
			"type": "native_attempt_held", "schema": 1,
			"backup_id": id, "attempt_id": work.request.Intent.AttemptID,
			"intent_sha256": work.request.IntentSHA256, "reason": reason,
		})
		r.holdCursor = id
	}
	return events
}

func (r *nativeRunner) retainReason(w *nativeWork, reason error) {
	r.mu.Lock()
	w.finished, w.held = true, true
	if errors.Is(reason, storageupload.ErrHeld) {
		// The uploader explicitly denied continuation. A duplicate delivery
		// cannot undo that decision even if the journal write was uncertain.
		w.uploadHeld = true
	}
	r.mu.Unlock()
	operation := "native attempt retained; no relaunch, abort or cleanup"
	if reason != nil {
		detail := reason.Error()
		if len(detail) > 1024 {
			detail = detail[:1024]
		}
		operation += ": " + detail
	}
	r.progress(w, models.TaskStatusCleanupRequired, operation)
}
func (r *nativeRunner) progress(w *nativeWork, status models.TaskStatus, operation string) {
	now := time.Now().UTC()
	progress := &models.BackupProgress{BackupID: w.request.Intent.BackupID, Status: status, CurrentOperation: &operation, StartedAt: &now}
	if status == models.TaskStatusCompleted {
		progress.ProgressPercent = 100
	}
	r.executor.mu.Lock()
	if old := r.executor.jobs[progress.BackupID]; old != nil {
		progress.StartedAt = old.StartedAt
	}
	r.executor.jobs[progress.BackupID] = progress
	r.executor.mu.Unlock()
}

func (e *Executor) CloseStorageTransactions() error {
	e.mu.RLock()
	r := e.nativeRunner
	e.mu.RUnlock()
	if r == nil {
		return nil
	}
	r.mu.Lock()
	r.closed = true
	r.cancel()
	r.mu.Unlock()
	<-r.done
	r.backend.CloseIdleConnections()
	r.provider.CloseIdleConnections()
	return r.lock.Close()
}

func readNativeFile(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > models.MaxStorageRequestBytes {
		return nil, ErrNativeUncertain
	}
	body, err := io.ReadAll(io.LimitReader(file, models.MaxStorageRequestBytes+1))
	if len(body) > models.MaxStorageRequestBytes {
		return nil, ErrNativeUncertain
	}
	return body, err
}
func syncNativeDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func writeNativeFile(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(body)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = syncNativeDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("native intent durability unavailable: %w", err)
	}
	return nil
}
