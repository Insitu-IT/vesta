package restore

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativerestore"
	"vnbui/agent/internal/operationbudget"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/restoreinput"
)

var errNativeRestoreHeld = errors.New("restore held: native destination custody or prerequisites require operator review")

type nativeRestoreState struct {
	Schema        int                          `json:"schema"`
	Request       models.NativeRestoreRequest  `json:"request"`
	PlanSHA       string                       `json:"plan_sha256"`
	Token         string                       `json:"token"`
	Root          string                       `json:"root"`
	URI           string                       `json:"uri"`
	CAPEM         string                       `json:"ca_pem"`
	Phase         string                       `json:"phase"`
	Members       []backup.NativeRestoreMember `json:"members"`
	Disks         []backup.NativeRestoredDisk  `json:"disks"`
	Budget        *operationbudget.Progress    `json:"budget,omitempty"`
	RequiredBytes int64                        `json:"required_bytes,omitempty"`
	Progress      models.RestoreProgress       `json:"progress"`
}

type nativeRestoreRunner struct {
	cfg         *config.Config
	resources   *resources.Manager
	mu          sync.RWMutex
	states      map[string]*nativeRestoreState
	root        string
	lock        *os.File
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	wake        chan struct{}
	reconstruct func(context.Context, []backup.NativeRestoreMember, string) ([]backup.NativeRestoredDisk, error)
	define      func(context.Context, nativerestore.DefinitionRequest) (map[string]interface{}, error)
}

func newNativeRestoreRunner(cfg *config.Config, res *resources.Manager) *nativeRestoreRunner {
	return &nativeRestoreRunner{cfg: cfg, resources: res, states: map[string]*nativeRestoreState{}, wake: make(chan struct{}, 1), reconstruct: backup.RestoreNativePush, define: nativerestore.Define}
}
func (e *Executor) FreshNativeRestore()                     {}
func (e *Executor) StartRestores(ctx context.Context) error { return e.fresh.initialize(ctx) }
func (e *Executor) CloseRestores() error                    { return e.fresh.close() }

func (r *nativeRestoreRunner) initialize(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil || r.cfg == nil || r.cfg.AgentID == "" || r.cfg.KeyFilePath == "" || !r.cfg.EnableAPIKeyValidation || r.cfg.OrchestratorAPIKey == "" ||
		!r.cfg.OrchestratorVerifySSL || r.cfg.LibvirtURI != "qemu:///system" || !filepath.IsAbs(r.cfg.NativeRestoreRoot) || filepath.Clean(r.cfg.NativeRestoreRoot) != r.cfg.NativeRestoreRoot || r.cfg.NativeRestoreRoot == "/" {
		return errors.New("native restore requires authenticated HTTPS, persistent private journals, qemu:///system and an explicit fresh image root")
	}
	r.root = filepath.Join(filepath.Dir(r.cfg.KeyFilePath), "native-restores")
	if err := os.MkdirAll(r.root, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(r.root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errNativeRestoreHeld
	}
	if err := os.MkdirAll(r.cfg.NativeRestoreRoot, 0711); err != nil {
		return err
	}
	actual, err := filepath.EvalSymlinks(r.cfg.NativeRestoreRoot)
	if err != nil || actual != r.cfg.NativeRestoreRoot {
		return errNativeRestoreHeld
	}
	imageRoot, err := os.Lstat(r.cfg.NativeRestoreRoot)
	if err != nil || !imageRoot.IsDir() || imageRoot.Mode().Perm()&0022 != 0 {
		return errors.New("native restore image root must not be group/other writable")
	}
	// MkdirAll's mode is filtered by the shipped service UMask=0027. Grant
	// search explicitly, as for the verified attempt directories below; do not
	// grant directory listing, disk access, or access to the private journals.
	if err := os.Chmod(r.cfg.NativeRestoreRoot, 0711); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(r.root, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		lock.Close()
		return errNativeRestoreHeld
	}
	r.lock = lock
	entries, err := os.ReadDir(r.root)
	if err == nil {
		for _, entry := range entries {
			if entry.Name() == ".lock" || strings.HasPrefix(entry.Name(), ".pending-") {
				continue
			}
			var state nativeRestoreState
			if restoreinput.ReadJSONFile(filepath.Join(r.root, entry.Name()), &state, 8<<20, true) != nil {
				err = errNativeRestoreHeld
				break
			}
			_, digest, check := nativerestore.ValidatePlan(&state.Request, state.Progress.Status != models.TaskStatusCompleted)
			if check != nil || state.Schema != 1 || state.PlanSHA != digest || entry.Name() != state.Request.RestoreID+".json" || state.Request.AgentID != r.cfg.AgentID ||
				state.Root != r.cfg.NativeRestoreRoot || state.URI != r.cfg.LibvirtURI || len(state.Token) != 64 {
				err = errNativeRestoreHeld
				break
			}
			r.states[state.Request.RestoreID] = &state
		}
	}
	if err != nil {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		lock.Close()
		r.lock = nil
		return err
	}
	r.ctx, r.cancel = context.WithCancel(ctx)
	r.done = make(chan struct{})
	go r.loop()
	return nil
}
func (r *nativeRestoreRunner) close() error {
	r.mu.RLock()
	cancel, done := r.cancel, r.done
	r.mu.RUnlock()
	if cancel == nil {
		return nil
	}
	cancel()
	<-done
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = syscall.Flock(int(r.lock.Fd()), syscall.LOCK_UN)
	err := r.lock.Close()
	r.cancel = nil
	return err
}
func (r *nativeRestoreRunner) start(request *models.RestoreRequest) (*models.RestoreProgress, error) {
	if request == nil || request.Native == nil || request.KubeVirt != nil || request.RestoreID != request.Native.RestoreID {
		return nil, errors.New("fresh accepted native restore plan required")
	}
	req := request.Native
	bundle, digest, err := nativerestore.ValidatePlan(req, true)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(req)
	if err != nil || len(body) > 900<<10 {
		return nil, errors.New("native restore control request exceeds 900 KiB")
	}
	var detached models.NativeRestoreRequest
	_ = json.Unmarshal(body, &detached)
	caPEM := ""
	if r.cfg.NativeRestoreCAFile != "" {
		pem, err := os.ReadFile(r.cfg.NativeRestoreCAFile)
		if err != nil || len(pem) > 256<<10 || !x509.NewCertPool().AppendCertsFromPEM(pem) {
			return nil, errors.New("native restore trusted S3 CA is unavailable")
		}
		caPEM = string(pem)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel == nil || r.ctx.Err() != nil || req.AgentID != r.cfg.AgentID {
		return nil, errors.New("native restore executor unavailable")
	}
	if previous := r.states[req.RestoreID]; previous != nil {
		if previous.PlanSHA != digest {
			return nil, errNativeRestoreHeld
		}
		return nativeObservedProgress(previous), nil
	}
	active := 0
	for _, s := range r.states {
		if s.Progress.Status != models.TaskStatusCompleted {
			active++
		}
		if s.Request.Target.VMName == req.Target.VMName || s.Request.Target.VMUUID == req.Target.VMUUID {
			return nil, errors.New("fresh domain identity is already reserved")
		}
	}
	if active >= 64 {
		return nil, errors.New("native restore queue is full")
	}
	transfer, materialized, err := operationbudget.BundleBytes(req.Bundle)
	if err != nil {
		return nil, err
	}
	var outputBytes int64
	for _, disk := range bundle.Members[len(bundle.Members)-1].PushResult.Manifest.Disks {
		outputBytes, err = operationbudget.SumBytes(outputBytes, disk.VirtualSize)
		if err != nil {
			return nil, err
		}
	}
	cost, err := operationbudget.SumBytes(transfer, materialized, outputBytes)
	if err != nil {
		return nil, err
	}
	budget, err := r.cfg.SafetyPolicy().Begin(cost, 8<<20, 24*time.Hour, time.Now())
	if err != nil {
		return nil, err
	}
	required, err := operationbudget.SumBytes(materialized, outputBytes)
	if err != nil {
		return nil, err
	}
	required, err = r.cfg.SafetyPolicy().ScratchBytes(required)
	if err != nil {
		return nil, err
	}
	var token [32]byte
	if _, err = rand.Read(token[:]); err != nil {
		return nil, err
	}
	op := "verifying native restore receipt chain"
	state := &nativeRestoreState{Schema: 1, Budget: budget, RequiredBytes: required, Request: detached, PlanSHA: digest, Token: hex.EncodeToString(token[:]), Root: r.cfg.NativeRestoreRoot, URI: r.cfg.LibvirtURI, CAPEM: caPEM, Phase: "prepared", Progress: models.RestoreProgress{RestoreID: req.RestoreID, Status: models.TaskStatusRunning, CurrentOperation: &op}}
	if err := r.write(state); err != nil {
		return nil, err
	}
	r.states[req.RestoreID] = state
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return nativeProgress(state.Progress), nil
}
func nativeProgress(p models.RestoreProgress) *models.RestoreProgress {
	body, _ := json.Marshal(p)
	var result models.RestoreProgress
	_ = json.Unmarshal(body, &result)
	return &result
}

// A blocked worker must not hide an expired queue behind it. This negative
// observation follows the already durable deadline; it neither mutates custody
// nor claims the original worker has stopped. The loop still reconciles it.
func nativeObservedProgress(s *nativeRestoreState) *models.RestoreProgress {
	p := nativeProgress(s.Progress)
	if p.Status == models.TaskStatusRunning || p.Status == models.TaskStatusPending {
		if _, reason := s.Budget.WorkerDeadline(time.Now()); reason != "" {
			p.Status = models.TaskStatusCleanupRequired
			message := reason + "; original worker and partial destination retained"
			p.ErrorMessage = &message
		}
	}
	return p
}
func (r *nativeRestoreRunner) progress(id string) *models.RestoreProgress {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if s := r.states[id]; s != nil {
		return nativeObservedProgress(s)
	}
	return nil
}
func (r *nativeRestoreRunner) activeCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, s := range r.states {
		if s.Progress.Status == models.TaskStatusRunning {
			n++
		}
	}
	return n
}
func (r *nativeRestoreRunner) write(state *nativeRestoreState) error {
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(r.root, ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(body)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(r.root, state.Request.RestoreID+".json")); err != nil {
		return err
	}
	return nativerestore.SyncDirectory(r.root)
}
func (r *nativeRestoreRunner) save(state *nativeRestoreState) error {
	if state.Budget != nil {
		stage := map[string]string{"prepared": "queued", "materializing": "transferring", "inputs_verified": "transferring", "assembling": "transferring", "disks_verified": "finalizing", "defining": "publishing", "complete": "complete"}[state.Phase]
		if stage == "" {
			return errNativeRestoreHeld
		}
		if _, err := state.Budget.Advance(time.Now(), stage, int64(state.Progress.ProgressPercent)); err != nil {
			return err
		}
	}
	if err := r.write(state); err != nil {
		return err
	}
	body, _ := json.Marshal(state)
	var detached nativeRestoreState
	_ = json.Unmarshal(body, &detached)
	r.mu.Lock()
	r.states[state.Request.RestoreID] = &detached
	r.mu.Unlock()
	return nil
}
func (r *nativeRestoreRunner) loop() {
	defer close(r.done)
	timer := time.NewTicker(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-r.wake:
		case <-timer.C:
		}
		r.mu.RLock()
		var todo []nativeRestoreState
		for _, s := range r.states {
			if s.Progress.Status == models.TaskStatusRunning {
				body, _ := json.Marshal(s)
				var c nativeRestoreState
				_ = json.Unmarshal(body, &c)
				todo = append(todo, c)
			}
		}
		r.mu.RUnlock()
		for i := range todo {
			if r.ctx.Err() != nil {
				return
			}
			deadline, reason := todo[i].Budget.WorkerDeadline(time.Now())
			if reason != "" {
				todo[i].Progress.Status = models.TaskStatusCleanupRequired
				message := reason + "; partial destination retained"
				todo[i].Progress.ErrorMessage = &message
				_ = r.save(&todo[i])
				continue
			}
			if r.resources.AcquireRestoreSlot() != nil {
				continue
			}
			ctx, cancel := context.WithDeadline(r.ctx, deadline)
			err := r.reconcile(ctx, &todo[i])
			cancel()
			r.resources.ReleaseRestoreSlot()
			if err != nil {
				reason := errNativeRestoreHeld.Error()
				todo[i].Progress.Status = models.TaskStatus("cleanup_required")
				todo[i].Progress.ErrorMessage = &reason
				_ = r.save(&todo[i])
			}
		}
	}
}
func (r *nativeRestoreRunner) reconcile(ctx context.Context, state *nativeRestoreState) error {
	bundle, _, err := nativerestore.ValidatePlan(&state.Request, true)
	if err != nil {
		return err
	}
	base := filepath.Join(state.Root, state.Request.RestoreID)
	output := filepath.Join(base, "disks")
	if state.Phase == "prepared" {
		if state.RequiredBytes > 0 {
			sample, err := operationbudget.SampleScratch(state.Root)
			if err != nil || sample.AvailableBytes < state.RequiredBytes {
				return errors.New("restore output and materialization reserve unavailable")
			}
		}
		state.Phase = "materializing"
		if err = r.save(state); err != nil {
			return err
		}
		if err = os.Mkdir(base, 0700); err != nil {
			return err
		}
		if err = nativerestore.SyncDirectory(state.Root); err != nil {
			return err
		}
		s3 := state.Request.S3
		open, close, err := restoreinput.S3SourceConfig(restoreinput.S3Configuration{Endpoint: s3.Endpoint, Bucket: s3.Bucket, Region: s3.Region, AccessKey: s3.AccessKey, SecretKey: s3.SecretKey, SessionToken: s3.SessionToken, CAPEM: state.CAPEM})
		if err != nil {
			return err
		}
		defer close()
		keys := func(_ context.Context, m nativerestore.Member) ([]byte, error) {
			return base64.StdEncoding.Strict().DecodeString(state.Request.Keys[m.Request.BackupID])
		}
		state.Members, err = nativerestore.Materialize(ctx, bundle, filepath.Join(base, "members"), open, keys)
		if err != nil {
			return err
		}
		state.Phase = "inputs_verified"
		state.Progress.ProgressPercent = 35
		if err = r.save(state); err != nil {
			return err
		}
	}
	if state.Phase == "inputs_verified" {
		state.Phase = "assembling"
		if err = r.save(state); err != nil {
			return err
		}
		state.Disks, err = r.reconstruct(ctx, state.Members, output)
		if err != nil {
			return err
		}
		if err = syncNativeDisks(state.Disks, output); err != nil {
			return err
		}
		state.Phase = "disks_verified"
		state.Progress.ProgressPercent = 85
		if err = r.save(state); err != nil {
			return err
		}
	}
	if state.Phase == "assembling" {
		// The helper atomically creates this success receipt only after all
		// conversions and hashes. Missing success evidence retains the hold.
		if err = restoreinput.ReadJSONFile(filepath.Join(output, "restored.json"), &state.Disks, 1<<20, true); err != nil {
			return err
		}
		if err = syncNativeDisks(state.Disks, output); err != nil {
			return err
		}
		state.Phase = "disks_verified"
		if err = r.save(state); err != nil {
			return err
		}
	}
	if state.Phase == "disks_verified" || state.Phase == "defining" {
		create := state.Phase == "disks_verified"
		last := bundle.Members[len(bundle.Members)-1]
		xml, err := os.ReadFile(filepath.Join(base, "members", fmt.Sprintf("member-%03d", len(bundle.Members)-1), "domain.xml"))
		if err != nil || len(xml) > 1<<20 {
			return errNativeRestoreHeld
		}
		// Only after every byte verifies may libvirt traverse these image paths.
		if err = os.Chmod(base, 0711); err != nil {
			return err
		}
		if err = os.Chmod(output, 0711); err != nil {
			return err
		}
		state.Phase = "defining"
		if err = r.save(state); err != nil {
			return err
		}
		state.Progress.Result, err = r.define(ctx, nativerestore.DefinitionRequest{URI: state.URI, DomainXML: string(xml), Manifest: last.PushResult.Manifest, Target: state.Request.Target, Disks: state.Disks, RestoreID: state.Request.RestoreID, Token: state.Token, PlanSHA256: state.PlanSHA, OutputPath: output, AllowCreate: create})
		if err != nil {
			return err
		}
		state.Phase = "complete"
		state.Progress.Status = models.TaskStatusCompleted
		state.Progress.ProgressPercent = 100
		state.Request.S3 = models.KubeVirtRestoreS3{}
		state.Request.Keys = nil
		return r.save(state)
	}
	return errNativeRestoreHeld
}
func syncNativeDisks(disks []backup.NativeRestoredDisk, output string) error {
	if len(disks) == 0 {
		return errNativeRestoreHeld
	}
	for _, d := range disks {
		if filepath.Base(d.Target) != d.Target || d.Path != filepath.Join(output, d.Target+".raw") {
			return errNativeRestoreHeld
		}
		f, err := os.OpenFile(d.Path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() != d.SizeBytes {
			f.Close()
			return errNativeRestoreHeld
		}
		err = errors.Join(f.Sync(), f.Close())
		if err != nil {
			return err
		}
	}
	return nativerestore.SyncDirectory(output)
}
