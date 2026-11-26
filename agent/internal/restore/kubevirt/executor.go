//go:build kubevirt

package kubevirt

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
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"k8s.io/client-go/dynamic"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/operationbudget"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/restore"
	"vnbui/agent/internal/restoreinput"
	"vnbui/agent/internal/storagerestore"
)

var errHeld = errors.New("restore held: destination ownership, prerequisite or worker result requires operator review")
var pinnedRestoreImage = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$`)

type restoreState struct {
	Schema         int                           `json:"schema"`
	ResourcePrefix string                        `json:"resource_prefix,omitempty"`
	Request        models.KubeVirtRestoreRequest `json:"request"`
	PlanSHA        string                        `json:"plan_sha256"`
	Token          string                        `json:"token"`
	Image          string                        `json:"image"`
	CAPEM          string                        `json:"ca_pem"`
	Phase          string                        `json:"phase"`
	Inflight       string                        `json:"inflight"`
	SecretUID      string                        `json:"secret_uid"`
	PVCUIDs        map[string]string             `json:"pvc_uids"`
	JobUID         string                        `json:"job_uid"`
	VMUID          string                        `json:"vm_uid"`
	VM             map[string]interface{}        `json:"vm"`
	Budget         *operationbudget.Progress     `json:"budget,omitempty"`
	Progress       models.RestoreProgress        `json:"progress"`
}

// Executor owns only new resources named in a persisted restore plan. It never
// overwrites a source, deletes a partial disk, or infers Job success from absence.
type Executor struct {
	cfg               *config.Config
	resources         *resources.Manager
	dynamic           dynamic.Interface
	namespace         string
	restoreNamespaces map[string]struct{}
	mu                sync.RWMutex
	states            map[string]*restoreState
	root              string
	lock              *os.File
	ctx               context.Context
	cancel            context.CancelFunc
	done              chan struct{}
	wake              chan struct{}
}

func NewExecutor(cfg *config.Config, res *resources.Manager, client dynamic.Interface, namespace string) *Executor {
	allowed := make(map[string]struct{})
	if cfg != nil {
		for _, target := range cfg.KubevirtRestoreNamespaces {
			allowed[target] = struct{}{}
		}
	}
	return &Executor{cfg: cfg, resources: res, dynamic: client, namespace: namespace, restoreNamespaces: allowed, states: map[string]*restoreState{}, wake: make(chan struct{}, 1)}
}

func (e *Executor) namespaceAllowed(namespace string) bool {
	_, ok := e.restoreNamespaces[namespace]
	return ok
}

// Progress is polled by the backend; no heartbeat event bypasses the state machine.
func (e *Executor) SetEventCallback(func(map[string]interface{})) {}
func (e *Executor) FreshKubeVirtRestore()                         {}

func (e *Executor) StartRestores(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cancel != nil {
		return errors.New("restore executor already started")
	}
	if e.cfg == nil || !validName(e.namespace) || e.cfg.AgentID == "" || e.cfg.KeyFilePath == "" ||
		!pinnedRestoreImage.MatchString(e.cfg.KubevirtRestoreImage) ||
		e.cfg.KubevirtPrefix() == "" || !e.cfg.EnableAPIKeyValidation || e.cfg.OrchestratorAPIKey == "" || !e.cfg.OrchestratorVerifySSL {
		return errors.New("fresh restore requires explicit namespace, persistent journal, authenticated HTTPS and an installation-pinned worker image")
	}
	if len(e.restoreNamespaces) == 0 || len(e.restoreNamespaces) > 32 || len(e.restoreNamespaces) != len(e.cfg.KubevirtRestoreNamespaces) {
		return errors.New("fresh restore requires 1 to 32 distinct installation-authorized destination namespaces")
	}
	for namespace := range e.restoreNamespaces {
		if !validName(namespace) {
			return errors.New("restore destination namespaces must be explicit DNS labels, not wildcards")
		}
	}
	e.root = filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "kubevirt-restores")
	if err := os.MkdirAll(e.root, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(e.root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("restore journal root must be a private directory")
	}
	lock, err := os.OpenFile(filepath.Join(e.root, ".lock"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return errors.New("restore journal is owned by another process")
	}
	e.lock = lock
	entries, err := os.ReadDir(e.root)
	if err == nil {
		for _, entry := range entries {
			if entry.Name() == ".lock" {
				continue
			}
			if !strings.HasSuffix(entry.Name(), ".json") {
				if strings.HasPrefix(entry.Name(), ".pending-") {
					continue
				}
				err = errHeld
				break
			}
			var state restoreState
			err = restoreinput.ReadJSONFile(filepath.Join(e.root, entry.Name()), &state, 4<<20, true)
			if err != nil {
				break
			}
			_, prefixErr := config.NormalizeKubevirtResourcePrefix(state.ResourcePrefix)
			_, digest, check := validatePlan(&state.Request, state.Progress.Status != models.TaskStatusCompleted)
			// Completed history is read-only. Revocation fences unfinished effects,
			// without making a completed destination an irrevocable installation grant.
			outsideActiveScope := !e.namespaceAllowed(state.Request.Target.Namespace) && state.Progress.Status != models.TaskStatusCompleted
			if prefixErr != nil || check != nil || state.Schema != 1 || state.PlanSHA != digest || state.Request.AgentID != e.cfg.AgentID || outsideActiveScope ||
				entry.Name() != state.Request.RestoreID+".json" || len(state.Token) != 64 || !pinnedRestoreImage.MatchString(state.Image) || state.PVCUIDs == nil {
				err = errHeld
				break
			}
			e.states[state.Request.RestoreID] = &state
		}
	}
	if err != nil {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		lock.Close()
		e.lock = nil
		return errHeld
	}
	e.ctx, e.cancel = context.WithCancel(ctx)
	e.done = make(chan struct{})
	go e.loop()
	return nil
}

func (e *Executor) CloseRestores() error {
	e.mu.Lock()
	cancel, done := e.cancel, e.done
	e.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	<-done
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = syscall.Flock(int(e.lock.Fd()), syscall.LOCK_UN)
	err := e.lock.Close()
	e.cancel = nil
	e.lock = nil
	return err
}

func (e *Executor) StartRestore(request *models.RestoreRequest) (*models.RestoreProgress, error) {
	if request == nil || request.KubeVirt == nil || request.RestoreID != request.KubeVirt.RestoreID {
		return nil, errors.New("fresh KubeVirt restore request required")
	}
	req := request.KubeVirt
	_, digest, err := ValidatePlan(req)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(req)
	if err != nil || len(body) > 900<<10 {
		return nil, errors.New("restore worker input exceeds private Secret limit (900 KiB)")
	}
	caPEM := ""
	if e.cfg.KubevirtRestoreCAFile != "" {
		pem, readErr := os.ReadFile(e.cfg.KubevirtRestoreCAFile)
		if readErr != nil || len(pem) > 256<<10 || len(pem)+len(body) > 900<<10 || !x509.NewCertPool().AppendCertsFromPEM(pem) {
			return nil, errors.New("configured restore CA bundle is unavailable, invalid or too large")
		}
		caPEM = string(pem)
	}
	var detached models.KubeVirtRestoreRequest
	_ = json.Unmarshal(body, &detached)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cancel == nil || e.ctx.Err() != nil || req.AgentID != e.cfg.AgentID || !e.namespaceAllowed(req.Target.Namespace) {
		return nil, errors.New("restore executor is unavailable for this agent or namespace")
	}
	if prior := e.states[req.RestoreID]; prior != nil {
		if prior.PlanSHA != digest {
			return nil, errors.New("restore ID is already bound to a different plan")
		}
		p := observedProgress(prior)
		return &p, nil
	}
	active := 0
	for _, s := range e.states {
		if s.Progress.Status != models.TaskStatusCompleted && s.Progress.Status != models.TaskStatusFailed {
			active++
		}
		if s.Request.Target.Namespace == req.Target.Namespace {
			if s.Request.Target.VMName == req.Target.VMName {
				return nil, restore.ErrPreJournalTargetReserved
			}
			for _, a := range s.Request.Target.Disks {
				for _, b := range req.Target.Disks {
					if a.PVCName == b.PVCName {
						return nil, restore.ErrPreJournalTargetReserved
					}
				}
			}
		}
	}
	if active >= 64 {
		return nil, errors.New("restore queue is full")
	}
	transfer, _, err := operationbudget.BundleBytes(req.Bundle)
	if err != nil {
		return nil, err
	}
	cost := transfer
	for _, disk := range req.Target.Disks {
		cost, err = operationbudget.SumBytes(cost, disk.CapacityBytes)
		if err != nil {
			return nil, err
		}
	}
	budget, err := e.cfg.SafetyPolicy().Begin(cost, 8<<20, 24*time.Hour, time.Now())
	if err != nil {
		return nil, err
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	op := "validating captured VM definition"
	state := &restoreState{Budget: budget, ResourcePrefix: e.cfg.KubevirtPrefix(), Schema: 1, Request: detached, PlanSHA: digest, Token: hex.EncodeToString(token[:]), Image: e.cfg.KubevirtRestoreImage, CAPEM: caPEM, Phase: "prepared", PVCUIDs: map[string]string{},
		Progress: models.RestoreProgress{RestoreID: req.RestoreID, Status: models.TaskStatusRunning, CurrentOperation: &op}}
	if err := e.save(state); err != nil {
		return nil, errHeld
	}
	e.states[req.RestoreID] = state
	select {
	case e.wake <- struct{}{}:
	default:
	}
	p := cloneProgress(state.Progress)
	return &p, nil
}

func (e *Executor) GetProgress(id string) *models.RestoreProgress {
	e.mu.RLock()
	defer e.mu.RUnlock()
	state := e.states[id]
	if state == nil {
		return nil
	}
	p := observedProgress(state)
	return &p
}

// Project a negative observation from the original durable deadline even when
// another reconciliation is waiting on Kubernetes. This is not worker closure
// or permission to reuse a partial destination.
func observedProgress(state *restoreState) models.RestoreProgress {
	p := cloneProgress(state.Progress)
	if p.Status == models.TaskStatusRunning || p.Status == models.TaskStatusPending {
		if _, reason := state.Budget.WorkerDeadline(time.Now()); reason != "" {
			p.Status = models.TaskStatusCleanupRequired
			message := reason + "; original worker and partial PVCs retained"
			p.ErrorMessage = &message
		}
	}
	return p
}
func cloneProgress(p models.RestoreProgress) models.RestoreProgress {
	var copy models.RestoreProgress
	b, _ := json.Marshal(p)
	_ = json.Unmarshal(b, &copy)
	return copy
}
func (e *Executor) ActiveCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := 0
	for _, s := range e.states {
		if s.Progress.Status == models.TaskStatusRunning {
			n++
		}
	}
	return n
}

func (e *Executor) save(state *restoreState) error {
	if state.Budget != nil {
		stage := map[string]string{"prepared": "queued", "provisioning": "preparing", "populating": "transferring", "defining": "finalizing", "credential_cleanup": "publishing", "completed": "complete"}[state.Phase]
		if stage == "" {
			return errHeld
		}
		if _, err := state.Budget.Advance(time.Now(), stage, int64(state.Progress.ProgressPercent)); err != nil {
			return err
		}
	}
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(e.root, ".pending-")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	if err = os.Rename(temp, filepath.Join(e.root, state.Request.RestoreID+".json")); err != nil {
		return err
	}
	dir, err := os.Open(e.root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (e *Executor) loop() {
	defer close(e.done)
	timer := time.NewTicker(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-timer.C:
		case <-e.wake:
		}
		e.mu.RLock()
		ids := make([]string, 0, len(e.states))
		for id, state := range e.states {
			if state.Progress.Status == models.TaskStatusRunning {
				ids = append(ids, id)
			}
		}
		e.mu.RUnlock()
		for _, id := range ids {
			if e.ctx.Err() != nil {
				return
			}
			e.mu.RLock()
			body, _ := json.Marshal(e.states[id])
			e.mu.RUnlock()
			state := &restoreState{}
			_ = json.Unmarshal(body, state)
			deadline, reason := state.Budget.WorkerDeadline(time.Now())
			if reason != "" {
				state.Progress.Status = models.TaskStatusCleanupRequired
				message := reason + "; original worker and partial PVCs retained"
				state.Progress.ErrorMessage = &message
				if e.save(state) == nil {
					e.mu.Lock()
					e.states[id] = state
					e.mu.Unlock()
				}
				continue
			}
			if err := e.resources.AcquireRestoreSlot(); err != nil {
				continue
			}
			ctx, cancel := context.WithDeadline(e.ctx, minTime(deadline, time.Now().Add(45*time.Second)))
			err := e.reconcile(ctx, state)
			cancel()
			if errors.Is(err, errHeld) {
				reason := err.Error() + ". Partial PVCs must not be used."
				state.Progress.Status = models.TaskStatusCleanupRequired
				state.Progress.ErrorMessage = &reason
				_ = e.save(state)
			}
			// Only expose the last fsynced record, never an in-memory success
			// whose journal write failed after a Kubernetes mutation.
			var durable restoreState
			if restoreinput.ReadJSONFile(filepath.Join(e.root, id+".json"), &durable, 4<<20, true) == nil {
				e.mu.Lock()
				e.states[id] = &durable
				e.mu.Unlock()
			}
			e.resources.ReleaseRestoreSlot()
		}
	}
}

func (e *Executor) capturedVM(ctx context.Context, state *restoreState) error {
	bundle, _, err := ValidatePlan(&state.Request)
	if err != nil {
		return errHeld
	}
	cfg := state.Request.S3
	open, close, err := restoreinput.S3SourceConfig(restoreinput.S3Configuration{Endpoint: cfg.Endpoint, Bucket: cfg.Bucket, Region: cfg.Region, AccessKey: cfg.AccessKey, SecretKey: cfg.SecretKey, SessionToken: cfg.SessionToken, CAPEM: state.CAPEM})
	if err != nil {
		return errHeld
	}
	defer close()
	keys := func(ctx context.Context, member storagerestore.Member) ([]byte, error) {
		return base64.StdEncoding.Strict().DecodeString(state.Request.Keys[member.Request.BackupID])
	}
	definition, err := storagerestore.ReadVMDefinition(ctx, bundle.Members, open, keys)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: captured definition unavailable or invalid", errHeld)
	}
	vm, err := RenderVM(definition, state.Request.Target, bundle.Members[len(bundle.Members)-1].Request.Plan.Source)
	if err != nil {
		return fmt.Errorf("%w: %v", errHeld, err)
	}
	state.VM = vm
	state.Phase = "provisioning"
	return e.save(state)
}

var _ restore.ExecutorIface = (*Executor)(nil)

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
