package verification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/operationbudget"
	"vnbui/agent/internal/storagerestore"
)

var ErrUnavailable = errors.New("verification executor unavailable")
var ErrConflict = errors.New("verification identity already owns a different plan")
var ErrBusy = errors.New("another verification is active")
var ErrJournal = errors.New("verification journal unavailable")

type Config struct {
	Root            string
	AgentID         string
	Provider        string
	CAFile          string
	Timeout         time.Duration
	BudgetPolicy    operationbudget.Policy
	MaxJournalBytes int64
	MinFreeBytes    int64
}

type Progress struct {
	Schema         string                             `json:"schema"`
	VerificationID string                             `json:"verification_id"`
	OrgID          string                             `json:"org_id"`
	AgentID        string                             `json:"agent_id"`
	PlanSHA256     string                             `json:"plan_sha256"`
	WorkerID       string                             `json:"worker_id"`
	Status         string                             `json:"status"`
	Message        string                             `json:"message"`
	Result         *storagerestore.VerificationResult `json:"result"`
}

type journal struct {
	Schema          int                                `json:"schema"`
	Plan            Plan                               `json:"plan"`
	PlanSHA256      string                             `json:"plan_sha256"`
	WorkerID        string                             `json:"worker_id"`
	Status          string                             `json:"status"`
	Message         string                             `json:"message"`
	Result          *storagerestore.VerificationResult `json:"result"`
	CancelRequested bool                               `json:"cancel_requested"`
	Budget          *operationbudget.Progress          `json:"budget,omitempty"`
	cancelDurable   bool
}

// Executor owns one bounded read-only worker. Credentials never enter states or
// journals. Startup loads results but never resumes reads without re-admission.
type Executor struct {
	cfg          Config
	mu           sync.Mutex
	states       map[string]*journal
	lock         *os.File
	ctx          context.Context
	cancel       context.CancelFunc
	active       string
	activeCancel context.CancelFunc
	wg           sync.WaitGroup
	closing      bool
	closed       chan struct{}
	runner       func(context.Context, Request, string) (*storagerestore.VerificationResult, error)
}

func New(cfg Config) *Executor {
	if cfg.BudgetPolicy == (operationbudget.Policy{}) {
		cfg.BudgetPolicy = operationbudget.DefaultPolicy()
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Hour
	}
	if cfg.MaxJournalBytes <= 0 {
		cfg.MaxJournalBytes = 128 << 20
	}
	if cfg.MinFreeBytes <= 0 {
		cfg.MinFreeBytes = 64 << 20
	}
	return &Executor{cfg: cfg, states: map[string]*journal{}, runner: run}
}

func (e *Executor) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || e.lock != nil || !filepath.IsAbs(e.cfg.Root) || !validID(e.cfg.AgentID) || (e.cfg.Provider != "libvirt" && e.cfg.Provider != "kubevirt") {
		return ErrUnavailable
	}
	if err := os.MkdirAll(e.cfg.Root, 0700); err != nil {
		return ErrJournal
	}
	info, err := os.Lstat(e.cfg.Root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return ErrJournal
	}
	lock, err := os.OpenFile(filepath.Join(e.cfg.Root, ".lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return ErrJournal
	}
	info, err = lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		_ = lock.Close()
		return ErrJournal
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		_ = lock.Close()
		return ErrJournal
	}
	ok := false
	defer func() {
		if !ok {
			_ = lock.Close()
		}
	}()
	entries, err := os.ReadDir(e.cfg.Root)
	if err != nil || len(entries) > 4097 {
		return ErrJournal
	}
	states := map[string]*journal{}
	for _, entry := range entries {
		if entry.Name() == ".lock" {
			continue
		}
		// Incomplete atomic-write temporaries cannot authorize reads or success.
		if strings.HasPrefix(entry.Name(), ".pending-") && entry.Type().IsRegular() {
			continue
		}
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".json") {
			return ErrJournal
		}
		var state journal
		if readJournal(filepath.Join(e.cfg.Root, entry.Name()), &state) != nil {
			return ErrJournal
		}
		expected, digest, err := ExpectedResult(state.Plan)
		if err != nil || state.Schema != 1 || state.PlanSHA256 != digest || !validID(state.WorkerID) || state.Plan.AgentID != e.cfg.AgentID || state.Plan.Provider != e.cfg.Provider || entry.Name() != state.Plan.VerificationID+".json" {
			return ErrJournal
		}
		state.cancelDurable = state.CancelRequested
		switch state.Status {
		case "passed":
			if !reflect.DeepEqual(state.Result, expected) || state.Message != "artifact_bytes_verified" {
				return ErrJournal
			}
		case "failed":
			if state.Result != nil || state.Message != "artifact_verification_failed" {
				return ErrJournal
			}
		case "pending", "running", "held":
			if state.Result != nil {
				return ErrJournal
			}
			state.Status, state.Message = "held", "readmission_required"
			if state.Budget == nil || !state.Budget.Valid() || time.Now().Before(state.Budget.StartedAt) || !time.Now().Before(state.Budget.Deadline()) {
				state.Message = "operation_budget_exhausted_or_missing"
			}
			if e.persist(&state) != nil {
				return ErrJournal
			}
		default:
			return ErrJournal
		}
		states[state.Plan.VerificationID] = &state
	}
	e.states, e.lock = states, lock
	e.ctx, e.cancel = context.WithCancel(ctx)
	e.closing, e.closed = false, make(chan struct{})
	ok = true
	return nil
}

func (e *Executor) Close() error {
	e.mu.Lock()
	if e.lock == nil {
		e.mu.Unlock()
		return nil
	}
	if e.closing {
		done := e.closed
		e.mu.Unlock()
		<-done
		return nil
	}
	e.closing = true
	lock := e.lock
	e.cancel()
	e.mu.Unlock()
	e.wg.Wait()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lock = nil
	close(e.closed)
	return lock.Close()
}

func (e *Executor) Submit(req Request) (*Progress, error) {
	expected, digest, err := ExpectedResult(req.Plan)
	if err != nil || validateCredentials(req) != nil || req.Plan.AgentID != e.cfg.AgentID || req.Plan.Provider != e.cfg.Provider {
		return nil, ErrPlan
	}
	// Do not retain caller-mutable buffers/maps or any credentials in journal state.
	req.Plan.Bundle = bytes.Clone(req.Plan.Bundle)
	req.Keys = maps.Clone(req.Keys)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lock == nil || e.ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	state := e.states[req.Plan.VerificationID]
	if state != nil {
		if state.PlanSHA256 != digest {
			return nil, ErrConflict
		}
		if state.CancelRequested || state.Status == "passed" || state.Status == "failed" || e.active == req.Plan.VerificationID {
			return progress(state), nil
		}
	}
	if e.active != "" {
		return nil, ErrBusy
	}
	if state == nil {
		cost, _, err := operationbudget.BundleBytes(req.Plan.Bundle)
		if err != nil {
			return nil, ErrPlan
		}
		budget, err := e.cfg.BudgetPolicy.Begin(cost, 8<<20, e.cfg.Timeout, time.Now())
		if err != nil {
			return nil, err
		}
		if len(e.states) >= 4096 {
			return nil, ErrUnavailable
		}
		state = &journal{Schema: 1, Budget: budget, Plan: req.Plan, PlanSHA256: digest, WorkerID: uuid.NewString(), Status: "pending", Message: "awaiting_worker"}
	} else {
		state.Status, state.Message = "pending", "awaiting_worker"
	}
	if state.Budget == nil || !state.Budget.Valid() || time.Now().Before(state.Budget.StartedAt) || !time.Now().Before(state.Budget.Deadline()) {
		state.Status, state.Message = "held", "operation_budget_exhausted_or_missing"
		_ = e.persist(state)
		e.states[req.Plan.VerificationID] = state
		return progress(state), nil
	}
	if e.persist(state) != nil {
		state.Status, state.Message = "held", "journal_unavailable"
		return nil, ErrJournal
	}
	e.states[req.Plan.VerificationID] = state
	ctx, cancel := context.WithDeadline(e.ctx, state.Budget.Deadline())
	e.active, e.activeCancel = req.Plan.VerificationID, cancel
	e.wg.Add(1)
	go e.execute(ctx, cancel, req, state, expected)
	return progress(state), nil
}

func (e *Executor) Get(id, org string) *Progress {
	e.mu.Lock()
	defer e.mu.Unlock()
	state := e.states[id]
	if state == nil || state.Plan.OrgID != org {
		return nil
	}
	return progress(state)
}

// Cancel fences only reads for the matching operation. It never touches a VM,
// backup, checkpoint, output file or S3 object. Completion may already be durable.
func (e *Executor) Cancel(id, org, planSHA string) *Progress {
	e.mu.Lock()
	defer e.mu.Unlock()
	state := e.states[id]
	if state == nil || state.Plan.OrgID != org || state.PlanSHA256 != planSHA {
		return nil
	}
	// Fence delayed submissions durably before reporting reader quiescence.
	// A failed write still stops local reads, but cannot acknowledge a fence
	// that would disappear after process loss.
	state.CancelRequested = true
	if !state.cancelDurable {
		_ = e.persist(state)
	}
	if e.active == id {
		e.activeCancel()
	}
	return progress(state)
}

func (e *Executor) execute(ctx context.Context, cancel context.CancelFunc, req Request, state *journal, expected *storagerestore.VerificationResult) {
	defer e.wg.Done()
	defer cancel()
	e.mu.Lock()
	state.Status, state.Message = "running", "reading_exact_artifacts"
	err := e.persist(state)
	e.mu.Unlock()
	var result *storagerestore.VerificationResult
	if err == nil && ctx.Err() == nil {
		result, err = e.callRunner(ctx, req)
	}
	// Drop ephemeral credential references before publishing terminal state.
	req.Keys = nil
	req.S3 = models.KubeVirtRestoreS3{}
	e.mu.Lock()
	defer e.mu.Unlock()
	state.Result = nil
	switch {
	case ctx.Err() != nil:
		state.Status, state.Message = "held", "readmission_required"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			state.Message = "operation_budget_exhausted"
		}
	case errors.Is(err, ErrJournal):
		state.Status, state.Message = "held", "journal_unavailable"
	case err != nil || !reflect.DeepEqual(result, expected):
		state.Status, state.Message = "failed", "artifact_verification_failed"
	default:
		state.Status, state.Message, state.Result = "passed", "artifact_bytes_verified", result
	}
	if e.persist(state) != nil {
		state.Status, state.Message, state.Result = "held", "journal_unavailable", nil
	}
	e.active, e.activeCancel = "", nil
}

func (e *Executor) callRunner(ctx context.Context, req Request) (result *storagerestore.VerificationResult, err error) {
	defer func() {
		if recover() != nil {
			result = nil
			err = errors.New("verification worker failed")
		}
	}()
	return e.runner(ctx, req, e.cfg.CAFile)
}

func readJournal(path string, state *journal) error {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrJournal
	}
	defer file.Close()
	info, err := file.Stat()
	limit := MaxRequestBytes + (1 << 20)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > int64(limit) {
		return ErrJournal
	}
	body, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || decodeDocument(body, state, limit) != nil {
		return ErrJournal
	}
	return nil
}

func (e *Executor) persist(state *journal) error {
	body, err := json.Marshal(state)
	if err != nil || len(body) > MaxRequestBytes+(1<<20) {
		return ErrJournal
	}
	if e.checkSpace(state.Plan.VerificationID, int64(len(body))) != nil {
		return ErrJournal
	}
	file, err := os.CreateTemp(e.cfg.Root, ".pending-")
	if err != nil {
		return ErrJournal
	}
	name := file.Name()
	defer func() { _ = os.Remove(name) }()
	_, err = file.Write(body)
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil || os.Rename(name, filepath.Join(e.cfg.Root, state.Plan.VerificationID+".json")) != nil {
		return ErrJournal
	}
	dir, err := os.Open(e.cfg.Root)
	if err != nil {
		return ErrJournal
	}
	err = errors.Join(dir.Sync(), dir.Close())
	if err != nil {
		return ErrJournal
	}
	if state.CancelRequested {
		state.cancelDurable = true
	}
	return nil
}

// Bound metadata and atomic-rewrite headroom on the journal filesystem. Scrub
// must not consume the backup agent's last free space merely to retain plans.
func (e *Executor) checkSpace(id string, size int64) error {
	entries, err := os.ReadDir(e.cfg.Root)
	if err != nil {
		return ErrJournal
	}
	var used int64
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return ErrJournal
		}
		info, err := entry.Info()
		if err != nil || info.Size() > e.cfg.MaxJournalBytes-used {
			return ErrJournal
		}
		used += info.Size()
	}
	required := size
	if _, err := os.Lstat(filepath.Join(e.cfg.Root, id+".json")); errors.Is(err, os.ErrNotExist) {
		// Reserve a rewrite plus the bounded terminal result before first read.
		required = 2*size + (1 << 20)
	} else if err != nil {
		return ErrJournal
	}
	if required > e.cfg.MaxJournalBytes-used {
		return ErrJournal
	}
	sample, err := operationbudget.SampleScratch(e.cfg.Root)
	if err != nil || sample.AvailableBytes < e.cfg.MinFreeBytes || sample.AvailableBytes-e.cfg.MinFreeBytes < required {
		return ErrJournal
	}
	return nil
}

func progress(state *journal) *Progress {
	var result *storagerestore.VerificationResult
	if state.Result != nil {
		copy := *state.Result
		copy.Members = append([]storagerestore.VerifiedMember{}, copy.Members...)
		result = &copy
	}
	status, message := state.Status, state.Message
	if state.CancelRequested && !state.cancelDurable {
		status, message, result = "running", "cancellation_pending", nil
	}
	return &Progress{Schema: ProgressSchema, VerificationID: state.Plan.VerificationID, OrgID: state.Plan.OrgID, AgentID: state.Plan.AgentID, PlanSHA256: state.PlanSHA256, WorkerID: state.WorkerID, Status: status, Message: message, Result: result}
}
