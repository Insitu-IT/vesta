//go:build kubevirt

package kubevirt

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

type transactionWork struct {
	request  *models.StorageTransactionRequest
	body     []byte
	finished bool
	held     bool
	safety   *operationSafety
}

type transactionRunner struct {
	executor *Executor
	root     string
	lock     *os.File
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	wake     chan struct{}
	backend  *http.Client
	provider *http.Client
	key      string
	retry    time.Duration

	mu             sync.Mutex
	closed         bool
	work           map[string]*transactionWork
	queue          []*transactionWork
	holdCursor     string
	progressCursor string
	step           func(context.Context, []byte, *http.Client, *http.Client, func(context.Context) (string, error)) (*storageupload.CheckpointProof, error)
}

// StartStorageTransactions activates the ordinary transaction runner
// and reopens accepted work from its durable requests. All provider effects are
// still performed by ReconcileStorageTransaction's existing journal protocol.
func (e *Executor) StartStorageTransactions(ctx context.Context) error {
	e.mu.Lock()
	if e.storageRunner != nil {
		e.mu.Unlock()
		return errors.New("storage transaction runner already initialized")
	}
	runner, err := newTransactionRunner(ctx, e)
	if err != nil {
		e.mu.Unlock()
		return err
	}
	e.storageRunner = runner
	e.mu.Unlock()
	for _, work := range runner.work {
		if work.finished && !work.held {
			runner.progress(work, models.TaskStatusCompleted, "backup published", true)
		} else if !work.finished {
			runner.progress(work, models.TaskStatusPending, "recovering durable storage transaction", false)
		}
	}
	go runner.run()
	return nil
}

func newTransactionRunner(ctx context.Context, e *Executor) (_ *transactionRunner, err error) {
	if ctx == nil || e.cfg == nil || e.dynamic == nil || e.resources == nil || !e.cfg.OrchestratorVerifySSL ||
		!e.cfg.EnableAPIKeyValidation || e.cfg.OrchestratorAPIKey == "" || e.cfg.AgentAPIKey == "" || e.cfg.AgentID == "" ||
		e.cfg.KeyFilePath == "" || (e.cfg.KubevirtBackupScratchPVC == "" && e.cfg.NamespaceScope == nil) {
		return nil, errors.New("storage transactions require registered credentials, authenticated API, verified HTTPS and durable journal/scratch configuration")
	}
	u, parseErr := url.Parse(e.cfg.OrchestratorURL)
	if parseErr != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("storage transactions require a canonical HTTPS orchestrator origin")
	}
	backendTLS, err := transactionCallbackTLS(e)
	if err != nil {
		return nil, err
	}
	root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, storageupload.ErrHeld
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, storageupload.ErrHeld
	}
	lock, err := os.Open(root)
	if err != nil {
		return nil, storageupload.ErrHeld
	}
	defer func() {
		if err != nil {
			_ = lock.Close()
		}
	}()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errors.New("another process owns the storage transaction journal")
	}
	parent, err := os.Open(filepath.Dir(root))
	if err != nil {
		return nil, storageupload.ErrHeld
	}
	err = parent.Sync()
	_ = parent.Close()
	if err != nil {
		return nil, storageupload.ErrHeld
	}
	requests, err := storageupload.RecoverRequests(root)
	if err != nil {
		return nil, storageupload.ErrHeld
	}
	client := func(tlsConfig *tls.Config) *http.Client {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = tlsConfig
		transport.MaxResponseHeaderBytes = 16 << 10
		transport.ResponseHeaderTimeout = 30 * time.Second
		return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &transactionRunner{
		executor: e, root: root, lock: lock, ctx: ctx, cancel: cancel,
		done: make(chan struct{}), wake: make(chan struct{}, 1), backend: client(backendTLS), provider: client(&tls.Config{MinVersion: tls.VersionTLS12}),
		key: e.cfg.AgentAPIKey, retry: 2 * time.Second, work: make(map[string]*transactionWork), step: e.ReconcileStorageTransaction,
	}
	for _, body := range requests {
		request, canonical, decodeErr := r.validate(body)
		if decodeErr != nil || r.work[request.BackupID] != nil {
			cancel()
			r.backend.CloseIdleConnections()
			r.provider.CloseIdleConnections()
			return nil, storageupload.ErrHeld
		}
		guard, guardErr := openSafety(root, request)
		if guardErr == nil {
			work := &transactionWork{request: request, body: canonical, safety: guard}
			if r.sealStoppedPreNative(work) {
				work.finished, work.held = true, true
				r.work[request.BackupID] = work
				continue
			}
		}
		// A validated journal's backend publication acknowledgement is terminal,
		// including legacy attempts with no safety record. It requires no new
		// producer, provider observation, deadline or API call after restart.
		journal, openErr := storageupload.Open(root, canonical)
		var state storageupload.State
		if openErr == nil {
			state, openErr = journal.Snapshot()
			if closeErr := journal.Close(); closeErr != nil {
				openErr = closeErr
			}
		}
		if openErr == nil && state.Finalize != nil && state.Finalize.Reported && state.Finalize.Proof != nil {
			r.work[request.BackupID] = &transactionWork{request: request, body: canonical, finished: true}
			continue
		}
		if guardErr == nil {
			// Recover the exact native identity from its authoritative journal,
			// including a crash between native observation and safety mirroring.
			if openErr == nil {
				guardErr = guard.bindNative(state.Native)
				if guardErr == nil {
					guardErr = guard.observeFinalize(state)
				}
				if guardErr == nil && state.Finalize != nil && (state.Finalize.TerminalResourceVersion != "" || state.Finalize.Proof != nil) && !guard.snapshot().SourceClosed {
					// A recovery observation cannot grant a fresh publication
					// window. Anchor the missing mirror at last durable progress.
					guardErr = guard.sourceClosed(guard.snapshot().Progress.LastProgressAt)
				}
			} else {
				guardErr = openErr
			}
		}
		work := &transactionWork{request: request, body: canonical, safety: guard}
		if guardErr != nil {
			work.finished, work.held = true, true
		}
		r.work[request.BackupID] = work
		if !work.finished {
			r.queue = append(r.queue, work)
		}
	}
	return r, nil
}

func transactionCallbackTLS(e *Executor) (*tls.Config, error) {
	return e.cfg.OutboundTLSConfig()
}

func (r *transactionRunner) validate(body []byte) (*models.StorageTransactionRequest, []byte, error) {
	request, err := models.DecodeStorageTransaction(body)
	if err != nil {
		return nil, nil, err
	}
	p := request.Plan
	if request.AgentID != r.executor.cfg.AgentID || p.Provider != "kubevirt" || p.CapabilityProfile != "db-rooted-consumer-verified/1" ||
		(r.executor.cfg.NamespaceScope == nil && r.executor.namespace != "" && p.Source.Namespace != r.executor.namespace) {
		return nil, nil, errors.New("storage request is outside this agent's supported transaction scope")
	}
	canonical, err := json.Marshal(request)
	return request, canonical, err
}

// StartStorageTransaction returns only after a new request is durable. Retries
// of the identical request reuse it; conflicts cannot start another producer.
func (e *Executor) StartStorageTransaction(ctx context.Context, body []byte) error {
	e.mu.RLock()
	r := e.storageRunner
	e.mu.RUnlock()
	if r == nil {
		return errors.New("storage transaction runner is not available")
	}
	request, canonical, err := r.validate(body)
	if err != nil {
		return err
	}
	if !e.cfg.SourceNamespaceAllowed(request.Plan.Source.Namespace) {
		return errors.New("source namespace is outside selected scope")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.ctx.Err() != nil || ctx.Err() != nil {
		return storageupload.ErrHeld
	}
	if previous := r.work[request.BackupID]; previous != nil {
		if !bytes.Equal(previous.body, canonical) {
			return errors.New("backup already has a different durable storage request")
		}
		if previous.finished && previous.held {
			if previous.safety == nil || previous.safety.snapshot().Stop != nil {
				return storageupload.ErrHeld
			}
			// An explicit exact redelivery may wake a stopped observer, but
			// never clear uncertain upload/native-create custody. Open applies
			// the existing interrupted-stream rules before this phase check.
			journal, err := storageupload.Open(r.root, canonical)
			if err != nil {
				return storageupload.ErrHeld
			}
			state, inspectErr := journal.Snapshot()
			closeErr := journal.Close()
			if inspectErr != nil || closeErr != nil || state.Phase == "held" || len(r.queue) >= 64 {
				return storageupload.ErrHeld
			}
			previous.finished, previous.held = false, false
			r.queue = append(r.queue, previous)
			r.progress(previous, models.TaskStatusPending, "resuming exact durable transaction", false)
			select {
			case r.wake <- struct{}{}:
			default:
			}
		}
		return nil
	}
	if len(r.queue) >= 64 {
		return errors.New("storage transaction queue is at capacity")
	}
	for _, previous := range r.work {
		if previous.request.ReservationID == request.ReservationID ||
			((!previous.finished || previous.held) && previous.request.Plan.Source.Namespace == request.Plan.Source.Namespace && previous.request.Plan.Source.VMUID == request.Plan.Source.VMUID) {
			return errors.New("the VM or reservation already has an unfinished storage transaction")
		}
	}
	// Pin naming with the first durable request, before the ordinary reconcile
	// path reopens it. Existing journals retain their original naming authority.
	journal, err := storageupload.CreateWithKubevirtPrefix(r.root, canonical, e.cfg.KubevirtResourcePrefix)
	if err != nil {
		return err
	}
	if err := journal.Close(); err != nil {
		return storageupload.ErrHeld
	}
	guard, err := e.createSafety(r.root, request)
	if err != nil {
		return err
	}
	work := &transactionWork{request: request, body: canonical, safety: guard}
	r.work[request.BackupID] = work
	r.queue = append(r.queue, work)
	r.progress(work, models.TaskStatusPending, "durable storage transaction accepted", false)
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return nil
}

func (r *transactionRunner) run() {
	defer close(r.done)
	queueDone := make(chan struct{})
	queueStopped := make(chan struct{})
	defer func() { close(queueDone); <-queueStopped }()
	go func() {
		defer close(queueStopped)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-queueDone:
				return
			case <-r.ctx.Done():
				return
			case <-ticker.C:
				r.expireQueued(nativeNow())
			}
		}
	}()
	for {
		if r.ctx.Err() != nil {
			return
		}
		r.mu.Lock()
		var work *transactionWork
		if len(r.queue) > 0 {
			work, r.queue = r.queue[0], r.queue[1:]
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

func stoppedPreNative(g *operationSafety) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	s := &g.state
	if g.poisoned || s.Stop == nil || s.Stop.Phase != "no_native_started" ||
		s.Stop.ResourceVersion != "" || s.Stop.HTTPStatus != 0 ||
		s.Stop.At.Before(s.Progress.StartedAt) || s.Fault == nil || s.Fault.Disposition != "refused" ||
		s.Progress.Stage != "queued" || s.Progress.Cursor != 0 ||
		!s.Progress.LastProgressAt.Equal(s.Progress.StartedAt) ||
		s.Native != nil || s.Scratch != nil || s.Map != nil || s.LastObservation != nil ||
		s.Uncertainty != nil || s.ReadUncertainty != nil || s.SourceClosed || s.PublicationDeadline != nil ||
		s.FirstByteAt != nil || s.FirstACKAt != nil || s.AcknowledgedBytes != 0 {
		return false
	}
	switch s.Fault.Reason {
	case "admission_wait_exhausted", "estimated_window_exceeds_native_limit":
		return true
	default:
		return false
	}
}

// Use the original positive stop before touching the payload journal. A failed
// seal still retains the stopped work. A nonpristine journal does not qualify
// for this transition and still needs the existing recovery/closure checks.
func (r *transactionRunner) sealStoppedPreNative(work *transactionWork) bool {
	if !stoppedPreNative(work.safety) {
		return false
	}
	eligible, err := storageupload.HoldStoppedPreNative(r.root, work.body)
	if err != nil {
		slog.Warn("pre-native stop journal remains under review", "backup_id", work.request.BackupID, "reservation_id", work.request.ReservationID)
	}
	return eligible
}

func recordQueuedStop(s *safetyState, now time.Time) {
	s.Fault = fault("admission", "admission_wait_exhausted", "refused")
	s.Stop = &nativeSafetyStop{At: now.UTC(), Phase: "no_native_started"}
}

// Admission and queue expiry serialize on the same safety record. A slot
// becoming available after the deadline cannot refresh the preparation clock.
func startTransactionPreparation(ctx context.Context, g *operationSafety) error {
	var expired *operationFault
	err := g.update(func(s *safetyState) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.Stop != nil {
			return storageupload.ErrHeld
		}
		now := nativeNow()
		if reason := safetyExhausted(*s, now); reason != "" {
			if s.Progress.Stage == "queued" && (reason == "admission_wait_exhausted" || reason == "operation_budget_exhausted") {
				recordQueuedStop(s, now)
				expired = s.Fault
				return nil
			}
			return fault(s.Progress.Stage, reason, "refused")
		}
		_, err := s.Progress.Advance(now, "preparing", 0)
		return err
	})
	if err != nil {
		return err
	}
	if expired != nil {
		return expired
	}
	return nil
}

// A long-running producer cannot hide expired jobs behind it in the queue.
// This observer can seal local pristine custody, but has no producer capability.
func (r *transactionRunner) expireQueued(_ time.Time) {
	r.expireQueuedWithClock(nativeNow)
}

// A timer timestamp predates lock acquisition and may even predate admission.
// Sample the decision clock only after reading the state it will be compared to.
func (r *transactionRunner) expireQueuedWithClock(clock func() time.Time) {
	r.mu.Lock()
	items := make([]*transactionWork, 0, len(r.work))
	for _, work := range r.work {
		if !work.finished && work.safety != nil {
			items = append(items, work)
		}
	}
	r.mu.Unlock()
	for _, work := range items {
		g := work.safety
		s := g.snapshot()
		if s.Stop != nil || s.Progress.Stage != "queued" || s.Progress.Exhausted(clock()) == "" {
			continue
		}
		var reason string
		err := g.update(func(s *safetyState) error {
			if s.Stop != nil || s.Progress.Stage != "queued" {
				return storageupload.ErrHeld
			}
			now := clock()
			reason = s.Progress.Exhausted(now)
			if reason == "" {
				return storageupload.ErrHeld
			}
			if reason == "admission_wait_exhausted" {
				recordQueuedStop(s, now)
			} else {
				// Invalid clocks/budgets are uncertainty, not positive proof that
				// this pristine attempt exhausted its admission window.
				s.Fault = fault("admission", reason, "refused")
				s.Stop = &nativeSafetyStop{At: now.UTC(), Phase: "requested"}
			}
			return nil
		})
		if err == nil {
			r.sealStoppedPreNative(work)
			r.retain(work, reason+"; original reservation retained")
		}
	}
}

func (r *transactionRunner) process(work *transactionWork) {
	if work.safety == nil {
		r.retain(work, "legacy transaction requires safety review; original custody retained")
		return
	}
	guard := work.safety
	if stoppedPreNative(guard) {
		r.sealStoppedPreNative(work)
		r.retain(work, "pre-native stop; original reservation retained")
		return
	}
	ctx, cancel := context.WithCancel(context.WithValue(r.ctx, safetyContextKey{}, guard))
	defer cancel()
	done := make(chan struct{})
	watchDone := make(chan struct{})
	go func() { defer close(watchDone); r.watchSafety(work, cancel, done) }()
	defer func() { close(done); <-watchDone }()
	stop := func(f *operationFault) {
		if f == nil {
			f = fault("reconciling", "retained_safety_stop", "uncertain")
		}
		if stoppedPreNative(guard) {
			cancel()
			r.sealStoppedPreNative(work)
			r.retain(work, "pre-native stop; original reservation retained")
			return
		}
		if errors.Is(guard.stop(f), errOperationPublished) {
			return
		}
		cancel()
		r.retain(work, f.Error()+"; original custody retained")
		r.executor.closeNativeSafety(r.ctx, work.request, guard)
		r.sealStoppedPreNative(work)
		_ = r.executor.releaseScratch(r.ctx, work.request, guard, true)
	}
	if state := guard.snapshot(); state.Stop != nil {
		stop(state.Fault)
		return
	}
	for r.executor.resources.AcquireBackupSlot() != nil {
		if !r.wait(ctx) {
			stop(fault("admission", "admission_wait_exhausted", "refused"))
			return
		}
	}
	defer r.executor.resources.ReleaseBackupSlot()
	r.executor.transactionMu.Lock()
	defer r.executor.transactionMu.Unlock()
	credential := func(ctx context.Context) (string, error) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return r.key, nil
	}
	if err := startTransactionPreparation(ctx, guard); err != nil {
		stop(faultOf(err))
		return
	}
	r.progress(work, models.TaskStatusRunning, "reconciling storage transaction", false)
	for {
		proof, err := r.step(ctx, work.body, r.backend, r.provider, credential)
		if err == nil && proof != nil {
			mirrorErr := guard.published()
			r.mu.Lock()
			work.finished, work.held = true, false
			// Reconcile returns a proof only after the backend acknowledges its
			// committed publication. No legacy heartbeat event can confer this.
			r.progress(work, models.TaskStatusCompleted, "backup published", true)
			r.mu.Unlock()
			if mirrorErr != nil {
				// The payload journal already records the backend's publication
				// ACK. An independent safety-mirror failure cannot revoke it;
				// retain scratch custody without projecting a false backup hold.
				slog.Warn("published backup safety record requires review; scratch reservation retained", "backup_id", work.request.BackupID)
				return
			}
			if err := r.executor.releaseScratch(r.ctx, work.request, guard, false); err != nil {
				slog.Warn("published backup scratch reservation retained", "backup_id", work.request.BackupID)
			}
			return
		}
		f := faultOf(err)
		if gstate := guard.snapshot(); gstate.Stop != nil {
			stop(gstate.Fault)
			return
		}
		if f.Disposition != "transient" {
			stop(f)
			return
		}
		_ = guard.update(func(s *safetyState) error { s.Fault = f; return nil })
		journal, openErr := storageupload.Open(r.root, work.body)
		var state storageupload.State
		if openErr == nil {
			state, openErr = journal.Snapshot()
			closeErr := journal.Close()
			if closeErr != nil {
				openErr = closeErr
			}
		}
		if openErr != nil || state.Phase == "held" || ctx.Err() != nil || (!guard.snapshot().SourceClosed && nativeLifetimeExpired(&state)) {
			if reason := safetyExhausted(guard.snapshot(), nativeNow()); reason != "" {
				f = fault(guard.snapshot().Progress.Stage, reason, "refused")
			}
			if state.Phase == "held" {
				f.Disposition = "uncertain"
			}
			stop(f)
			slog.Warn("storage transaction retained", "backup_id", work.request.BackupID, "reservation_id", work.request.ReservationID)
			return
		}
		r.progress(work, models.TaskStatusRunning, "waiting for transaction reconciliation", false)
		if state.Compensation != nil {
			r.progress(work, models.TaskStatusCleanupRequired, "retrying exact pre-finalize payload compensation; native custody retained", false)
			timer := time.NewTimer(30 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				stop(fault("compensation", "operation_interrupted", "uncertain"))
				return
			case <-timer.C:
				continue
			}
		}
		if !r.wait(ctx) {
			stop(fault(guard.snapshot().Progress.Stage, "operation_interrupted", "uncertain"))
			return
		}
	}
}

func (r *transactionRunner) retain(work *transactionWork, operation string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if work.finished && !work.held {
		return
	}
	work.finished, work.held = true, true
	r.progress(work, models.TaskStatusCleanupRequired, operation, false)
}

// StorageHoldEvents repeats exact retained transaction identities on heartbeats.
// It carries no cleanup, checkpoint or publication authority. Pagination keeps
// delivery bounded and retries lost observations, including after restart.
func (e *Executor) StorageHoldEvents() []map[string]interface{} {
	e.mu.RLock()
	r := e.storageRunner
	e.mu.RUnlock()
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0)
	for id, work := range r.work {
		if work.finished && work.held {
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
		request := r.work[id].request
		event := map[string]interface{}{
			"type": "storage_transaction_held", "schema": 1,
			"backup_id": request.BackupID, "reservation_id": request.ReservationID,
			"plan_sha256": request.PlanSHA256, "reason": "storage_transaction_retained",
		}
		if g := r.work[id].safety; g != nil {
			event["schema"], event["diagnostic"] = 2, g.diagnostic()
		}
		events = append(events, event)
		r.holdCursor = id
	}
	return events
}

func (r *transactionRunner) wait(ctx context.Context) bool {
	timer := time.NewTimer(r.retry)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (r *transactionRunner) progress(work *transactionWork, status models.TaskStatus, operation string, checkpoint bool) {
	now := time.Now().UTC()
	progress := &models.BackupProgress{BackupID: work.request.BackupID, VMName: &work.request.Plan.VMName,
		Status: status, CurrentOperation: &operation, StartedAt: &now, CheckpointCommitted: &checkpoint}
	if status == models.TaskStatusCompleted {
		progress.ProgressPercent = 100
	}
	r.executor.mu.Lock()
	if previous := r.executor.jobs[work.request.BackupID]; previous != nil {
		progress.StartedAt = previous.StartedAt
		progress.BytesTransferred, progress.TotalBytes = previous.BytesTransferred, previous.TotalBytes
		if status != models.TaskStatusCompleted {
			progress.ProgressPercent = previous.ProgressPercent
		}
	}
	// Replace immutable snapshots so concurrent HTTP readers never race with
	// a mutable progress pointer returned by GetProgress.
	r.executor.jobs[work.request.BackupID] = progress
	r.executor.mu.Unlock()
}

// CloseStorageTransactions interrupts only our work and waits for its handles
// to close. Durable records and uncertain provider state are retained verbatim.
func (e *Executor) CloseStorageTransactions() error {
	e.mu.RLock()
	r := e.storageRunner
	e.mu.RUnlock()
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		<-r.done
		return nil
	}
	r.closed = true
	r.cancel()
	r.mu.Unlock()
	<-r.done
	r.backend.CloseIdleConnections()
	r.provider.CloseIdleConnections()
	if err := r.lock.Close(); err != nil {
		return fmt.Errorf("close storage journal ownership: %w", err)
	}
	return nil
}
