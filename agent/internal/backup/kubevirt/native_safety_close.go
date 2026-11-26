//go:build kubevirt

package kubevirt

import (
	"context"
	"errors"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/operationbudget"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
)

// closeNativeSafety has no backend, S3, tracker-delete, guest-resume or capacity
// release capability. Its only mutation targets the original observed VMB by
// UID and resourceVersion after a separate durable stop/delete intent.
func (e *Executor) closeNativeSafety(parent context.Context, r *models.StorageTransactionRequest, g *operationSafety) {
	g.closeMu.Lock()
	defer g.closeMu.Unlock()
	s := g.snapshot()
	if s.Stop == nil || s.SourceClosed {
		return
	}
	record := func(phase string) { _ = g.update(func(s *safetyState) error { s.Stop.Phase = phase; return nil }) }
	now := nativeNow()
	remaining := s.Stop.At.Add(time.Duration(s.Progress.Budget.ClosureSeconds) * time.Second).Sub(now)
	if now.Before(s.Stop.At) || remaining <= 0 {
		record("native_close_budget_exhausted")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), remaining)
	defer cancel()
	n := s.Native
	if n == nil || len(n.Objects) != 3 || n.Objects[1].Phase == "planned" {
		record("no_native_started")
		return
	}
	if n.Objects[1].Phase != "observed" || n.Objects[1].UID == "" || !n.Objects[1].Created {
		record("native_creation_uncertain")
		return
	}
	resource := e.dynamic.Resource(kvtypes.BackupResource).Namespace(r.Plan.Source.Namespace)
	var b *unstructured.Unstructured
	var err error
	for {
		s = g.snapshot()
		b, err = resource.Get(ctx, n.Objects[1].Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			record("native_absent_unproven")
			return
		}
		if err != nil {
			record("native_observation_unavailable")
			return
		}
		copy := b.DeepCopy()
		copy.SetDeletionTimestamp(nil)
		if string(b.GetUID()) != n.Objects[1].UID || !validNativeObject(copy, r, n, 1, true) {
			record("native_identity_refused")
			return
		}
		if b.GetDeletionTimestamp() == nil {
			if s.Stop.ResourceVersion != "" {
				record("native_delete_outcome_uncertain")
				return
			}
			rv, uid := b.GetResourceVersion(), types.UID(n.Objects[1].UID)
			if rv == "" {
				record("native_identity_refused")
				return
			}
			if g.update(func(s *safetyState) error {
				s.Stop.Phase = "native_delete_intent"
				s.Stop.ResourceVersion = rv
				s.Stop.HTTPStatus = 0
				return nil
			}) != nil {
				return
			}
			err = resource.Delete(ctx, b.GetName(), metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
			if apierrors.IsConflict(err) {
				// A definitive precondition rejection means no deletion occurred.
				// Only that response permits rereading the same UID and retrying
				// with its new resourceVersion inside the original close budget.
				if g.update(func(s *safetyState) error {
					s.Stop.Phase, s.Stop.ResourceVersion, s.Stop.HTTPStatus = "native_delete_conflict", "", 409
					return nil
				}) != nil {
					return
				}
				timer := time.NewTimer(time.Second)
				select {
				case <-ctx.Done():
					timer.Stop()
					record("native_close_budget_exhausted")
					return
				case <-timer.C:
					continue
				}
			}
			if err != nil {
				_ = g.update(func(s *safetyState) error {
					s.Stop.Phase = "native_delete_outcome_uncertain"
					if status, ok := err.(apierrors.APIStatus); ok {
						s.Stop.HTTPStatus = int(status.Status().Code)
						if status.Status().Code >= 400 && status.Status().Code < 500 {
							s.Stop.Phase = "native_delete_refused"
						}
					}
					return nil
				})
				return
			}
			record("native_delete_acknowledged")
		}
		break
	}
	// Observe, never repeat the mutation or turn disappearance into publication.
	for {
		b, err = resource.Get(ctx, n.Objects[1].Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			record("native_absent_unproven")
			return
		}
		if err == nil && string(b.GetUID()) != n.Objects[1].UID {
			record("native_identity_refused")
			return
		}
		if err == nil && hasTerminalCondition(b) {
			record("native_terminal_observed_custody_retained")
			return
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			record("native_close_budget_exhausted")
			return
		case <-timer.C:
		}
	}
}

// This is negative lifecycle telemetry, not checkpoint success proof.
func hasTerminalCondition(b interface{ UnstructuredContent() map[string]interface{} }) bool {
	status, _ := b.UnstructuredContent()["status"].(map[string]interface{})
	conditions, _ := status["conditions"].([]interface{})
	for _, raw := range conditions {
		c, _ := raw.(map[string]interface{})
		if (c["type"] == "Done" || c["type"] == "Failed") && c["status"] == "True" {
			return true
		}
	}
	return false
}

func (e *Executor) inspectSafety(ctx context.Context, r *models.StorageTransactionRequest, g *operationSafety) error {
	s := g.snapshot()
	started := nativeNow()
	if reason := safetyExhausted(s, nativeNow()); reason != "" {
		return fault(s.Progress.Stage, reason, "refused")
	}
	if s.SourceClosed || s.Native == nil || len(s.Native.Objects) != 3 || s.Native.Objects[1].Phase != "observed" {
		return nil
	}
	node, err := e.sourceAvailability(ctx, r)
	if err != nil {
		return err
	}
	if err := inspectServiceHealth(ctx, g); err != nil {
		return err
	}
	if s.Scratch == nil || s.Scratch.Node != node {
		return fault("scratch", "scratch_source_node_changed", "refused")
	}
	pvc, err := e.dynamic.Resource(pvcResource).Namespace(r.Plan.Source.Namespace).Get(ctx, s.Scratch.Name, metav1.GetOptions{})
	if err != nil {
		return safetyReadFault(err, "scratch", "scratch_identity_unavailable")
	}
	if string(pvc.GetUID()) != s.Scratch.UID || pvc.GetDeletionTimestamp() != nil {
		return fault("scratch", "scratch_identity_unavailable", "refused")
	}
	lease, err := e.dynamic.Resource(scratchLeases).Namespace(r.Plan.Source.Namespace).Get(ctx, s.Scratch.LeaseName, metav1.GetOptions{})
	if err != nil {
		return safetyReadFault(err, "scratch", "scratch_reservation_unavailable")
	}
	if string(lease.GetUID()) != s.Scratch.LeaseUID || !scratchIdentity(lease, r) || textAt(lease, "spec", "holderIdentity") != r.ReservationID {
		return fault("scratch", "scratch_reservation_changed", "refused")
	}
	next, err := e.readScratchSample(ctx, r, s.Scratch)
	if err != nil {
		return err
	}
	if err := g.update(func(s *safetyState) error { return updateScratchGrowth(s, next) }); err != nil {
		return err
	}
	s = g.snapshot()
	reserve, err := operationbudget.GrowthReserve(s.Scratch.PeakGrowthBytesPerSecond, 20, s.Progress.Budget.ClosureSeconds, s.Policy.ScratchCoefficient)
	if err != nil {
		return fault("scratch", "scratch_growth_unbounded", "refused")
	}
	// Keep the format/metadata margin even before a growth sample exists.
	reserve = max(reserve, s.Scratch.RequiredBytes-s.Progress.Budget.ExpectedBytes)
	if next.AvailableBytes <= reserve {
		return fault("scratch", "scratch_exhaustion_risk", "refused")
	}
	b, err := e.dynamic.Resource(kvtypes.BackupResource).Namespace(r.Plan.Source.Namespace).Get(ctx, s.Native.Objects[1].Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) && s.Progress.Stage == "finalizing" {
		return nil
	}
	if err != nil {
		return safetyReadFault(err, "native", "native_health_unavailable")
	}
	if string(b.GetUID()) != s.Native.Objects[1].UID {
		return fault("native", "native_identity_changed", "refused")
	}
	// Deletion is also the normal finalize handshake; its proof remains owned
	// by the finalize journal. Only its owned Pull-mode Aborting transition may
	// be deferred to that proof path; a real Failed state always refuses.
	if nativeHardFailure(b) {
		return fault("native", "native_failed", "refused")
	}
	if nativeConditionTrue(b.Object, "Aborting") && !e.ownedFinalizeAborting(r, g, b) {
		return fault("native", "native_failed", "refused")
	}
	return g.recordSafetyObservation(s, next, started, nativeNow())
}

func nativeConditionTrue(object map[string]interface{}, name string) bool {
	status, _ := object["status"].(map[string]interface{})
	conditions, _ := status["conditions"].([]interface{})
	for _, raw := range conditions {
		c, _ := raw.(map[string]interface{})
		if c["type"] == name && c["status"] == "True" {
			return true
		}
	}
	return false
}

func (r *transactionRunner) watchSafety(work *transactionWork, cancel context.CancelFunc, done <-chan struct{}) {
	g := work.safety
	if g == nil {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-r.ctx.Done():
			if errors.Is(g.stop(fault("shutdown", "agent_stopped_during_operation", "uncertain")), errOperationPublished) {
				return
			}
			cancel()
			r.retain(work, "agent stopped; closing original native operation and retaining custody")
			r.executor.closeNativeSafety(r.ctx, work.request, g)
			return
		case <-ticker.C:
			s := g.snapshot()
			if s.Progress.Stage == "complete" {
				return
			}
			deadline := nativeNow().Add(20 * time.Second)
			if s.Uncertainty != nil {
				deadline = earlier(deadline, s.Uncertainty.Deadline)
			}
			if s.ReadUncertainty != nil {
				deadline = earlier(deadline, s.ReadUncertainty.Deadline)
			}
			deadline = earlier(deadline, s.Progress.Deadline())
			ctx, finish := context.WithTimeout(r.ctx, max(time.Duration(0), deadline.Sub(nativeNow())))
			err := r.executor.inspectSafetyObservation(ctx, work.request, g)
			finish()
			if s.Stop != nil || err != nil {
				// Observation recovery cannot renew operation or closure budgets.
				f := faultOf(err)
				if err == nil {
					f = s.Fault
				}
				if errors.Is(g.stop(f), errOperationPublished) {
					return
				}
				cancel()
				r.retain(work, "safety stop; closing original native operation and retaining custody")
				r.executor.closeNativeSafety(r.ctx, work.request, g)
				return
			}
		}
	}
}

func safetyProgress(ctx context.Context, stage string, cursor int64) error {
	if err := checkSafety(ctx); err != nil {
		return err
	}
	if g := safetyFrom(ctx); g != nil {
		return g.advance(stage, cursor)
	}
	return nil
}

func permitPublication(ctx context.Context) error {
	if err := checkSafety(ctx); err != nil {
		return err
	}
	if g := safetyFrom(ctx); g != nil {
		return g.sourceClosed(nativeNow())
	}
	return nil
}
