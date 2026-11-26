//go:build kubevirt

package kubevirt

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

// finalizeSafetyObservation deliberately excludes payload objects, maps, source
// URLs, receipts and VM definitions. It is not part of safetyState's disk schema.
type finalizeSafetyObservation struct {
	requestSHA256         string
	resourcePrefix        string
	deleteResourceVersion string
	checkpoint            string
	native                storageupload.NativeState
	exportLifetime        *storageupload.ExportLifetime
}

// observeFinalize accepts only the detached Snapshot of an already validated,
// locked journal. It is an in-memory observation aid, never publication proof or
// a persisted authority field. A prior safety stop cannot be cleared by it.
func (g *operationSafety) observeFinalize(s storageupload.State) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.finalizeObservation = nil
	if g.poisoned {
		return storageupload.ErrHeld
	}
	// Stopped work must still reach the existing bounded closure recovery.
	// It never receives an observation exception.
	if g.state.Stop != nil {
		return nil
	}
	f := s.Finalize
	if f == nil {
		return nil
	}
	if f.DeleteRefused {
		// Refusal grants no observation exception, but must not remove this
		// attempt from the existing bounded watch/closure recovery queue.
		return nil
	}
	if f.DeleteResourceVersion == "" {
		return nil
	}
	n := s.Native
	if s.Phase != "accepted" || s.Acceptance == nil || n == nil || len(n.Objects) != 3 ||
		g.state.Native == nil || len(g.state.Native.Objects) != 3 ||
		f.IntentID == "" || f.Binding.ReservationID != s.Request.ReservationID ||
		f.Binding.AttemptID != s.Request.Plan.AttemptID || f.Binding.PlanSHA256 != s.Request.PlanSHA256 ||
		f.Binding.VMBUID != n.Objects[1].UID || f.Binding.VMBName != n.Objects[1].Name ||
		f.Binding.Namespace != s.Request.Plan.Source.Namespace ||
		f.Binding.VMBUID != g.state.Native.Objects[1].UID ||
		!n.Objects[1].Created || requestDigest(&s.Request) != g.state.RequestSHA256 {
		return storageupload.ErrHeld
	}
	native := storageupload.NativeState{ScratchName: n.ScratchName, ScratchUID: n.ScratchUID,
		Objects: append([]storageupload.NativeObject(nil), n.Objects...)}
	if n.Lifetime != nil {
		lifetime := *n.Lifetime
		native.Lifetime = &lifetime
	}
	mirror := &finalizeSafetyObservation{requestSHA256: requestDigest(&s.Request), resourcePrefix: s.ResourcePrefix,
		deleteResourceVersion: f.DeleteResourceVersion, checkpoint: f.Binding.Checkpoint, native: native}
	if s.Export != nil && s.Export.Lifetime != nil {
		lifetime := *s.Export.Lifetime
		mirror.exportLifetime = &lifetime
	}
	g.finalizeObservation = mirror
	return nil
}

func (g *operationSafety) refuseFinalizeObservation() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.finalizeObservation = nil
}

// Pull-mode controller cleanup temporarily reports Aborting=True after our own
// durable finalize/delete intent. Defer only that observation to the existing
// terminal-history/checkpoint proof path; all health/budget/scratch checks ran
// first, and a real Failed state always refuses before this gate is considered.
func (e *Executor) ownedFinalizeAborting(r *models.StorageTransactionRequest, g *operationSafety, b *unstructured.Unstructured) bool {
	g.mu.Lock()
	mirror := g.finalizeObservation
	live := !g.poisoned && g.state.Stop == nil && g.state.Progress.Stage == "finalizing"
	g.mu.Unlock()
	if !live || mirror == nil || mirror.deleteResourceVersion == "" ||
		requestDigest(r) != mirror.requestSHA256 ||
		b.GetDeletionTimestamp() == nil || b.GetResourceVersion() == "" ||
		b.GetResourceVersion() == mirror.deleteResourceVersion ||
		string(b.GetUID()) != mirror.native.Objects[1].UID ||
		textAt(b, "status", "checkpointName") != mirror.checkpoint || nativeHardFailure(b) {
		return false
	}
	state := &storageupload.State{Request: *r, ResourcePrefix: mirror.resourcePrefix, Native: &mirror.native}
	if mirror.exportLifetime != nil {
		state.Export = &storageupload.ExportState{Lifetime: mirror.exportLifetime}
	}
	if !e.namingMatches(state) || !beforeFinalizeDeadline(b, state) {
		return false
	}
	projected := b.DeepCopy()
	projected.SetDeletionTimestamp(nil)
	return validNativeObject(projected, r, &mirror.native, 1, true)
}

func nativeHardFailure(b *unstructured.Unstructured) bool {
	return textAt(b, "status", "phase") == "Failed" || nativeConditionTrue(b.Object, "Failed")
}
