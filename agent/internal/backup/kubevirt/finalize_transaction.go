//go:build kubevirt

package kubevirt

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"vnbui/agent/internal/models"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/storageupload"
)

// ReconcileStorageTransaction connects preparation/upload/acceptance to the
// original-VMB-only finalize exception. It returns checkpoint evidence only
// after the backend acknowledges durable generation publication and completion.
// One bounded observation per invocation: callers may reopen/wait, never turn
// an absent VMB or a timed-out controller into success.
func (e *Executor) ReconcileStorageTransaction(ctx context.Context, body []byte, backend, provider *http.Client, credential func(context.Context) (string, error)) (*storageupload.CheckpointProof, error) {
	r, err := models.DecodeStorageTransaction(body)
	if err != nil || r.Plan.Provider != "kubevirt" {
		return nil, storageupload.ErrHeld
	}
	root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
	if safetyFrom(ctx) == nil {
		if g, err := openSafety(root, r); err == nil {
			ctx = context.WithValue(ctx, safetyContextKey{}, g)
		}
	}
	if err := checkSafety(ctx); err != nil {
		return nil, err
	}
	// Resume a finalize journal directly: export/token/utility resources may
	// legitimately be removed by their controller after our accepted intent.
	var j *storageupload.Journal
	if _, err = os.Stat(filepath.Join(root, r.ReservationID)); err == nil {
		j, err = storageupload.Open(root, body)
		if err != nil {
			return nil, storageupload.ErrHeld
		}
		s, se := j.Snapshot()
		if se != nil || (!e.namingMatches(&s) && (s.Finalize == nil || s.Finalize.Proof == nil)) {
			_ = j.Close()
			return nil, storageupload.ErrHeld
		}
		if g := safetyFrom(ctx); g != nil {
			if err := g.observeFinalize(s); err != nil {
				_ = j.Close()
				return nil, err
			}
		}
		if handled, cleanupErr := e.compensateLostNative(ctx, j, backend, credential); handled {
			_ = j.Close()
			return nil, cleanupErr
		}
		if s.Finalize == nil {
			_ = j.Close()
			j = nil
		}
	} else if !os.IsNotExist(err) {
		return nil, storageupload.ErrHeld
	}
	if j == nil {
		if _, err = e.AcceptStorageTransaction(ctx, body, backend, provider, credential); err != nil {
			return nil, err
		}
		j, err = storageupload.Open(root, body)
		if err != nil {
			return nil, storageupload.ErrHeld
		}
	}
	defer j.Close()
	s, err := j.Snapshot()
	if err != nil || s.Phase != "accepted" || s.Acceptance == nil || (!e.namingMatches(&s) && (s.Finalize == nil || s.Finalize.Proof == nil)) {
		return nil, storageupload.ErrHeld
	}
	if nativeLifetimeExpired(&s) {
		return nil, storageupload.ErrHeld
	}
	if s.Finalize == nil {
		if handled, cleanupErr := e.compensateLostNative(ctx, j, backend, credential); handled {
			return nil, cleanupErr
		}
		if err := e.revalidateExport(ctx, &s); err != nil {
			return nil, err
		}
		b, err := e.dynamic.Resource(kvtypes.BackupResource).Namespace(r.Plan.Source.Namespace).Get(ctx, s.Native.Objects[1].Name, metav1.GetOptions{})
		if err != nil || string(b.GetUID()) != s.Native.Objects[1].UID || !beforeFinalizeDeadline(b, &s) {
			return nil, storageupload.ErrHeld
		}
		guest, ok := guestEvidence(b)
		if !ok {
			return nil, storageupload.ErrHeld
		}
		if j.PrepareFinalize(guest) != nil {
			return nil, storageupload.ErrHeld
		}
		s, err = j.Snapshot()
		if err != nil {
			return nil, storageupload.ErrHeld
		}
	}
	if err := checkSafety(ctx); err != nil {
		return nil, err
	}
	if s.Finalize.Proof != nil {
		if permitPublication(ctx) != nil || j.FinalizeControl(ctx, e.cfg.OrchestratorURL, backend, credential, true) != nil {
			return nil, storageupload.ErrHeld
		}
		return s.Finalize.Proof, nil
	}
	// Every attempt, including an identical retry, re-admits persisted backend
	// lifecycle/actor/org/agent/source/parent/target/custody before native work.
	if j.FinalizeControl(ctx, e.cfg.OrchestratorURL, backend, credential, false) != nil {
		return nil, storageupload.ErrHeld
	}
	s, err = j.Snapshot()
	if err != nil {
		return nil, storageupload.ErrHeld
	}
	b, err := e.dynamic.Resource(kvtypes.BackupResource).Namespace(r.Plan.Source.Namespace).Get(ctx, s.Native.Objects[1].Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if s.Finalize.TerminalResourceVersion == "" {
			// A controller can publish Complete and remove the original object
			// between polls. Replay retained watch history from our durable delete
			// cursor; absence or tracker advancement alone is still insufficient.
			if e.observeTerminalHistory(ctx, j, &s) != nil {
				return nil, storageupload.ErrHeld
			}
			if g := safetyFrom(ctx); g != nil {
				if err := g.sourceClosed(nativeNow()); err != nil {
					return nil, err
				}
			}
			s, err = j.Snapshot()
			if err != nil {
				return nil, storageupload.ErrHeld
			}
			_, err = e.dynamic.Resource(kvtypes.BackupResource).Namespace(r.Plan.Source.Namespace).Get(ctx, s.Native.Objects[1].Name, metav1.GetOptions{})
			if !apierrors.IsNotFound(err) {
				return nil, storageupload.ErrHeld
			}
		}
		tracker, err := e.finalizeSource(ctx, &s, true)
		if err != nil {
			return nil, err
		}
		if j.RecordCheckpoint(tracker.GetResourceVersion()) != nil {
			return nil, storageupload.ErrHeld
		}
		s, err = j.Snapshot()
		if err != nil {
			return nil, storageupload.ErrHeld
		}
		if permitPublication(ctx) != nil || j.FinalizeControl(ctx, e.cfg.OrchestratorURL, backend, credential, true) != nil {
			return nil, storageupload.ErrHeld
		}
		return s.Finalize.Proof, nil
	}
	if err != nil || string(b.GetUID()) != s.Native.Objects[1].UID || !beforeFinalizeDeadline(b, &s) {
		return nil, storageupload.ErrHeld
	}
	projected := b.DeepCopy()
	projected.SetDeletionTimestamp(nil)
	if !validNativeObject(projected, r, s.Native, 1, true) {
		return nil, storageupload.ErrHeld
	}
	if b.GetDeletionTimestamp() == nil {
		if s.Finalize.TerminalResourceVersion != "" || textAt(b, "status", "checkpointName") != s.Export.Checkpoint {
			return nil, storageupload.ErrHeld
		}
		if err := e.revalidateExport(ctx, &s); err != nil {
			return nil, err
		}
		guest, ok := guestEvidence(b)
		if !ok || guest != s.Finalize.Binding.GuestConsistency {
			return nil, storageupload.ErrHeld
		}
		rv, uid := b.GetResourceVersion(), types.UID(s.Native.Objects[1].UID)
		if j.RecordDeleteIntent(rv) != nil {
			return nil, storageupload.ErrHeld
		}
		// Snapshot only after the delete cursor is durable, before the HTTP delete.
		observed, err := j.Snapshot()
		if err != nil {
			return nil, storageupload.ErrHeld
		}
		if g := safetyFrom(ctx); g != nil {
			if err := g.observeFinalize(observed); err != nil {
				return nil, err
			}
		}
		// This is the only native mutation in this stage. No child cleanup,
		// finalizer manipulation, status patch or replacement adoption is possible.
		if err := checkSafety(ctx); err != nil {
			return nil, err
		}
		err = e.dynamic.Resource(kvtypes.BackupResource).Namespace(r.Plan.Source.Namespace).Delete(ctx, b.GetName(), metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
		if err != nil {
			var status apierrors.APIStatus
			if errors.As(err, &status) && status.Status().Code >= 400 && status.Status().Code < 500 {
				// A known refusal cannot later be laundered into our finalize
				// by an external abort/incidental checkpoint. Retain for D07.
				_ = j.RecordDeleteRefusal()
				if g := safetyFrom(ctx); g != nil {
					g.refuseFinalizeObservation()
				}
			}
			return nil, storageupload.ErrHeld
		}
		return nil, storageupload.ErrHeld
	}
	if s.Finalize.DeleteResourceVersion == "" {
		return nil, storageupload.ErrHeld
	}
	// A deleting/stuck-finalizer object is never re-deleted. Require a terminal
	// success observation *while the original VMB still exists*. Missing that
	// observation during a crash is explicit uncertainty, not inferred success.
	if terminalSuccess(b, &s) {
		if _, err = e.finalizeSource(ctx, &s, true); err != nil {
			return nil, err
		}
		if j.RecordTerminal(b.GetResourceVersion()) != nil {
			return nil, storageupload.ErrHeld
		}
		if g := safetyFrom(ctx); g != nil {
			if err := g.sourceClosed(nativeNow()); err != nil {
				return nil, err
			}
		}
	} else {
		if _, err = e.finalizeSource(ctx, &s, false); err != nil {
			return nil, err
		}
	}
	return nil, storageupload.ErrHeld
}

// observeTerminalHistory uses Kubernetes' retained event history, including a
// Deleted event's final object, to avoid losing a short-lived terminal update.
// An expired cursor is uncertainty: never restart from "now" or list a new VM.
func (e *Executor) observeTerminalHistory(ctx context.Context, journal *storageupload.Journal, state *storageupload.State) error {
	if state.Finalize == nil || state.Finalize.DeleteResourceVersion == "" || state.Finalize.DeleteRefused || state.Finalize.TerminalResourceVersion != "" || state.Native == nil {
		return storageupload.ErrHeld
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	seconds := int64(5)
	name := state.Native.Objects[1].Name
	stream, err := e.dynamic.Resource(kvtypes.BackupResource).Namespace(state.Request.Plan.Source.Namespace).Watch(ctx, metav1.ListOptions{
		FieldSelector: "metadata.name=" + name, ResourceVersion: state.Finalize.DeleteResourceVersion,
		AllowWatchBookmarks: true, TimeoutSeconds: &seconds,
	})
	if err != nil {
		return storageupload.ErrHeld
	}
	defer stream.Stop()
	for {
		select {
		case <-ctx.Done():
			return storageupload.ErrHeld
		case event, open := <-stream.ResultChan():
			if !open || event.Type == watch.Error {
				return storageupload.ErrHeld
			}
			if event.Type == watch.Bookmark {
				continue
			}
			if event.Type != watch.Added && event.Type != watch.Modified && event.Type != watch.Deleted {
				return storageupload.ErrHeld
			}
			object, ok := event.Object.(*unstructured.Unstructured)
			if !ok || object.GetName() != name || object.GetNamespace() != state.Request.Plan.Source.Namespace ||
				string(object.GetUID()) != state.Native.Objects[1].UID || object.GetResourceVersion() == "" ||
				object.GetResourceVersion() == state.Finalize.DeleteResourceVersion || !beforeFinalizeDeadline(object, state) {
				return storageupload.ErrHeld
			}
			projected := object.DeepCopy()
			projected.SetDeletionTimestamp(nil)
			if !validNativeObject(projected, &state.Request, state.Native, 1, true) {
				return storageupload.ErrHeld
			}
			if object.GetDeletionTimestamp() != nil && terminalSuccess(object, state) {
				if _, err := e.finalizeSource(ctx, state, true); err != nil {
					return storageupload.ErrHeld
				}
				return journal.RecordTerminal(object.GetResourceVersion())
			}
			if event.Type == watch.Deleted {
				return storageupload.ErrHeld
			}
		}
	}
}

func guestEvidence(b *unstructured.Unstructured) (string, bool) {
	rows, _, err := unstructured.NestedSlice(b.Object, "status", "conditions")
	if err != nil || len(rows) > 16 {
		return "", false
	}
	seen := map[string]bool{}
	guest := "unknown"
	for _, raw := range rows {
		c, ok := raw.(map[string]interface{})
		if !ok {
			return "", false
		}
		name, ok := c["type"].(string)
		if !ok || name == "" || seen[name] {
			return "", false
		}
		seen[name] = true
		status, ok := c["status"].(string)
		if !ok || (status != "True" && status != "False" && status != "Unknown") {
			return "", false
		}
		if name == "Quiesced" {
			// KubeVirt 1.8 has no guest-consistency backup condition.
			return "", false
		}
	}
	return guest, true
}
func terminalSuccess(b *unstructured.Unstructured, s *storageupload.State) bool {
	if nativeHardFailure(b) {
		return false
	}
	if textAt(b, "status", "checkpointName") != s.Export.Checkpoint {
		return false
	}
	guest, ok := guestEvidence(b)
	if !ok || guest != s.Finalize.Binding.GuestConsistency {
		return false
	}
	rows, _, _ := unstructured.NestedSlice(b.Object, "status", "conditions")
	complete, stopped := false, false
	for _, raw := range rows {
		c := raw.(map[string]interface{})
		if c["type"] == "Aborting" && c["status"] != "False" {
			return false
		}
		if c["type"] == "Done" {
			complete = c["status"] == "True"
		}
		if c["type"] == "Progressing" {
			stopped = c["status"] == "False"
		}
	}
	return complete && stopped
}
func (e *Executor) finalizeSource(ctx context.Context, s *storageupload.State, advanced bool) (*unstructured.Unstructured, error) {
	r, n := &s.Request, s.Native
	scratch, err := e.dynamic.Resource(pvcResource).Namespace(r.Plan.Source.Namespace).Get(ctx, n.ScratchName, metav1.GetOptions{})
	if err != nil || string(scratch.GetUID()) != n.ScratchUID || scratch.GetDeletionTimestamp() != nil {
		return nil, storageupload.ErrHeld
	}
	tracker, err := e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace(r.Plan.Source.Namespace).Get(ctx, n.Objects[0].Name, metav1.GetOptions{})
	if err != nil || string(tracker.GetUID()) != n.Objects[0].UID || tracker.GetDeletionTimestamp() != nil {
		return nil, storageupload.ErrHeld
	}
	// Compare source/ownership without mutating the durable parent binding.
	check := *r
	check.Plan = r.Plan
	check.Plan.Parent = nil
	if !validNativeObject(tracker, &check, n, 0, n.Objects[0].Created) {
		return nil, storageupload.ErrHeld
	}
	checkpoint := ""
	if r.Plan.Parent != nil {
		checkpoint = r.Plan.Parent.Checkpoint
	}
	if advanced {
		checkpoint = s.Export.Checkpoint
	}
	if textAt(tracker, "status", "latestCheckpoint", "name") != checkpoint {
		return nil, storageupload.ErrHeld
	}
	if advanced {
		stamp := textAt(tracker, "status", "latestCheckpoint", "creationTime")
		t, err := time.Parse(time.RFC3339Nano, stamp)
		if err != nil || t.UTC().Format(time.RFC3339Nano) != s.Utility.StartedAt {
			return nil, storageupload.ErrHeld
		}
		volumes, found, err := unstructured.NestedSlice(tracker.Object, "status", "latestCheckpoint", "volumes")
		if err != nil || !found || len(volumes) != len(s.Export.Volumes) {
			return nil, storageupload.ErrHeld
		}
		for i, v := range volumes {
			m, ok := v.(map[string]interface{})
			if !ok || !reflect.DeepEqual(m, map[string]interface{}{"volumeName": s.Export.Volumes[i].Name, "diskTarget": s.Export.Volumes[i].DiskTarget}) {
				return nil, storageupload.ErrHeld
			}
		}
	}
	vmi, err := e.dynamic.Resource(kvtypes.VMIResource).Namespace(r.Plan.Source.Namespace).Get(ctx, r.Plan.VMName, metav1.GetOptions{})
	if err != nil {
		return nil, storageupload.ErrHeld
	}
	utilities, _, err := unstructured.NestedSlice(vmi.Object, "spec", "utilityVolumes")
	if err != nil {
		return nil, storageupload.ErrHeld
	}
	var utility *storageupload.BorrowedUtility
	if len(utilities) > 0 {
		utility = s.Utility
	}
	if e.verifyTransactionSourceCheckpoint(ctx, r, utility, checkpoint) != nil {
		return nil, storageupload.ErrHeld
	}
	return tracker, nil
}
