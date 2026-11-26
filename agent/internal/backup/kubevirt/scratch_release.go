//go:build kubevirt

package kubevirt

import (
	"context"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

// Called only after the collector has returned, or after accepted terminal
// proof. A stopped/absent native job is not enough to release scratch custody.
// The scratch PVC, tracker, native children and payload objects are untouched.
func (e *Executor) releaseScratch(parent context.Context, r *models.StorageTransactionRequest, g *operationSafety, noNative bool) error {
	s := g.snapshot()
	if s.Scratch == nil || s.Scratch.Intent == "released" {
		return nil
	}
	if !s.SourceClosed {
		if !noNative || s.Stop == nil || s.Stop.Phase != "no_native_started" || (s.Native != nil && (len(s.Native.Objects) != 3 || s.Native.Objects[1].Phase != "planned")) {
			return storageupload.ErrHeld
		}
	}
	a := s.Scratch
	if (a.ProbeUID == "" && a.Intent == "probe_create_intent") || (a.LeaseUID == "" && a.Intent == "lease_create_intent") {
		return storageupload.ErrHeld
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), time.Duration(s.Progress.Budget.ClosureSeconds)*time.Second)
	defer cancel()
	remove := func(resource schema.GroupVersionResource, name, uid string) error {
		if uid == "" {
			return nil
		}
		client := e.dynamic.Resource(resource).Namespace(r.Plan.Source.Namespace)
		object, err := client.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil || string(object.GetUID()) != uid {
			return storageupload.ErrHeld
		}
		if object.GetDeletionTimestamp() == nil {
			if !scratchIdentity(object, r) {
				return storageupload.ErrHeld
			}
			id, rv := types.UID(uid), object.GetResourceVersion()
			if rv == "" {
				return storageupload.ErrHeld
			}
			if err = client.Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &id, ResourceVersion: &rv}}); err != nil {
				return storageupload.ErrHeld
			}
		}
		for {
			obj, err := client.Get(ctx, name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return nil
			}
			if err == nil && string(obj.GetUID()) != uid {
				return storageupload.ErrHeld
			}
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return storageupload.ErrHeld
			case <-timer.C:
			}
		}
	}
	if err := remove(exportPodResource, a.ProbeName, a.ProbeUID); err != nil {
		return err
	}
	if err := remove(scratchLeases, a.LeaseName, a.LeaseUID); err != nil {
		return err
	}
	return g.update(func(s *safetyState) error { s.Scratch.Intent = "released"; return nil })
}
