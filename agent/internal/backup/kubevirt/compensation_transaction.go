//go:build kubevirt

package kubevirt

import (
	"context"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/storageupload"
)

// compensateLostNative accepts only complete accepted receipts before finalize.
// Native resources are read, never deleted or adopted by this slice.
func (e *Executor) compensateLostNative(ctx context.Context, j *storageupload.Journal, backend *http.Client, credential func(context.Context) (string, error)) (bool, error) {
	s, err := j.Snapshot()
	if err != nil || (!e.namingMatches(&s) && (s.Finalize == nil || s.Finalize.Proof == nil)) {
		return true, storageupload.ErrHeld
	}
	if s.Compensation == nil {
		if s.Phase != "accepted" || s.Finalize != nil || s.Native == nil || s.Acceptance == nil || s.Receipt == nil || s.Request.Plan.CapabilityProfile != "db-rooted-consumer-verified/1" {
			return false, nil
		}
		lost := false
		for i := 0; i < 2; i++ {
			o := s.Native.Objects[i]
			if o.Phase != "observed" || o.UID == "" {
				return false, nil
			}
			gvr := kvtypes.BackupTrackerResource
			if i == 1 {
				gvr = kvtypes.BackupResource
			}
			current, readErr := e.dynamic.Resource(gvr).Namespace(s.Request.Plan.Source.Namespace).Get(ctx, o.Name, metav1.GetOptions{})
			if apierrors.IsNotFound(readErr) || (readErr == nil && string(current.GetUID()) != o.UID) {
				lost = true
			}
		}
		if !lost {
			return false, nil
		}
		if !storageupload.ImmutableCompensationVersions(&s) {
			_ = j.HoldUnversionedCompensation()
			return true, storageupload.ErrHeld
		}
		if j.BeginCompensation() != nil {
			return true, storageupload.ErrHeld
		}
	}
	if err = j.Compensate(ctx, e.cfg.OrchestratorURL, backend, credential); err != nil {
		return true, err
	}
	return true, storageupload.ErrHeld // S3 absence still leaves native custody held.
}
