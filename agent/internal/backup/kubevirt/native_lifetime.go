//go:build kubevirt

package kubevirt

import (
	"context"
	"errors"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"vnbui/agent/internal/storageupload"
)

var nativeNow = time.Now
var errExportLifetime = errors.New("original exporter cannot cover the pinned native lifetime; retain native custody")

func beforePinnedNativeDeadline(n *storageupload.NativeState) bool {
	if n.Lifetime == nil {
		return true
	}
	deadline := n.Lifetime.Deadline()
	return n.Lifetime.Valid() && (deadline.IsZero() || nativeNow().Before(deadline))
}

func beforeNativeTTL(b *unstructured.Unstructured, n *storageupload.NativeState) bool {
	d, err := time.ParseDuration(textAt(b, "spec", "ttlDuration"))
	created := b.GetCreationTimestamp()
	if err != nil || d != n.BackupTTL() || created.IsZero() || !nativeNow().Before(created.Add(d)) || !beforePinnedNativeDeadline(n) {
		return false
	}
	return n.Lifetime == nil || n.Lifetime.CreatedAt == created.UTC().Format(time.RFC3339Nano)
}

func beforeFinalizeDeadline(b *unstructured.Unstructured, s *storageupload.State) bool {
	return beforeNativeTTL(b, s.Native) && (s.Export == nil || s.Export.Lifetime == nil || nativeNow().Before(s.Export.Lifetime.Deadline()))
}

// Pin the controller's remaining TTL and exporter process deadline before any
// source/key/S3 access. Certificate rotation can end the original pod earlier
// than the VMB TTL; that unsupported window must not silently become a new pod.
func inspectExportLifetime(ex, pod *unstructured.Unstructured, n *storageupload.NativeState) (*storageupload.ExportLifetime, error) {
	created := ex.GetCreationTimestamp()
	l := &storageupload.ExportLifetime{CreatedAt: created.UTC().Format(time.RFC3339Nano), TTL: textAt(ex, "spec", "ttlDuration")}
	containers, found, err := unstructured.NestedSlice(pod.Object, "spec", "containers")
	if err != nil || !found || len(containers) != 1 {
		return nil, errExportLifetime
	}
	container, ok := containers[0].(map[string]interface{})
	if !ok {
		return nil, errExportLifetime
	}
	env, found, err := unstructured.NestedSlice(container, "env")
	if err != nil || !found || len(env) > 128 {
		return nil, errExportLifetime
	}
	for _, raw := range env {
		v, ok := raw.(map[string]interface{})
		if !ok {
			return nil, errExportLifetime
		}
		if v["name"] == "DEADLINE" {
			if l.PodDeadline != "" || v["valueFrom"] != nil {
				return nil, errExportLifetime
			}
			l.PodDeadline, ok = v["value"].(string)
			if !ok || l.PodDeadline == "" {
				return nil, errExportLifetime
			}
		}
	}
	if !l.Valid(n.Lifetime) || !nativeNow().Before(l.Deadline()) {
		return nil, errExportLifetime
	}
	return l, nil
}

func nativeLifetimeExpired(s *storageupload.State) bool {
	// Already observed terminal success/proof may finish publication after the
	// producer is gone. Compensation has its own independently admitted protocol.
	if s.Compensation != nil || (s.Finalize != nil && (s.Finalize.Proof != nil || s.Finalize.TerminalResourceVersion != "")) {
		return false
	}
	if s.Native != nil && !beforePinnedNativeDeadline(s.Native) {
		return true
	}
	if deadline := nativeStateDeadline(s); !deadline.IsZero() && !nativeNow().Before(deadline) {
		return true
	}
	return s.Export != nil && s.Export.Lifetime != nil && !nativeNow().Before(s.Export.Lifetime.Deadline())
}

func nativeStateDeadline(s *storageupload.State) time.Time {
	if s.Native != nil && s.Native.Lifetime != nil {
		return s.Native.Lifetime.Deadline()
	}
	if s.Native != nil && s.Utility != nil {
		// The original utility admission bound this timestamp to VMB creation.
		created, err := time.Parse(time.RFC3339Nano, s.Utility.StartedAt)
		if err == nil {
			return created.Add(s.Native.BackupTTL())
		}
	}
	return time.Time{}
}

func nativeUploadContext(ctx context.Context, s *storageupload.State) (context.Context, context.CancelFunc) {
	deadline := nativeStateDeadline(s)
	if s.Export != nil && s.Export.Lifetime != nil {
		export := s.Export.Lifetime.Deadline()
		if deadline.IsZero() || export.Before(deadline) {
			deadline = export
		}
	}
	if deadline.IsZero() {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, deadline.Sub(nativeNow()))
}
