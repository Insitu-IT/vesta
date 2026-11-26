package storageupload

import (
	"time"

	"vnbui/agent/internal/config"
)

// Absence means the original, fixed two-hour native policy. Optional fields
// preserve old journal bytes/checksums; no recovery path retrofits a lifetime.
type NativeLifetime struct {
	TTLSeconds                int    `json:"ttl_seconds"`
	PreparedAt                string `json:"prepared_at"`
	TransactionTimeoutSeconds int    `json:"transaction_timeout_seconds"`
	CreatedAt                 string `json:"created_at"`
}

func lifetimeTime(value string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, value)
	return t, err == nil && !t.IsZero() && t.UTC().Format(time.RFC3339Nano) == value
}

func (l *NativeLifetime) Valid() bool {
	if l == nil || l.TTLSeconds < config.MinNativeBackupTTLSeconds || l.TTLSeconds > config.MaxNativeBackupTTLSeconds ||
		l.TransactionTimeoutSeconds < 0 || l.TransactionTimeoutSeconds > l.TTLSeconds {
		return false
	}
	if _, ok := lifetimeTime(l.PreparedAt); !ok {
		return false
	}
	if l.CreatedAt != "" {
		_, ok := lifetimeTime(l.CreatedAt)
		return ok
	}
	return true
}

func (n *NativeState) BackupTTL() time.Duration {
	if n.Lifetime == nil {
		return 2 * time.Hour
	}
	return time.Duration(n.Lifetime.TTLSeconds) * time.Second
}

// Deadline combines the pinned native creation and optional transaction limit.
// Before creation, only the latter applies; zero means creation is still pending.
func (l *NativeLifetime) Deadline() time.Time {
	var deadline time.Time
	if l.CreatedAt != "" {
		created, _ := lifetimeTime(l.CreatedAt)
		deadline = created.Add(time.Duration(l.TTLSeconds) * time.Second)
	}
	if l.TransactionTimeoutSeconds > 0 {
		prepared, _ := lifetimeTime(l.PreparedAt)
		total := prepared.Add(time.Duration(l.TransactionTimeoutSeconds) * time.Second)
		if deadline.IsZero() || total.Before(deadline) {
			deadline = total
		}
	}
	return deadline
}

type ExportLifetime struct {
	CreatedAt   string `json:"created_at"`
	TTL         string `json:"ttl"`
	PodDeadline string `json:"pod_deadline"`
}

func (l *ExportLifetime) Valid(n *NativeLifetime) bool {
	if l == nil || n == nil || !n.Valid() || n.CreatedAt == "" {
		return false
	}
	created, ok := lifetimeTime(l.CreatedAt)
	d, err := time.ParseDuration(l.TTL)
	pod, podOK := lifetimeTime(l.PodDeadline)
	if !ok || err != nil || d <= 0 || d > time.Duration(n.TTLSeconds)*time.Second || !podOK || !pod.After(created) {
		return false
	}
	// API timestamps and exporter DEADLINE are rounded to seconds, while the
	// controller computes remaining TTL in nanoseconds. Permit only that rounding;
	// actual execution always stops at the earliest observed deadline.
	required := n.Deadline()
	return !created.Add(d).Add(time.Second).Before(required) && !pod.Add(time.Second).Before(required)
}

func (l *ExportLifetime) Deadline() time.Time {
	created, _ := lifetimeTime(l.CreatedAt)
	d, _ := time.ParseDuration(l.TTL)
	deadline := created.Add(d)
	pod, _ := lifetimeTime(l.PodDeadline)
	if pod.Before(deadline) {
		return pod
	}
	return deadline
}

// HoldBeforePayload records an unsupported native/export lifetime without
// conferring cleanup, capacity release, checkpoint or replacement authority.
func (j *Journal) HoldBeforePayload() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.state.Phase != "uploading" || j.state.Native == nil || j.state.Export != nil || len(j.state.Maps) != 0 || j.state.Acceptance != nil || j.state.Finalize != nil {
		return ErrHeld
	}
	for _, object := range j.state.Objects {
		if object.Phase != "planned" || object.UploadID != "" || len(object.Parts) != 0 || object.PendingPart != nil || object.Receipt != nil || object.Provider != nil {
			return ErrHeld
		}
	}
	j.state.Phase = "held"
	return j.save()
}
