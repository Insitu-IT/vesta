package storageupload

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func TestNativeLifetimeLegacyJournalBytesAndTTLUnchanged(t *testing.T) {
	root, body := t.TempDir(), request(t, false)
	j, err := Create(root, body)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.PrepareNative(nativePlan()); err != nil {
		t.Fatal(err)
	}
	path := j.path
	j.Close()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	j, err = Open(root, body)
	if err != nil {
		t.Fatal(err)
	}
	s, err := j.Snapshot()
	j.Close()
	after, readErr := os.ReadFile(path)
	if err != nil || readErr != nil || s.Native.Lifetime != nil || s.Native.BackupTTL() != 2*time.Hour || !bytes.Equal(before, after) {
		t.Fatal("legacy journal was rewritten or extended", err, readErr)
	}
}

func TestNativeLifetimeCreationBoundAtomicallyAndImmutable(t *testing.T) {
	j, err := Create(t.TempDir(), request(t, false))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	n := nativePlan()
	start := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	n.Lifetime = &NativeLifetime{TTLSeconds: 4 * 3600, PreparedAt: start.Format(time.RFC3339Nano), TransactionTimeoutSeconds: 3 * 3600}
	if j.PrepareNative(n) != nil || j.BeginNativeCreate("tracker", j.state.Request.Plan.Source.VMUID) != nil || j.ObserveNative("tracker", "tracker-original", j.state.Request.Plan.Source.VMUID, true) != nil || j.BeginNativeCreate("backup", "tracker-original") != nil {
		t.Fatal("fixture")
	}
	if j.ObserveNative("backup", "backup-original", "tracker-original", true) == nil {
		t.Fatal("missing creation accepted")
	}
	if j.ObserveNativeBackup("backup-original", "tracker-original", start.Add(time.Minute)) != nil {
		t.Fatal("creation refused")
	}
	if j.ObserveNativeBackup("backup-original", "tracker-original", start.Add(2*time.Minute)) == nil {
		t.Fatal("creation extended")
	}
	s, err := j.Snapshot()
	if err != nil || !s.Native.Lifetime.Deadline().Equal(start.Add(3*time.Hour)) {
		t.Fatal("optional total deadline moved", err)
	}
}
