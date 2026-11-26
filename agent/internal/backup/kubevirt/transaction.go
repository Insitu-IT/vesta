//go:build kubevirt

package kubevirt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
)

// The journal is outside the disposable VM namespace, beside the persistent
// keystore. It contains identity and phase only, never credentials or tokens.
type pullTransaction struct {
	BackupID       string    `json:"backup_id"`
	ResourcePrefix string    `json:"resource_prefix,omitempty"`
	VMName         string    `json:"vm_name"`
	VMUID          string    `json:"vm_uid,omitempty"`
	Namespace      string    `json:"namespace"`
	Tracker        string    `json:"tracker"`
	TrackerUID     types.UID `json:"tracker_uid"`
	BackupUID      types.UID `json:"backup_uid,omitempty"`
	AbortPhase     string    `json:"abort_phase,omitempty"`
	Checkpoint     string    `json:"checkpoint"`
	Endpoint       string    `json:"endpoint"`
	UseSSL         bool      `json:"use_ssl"`
	Bucket         string    `json:"bucket"`
	Prefix         string    `json:"prefix"`
	Phase          string    `json:"phase"`
	Bytes          int64     `json:"bytes"`
	Error          string    `json:"error,omitempty"`
	CleanupError   string    `json:"cleanup_error,omitempty"`
}

func (t *pullTransaction) location() string {
	return "s3://" + t.Bucket + "/" + strings.TrimSuffix(t.Prefix, "/")
}

func (e *Executor) transactionDir() string {
	return filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "pull-transactions")
}

func (e *Executor) saveTransaction(t *pullTransaction) error {
	if t.BackupID == "" || strings.ContainsAny(t.BackupID, "/\\") || t.BackupID == "." || t.BackupID == ".." {
		return fmt.Errorf("invalid transaction backup id")
	}
	dir := e.transactionDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(t)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".transaction-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, t.BackupID+".json")); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Called only after durable VMB-absence evidence and invalidation intent. Native
// abort may advance the checkpoint, so invalidate that lineage after its cleanup.
func (e *Executor) abortTracker(ctx context.Context, t *pullTransaction) error {
	tracker, err := e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace(t.Namespace).Get(ctx, t.Tracker, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if t.TrackerUID == "" || tracker.GetUID() != t.TrackerUID {
		return fmt.Errorf("tracker identity changed; refusing to delete replacement")
	}
	uid := t.TrackerUID
	err = e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace(t.Namespace).Delete(ctx, t.Tracker, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	_, err = e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace(t.Namespace).Get(ctx, t.Tracker, metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("tracker removal not confirmed: %v", err)
	}
	return nil
}

func (e *Executor) checkpointCommitted(ctx context.Context, t *pullTransaction) (bool, error) {
	if t.VMUID != "" {
		if err := e.verifyVMIdentity(ctx, &models.BackupRequest{VMName: t.VMName, VMNamespace: t.Namespace, VMUID: t.VMUID}); err != nil {
			if errors.Is(err, errVMIdentityChanged) {
				return false, nil
			}
			return false, err
		}
	}
	obj, err := e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace(t.Namespace).Get(ctx, t.Tracker, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	latest, _, _ := unstructured.NestedString(obj.Object, "status", "latestCheckpoint", "name")
	return t.Checkpoint != "" && obj.GetUID() == t.TrackerUID && latest == t.Checkpoint, nil
}

func deleteBackupPrefix(ctx context.Context, cfg *backup.S3Config, t *pullTransaction) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Never reinterpret an old transaction using a changed bucket or endpoint.
	if cfg.Endpoint != t.Endpoint || cfg.UseSSL != t.UseSSL || cfg.Bucket != t.Bucket || t.Prefix != strings.Trim(cfg.Prefix, "/")+"/"+t.BackupID+"/" {
		return fmt.Errorf("S3 configuration differs from transaction; cleanup requires original destination")
	}
	c, err := minio.New(cfg.Endpoint, &minio.Options{Creds: credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""), Secure: cfg.UseSSL, Region: cfg.Region})
	if err != nil {
		return err
	}
	// Include versions and delete markers: an ordinary DELETE in a versioned
	// bucket only hides an orphan. Remove unfinished multipart uploads as well.
	for upload := range c.ListIncompleteUploads(ctx, t.Bucket, t.Prefix, true) {
		if upload.Err != nil {
			return upload.Err
		}
		if err := c.RemoveIncompleteUpload(ctx, t.Bucket, upload.Key); err != nil {
			return err
		}
	}
	for obj := range c.ListObjects(ctx, t.Bucket, minio.ListObjectsOptions{Prefix: t.Prefix, Recursive: true, WithVersions: true}) {
		if obj.Err != nil {
			return obj.Err
		}
		if err := c.RemoveObject(ctx, t.Bucket, obj.Key, minio.RemoveObjectOptions{VersionID: obj.VersionID}); err != nil {
			return err
		}
	}
	for obj := range c.ListObjects(ctx, t.Bucket, minio.ListObjectsOptions{Prefix: t.Prefix, Recursive: true, WithVersions: true}) {
		if obj.Err != nil {
			return obj.Err
		}
		return fmt.Errorf("backup prefix still contains object versions after compensation")
	}
	for upload := range c.ListIncompleteUploads(ctx, t.Bucket, t.Prefix, true) {
		if upload.Err != nil {
			return upload.Err
		}
		return fmt.Errorf("backup prefix still contains multipart uploads after compensation")
	}
	return ctx.Err()
}

// DELETE acceptance is not absence: both supported controller lines can retain
// vmbackup-protection after the tracker disappears. Never strip that finalizer:
// it also protects export, utility-volume and VMI backup-state cleanup.
func (e *Executor) removeAbortedBackup(ctx context.Context, t *pullTransaction) error {
	r := e.dynamic.Resource(kvtypes.BackupResource).Namespace(t.Namespace)
	name := pullBackupName(t)
	obj, err := r.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if t.BackupUID == "" {
		return fmt.Errorf("backup identity not journaled; refusing deletion of %s", name)
	}
	if obj.GetUID() != t.BackupUID {
		return fmt.Errorf("backup identity changed; refusing deletion of replacement %s", name)
	}
	uid, rv := obj.GetUID(), obj.GetResourceVersion()
	if obj.GetDeletionTimestamp() == nil {
		err = r.Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	obj, err = r.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("backup removal not confirmed: %s uid=%s finalizers=%v; controller-side export, utility-volume and VMI cleanup required", name, obj.GetUID(), obj.GetFinalizers())
}

func (e *Executor) compensate(ctx context.Context, t *pullTransaction, cfg *backup.S3Config) error {
	if !e.pullNamingMatches(t) {
		return fmt.Errorf("pull transaction naming differs from installation; retain journal")
	}
	// Controller cleanup needs the original tracker. S3 cleanup remains useful
	// even when external identity loss prevents completing the native abort.
	trackerErr := e.abortNative(ctx, t)
	s3Err := deleteBackupPrefix(ctx, cfg, t)
	if trackerErr != nil || s3Err != nil {
		return fmt.Errorf("cleanup requires retry (tracker: %v; S3: %v)", trackerErr, s3Err)
	}
	err := e.dynamic.Resource(coreV1Secret).Namespace(t.Namespace).Delete(ctx, pullBackupName(t)+"-token", metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

func (e *Executor) abortNative(ctx context.Context, t *pullTransaction) error {
	if !e.pullNamingMatches(t) {
		return fmt.Errorf("pull transaction naming differs from installation; retain journal")
	}
	if t.AbortPhase == "invalidated" {
		return nil
	}
	// A tracker addresses its VM by name. Never let an old abort operate on a
	// new incarnation at that name. Legacy journals retain their original fences.
	if t.VMUID != "" {
		if err := e.verifyVMIdentity(ctx, &models.BackupRequest{VMName: t.VMName, VMNamespace: t.Namespace, VMUID: t.VMUID}); err != nil {
			return err
		}
	}
	if t.AbortPhase != "" && t.AbortPhase != "vmb_deleting" && t.AbortPhase != "vmb_absent" && t.AbortPhase != "tracker_deleting" {
		return fmt.Errorf("unknown abort phase %q; operator reconciliation required", t.AbortPhase)
	}
	if t.AbortPhase != "tracker_deleting" {
		tracker, err := e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace(t.Namespace).Get(ctx, t.Tracker, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("native abort requires original tracker: %w", err)
		}
		if t.TrackerUID == "" || tracker.GetUID() != t.TrackerUID || tracker.GetDeletionTimestamp() != nil {
			return fmt.Errorf("native abort requires original non-deleting tracker; refusing replacement or deleting tracker")
		}
	}
	if t.AbortPhase == "" || t.AbortPhase == "vmb_deleting" {
		t.AbortPhase = "vmb_deleting"
		if err := e.saveTransaction(t); err != nil {
			return err
		}
		if err := e.removeAbortedBackup(ctx, t); err != nil {
			return err
		}
		t.AbortPhase = "vmb_absent"
		if err := e.saveTransaction(t); err != nil {
			return err
		}
	}
	// Re-read even on resumed invalidation. A same-name replacement must never
	// be deleted here or allowed to lose its source tracker through this abort.
	_, err := e.dynamic.Resource(kvtypes.BackupResource).Namespace(t.Namespace).Get(ctx, pullBackupName(t), metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("VMB absence no longer confirmed before tracker invalidation: %v", err)
	}
	t.AbortPhase = "tracker_deleting"
	if err := e.saveTransaction(t); err != nil {
		return err
	}
	if err := e.abortTracker(ctx, t); err != nil {
		return err
	}
	t.AbortPhase = "invalidated"
	return e.saveTransaction(t)
}

func (e *Executor) finishTransaction(t *pullTransaction, cfg *backup.S3Config, p *models.BackupProgress) {
	if t.Phase != "committed" && t.Phase != "failed" {
		t.Phase = "cleanup_required"
		t.CleanupError = ""
		// Persist abort intent before performing any compensating action. Recovery
		// must never promote this transaction on a late checkpoint observation.
		if err := e.saveTransaction(t); err != nil {
			t.CleanupError = "persist abort intent: " + err.Error()
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			err := e.compensate(ctx, t, cfg)
			cancel()
			if err == nil {
				t.Phase = "failed"
			} else {
				t.CleanupError = err.Error()
			}
		}
		if err := e.saveTransaction(t); err != nil {
			t.Phase = "cleanup_required"
			t.CleanupError += "; persist outcome: " + err.Error()
		}
	}
	committed := t.Phase == "committed"
	location := t.location()
	p.CheckpointCommitted = &committed
	p.S3Location = &location
	p.BytesTransferred = t.Bytes
	p.Status = models.TaskStatusFailed
	if t.Phase == "cleanup_required" {
		p.Status = models.TaskStatusCleanupRequired
	}
	if committed {
		p.Status = models.TaskStatusCompleted
		p.ProgressPercent = 100
	} else {
		reason := t.Error
		if t.CleanupError != "" {
			reason += "; " + t.CleanupError
		}
		p.ErrorMessage = &reason
	}
	e.setOp(p, string(p.Status))
	reason := t.Error
	if p.ErrorMessage != nil {
		reason = *p.ErrorMessage
	}
	e.emitEvent(t.BackupID, t.VMName, string(p.Status), reason, p)
}

// Called after heartbeat supplies S3 configuration, including after restart.
// Serialized with live backups; unresolved journal entries block new backups.
func (e *Executor) recoverTransactions(cfg *backup.S3Config) {
	if !e.transactionMu.TryLock() {
		return
	}
	defer e.transactionMu.Unlock()
	e.recovered = false
	entries, err := os.ReadDir(e.transactionDir())
	if err != nil && !os.IsNotExist(err) {
		slog.Error("read pull transaction journal", "error", err)
		return
	}
	clean := true
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(e.transactionDir(), entry.Name()))
		var t pullTransaction
		if err != nil || json.Unmarshal(data, &t) != nil || entry.Name() != t.BackupID+".json" {
			slog.Error("unreadable pull transaction", "file", entry.Name())
			clean = false
			continue
		}
		_, prefixErr := config.NormalizeKubevirtResourcePrefix(t.ResourcePrefix)
		terminal := t.Phase == "committed" || (t.Phase == "failed" && t.AbortPhase == "invalidated")
		if prefixErr != nil || (!e.pullNamingMatches(&t) && !terminal) {
			slog.Error("pull transaction naming differs from installation; retain journal", "backup_id", t.BackupID)
			clean = false
			continue
		}
		if e.reported[t.BackupID] && (t.Phase == "committed" || t.Phase == "failed") {
			continue
		}
		// Older journal writers treated accepted DELETE as completed cleanup.
		// Revalidate failed records at startup rather than replaying that claim.
		if t.Phase == "failed" && t.AbortPhase != "invalidated" {
			t.Phase = "cleanup_required"
		}
		if t.Phase == "published" {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			committed, err := e.checkpointCommitted(ctx, &t)
			cancel()
			if err != nil && !apierrors.IsNotFound(err) {
				clean = false
				continue
			}
			if committed {
				t.Phase = "committed"
				if err := e.saveTransaction(&t); err != nil {
					clean = false
					continue
				}
			}
		}
		if t.Error == "" && t.Phase != "committed" {
			t.Error = "agent restarted before checkpoint commit; fresh full seed required"
		}
		p := &models.BackupProgress{BackupID: t.BackupID, VMName: &t.VMName}
		e.finishTransaction(&t, cfg, p)
		e.mu.Lock()
		e.jobs[t.BackupID] = p
		e.mu.Unlock()
		e.reported[t.BackupID] = true
		if t.Phase == "cleanup_required" {
			clean = false
		}
	}
	e.recovered = clean
}
