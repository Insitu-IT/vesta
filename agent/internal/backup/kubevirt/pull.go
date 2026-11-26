//go:build kubevirt

package kubevirt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/encryption"
	"vnbui/agent/internal/models"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
)

const exportTokenHeader = "x-kubevirt-export-token"

var coreV1Secret = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}

type pullVolume struct {
	Name         string
	DataEndpoint string
	MapEndpoint  string
}

type pullTarget struct {
	BackupType    string
	Checkpoint    string
	EndpointCAPEM string
	Volumes       []pullVolume
}

type mapPage struct {
	Extents    []mapExtent `json:"extents"`
	NextOffset *uint64     `json:"next_offset"`
}

type volumeManifest struct {
	VMDefinition  string         `json:"vm_definition,omitempty"`
	VMNamespace   string         `json:"vm_namespace,omitempty"`
	VMUID         string         `json:"vm_uid,omitempty"`
	Format        string         `json:"format"`
	BackupType    string         `json:"backup_type"`
	Checkpoint    string         `json:"checkpoint"`
	Volume        string         `json:"volume"`
	VirtualSize   uint64         `json:"virtual_size"`
	Encrypted     bool           `json:"encrypted"`
	PayloadKey    string         `json:"payload_key"`
	StoredExtents []storedExtent `json:"stored_extents"`
}

func (e *Executor) createTokenSecret(ctx context.Context, namespace, name string) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)
	secret := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]interface{}{
			"name": name, "namespace": namespace,
			"labels": map[string]interface{}{"app.kubernetes.io/managed-by": e.cfg.KubevirtPrefix()},
		},
		"stringData": map[string]interface{}{"token": token},
	}}
	if _, err := e.dynamic.Resource(coreV1Secret).Namespace(namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		return "", fmt.Errorf("create secret: %w", err)
	}
	return token, nil
}

func (e *Executor) runPullBackup(ctx context.Context, cancel context.CancelFunc, req *models.BackupRequest, progress *models.BackupProgress, s3Cfg *backup.S3Config) {
	defer cancel()
	defer e.resources.ReleaseBackupSlot()
	defer e.transactionMu.Unlock()

	if err := e.verifyVMIdentity(ctx, req); err != nil {
		e.fail(progress, req, err.Error())
		return
	}
	ns := req.VMNamespace
	trackerName := e.trackerName(ns + "/" + req.VMUID)
	backupName := e.cfg.KubevirtPrefix() + "-" + strings.ToLower(req.BackupID)
	secretName := backupName + "-token"

	e.setOp(progress, "checking backup tracker")
	hasCheckpoint, err := e.ensureBackupTracker(ctx, ns, trackerName, req.VMName, req.VMUID)
	if err != nil {
		e.fail(progress, req, fmt.Sprintf("incremental prerequisite: %v", err))
		return
	}
	if req.BackupType == models.BackupTypeIncremental && !hasCheckpoint {
		e.fail(progress, req, "incremental prerequisite: tracker has no completed checkpoint; request a full CBT seed first")
		return
	}
	tracker, err := e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace(ns).Get(ctx, trackerName, metav1.GetOptions{})
	if err != nil || tracker.GetUID() == "" {
		e.fail(progress, req, fmt.Sprintf("read tracker identity: %v", err))
		return
	}
	tx := &pullTransaction{ResourcePrefix: e.cfg.KubevirtPrefix(), BackupID: req.BackupID, VMName: req.VMName, VMUID: req.VMUID, Namespace: ns,
		Tracker: trackerName, TrackerUID: tracker.GetUID(), Endpoint: s3Cfg.Endpoint, UseSSL: s3Cfg.UseSSL,
		Bucket: s3Cfg.Bucket, Prefix: strings.Trim(s3Cfg.Prefix, "/") + "/" + req.BackupID + "/", Phase: "prepared"}
	if err := e.saveTransaction(tx); err != nil {
		e.fail(progress, req, fmt.Sprintf("persist pull transaction before publication: %v", err))
		return
	}
	committedFlag := false
	s3Location := tx.location()
	progress.CheckpointCommitted = &committedFlag
	progress.S3Location = &s3Location
	defer func() {
		e.finishTransaction(tx, s3Cfg, progress)
		e.reported[tx.BackupID] = true
		if tx.Phase == "cleanup_required" {
			e.recovered = false
		}
	}()
	fail := func(reason string) { tx.Error = reason }

	token, err := e.createTokenSecret(ctx, ns, secretName)
	if err != nil {
		fail(fmt.Sprintf("create pull token: %v", err))
		return
	}

	defer func() {
		// Failed transactions retain the token until native VMB cleanup finishes.
		// Compensation owns its deletion; do not mutate export inputs mid-abort.
		if tx.Phase != "committed" {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := e.dynamic.Resource(coreV1Secret).Namespace(ns).Delete(cleanupCtx, secretName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			slog.Warn("cleanup: failed to delete pull token", "name", secretName, "error", err)
		}
	}()

	e.setOp(progress, "creating incremental backup")
	if err := e.verifyVMIdentity(ctx, req); err != nil {
		fail(err.Error())
		return
	}
	created, err := e.createPullBackup(ctx, ns, backupName, trackerName, secretName, req.BackupType == models.BackupTypeFull)
	if err != nil {
		fail(fmt.Sprintf("create VirtualMachineBackup: %v", err))
		return
	}
	tx.BackupUID = created.GetUID()
	if err := e.saveTransaction(tx); err != nil {
		fail(fmt.Sprintf("persist VirtualMachineBackup identity: %v", err))
		return
	}

	e.setOp(progress, "waiting for pull endpoints")
	// CR creation is not admission. Keep progress at zero until the controller
	// publishes usable endpoints; Progressing=False may already be authoritative.
	target, err := e.waitForPullReady(ctx, ns, backupName)
	if err != nil {
		fail(fmt.Sprintf("pull endpoints unavailable: %v", err))
		return
	}
	expectedType := "Incremental"
	if req.BackupType == models.BackupTypeFull {
		expectedType = "Full"
	}
	if !strings.EqualFold(target.BackupType, expectedType) {
		fail(fmt.Sprintf("KubeVirt returned backup type %q for requested %q; refusing to misreport coverage", target.BackupType, req.BackupType))
		return
	}
	progress.ProgressPercent = 20
	tx.Checkpoint = target.Checkpoint

	var encKey []byte
	if req.EncryptionKey != nil && *req.EncryptionKey != "" {
		encKey, err = encryption.DeriveKey(*req.EncryptionKey, string(req.EncryptionType))
		if err != nil {
			fail(fmt.Sprintf("derive encryption key: %v", err))
			return
		}
	}

	client, err := newPullHTTPClient(target.EndpointCAPEM)
	if err != nil {
		fail(fmt.Sprintf("pull endpoint TLS: %v", err))
		return
	}

	var totalBytes int64
	for i, volume := range target.Volumes {
		e.setOp(progress, "reading changed-block map")
		extents, virtualSize, err := fetchExtentMap(ctx, client, volume.MapEndpoint, token)
		if err != nil {
			fail(fmt.Sprintf("[volume %s] read map: %v", volume.Name, err))
			return
		}

		objectBase := tx.Prefix + volume.Name
		payloadKey := objectBase + ".cbt"
		if len(encKey) > 0 {
			payloadKey += ".vnbu"
		}

		e.setOp(progress, "streaming changed blocks to S3")
		manifest, bytesRead, err := streamMappedExtents(ctx, client, volume, token, extents, virtualSize, target, s3Cfg, payloadKey, encKey, func(n int64) {
			progress.BytesTransferred = totalBytes + n
		})
		if err != nil {
			fail(fmt.Sprintf("[volume %s] stream changed blocks: %v", volume.Name, err))
			return
		}
		manifest.VMNamespace, manifest.VMUID = req.VMNamespace, req.VMUID
		if err := uploadJSON(ctx, s3Cfg, objectBase+".manifest.json", manifest); err != nil {
			fail(fmt.Sprintf("[volume %s] upload manifest: %v", volume.Name, err))
			return
		}

		totalBytes += bytesRead
		tx.Bytes = totalBytes
		progress.ProgressPercent = 20 + (75 * (i + 1) / len(target.Volumes))
	}

	e.setOp(progress, "committing backup checkpoint")
	if err := e.verifyVMIdentity(ctx, req); err != nil {
		fail(err.Error())
		return
	}
	tx.Phase = "published"
	if err := e.saveTransaction(tx); err != nil {
		fail(fmt.Sprintf("persist durable publication: %v", err))
		return
	}
	if err := e.finalizePullBackup(ctx, ns, backupName, trackerName, target.Checkpoint); err != nil {
		fail(fmt.Sprintf("commit backup checkpoint: %v", err))
		return
	}
	committed, err := e.checkpointCommitted(ctx, tx)
	if err != nil || !committed {
		fail(fmt.Sprintf("checkpoint identity confirmation failed: %v", err))
		return
	}
	tx.Phase = "committed"
	if err := e.saveTransaction(tx); err != nil {
		tx.Phase = "published"
		fail(fmt.Sprintf("persist checkpoint confirmation: %v", err))
	}
}

func kubevirtTrackerName(vmName string) string { return trackerName("vnbui", vmName) }
func trackerName(prefix, vmName string) string {
	return kvtypes.TrackerName(prefix, vmName)
}

func (e *Executor) ensureBackupTracker(ctx context.Context, ns, name, vmName, vmUID string) (bool, error) {
	tracker, err := e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		source, _, _ := unstructured.NestedString(tracker.Object, "spec", "source", "name")
		if tracker.GetAnnotations()["vnbui.insitu/vm-uid"] != vmUID || source != vmName || tracker.GetDeletionTimestamp() != nil {
			return false, fmt.Errorf("tracker does not belong to requested VM incarnation")
		}
		checkpointName, _, _ := unstructured.NestedString(tracker.Object, "status", "latestCheckpoint", "name")
		return checkpointName != "", nil
	}
	if !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("get VirtualMachineBackupTracker: %w", err)
	}
	tracker = &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "backup.kubevirt.io/v1alpha1",
		"kind":       "VirtualMachineBackupTracker",
		"metadata": map[string]interface{}{
			"name": name, "namespace": ns,
			"annotations": map[string]interface{}{"vnbui.insitu/vm-uid": vmUID},
			"labels":      map[string]interface{}{"app.kubernetes.io/managed-by": e.cfg.KubevirtPrefix()},
		},
		"spec": map[string]interface{}{"source": map[string]interface{}{
			"apiGroup": "kubevirt.io", "kind": "VirtualMachine", "name": vmName,
		}},
	}}
	_, err = e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace(ns).Create(ctx, tracker, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return false, fmt.Errorf("tracker appeared concurrently; retry after identity verification")
	}
	if err != nil {
		return false, fmt.Errorf("create VirtualMachineBackupTracker: %w", err)
	}
	return false, nil
}

func (e *Executor) createPullBackup(ctx context.Context, ns, name, trackerName, secretName string, forceFull bool) (*unstructured.Unstructured, error) {
	if err := e.cfg.ValidateNativeLifetime(); err != nil {
		return nil, err
	}
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "backup.kubevirt.io/v1alpha1",
		"kind":       "VirtualMachineBackup",
		"metadata": map[string]interface{}{
			"name": name, "namespace": ns,
			"labels": map[string]interface{}{"app.kubernetes.io/managed-by": e.cfg.KubevirtPrefix()},
		},
		"spec": map[string]interface{}{
			"source": map[string]interface{}{
				"apiGroup": "backup.kubevirt.io", "kind": "VirtualMachineBackupTracker", "name": trackerName,
			},
			"mode": "Pull", "pvcName": e.cfg.ScratchPVC(ns),
			"tokenSecretRef": secretName, "ttlDuration": (time.Duration(e.cfg.KubevirtNativeTTLSeconds) * time.Second).String(), "forceFullBackup": forceFull,
		},
	}}
	return e.dynamic.Resource(kvtypes.BackupResource).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
}

func (e *Executor) waitForPullReady(ctx context.Context, ns, name string) (pullTarget, error) {
	var target pullTarget
	var rejection error
	err := backup.PollUntil(ctx, 5*time.Second, 15*time.Minute, func() (bool, error) {
		obj, err := e.dynamic.Resource(kvtypes.BackupResource).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		conditions, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
		for _, raw := range conditions {
			condition, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			status, _, _ := unstructured.NestedString(condition, "status")
			conditionType, _, _ := unstructured.NestedString(condition, "type")
			reason, _, _ := unstructured.NestedString(condition, "reason")
			message, _, _ := unstructured.NestedString(condition, "message")
			if conditionType == "Progressing" && status == "False" && (reason != "" || message != "") {
				rejection = fmt.Errorf("KubeVirt backup rejected: %s: %s", reason, message)
				return true, nil
			}
		}

		volumes, found, _ := unstructured.NestedSlice(obj.Object, "status", "includedVolumes")
		caPEM, caFound, _ := unstructured.NestedString(obj.Object, "status", "endpointCert")
		checkpoint, checkpointFound, _ := unstructured.NestedString(obj.Object, "status", "checkpointName")
		if !found || len(volumes) == 0 || !caFound || caPEM == "" || !checkpointFound || checkpoint == "" {
			return false, nil
		}
		parsed := make([]pullVolume, 0, len(volumes))
		for _, raw := range volumes {
			volume, ok := raw.(map[string]interface{})
			if !ok {
				return false, fmt.Errorf("invalid includedVolumes entry")
			}
			name, _, _ := unstructured.NestedString(volume, "volumeName")
			dataEndpoint, _, _ := unstructured.NestedString(volume, "dataEndpoint")
			mapEndpoint, _, _ := unstructured.NestedString(volume, "mapEndpoint")
			if name == "" || dataEndpoint == "" || mapEndpoint == "" {
				return false, nil
			}
			parsed = append(parsed, pullVolume{Name: name, DataEndpoint: dataEndpoint, MapEndpoint: mapEndpoint})
		}
		backupType, _, _ := unstructured.NestedString(obj.Object, "status", "type")
		target = pullTarget{BackupType: backupType, Checkpoint: checkpoint, EndpointCAPEM: caPEM, Volumes: parsed}
		return true, nil
	})
	if rejection != nil {
		return target, rejection
	}
	return target, err
}

func (e *Executor) finalizePullBackup(ctx context.Context, ns, backupName, trackerName, checkpoint string) error {
	if err := e.dynamic.Resource(kvtypes.BackupResource).Namespace(ns).Delete(ctx, backupName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete VirtualMachineBackup: %w", err)
	}
	pollCtx, stop := context.WithCancel(ctx)
	defer stop()
	var terminal error
	err := backup.PollUntil(pollCtx, 2*time.Second, 2*time.Minute, func() (bool, error) {
		tracker, err := e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace(ns).Get(ctx, trackerName, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				terminal = fmt.Errorf("tracker disappeared before commit: %w", err)
				stop()
			}
			return false, err
		}
		latest, _, _ := unstructured.NestedString(tracker.Object, "status", "latestCheckpoint", "name")
		return latest == checkpoint, nil
	})
	if terminal != nil {
		return terminal
	}
	return err
}

func newPullHTTPClient(caPEM string) (*http.Client, error) {
	tlsCfg, err := exportTLSConfig(caPEM)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}, nil
}

func fetchExtentMap(ctx context.Context, client *http.Client, endpoint, token string) ([]mapExtent, uint64, error) {
	var extents []mapExtent
	var offset uint64
	for {
		u, err := url.Parse(endpoint)
		if err != nil {
			return nil, 0, fmt.Errorf("parse map endpoint: %w", err)
		}
		if u.Scheme != "https" || u.Host == "" {
			return nil, 0, fmt.Errorf("map endpoint must be an absolute HTTPS URL")
		}
		q := u.Query()
		q.Set("offset", strconv.FormatUint(offset, 10))
		q.Set("page_size", "512")
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set(exportTokenHeader, token)
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, fmt.Errorf("GET map endpoint: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, 0, fmt.Errorf("map endpoint returned HTTP %d", resp.StatusCode)
		}
		var page mapPage
		err = json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return nil, 0, fmt.Errorf("decode map page: %w", err)
		}
		extents = append(extents, page.Extents...)
		if page.NextOffset == nil {
			break
		}
		if *page.NextOffset <= offset {
			return nil, 0, fmt.Errorf("map next_offset did not advance (%d -> %d)", offset, *page.NextOffset)
		}
		offset = *page.NextOffset
	}
	var virtualSize uint64
	for _, extent := range extents {
		if extent.Length == 0 || extent.Offset > ^uint64(0)-extent.Length {
			return nil, 0, fmt.Errorf("invalid map extent offset=%d length=%d", extent.Offset, extent.Length)
		}
		if end := extent.Offset + extent.Length; end > virtualSize {
			virtualSize = end
		}
	}
	return extents, virtualSize, nil
}

func streamMappedExtents(ctx context.Context, client *http.Client, volume pullVolume, token string, extents []mapExtent, virtualSize uint64, target pullTarget, s3Cfg *backup.S3Config, payloadKey string, encryptionKey []byte, progress func(int64)) (volumeManifest, int64, error) {
	stored, err := storedExtents(extents, target.BackupType)
	if err != nil {
		return volumeManifest{}, 0, err
	}
	var payloadOffset uint64
	for _, extent := range stored {
		if extent.PayloadOffset != nil {
			payloadOffset += extent.Length
		}
	}
	manifest := volumeManifest{
		Format: "vnbui-kubevirt-cbt-v1", BackupType: target.BackupType, Checkpoint: target.Checkpoint,
		Volume: volume.Name, VirtualSize: virtualSize, Encrypted: len(encryptionKey) > 0,
		PayloadKey: payloadKey, StoredExtents: stored,
	}

	pr, pw := io.Pipe()
	go func() {
		var copied int64
		for _, extent := range stored {
			if extent.ZeroFill {
				continue
			}
			u, err := url.Parse(volume.DataEndpoint)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			if u.Scheme != "https" || u.Host == "" {
				pw.CloseWithError(fmt.Errorf("data endpoint must be an absolute HTTPS URL"))
				return
			}
			q := u.Query()
			q.Set("offset", strconv.FormatUint(extent.DiskOffset, 10))
			q.Set("length", strconv.FormatUint(extent.Length, 10))
			u.RawQuery = q.Encode()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			req.Header.Set(exportTokenHeader, token)
			started := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				slog.Error("KubeVirt pull extent GET failed",
					"volume", volume.Name,
					"offset", extent.DiskOffset,
					"requested_bytes", extent.Length,
					"received_bytes", 0,
					"elapsed", time.Since(started),
					"transport_error", err,
				)
				pw.CloseWithError(err)
				return
			}
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
				resp.Body.Close()
				slog.Error("KubeVirt pull extent GET rejected",
					"volume", volume.Name,
					"offset", extent.DiskOffset,
					"requested_bytes", extent.Length,
					"content_length", resp.ContentLength,
					"received_bytes", 0,
					"elapsed", time.Since(started),
					"http_status", resp.StatusCode,
				)
				pw.CloseWithError(fmt.Errorf("data endpoint returned HTTP %d", resp.StatusCode))
				return
			}
			n, copyErr := io.CopyN(pw, resp.Body, int64(extent.Length))
			resp.Body.Close()
			slog.Info("KubeVirt pull extent GET",
				"volume", volume.Name,
				"offset", extent.DiskOffset,
				"requested_bytes", extent.Length,
				"content_length", resp.ContentLength,
				"received_bytes", n,
				"elapsed", time.Since(started),
				"transport_error", copyErr,
			)
			copied += n
			if progress != nil {
				progress(copied)
			}
			if copyErr != nil {
				pw.CloseWithError(fmt.Errorf("read extent offset=%d length=%d: %w", extent.DiskOffset, extent.Length, copyErr))
				return
			}
		}
		pw.Close()
	}()

	var reader io.Reader = pr
	if len(encryptionKey) > 0 {
		encryptedReader, encryptedWriter := io.Pipe()
		go func() {
			// Keep plaintext reads coupled to the same 5 MiB bound as S3 parts.
			// The default 64 MiB encryption chunk would otherwise recreate the
			// export-source pause this multipart path is designed to prevent.
			err := encryption.EncryptStreamChunked(pr, encryptedWriter, encryptionKey, int(pullMultipartPartSize))
			encryptedWriter.CloseWithError(err)
		}()
		reader = encryptedReader
	}
	clientS3, err := newS3Core(s3Cfg)
	if err != nil {
		return manifest, 0, err
	}
	partSize, err := pullPartSize(payloadOffset)
	if err != nil {
		return manifest, 0, err
	}
	_, err = uploadPullStream(ctx, clientS3, s3Cfg.Bucket, payloadKey, reader, partSize, time.Now)
	if err != nil {
		_ = pr.CloseWithError(err)
		return manifest, 0, fmt.Errorf("S3 upload: %w", err)
	}
	return manifest, int64(payloadOffset), nil
}

func uploadJSON(ctx context.Context, cfg *backup.S3Config, key string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	client, err := newS3Client(cfg)
	if err != nil {
		return err
	}
	_, err = client.PutObject(ctx, cfg.Bucket, key, strings.NewReader(string(data)), int64(len(data)), minio.PutObjectOptions{ContentType: "application/json"})
	return err
}

func newS3Client(cfg *backup.S3Config) (*minio.Client, error) {
	return minio.New(cfg.Endpoint, &minio.Options{
		Creds: credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""), Secure: cfg.UseSSL, Region: cfg.Region,
	})
}

func newS3Core(cfg *backup.S3Config) (*minio.Core, error) {
	return minio.NewCore(cfg.Endpoint, &minio.Options{
		Creds: credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""), Secure: cfg.UseSSL, Region: cfg.Region,
	})
}
