package filebackup

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/files3"
)

const archiveObject = "archive.age"

func newClient(cfg *backup.S3Config, caPath string) (*minio.Client, error) {
	transport, err := minio.DefaultTransport(true)
	if err != nil {
		return nil, err
	}
	if caPath != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		pem, err := os.ReadFile(caPath)
		if err != nil || !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("read managed file backup S3 trust bundle")
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	}
	return files3.NewClient("https://"+cfg.Endpoint, cfg.Region, cfg.Bucket,
		credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""), transport)
}

const (
	archiveProbeTimeout  = 20 * time.Second
	archiveUploadTimeout = 24 * time.Hour
	archiveUploadIdle    = time.Minute
)

var (
	errArchiveAbsent      = errors.New("S3 confirms there are no object versions or delete markers")
	errStageInvalid       = errors.New("staged encrypted archive does not match its journal")
	errVersioningDisabled = errors.New("archive bucket must have versioning enabled")
)

func (r *Runner) storeArchive(ctx context.Context, j *job) (string, error) {
	var version string
	var err error
	if j.PutPhase == putReady {
		// Establish the scoped listing grant before giving S3 any bytes. An
		// existing delete marker would otherwise allow conditional creation.
		version, err = r.listArchiveVersions(ctx, *j)
	} else {
		version, err = r.probeArchive(ctx, *j)
	}
	if version != "" {
		j.PutPhase = putPossible
	}
	if j.PutVersion != "" || !errors.Is(err, errArchiveAbsent) {
		return version, err
	}
	// Conditional create also fences a previous request that is still
	// completing server-side after the version listing.
	return r.putArchive(ctx, j)
}

func (r *Runner) putArchive(ctx context.Context, j *job) (string, error) {
	probe, cancelProbe := context.WithTimeout(ctx, archiveProbeTimeout)
	versioning, err := r.client.GetBucketVersioning(probe, r.bucket)
	cancelProbe()
	if err != nil {
		return "", fmt.Errorf("check archive bucket versioning: %w", err)
	}
	if versioning.Status != "Enabled" {
		return "", errVersioningDisabled
	}

	deadline := time.Now().Add(archiveUploadTimeout)
	if j.PutPhase == putReady {
		deadline = j.AcceptedAt.Add(archiveUploadTimeout)
	}
	upload, cancelUpload := context.WithDeadline(ctx, deadline)
	defer cancelUpload()
	file, err := os.Open(r.archivePath(j.BackupID))
	if err != nil {
		return "", fmt.Errorf("%w: %w", errStageInvalid, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != j.ArchiveSize {
		return "", errStageInvalid
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, contextReader{ctx: upload, reader: file}); err != nil {
		return "", err
	}
	if hex.EncodeToString(hash.Sum(nil)) != j.ArchiveSHA {
		return "", errStageInvalid
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	// Persist uncertainty before giving S3 any bytes. A crash at any later
	// point must reconcile this same encrypted archive before writing again.
	j.PutPhase = putPossible
	if err := r.save(*j); err != nil {
		return "", err
	}
	idle := time.AfterFunc(archiveUploadIdle, cancelUpload)
	opts := minio.PutObjectOptions{
		ContentType:  "application/octet-stream",
		UserMetadata: map[string]string{"Vesta-Archive-Sha256": j.ArchiveSHA},
		NumThreads:   1,
		Progress:     uploadProgress{idle},
	}
	opts.SetMatchETagExcept("*")
	put, putErr := r.client.PutObject(upload, r.bucket, r.objectKey(*j), file, j.ArchiveSize, opts)
	idle.Stop()
	if putErr == nil && validVersion(put.VersionID) {
		// Retain the exact version across outages and shutdown before HEAD.
		// Do not downgrade to probing the latest version of this object.
		j.PutVersion = put.VersionID
		if err := r.save(*j); err != nil {
			return "", err
		}
	}
	version, statErr := r.probeArchive(ctx, *j)
	if statErr != nil {
		return "", fmt.Errorf("confirm archive storage: %w", errors.Join(putErr, statErr))
	}
	return version, nil
}

type uploadProgress struct {
	idle *time.Timer
}

func (p uploadProgress) Read(b []byte) (int, error) {
	if len(b) > 0 {
		p.idle.Reset(archiveUploadIdle)
	}
	return len(b), nil
}

func (r *Runner) probeArchive(ctx context.Context, j job) (string, error) {
	probe, cancel := context.WithTimeout(ctx, archiveProbeTimeout)
	remote, err := r.client.StatObject(probe, r.bucket, r.objectKey(j), minio.StatObjectOptions{VersionID: j.PutVersion})
	cancel()
	if err == nil {
		return matchArchive(remote, j, j.PutVersion)
	}
	if j.PutVersion != "" {
		return "", err
	}
	response := minio.ToErrorResponse(err)
	if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusNotFound {
		// AWS can mask a missing key as 403 without a broad s3:ListBucket
		// grant. The exact-prefix list establishes absence and sees history.
		version, listErr := r.listArchiveVersions(ctx, j)
		if errors.Is(listErr, errArchiveAbsent) && (remote.IsDeleteMarker || remote.VersionID != "") {
			return "", errors.New("archive version history changed during reconciliation")
		}
		return version, listErr
	}
	return "", err
}

func (r *Runner) listArchiveVersions(ctx context.Context, j job) (string, error) {
	probe, cancel := context.WithTimeout(ctx, archiveProbeTimeout)
	defer cancel()
	key := r.objectKey(j)
	var version string
	var marker bool
	count := 0
	opts := minio.ListObjectsOptions{Prefix: key, WithVersions: true, Recursive: true, MaxKeys: 16}
	for object := range r.client.ListObjectsIter(probe, r.bucket, opts) {
		if object.Err != nil {
			return "", fmt.Errorf("list exact archive versions; check s3:ListBucketVersions scoped to the managed-files prefix: %w", object.Err)
		}
		count++
		if count > 128 {
			return "", errors.New("archive prefix history exceeds the reconciliation limit")
		}
		if object.Key != key {
			continue
		}
		if object.IsDeleteMarker {
			marker = true
			continue
		}
		if version != "" || !validVersion(object.VersionID) || object.Size != j.ArchiveSize {
			return "", errors.New("archive history does not identify a single matching retained version")
		}
		version = object.VersionID
	}
	if err := probe.Err(); err != nil {
		return "", err
	}
	if version == "" {
		if marker {
			return "", errors.New("archive key has a delete marker and no recoverable data version")
		}
		return "", errArchiveAbsent
	}
	remote, err := r.client.StatObject(probe, r.bucket, key, minio.StatObjectOptions{VersionID: version})
	if err != nil {
		return "", fmt.Errorf("read retained archive version metadata: %w", err)
	}
	return matchArchive(remote, j, version)
}

func matchArchive(remote minio.ObjectInfo, j job, version string) (string, error) {
	if remote.Size != j.ArchiveSize || remote.Metadata.Get("X-Amz-Meta-Vesta-Archive-Sha256") != j.ArchiveSHA {
		return "", errors.New("existing S3 object differs from the staged archive")
	}
	if !validVersion(remote.VersionID) || version != "" && remote.VersionID != version {
		return "", errors.New("archive does not have a confirmed S3 version ID")
	}
	return remote.VersionID, nil
}

func (r *Runner) verifyArchive(ctx context.Context, j job) (readErr error) {
	verify, cancel := context.WithTimeout(ctx, archiveUploadTimeout)
	defer cancel()
	// A slow archive can take time to read. An idle connection releases the
	// worker promptly so this custody check cannot starve the other jobs.
	idle := time.AfterFunc(archiveProbeTimeout, cancel)
	defer idle.Stop()
	client := minio.Core{Client: r.client}
	body, info, _, err := client.GetObject(verify, r.bucket, r.objectKey(j), minio.GetObjectOptions{VersionID: j.PutVersion})
	if err != nil {
		return fmt.Errorf("read exact stored archive version: %w", err)
	}
	defer func() { readErr = errors.Join(readErr, body.Close()) }()
	if info.Size != j.ArchiveSize || info.VersionID != j.PutVersion {
		return errors.New("S3 read returned a different archive version or length")
	}
	digest := sha256.New()
	count, err := io.Copy(digest, io.LimitReader(archiveReadProgress{body, idle}, j.ArchiveSize+1))
	if err != nil {
		return fmt.Errorf("read exact stored archive version: %w", err)
	}
	if count != j.ArchiveSize || hex.EncodeToString(digest.Sum(nil)) != j.ArchiveSHA {
		return errors.New("stored archive bytes differ from the staged ciphertext")
	}
	return nil
}

type archiveReadProgress struct {
	reader io.Reader
	idle   *time.Timer
}

func (r archiveReadProgress) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.idle.Reset(archiveProbeTimeout)
	}
	return n, err
}

func validVersion(version string) bool {
	return version != "" && version != "null" && len(version) <= 1024
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
