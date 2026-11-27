package backup

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3Config holds S3 connection configuration.
type S3Config struct {
	Endpoint    string
	Bucket      string
	Region      string
	AccessKey   string
	SecretKey   string
	Prefix      string
	UseSSL      bool
	DeleteLocal bool
}

// s3StallTimeout is how long we wait without any bytes uploaded before
// considering the upload stalled. Resets every time data flows.
const s3StallTimeout = 15 * time.Minute

// uploadMockStage uploads only the closed inventory from a successful mock job.
func uploadMockStage(ctx context.Context, cfg S3Config, stage mockBackupStage, backupID string, onProgress func(completedBytes, totalBytes int64)) (string, error) {
	if err := stage.recheck(); err != nil {
		return "", err
	}
	outputPath := stage.path
	stateDir := filepath.Join(filepath.Dir(outputPath), ".upload-state")
	s3Prefix := cfg.Prefix + "/" + backupID

	// Client factory — creates fresh client with latest credentials on each call
	newClient := func() (*minio.Core, error) {
		return minio.NewCore(cfg.Endpoint, &minio.Options{
			Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
			Secure: cfg.UseSSL,
			Region: cfg.Region,
		})
	}

	uploader, err := NewMultipartUploader(newClient, cfg.Bucket, stateDir, backupID, onProgress)
	if err != nil {
		return "", fmt.Errorf("create uploader: %w", err)
	}

	for _, file := range stage.files {
		path := filepath.Join(outputPath, file.name)
		info, err := os.Lstat(path)
		if err != nil || !sameMockFile(file.info, info) {
			return "", fmt.Errorf("mock staging file changed: %s", file.name)
		}
		objectKey := s3Prefix + "/" + filepath.ToSlash(file.name)
		if err := uploader.UploadFile(ctx, path, objectKey, file.info.Size()); err != nil {
			return "", fmt.Errorf("upload %s: %w", file.name, err)
		}
	}

	if err := uploader.Complete(); err != nil {
		return "", fmt.Errorf("cleanup mock upload state: %w", err)
	}

	return fmt.Sprintf("s3://%s/%s", cfg.Bucket, s3Prefix), nil
}

// activityReader wraps an io.Reader and records last read time for stall detection.
type activityReader struct {
	r            io.Reader
	lastActivity *atomic.Int64
}

func (ar *activityReader) Read(p []byte) (int, error) {
	n, err := ar.r.Read(p)
	if n > 0 {
		ar.lastActivity.Store(time.Now().UnixNano())
	}
	return n, err
}

// AbortUpload aborts any in-progress multipart upload and cleans up state.
func AbortUpload(cfg S3Config, outputPath, backupID string) error {
	stateDir := filepath.Join(filepath.Dir(outputPath), ".upload-state")

	newClient := func() (*minio.Core, error) {
		return minio.NewCore(cfg.Endpoint, &minio.Options{
			Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
			Secure: cfg.UseSSL,
			Region: cfg.Region,
		})
	}

	uploader, err := NewMultipartUploader(newClient, cfg.Bucket, stateDir, backupID, nil)
	if err != nil {
		return err
	}
	return uploader.Abort()
}
