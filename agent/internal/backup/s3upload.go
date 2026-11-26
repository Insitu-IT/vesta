package backup

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
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

// UploadToS3 uploads all files in outputPath to S3 using resumable multipart upload.
// If a previous upload was interrupted, it resumes from the last completed part.
// On failure, partial state is preserved for future resume (not cleaned up).
func UploadToS3(ctx context.Context, cfg S3Config, outputPath, backupID string, onProgress func(completedBytes, totalBytes int64)) (string, error) {
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

	// Collect files to upload
	err = filepath.WalkDir(outputPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		relPath, _ := filepath.Rel(outputPath, path)
		objectKey := s3Prefix + "/" + relPath

		info, _ := d.Info()
		var size int64
		if info != nil {
			size = info.Size()
		}

		if err := uploader.UploadFile(ctx, path, objectKey, size); err != nil {
			return fmt.Errorf("upload %s: %w", relPath, err)
		}

		slog.Info("uploaded to S3", "file", relPath, "key", objectKey)
		return nil
	})

	if err != nil {
		// Do NOT clean up — leave partial state for resume
		return "", err
	}

	// All files uploaded — finalize
	if err := uploader.Complete(); err != nil {
		slog.Warn("cleanup upload state failed", "error", err)
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
