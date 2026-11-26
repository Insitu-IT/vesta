package backup

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"sync/atomic"
	"time"

	"github.com/minio/minio-go/v7"
)

const (
	minPartSize     = 5 * 1024 * 1024            // 5 MB (S3 minimum)
	defaultPartSize = 128 * 1024 * 1024           // 128 MB
	maxPartSize     = 5 * 1024 * 1024 * 1024      // 5 GB (S3 maximum)
	maxParts        = 10000                        // S3 limit
	partRetries     = 3                            // retries per individual part
)

// CalculatePartSize selects the part size based on file size.
// 128MB default, auto-scales for files that would exceed 10000 parts.
func CalculatePartSize(fileSize int64) int64 {
	partSize := int64(defaultPartSize)

	if fileSize/partSize >= maxParts {
		partSize = (fileSize / maxParts) + 1
		// Round up to nearest 64MB for alignment
		partSize = ((partSize + 67108863) / 67108864) * 67108864
	}

	if partSize < minPartSize {
		partSize = minPartSize
	}
	if partSize > maxPartSize {
		partSize = maxPartSize
	}
	return partSize
}

// ClientFactory creates a minio.Core client with the latest credentials.
type ClientFactory func() (*minio.Core, error)

// MultipartUploader manages resumable multipart uploads for a single backup.
type MultipartUploader struct {
	newClient  ClientFactory
	bucket     string
	stateDir   string
	backupID   string
	state      *MultipartUploadState
	onProgress func(completedBytes, totalBytes int64)
}

// NewMultipartUploader creates an uploader, loading existing state if available.
func NewMultipartUploader(newClient ClientFactory, bucket, stateDir, backupID string, onProgress func(int64, int64)) (*MultipartUploader, error) {
	state, err := LoadUploadState(stateDir, backupID)
	if err != nil {
		slog.Warn("corrupt upload state, starting fresh", "backup_id", backupID, "error", err)
		DeleteUploadState(stateDir, backupID)
		state = nil
	}

	if state != nil && state.Bucket != bucket {
		slog.Warn("S3 bucket changed since last upload, starting fresh",
			"old_bucket", state.Bucket, "new_bucket", bucket)
		state = nil
		DeleteUploadState(stateDir, backupID)
	}

	if state == nil {
		state = &MultipartUploadState{
			Version:  1,
			BackupID: backupID,
			Bucket:   bucket,
			Created:  time.Now().UTC(),
		}
	}

	return &MultipartUploader{
		newClient:  newClient,
		bucket:     bucket,
		stateDir:   stateDir,
		backupID:   backupID,
		state:      state,
		onProgress: onProgress,
	}, nil
}

// UploadFile uploads a single file using resumable multipart upload.
func (u *MultipartUploader) UploadFile(ctx context.Context, localPath, objectKey string, fileSize int64) error {
	client, err := u.newClient()
	if err != nil {
		return fmt.Errorf("create S3 client: %w", err)
	}

	partSize := CalculatePartSize(fileSize)

	// Find or create file state
	fileState := u.state.FindFile(objectKey)
	if fileState == nil {
		fs := FileUploadState{
			LocalPath: localPath,
			ObjectKey: objectKey,
			FileSize:  fileSize,
			PartSize:  partSize,
			Status:    "pending",
		}
		u.state.Files = append(u.state.Files, fs)
		fileState = &u.state.Files[len(u.state.Files)-1]
	}

	if fileState.Status == "completed" {
		slog.Info("file already uploaded, skipping", "key", objectKey)
		return nil
	}

	// Initialize multipart upload if needed
	if fileState.UploadID == "" {
		uploadID, err := client.NewMultipartUpload(ctx, u.bucket, objectKey, minio.PutObjectOptions{
			ContentType: "application/octet-stream",
		})
		if err != nil {
			return fmt.Errorf("new multipart upload: %w", err)
		}
		fileState.UploadID = uploadID
		fileState.Status = "in_progress"
		if err := SaveUploadState(u.stateDir, u.state); err != nil {
			slog.Warn("save upload state failed", "error", err)
		}
		slog.Info("started multipart upload",
			"key", objectKey,
			"upload_id", uploadID,
			"parts", (fileSize+partSize-1)/partSize,
			"part_size_mb", partSize/(1024*1024),
		)
	} else {
		// Validate existing parts against S3
		if err := u.validateParts(ctx, client, fileState); err != nil {
			slog.Warn("part validation failed, resetting", "key", objectKey, "error", err)
			fileState.CompletedParts = nil
			SaveUploadState(u.stateDir, u.state)
		}
	}

	// Open local file
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", localPath, err)
	}
	defer f.Close()

	// Calculate resume point
	nextPart := len(fileState.CompletedParts) + 1
	resumeOffset := int64(nextPart-1) * fileState.PartSize
	if resumeOffset > 0 {
		if _, err := f.Seek(resumeOffset, io.SeekStart); err != nil {
			return fmt.Errorf("seek to part %d: %w", nextPart, err)
		}
		slog.Info("resuming upload",
			"key", objectKey,
			"from_part", nextPart,
			"offset", resumeOffset,
			"completed_bytes", fileState.CompletedBytes(),
		)
	}

	totalParts := int((fileSize + fileState.PartSize - 1) / fileState.PartSize)

	// Upload remaining parts
	for partNum := nextPart; partNum <= totalParts; partNum++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Calculate this part's size
		offset := int64(partNum-1) * fileState.PartSize
		thisPartSize := fileState.PartSize
		if offset+thisPartSize > fileSize {
			thisPartSize = fileSize - offset
		}

		if err := u.uploadPart(ctx, client, fileState, f, partNum, thisPartSize); err != nil {
			return fmt.Errorf("part %d/%d: %w", partNum, totalParts, err)
		}

		// Report progress
		if u.onProgress != nil {
			u.onProgress(u.state.TotalCompletedBytes(), u.state.TotalBytes())
		}
	}

	// Complete multipart upload
	parts := make([]minio.CompletePart, len(fileState.CompletedParts))
	for i, p := range fileState.CompletedParts {
		parts[i] = minio.CompletePart{
			PartNumber: p.PartNumber,
			ETag:       p.ETag,
		}
	}

	if _, err := client.CompleteMultipartUpload(ctx, u.bucket, objectKey, fileState.UploadID, parts, minio.PutObjectOptions{}); err != nil {
		return fmt.Errorf("complete multipart: %w", err)
	}

	fileState.Status = "completed"
	SaveUploadState(u.stateDir, u.state)

	slog.Info("multipart upload completed", "key", objectKey, "parts", len(parts))
	return nil
}

// uploadPart uploads a single part with retry and stall detection.
func (u *MultipartUploader) uploadPart(ctx context.Context, client *minio.Core, fs *FileUploadState, f *os.File, partNum int, size int64) error {
	var lastErr error

	for attempt := 0; attempt < partRetries; attempt++ {
		if attempt > 0 {
			// Seek back to part start for retry
			offset := int64(partNum-1) * fs.PartSize
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				return fmt.Errorf("seek for retry: %w", err)
			}

			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			slog.Warn("retrying part upload",
				"part", partNum,
				"attempt", attempt+1,
				"backoff", backoff,
			)

			// Refresh client on retry (handles credential rotation)
			newClient, err := u.newClient()
			if err != nil {
				lastErr = fmt.Errorf("refresh client: %w", err)
				continue
			}
			client = newClient

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}

		// Stall detection context
		stallCtx, stallCancel := context.WithCancel(ctx)
		var lastActivity atomic.Int64
		lastActivity.Store(time.Now().UnixNano())

		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stallCtx.Done():
					return
				case <-ticker.C:
					last := time.Unix(0, lastActivity.Load())
					if time.Since(last) > s3StallTimeout {
						slog.Error("part upload stalled", "part", partNum)
						stallCancel()
						return
					}
				}
			}
		}()

		reader := &activityReader{r: io.LimitReader(f, size), lastActivity: &lastActivity}

		objPart, err := client.PutObjectPart(stallCtx, u.bucket, fs.ObjectKey, fs.UploadID, partNum, reader, size, minio.PutObjectPartOptions{})
		stallCancel()

		if err != nil {
			lastErr = err
			continue
		}

		// Part succeeded — persist state
		fs.CompletedParts = append(fs.CompletedParts, CompletedPart{
			PartNumber: partNum,
			ETag:       objPart.ETag,
			Size:       size,
		})
		if err := SaveUploadState(u.stateDir, u.state); err != nil {
			slog.Warn("save state after part failed", "part", partNum, "error", err)
		}
		return nil
	}

	return fmt.Errorf("after %d retries: %w", partRetries, lastErr)
}

// validateParts checks that locally recorded parts actually exist in S3.
func (u *MultipartUploader) validateParts(ctx context.Context, client *minio.Core, fs *FileUploadState) error {
	if len(fs.CompletedParts) == 0 {
		return nil
	}

	result, err := client.ListObjectParts(ctx, u.bucket, fs.ObjectKey, fs.UploadID, 0, maxParts)
	if err != nil {
		return fmt.Errorf("list parts: %w", err)
	}

	s3Parts := make(map[int]string) // partNumber → etag
	for _, p := range result.ObjectParts {
		s3Parts[p.PartNumber] = p.ETag
	}

	// Keep only parts confirmed by S3
	var confirmed []CompletedPart
	for _, p := range fs.CompletedParts {
		if etag, ok := s3Parts[p.PartNumber]; ok && etag == p.ETag {
			confirmed = append(confirmed, p)
		} else {
			slog.Warn("discarding unconfirmed part",
				"part", p.PartNumber,
				"local_etag", p.ETag,
				"s3_etag", s3Parts[p.PartNumber],
			)
		}
	}

	if len(confirmed) != len(fs.CompletedParts) {
		slog.Info("part validation adjusted",
			"before", len(fs.CompletedParts),
			"after", len(confirmed),
		)
	}
	fs.CompletedParts = confirmed
	return nil
}

// Complete finalizes all uploads and removes the state file.
func (u *MultipartUploader) Complete() error {
	return DeleteUploadState(u.stateDir, u.backupID)
}

// Abort aborts all in-progress multipart uploads and removes state.
func (u *MultipartUploader) Abort() error {
	client, err := u.newClient()
	if err != nil {
		return fmt.Errorf("create client for abort: %w", err)
	}

	for _, fs := range u.state.Files {
		if fs.UploadID != "" && fs.Status != "completed" {
			if err := client.AbortMultipartUpload(context.Background(), u.bucket, fs.ObjectKey, fs.UploadID); err != nil {
				slog.Warn("abort multipart failed", "key", fs.ObjectKey, "error", err)
			}
		}
	}

	return DeleteUploadState(u.stateDir, u.backupID)
}
