//go:build kubevirt

package kubevirt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/minio/minio-go/v7"
)

const pullMultipartPartSize int64 = 5 * 1024 * 1024

const (
	pullMultipartMaxParts = 10000
	pullMultipartMaxSize  = 5 * 1024 * 1024 * 1024
)

type multipartObjectClient interface {
	PutObject(context.Context, string, string, io.Reader, int64, string, string, minio.PutObjectOptions) (minio.UploadInfo, error)
	NewMultipartUpload(context.Context, string, string, minio.PutObjectOptions) (string, error)
	PutObjectPart(context.Context, string, string, string, int, io.Reader, int64, minio.PutObjectPartOptions) (minio.ObjectPart, error)
	CompleteMultipartUpload(context.Context, string, string, string, []minio.CompletePart, minio.PutObjectOptions) (minio.UploadInfo, error)
	AbortMultipartUpload(context.Context, string, string, string) error
}

// uploadPullStream keeps export-endpoint read pauses bounded to one S3 part.
// The explicit multipart implementation also exposes part timing and guarantees
// that an error aborts the upload rather than leaving an orphan multipart upload.
func uploadPullStream(ctx context.Context, client multipartObjectClient, bucket, key string, reader io.Reader, partSize int64, now func() time.Time) (written int64, err error) {
	if partSize < pullMultipartPartSize {
		return 0, fmt.Errorf("multipart part size %d is below the S3 minimum %d", partSize, pullMultipartPartSize)
	}
	if now == nil {
		now = time.Now
	}

	buf := make([]byte, partSize)
	var previousReadFinished time.Time
	readPart := func(partNumber int) (int, error) {
		started := now()
		var sourcePause time.Duration
		if !previousReadFinished.IsZero() {
			sourcePause = started.Sub(previousReadFinished)
		}
		n, readErr := io.ReadFull(reader, buf)
		finished := now()
		slog.Info("KubeVirt pull source part read",
			"part", partNumber,
			"bytes", n,
			"source_pause", sourcePause,
			"elapsed", finished.Sub(started),
			"error", readErr,
		)
		previousReadFinished = finished
		return n, readErr
	}

	n, readErr := readPart(1)
	if n == 0 && errors.Is(readErr, io.EOF) {
		started := now()
		info, putErr := client.PutObject(ctx, bucket, key, bytes.NewReader(nil), 0, "", "", minio.PutObjectOptions{ContentType: "application/octet-stream"})
		slog.Info("KubeVirt pull empty object upload", "elapsed", now().Sub(started), "error", putErr)
		return info.Size, putErr
	}
	if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		return 0, fmt.Errorf("read source part 1: %w", readErr)
	}

	uploadID, err := client.NewMultipartUpload(ctx, bucket, key, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return 0, fmt.Errorf("start multipart upload: %w", err)
	}
	completed := false
	defer func() {
		if completed {
			return
		}
		abortCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if abortErr := client.AbortMultipartUpload(abortCtx, bucket, key, uploadID); abortErr != nil {
			slog.Error("failed to abort KubeVirt pull multipart upload", "upload_id", uploadID, "error", abortErr)
			if err == nil {
				err = fmt.Errorf("abort multipart upload: %w", abortErr)
			} else {
				err = errors.Join(err, fmt.Errorf("abort multipart upload: %w", abortErr))
			}
		} else {
			slog.Info("aborted KubeVirt pull multipart upload", "upload_id", uploadID)
		}
	}()

	parts := make([]minio.CompletePart, 0, 8)
	for partNumber := 1; ; partNumber++ {
		started := now()
		part, uploadErr := client.PutObjectPart(ctx, bucket, key, uploadID, partNumber, bytes.NewReader(buf[:n]), int64(n), minio.PutObjectPartOptions{})
		slog.Info("KubeVirt pull S3 part upload",
			"part", partNumber,
			"bytes", n,
			"elapsed", now().Sub(started),
			"error", uploadErr,
		)
		if uploadErr != nil {
			return written, fmt.Errorf("upload part %d: %w", partNumber, uploadErr)
		}
		parts = append(parts, minio.CompletePart{PartNumber: partNumber, ETag: part.ETag})
		written += int64(n)

		if errors.Is(readErr, io.ErrUnexpectedEOF) {
			break
		}
		n, readErr = readPart(partNumber + 1)
		if n == 0 && errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return written, fmt.Errorf("read source part %d: %w", partNumber+1, readErr)
		}
	}

	started := now()
	info, err := client.CompleteMultipartUpload(ctx, bucket, key, uploadID, parts, minio.PutObjectOptions{})
	slog.Info("KubeVirt pull multipart completion", "parts", len(parts), "bytes", written, "elapsed", now().Sub(started), "error", err)
	if err != nil {
		return written, fmt.Errorf("complete multipart upload: %w", err)
	}
	completed = true
	return info.Size, nil
}

// pullPartSize keeps the part count within S3's limit while using the 5 MiB
// minimum for ordinary backups. Reserving one part leaves room for streaming
// encryption framing without needing to buffer the whole payload to size it.
func pullPartSize(payloadBytes uint64) (int64, error) {
	partSize := uint64(pullMultipartPartSize)
	if payloadBytes > partSize*uint64(pullMultipartMaxParts-1) {
		partSize = (payloadBytes + uint64(pullMultipartMaxParts-2)) / uint64(pullMultipartMaxParts-1)
		const mebibyte = uint64(1024 * 1024)
		partSize = ((partSize + mebibyte - 1) / mebibyte) * mebibyte
	}
	if partSize > uint64(pullMultipartMaxSize) {
		return 0, fmt.Errorf("payload %d requires multipart parts larger than the S3 maximum", payloadBytes)
	}
	return int64(partSize), nil
}
