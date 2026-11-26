//go:build kubevirt

package kubevirt

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/encryption"
)

// stallTimeout matches the libvirt executor's S3 stall detection.
const stallTimeout = 15 * time.Minute

// StreamResult holds the result of a stream-through operation.
type StreamResult struct {
	S3Location   string
	BytesRead    int64
	BytesWritten int64
}

// StreamToS3 pulls data from sourceURL and streams it to S3, optionally encrypting.
// Zero local storage — data flows: HTTP GET → encrypt → S3 PutObject.
//
// caPEM is the CA certificate published by the VMExport link this URL came from.
// It must be the certificate belonging to that same link: external and internal
// links can be signed by different issuers, so pairing one link's URL with the
// other's CA fails in a way that looks like a broken cluster CA rather than a
// mismatched pair.
func StreamToS3(ctx context.Context, sourceURL, bearerToken, caPEM string,
	s3Cfg *backup.S3Config, objectKey string,
	encryptionKey []byte, progressCb func(bytesRead int64),
) (*StreamResult, error) {

	// Verify the export endpoint before sending it a bearer token and streaming a
	// disk image through it. exportTLSConfig fails closed; see its comment for why
	// there is no escape hatch here.
	tlsCfg, err := exportTLSConfig(caPEM)
	if err != nil {
		return nil, fmt.Errorf("export endpoint TLS: %w", err)
	}
	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", sourceURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET export endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("export endpoint returned HTTP %d", resp.StatusCode)
	}

	// Wrap body with progress tracking + stall detection
	countingReader := encryption.NewCountingReader(resp.Body, stallTimeout, progressCb)

	// Set up the reader pipeline: source → [encrypt] → S3
	var uploadReader io.Reader = countingReader

	if len(encryptionKey) > 0 {
		pr, pw := io.Pipe()
		go func() {
			err := encryption.EncryptStream(countingReader, pw, encryptionKey)
			if err != nil {
				slog.Error("encrypt stream failed", "error", err)
			}
			pw.CloseWithError(err)
		}()
		uploadReader = pr
	}

	// S3 client
	s3Client, err := minio.New(s3Cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(s3Cfg.AccessKey, s3Cfg.SecretKey, ""),
		Secure: s3Cfg.UseSSL,
		Region: s3Cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("create S3 client: %w", err)
	}

	slog.Info("streaming backup to S3",
		"bucket", s3Cfg.Bucket,
		"key", objectKey,
		"encrypted", len(encryptionKey) > 0,
	)

	info, err := s3Client.PutObject(ctx, s3Cfg.Bucket, objectKey, uploadReader, -1,
		minio.PutObjectOptions{
			ContentType: "application/octet-stream",
			PartSize:    64 * 1024 * 1024,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("S3 upload: %w", err)
	}

	return &StreamResult{
		S3Location:   fmt.Sprintf("s3://%s/%s", s3Cfg.Bucket, objectKey),
		BytesRead:    countingReader.BytesRead.Load(),
		BytesWritten: info.Size,
	}, nil
}
