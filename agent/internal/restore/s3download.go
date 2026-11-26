package restore

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3Config mirrors backup.S3Config for restore operations.
type S3Config struct {
	Endpoint  string
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	UseSSL    bool
}

// ChainMember represents a single backup in a chain to download.
type ChainMember struct {
	BackupID       string
	S3Prefix       string
	ChainPosition  int
	EncryptionKey  string
	EncryptionType string
}

// DownloadChain downloads all chain members from S3 and assembles a flat directory.
// Returns a map of backupID → list of filenames downloaded for that member.
func DownloadChain(ctx context.Context, s3Cfg S3Config, members []ChainMember, outputDir string) (map[string][]string, error) {
	client, err := minio.New(s3Cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(s3Cfg.AccessKey, s3Cfg.SecretKey, ""),
		Secure: s3Cfg.UseSSL,
		Region: s3Cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("create S3 client: %w", err)
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	memberFiles := make(map[string][]string)

	for _, member := range members {
		slog.Info("downloading chain member",
			"backup_id", member.BackupID,
			"prefix", member.S3Prefix,
			"position", member.ChainPosition,
		)

		// List objects under the S3 prefix
		objectCh := client.ListObjects(ctx, s3Cfg.Bucket, minio.ListObjectsOptions{
			Prefix:    member.S3Prefix,
			Recursive: true,
		})

		for object := range objectCh {
			if object.Err != nil {
				return nil, fmt.Errorf("list objects: %w", object.Err)
			}

			// Download to flat dir (basename only)
			filename := filepath.Base(object.Key)
			localPath := filepath.Join(outputDir, filename)

			// For chain restores, later vmconfig*.xml wins (latest config)
			if err := downloadFileWithRetry(ctx, client, s3Cfg.Bucket, object.Key, localPath, 3); err != nil {
				return nil, fmt.Errorf("download %s: %w", object.Key, err)
			}

			memberFiles[member.BackupID] = append(memberFiles[member.BackupID], filename)
			slog.Debug("downloaded", "key", object.Key, "local", localPath)
		}
	}

	return memberFiles, nil
}

func downloadFileWithRetry(ctx context.Context, client *minio.Client, bucket, objectKey, localPath string, maxRetries int) error {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			slog.Warn("S3 download retry",
				"attempt", attempt+1,
				"backoff", backoff,
				"key", filepath.Base(objectKey),
			)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}

		if err := client.FGetObject(ctx, bucket, objectKey, localPath, minio.GetObjectOptions{}); err != nil {
			lastErr = err
			continue
		}
		return nil
	}

	return fmt.Errorf("download failed after %d retries: %w", maxRetries, lastErr)
}
