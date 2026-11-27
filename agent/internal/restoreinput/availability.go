package restoreinput

import (
	"context"
	"errors"
	"net/http"

	"github.com/minio/minio-go/v7"
	"vnbui/agent/internal/models"
)

// VersionAvailable checks the precise generation reference of a signed record.
// A provider, authorization or transport error does not establish absence.
func (b *Bucket) VersionAvailable(ctx context.Context, pin models.StorageObjectReceipt) (bool, error) {
	etag, ok := quotedETag(pin.ETag)
	if !ok || !ValidObjectKey(pin.Key) || pin.VersionID == nil ||
		!ValidVersion(*pin.VersionID) || pin.CiphertextBytes < 0 {
		return false, errors.New("S3 availability requires an exact object identity")
	}
	opts := minio.StatObjectOptions{VersionID: *pin.VersionID}
	if err := opts.SetMatchETag(etag); err != nil {
		return false, errors.New("invalid S3 object ETag")
	}
	info, err := b.client.StatObject(ctx, b.target.Bucket, pin.Key, opts)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		response := minio.ToErrorResponse(err)
		if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusPreconditionFailed ||
			response.Code == "NoSuchKey" || response.Code == "NoSuchVersion" || response.Code == "PreconditionFailed" {
			return false, nil
		}
		return false, errors.New("S3 could not inspect the exact recovery generation version")
	}
	return info.ETag == etag && info.VersionID == *pin.VersionID && info.Size == pin.CiphertextBytes, nil
}
