// The bucket reader provides versioned, read-only bucket discovery.
package restoreinput

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/minio/minio-go/v7"
	"vnbui/agent/internal/files3"
	"vnbui/agent/internal/models"
)

type Bucket struct {
	target models.StorageTarget
	client *minio.Core
	scope  scopedTransport
	cfg    S3Configuration
}

func OpenBucket(configPath string, files bool) (*Bucket, func(), error) {
	cfg, err := readS3Configuration(configPath)
	if err != nil {
		return nil, nil, err
	}
	if files {
		cfg.Endpoint, cfg.Region, err = files3.Normalize(cfg.Endpoint, cfg.Region)
		if err != nil {
			return nil, nil, err
		}
	}
	client, scope, closeClient, err := newS3Client(cfg, files)
	if err != nil {
		return nil, nil, err
	}
	return &Bucket{models.StorageTarget{Endpoint: cfg.Endpoint, Bucket: cfg.Bucket, Region: cfg.Region}, client, scope, cfg}, closeClient, nil
}

func (b *Bucket) Matches(wanted models.StorageTarget) bool {
	return wanted.Endpoint == b.target.Endpoint && wanted.Bucket == b.target.Bucket && wanted.Region == b.target.Region
}

func ValidObjectKey(key string) bool {
	return key != "" && len(key) <= 1024 && utf8.ValidString(key) && !path.IsAbs(key) &&
		path.Clean(key) == key && key != "." && key != ".." && !strings.HasPrefix(key, "../") &&
		!strings.Contains(key, "\\") && strings.IndexFunc(key, unicode.IsControl) < 0
}

func ValidVersion(version string) bool {
	return version != "" && version != "null" && len(version) <= 1024 &&
		utf8.ValidString(version) && strings.IndexFunc(version, unicode.IsControl) < 0
}

func quotedETag(value string) (string, bool) {
	tag, err := strconv.Unquote(value)
	return tag, err == nil && tag != "" && len(tag) <= 1024 && strconv.Quote(tag) == value &&
		strings.IndexFunc(tag, unicode.IsControl) < 0
}

// Versions checks a bounded sequence of exact version pages, including delete
// markers. Exhausting the limit cannot be mistaken for complete discovery.
func (b *Bucket) Versions(ctx context.Context, prefix string, limit int, visit func(minio.ObjectInfo) error) error {
	var marker VersionMarker
	for limit > 0 {
		objects, next, err := b.VersionPage(ctx, prefix, marker, min(limit, 1000))
		if err != nil {
			return err
		}
		for _, object := range objects {
			if err := visit(object); err != nil {
				return err
			}
		}
		if next.Key == "" {
			return nil
		}
		limit -= max(1, len(objects))
		marker = next
	}
	return errors.New("S3 version listing exceeded its limit; use a cursor or select an exact object key")
}

// Get requires an exact immutable version even if the storage provider also
// accepts an ETag as a predicate. The caller still verifies content digests.
func (b *Bucket) Get(ctx context.Context, pin models.StorageObjectReceipt) (io.ReadCloser, error) {
	etag, ok := quotedETag(pin.ETag)
	if !ok || !ValidObjectKey(pin.Key) || pin.VersionID == nil || !ValidVersion(*pin.VersionID) || pin.CiphertextBytes < 0 {
		return nil, errors.New("S3 read requires a valid key, version, ETag and length")
	}
	opts := minio.GetObjectOptions{VersionID: *pin.VersionID}
	if err := opts.SetMatchETag(etag); err != nil {
		return nil, errors.New("invalid S3 object ETag")
	}
	body, info, _, err := b.client.GetObject(ctx, b.target.Bucket, pin.Key, opts)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("S3 could not read the exact object version; check s3:GetObjectVersion")
	}
	if info.ETag != etag || info.Size != pin.CiphertextBytes || info.VersionID != *pin.VersionID {
		_ = body.Close()
		return nil, errors.New("S3 returned a different object version, ETag or size")
	}
	return body, nil
}

func ObjectPin(object minio.ObjectInfo) models.StorageObjectReceipt {
	return models.StorageObjectReceipt{Key: object.Key, VersionID: &object.VersionID,
		ETag: strconv.Quote(object.ETag), CiphertextBytes: object.Size}
}

// Open is the stable opener for VM payload readers. Historical receipts may
// omit a version. An exact-key listing must identify one matching retained
// version before any bytes are read, while the reader checks receipt hashes.
func (b *Bucket) Open(ctx context.Context, target models.StorageTarget, pin models.StorageObjectReceipt) (io.ReadCloser, error) {
	if !b.Matches(target) {
		return nil, errors.New("restore data storage target differs from the private S3 configuration")
	}
	if pin.VersionID == nil {
		etag, ok := quotedETag(pin.ETag)
		if !ok || !ValidObjectKey(pin.Key) {
			return nil, errors.New("invalid historical receipt object identity")
		}
		if err := b.Versions(ctx, pin.Key, 256, func(object minio.ObjectInfo) error {
			if object.Key == pin.Key && !object.IsDeleteMarker && object.ETag == etag &&
				object.Size == pin.CiphertextBytes && ValidVersion(object.VersionID) {
				if pin.VersionID != nil {
					return errors.New("historical receipt corresponds to multiple object versions")
				}
				pin.VersionID = &object.VersionID
			}
			return nil
		}); err != nil {
			return nil, err
		}
		if pin.VersionID == nil {
			return nil, fmt.Errorf("no retained version matches a historical payload receipt")
		}
	}
	return b.Get(ctx, pin)
}
