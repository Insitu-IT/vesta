package restoreinput

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/signer"
)

type VersionMarker struct {
	Key     string `json:"key"`
	Version string `json:"version"`
}

type versionEntry struct {
	Key          string
	Version      string `xml:"VersionId"`
	ETag         string
	IsLatest     bool
	Size         int64
	LastModified time.Time
}

// DiscoveryScope binds cursors to the exact local destination and prefix.
func (b *Bucket) DiscoveryScope(prefix string) string {
	sum := sha256.Sum256([]byte(b.target.Endpoint + "\x00" + b.target.Bucket + "\x00" + b.target.Region + "\x00" + prefix))
	return hex.EncodeToString(sum[:])
}

func validMarker(m VersionMarker, prefix string) bool {
	if m.Key == "" {
		return m.Version == ""
	}
	return len(m.Key) <= 1024 && utf8.ValidString(m.Key) && strings.HasPrefix(m.Key, prefix) &&
		(m.Version == "" || m.Version == "null" || ValidVersion(m.Version))
}

// VersionPage uses the S3 ListObjectVersions API markers. MinIO's version
// iterator automatically follows pages and cannot resume from a saved marker.
func (b *Bucket) VersionPage(ctx context.Context, prefix string, after VersionMarker, maxKeys int) ([]minio.ObjectInfo, VersionMarker, error) {
	invalid := errors.New("invalid S3 version listing scope or cursor")
	if !ValidObjectKey(strings.TrimSuffix(prefix, "/")) || maxKeys < 1 || maxKeys > 1000 || !validMarker(after, prefix) {
		return nil, VersionMarker{}, invalid
	}
	query := url.Values{"versions": {""}, "prefix": {prefix}, "max-keys": {strconv.Itoa(maxKeys)}, "encoding-type": {"url"}}
	if after.Key != "" {
		query.Set("key-marker", after.Key)
	}
	if after.Version != "" {
		query.Set("version-id-marker", after.Version)
	}
	address := url.URL{Scheme: "https", Host: b.scope.host, Path: "/" + b.target.Bucket + "/", RawQuery: query.Encode()}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address.String(), nil)
	if err != nil {
		return nil, VersionMarker{}, invalid
	}
	request.Header.Set("X-Amz-Content-Sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	signed := signer.SignV4(*request, b.cfg.AccessKey, b.cfg.SecretKey, b.cfg.SessionToken, b.scope.region)
	response, err := b.scope.RoundTrip(signed)
	if err != nil {
		if ctx.Err() != nil {
			return nil, VersionMarker{}, ctx.Err()
		}
		return nil, VersionMarker{}, errors.New("S3 version listing connection failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, VersionMarker{}, errors.New("S3 version listing failed; check s3:ListBucketVersions for the selected prefix")
	}
	var result struct {
		XMLName             xml.Name `xml:"ListVersionsResult"`
		Name                string
		Prefix              string
		EncodingType        string
		IsTruncated         bool
		NextKeyMarker       string
		NextVersionIdMarker string
		Versions            []versionEntry `xml:"Version"`
		DeleteMarkers       []versionEntry `xml:"DeleteMarker"`
	}
	malformed := errors.New("malformed S3 version response")
	if err := xml.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, VersionMarker{}, malformed
	}
	unescape := func(key string) (string, error) {
		if result.EncodingType == "url" {
			return url.PathUnescape(key)
		}
		return key, nil
	}
	responsePrefix, err := unescape(result.Prefix)
	if err != nil || (responsePrefix != "" && responsePrefix != prefix) || result.Name != b.target.Bucket ||
		(result.EncodingType != "" && result.EncodingType != "url") || len(result.Versions)+len(result.DeleteMarkers) > maxKeys {
		return nil, VersionMarker{}, malformed
	}
	objects := make([]minio.ObjectInfo, 0, len(result.Versions)+len(result.DeleteMarkers))
	for group, rows := range [][]versionEntry{result.Versions, result.DeleteMarkers} {
		for _, row := range rows {
			key, err := unescape(row.Key)
			if err != nil || len(key) > 1024 || !utf8.ValidString(key) || !strings.HasPrefix(key, prefix) {
				return nil, VersionMarker{}, malformed
			}
			objects = append(objects, minio.ObjectInfo{Key: key, VersionID: row.Version, IsLatest: row.IsLatest,
				Size: row.Size, ETag: strings.Trim(row.ETag, "\""), LastModified: row.LastModified, IsDeleteMarker: group == 1})
		}
	}
	var next VersionMarker
	if result.IsTruncated {
		next.Key, err = unescape(result.NextKeyMarker)
		next.Version = result.NextVersionIdMarker
		if err != nil || next.Key == "" || !validMarker(next, prefix) || next == after || next.Key < after.Key {
			return nil, VersionMarker{}, malformed
		}
	}
	return objects, next, nil
}

// VersionInfo resolves an explicit immutable version without older versions
// delaying direct recovery. Consumers still read with a matching ETag and
// validate the entire archive or signed control record.
func (b *Bucket) VersionInfo(ctx context.Context, key, version string) (minio.ObjectInfo, error) {
	if !ValidObjectKey(key) || !ValidVersion(version) {
		return minio.ObjectInfo{}, errors.New("invalid exact S3 recovery record selection")
	}
	info, err := b.client.StatObject(ctx, b.target.Bucket, key, minio.StatObjectOptions{VersionID: version})
	if err != nil || info.VersionID != version || info.Size <= 0 || info.ETag == "" {
		if ctx.Err() != nil {
			return minio.ObjectInfo{}, ctx.Err()
		}
		return minio.ObjectInfo{}, errors.New("S3 could not inspect the exact recovery record version")
	}
	info.Key = key
	return info, nil
}
