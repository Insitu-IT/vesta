package s3recovery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/minio/minio-go/v7"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/restoreinput"
)

type PageOptions struct {
	Limit  int
	Cursor string
}

type CatalogIssue struct {
	ObjectKey string `json:"object_key"`
	VersionID string `json:"version_id"`
	Error     string `json:"error"`
}

type CatalogPage struct {
	Items      []Item         `json:"items"`
	NextCursor string         `json:"next_cursor,omitempty"`
	Incomplete bool           `json:"incomplete"`
	Issues     []CatalogIssue `json:"issues"`
}

type catalogCursor struct {
	Schema string                     `json:"schema"`
	Scope  string                     `json:"scope"`
	Marker restoreinput.VersionMarker `json:"marker"`
}

type objectScanner func(context.Context, *restoreinput.Bucket, string, func(minio.ObjectInfo) error) error

func pageScanner(result *CatalogPage, options PageOptions) objectScanner {
	result.Items = make([]Item, 0)
	result.Issues = make([]CatalogIssue, 0)
	return func(ctx context.Context, b *restoreinput.Bucket, prefix string, visit func(minio.ObjectInfo) error) error {
		scope := b.DiscoveryScope(prefix)
		var cursor catalogCursor
		if options.Cursor != "" {
			if len(options.Cursor) > 6144 {
				return errors.New("invalid S3 recovery cursor")
			}
			body, err := decode64(base64.RawURLEncoding, options.Cursor)
			if err != nil || models.DecodeStorageValue(body, &cursor, 4096) != nil ||
				cursor.Schema != "vesta-s3-cursor/1" || cursor.Scope != scope || cursor.Marker.Key == "" {
				return errors.New("S3 recovery cursor does not match the configured listing scope")
			}
		}
		objects, next, err := b.VersionPage(ctx, prefix, cursor.Marker, options.Limit)
		if err != nil {
			return err
		}
		if next.Key != "" {
			raw, err := json.Marshal(catalogCursor{Schema: "vesta-s3-cursor/1", Scope: scope, Marker: next})
			if err != nil {
				return err
			}
			result.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
		}
		for _, object := range objects {
			if err := visit(object); err != nil {
				result.Issues = append(result.Issues, CatalogIssue{ObjectKey: object.Key, VersionID: object.VersionID, Error: err.Error()})
			}
		}
		result.Incomplete = result.Incomplete || result.NextCursor != "" || len(result.Issues) != 0
		return nil
	}
}
