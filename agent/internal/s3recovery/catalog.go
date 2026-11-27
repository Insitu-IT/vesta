package s3recovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/restoreinput"
)

const maxListed = 4096

var legacyKeyPattern = regexp.MustCompile(`^vnbui-owned/v1/[0-9a-f]{64}/[0-9a-f]{64}/(?:generations/[0-9a-f-]{36}\.json|chain\.json)$`)
var safeFilePrefix = regexp.MustCompile(`^[a-zA-Z0-9_.-]+(/[a-zA-Z0-9_.-]+)*$`)
var fileSet = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

type Item struct {
	Trust      string `json:"trust"`
	Status     string `json:"status"`
	BackupID   string `json:"backup_id,omitempty"`
	Name       string `json:"name,omitempty"`
	Time       string `json:"time,omitempty"`
	TimeSource string `json:"time_source,omitempty"`
	Provider   string `json:"provider,omitempty"`
	ObjectKey  string `json:"object_key"`
	VersionID  string `json:"version_id"`
	Latest     bool   `json:"latest"`
	Available  *bool  `json:"available,omitempty"`
}

// LegacyScope comes from independent local recovery records, never from a
// generation discovered in S3.
type LegacyScope struct {
	InstallationID string
	OrgID          string
}

type Query struct {
	BackupID      string
	GenerationKey string
	VersionID     string
	OrgID         string
	LegacyScope   *LegacyScope
}

func objectItem(o minio.ObjectInfo, trust string) Item {
	return Item{Trust: trust, Status: "complete", Time: o.LastModified.UTC().Format(time.RFC3339Nano),
		TimeSource: "s3-last-modified", ObjectKey: o.Key, VersionID: o.VersionID, Latest: o.IsLatest}
}

func readExact(ctx context.Context, b *restoreinput.Bucket, pin models.StorageObjectReceipt, limit int) ([]byte, error) {
	if pin.CiphertextBytes <= 0 || pin.CiphertextBytes > int64(limit) {
		return nil, errors.New("recovery metadata object outside permitted length")
	}
	body, err := b.Get(ctx, pin)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, pin.CiphertextBytes+1))
	if err != nil || int64(len(raw)) != pin.CiphertextBytes {
		return nil, errors.New("recovery metadata read did not match its pinned size")
	}
	return raw, nil
}

func scan(ctx context.Context, b *restoreinput.Bucket, prefix string, visit func(minio.ObjectInfo) error) error {
	return b.Versions(ctx, prefix, maxListed, visit)
}

func signedItem(bucket *restoreinput.Bucket, trust Trust, key string, raw []byte) (Item, point, error) {
	p, err := trust.verify(raw, key)
	if err != nil {
		return Item{}, point{}, fmt.Errorf("verify recovery point %q: %w", key, err)
	}
	g := p.Generation
	if !bucket.Matches(models.StorageTarget{Endpoint: g.Endpoint, Bucket: g.Bucket, Region: g.Region}) ||
		!restoreinput.ValidVersion(g.VersionID) {
		return Item{}, point{}, errors.New("signed recovery point does not reference the configured versioned bucket")
	}
	return Item{Trust: "signed", Status: "complete", BackupID: p.BackupID, Name: p.Name, Provider: p.Provider,
		Time: p.CompletedAt, TimeSource: "signed-completion", ObjectKey: key}, p, nil
}

func ListSigned(ctx context.Context, b *restoreinput.Bucket, trust Trust, options PageOptions) (CatalogPage, error) {
	var result CatalogPage
	if _, err := trust.key(); err != nil {
		return result, err
	}
	prefix := trust.prefix()
	seen := map[string]bool{}
	err := pageScanner(&result, options)(ctx, b, prefix, func(object minio.ObjectInfo) error {
		leaf := strings.TrimPrefix(object.Key, prefix)
		if !object.IsLatest || !strings.HasSuffix(leaf, ".json") || !ValidID(strings.TrimSuffix(leaf, ".json")) {
			return nil
		}
		if seen[object.Key] {
			return errors.New("ambiguous recovery point version listing")
		}
		seen[object.Key] = true
		if object.IsDeleteMarker {
			return nil
		}
		raw, err := readExact(ctx, b, restoreinput.ObjectPin(object), maxPoint)
		if err != nil {
			return fmt.Errorf("read recovery point: %w", err)
		}
		item, point, err := signedItem(b, trust, object.Key, raw)
		if err != nil {
			return err
		}
		item.VersionID, item.Latest = object.VersionID, object.IsLatest
		pin := point.Generation
		available, err := b.VersionAvailable(ctx, models.StorageObjectReceipt{
			Key: pin.Key, VersionID: &pin.VersionID, ETag: pin.ETag, CiphertextBytes: pin.Bytes,
		})
		switch {
		case err != nil:
			item.Status = "try-later"
		case available:
			item.Status, item.Available = "available", &available
		default:
			item.Status, item.Available = "unavailable", &available
		}
		result.Items = append(result.Items, item)
		return err
	})
	return result, err
}

func FindSigned(ctx context.Context, b *restoreinput.Bucket, trust Trust, q Query) (Item, Plan, error) {
	if _, err := trust.key(); err != nil {
		return Item{}, Plan{}, err
	}
	key := trust.prefix() + q.BackupID + ".json"
	var raw []byte
	var version string
	var err error
	if q.VersionID != "" {
		version = q.VersionID
		var object minio.ObjectInfo
		object, err = b.VersionInfo(ctx, key, version)
		if err == nil {
			raw, err = readExact(ctx, b, restoreinput.ObjectPin(object), maxPoint)
		}
	} else {
		var objects []minio.ObjectInfo
		objects, _, err = b.VersionPage(ctx, key, restoreinput.VersionMarker{}, 100)
		if err == nil {
			for _, object := range objects {
				if object.Key != key || !object.IsLatest {
					continue
				}
				if version != "" || object.IsDeleteMarker {
					return Item{}, Plan{}, errors.New("no unique current signed recovery point in the trusted scope")
				}
				version = object.VersionID
				raw, err = readExact(ctx, b, restoreinput.ObjectPin(object), maxPoint)
				if err != nil {
					break
				}
			}
		}
	}
	if err != nil {
		return Item{}, Plan{}, err
	}
	if version == "" {
		return Item{}, Plan{}, errors.New("no matching signed recovery point in the trusted scope")
	}
	selected, record, err := signedItem(b, trust, key, raw)
	if err != nil {
		return Item{}, Plan{}, err
	}
	selected.VersionID, selected.Latest = version, q.VersionID == ""
	pin := record.Generation
	raw, err = readExact(ctx, b, models.StorageObjectReceipt{
		Key: pin.Key, VersionID: &pin.VersionID, ETag: pin.ETag, CiphertextBytes: pin.Bytes,
	}, maxGeneration)
	if err != nil {
		return Item{}, Plan{}, err
	}
	if hash(raw) != pin.SHA256 {
		return Item{}, Plan{}, errors.New("generation bytes do not match the signed SHA-256")
	}
	g, scopes, plan, err := parseGeneration(raw, pin.Key, b)
	if err != nil {
		return Item{}, Plan{}, err
	}
	if g.InstallationID != record.InstallationID || g.OrgID != record.OrgID || g.BackupID != record.BackupID ||
		g.RootBackupID != record.RootBackupID || g.GenerationID != record.GenerationID ||
		scopes[len(scopes)-1].Provider != record.Provider {
		return Item{}, Plan{}, errors.New("generation identity differs from the signed recovery point")
	}
	return selected, plan, nil
}

// Discover signed history by backup ID independently of the installation
// and organization claimed by unsigned metadata. Invalid signed bytes and
// delete markers still prevent a downgrade.
func signedPointHistory(ctx context.Context, bucket *restoreinput.Bucket) (map[string]bool, error) {
	const prefix = "vesta-recovery/v1/"
	history := map[string]bool{}
	err := bucket.Versions(ctx, prefix, 65536, func(object minio.ObjectInfo) error {
		fields := strings.Split(strings.TrimPrefix(object.Key, prefix), "/")
		if len(fields) != 3 || !ValidID(fields[0]) || !ValidID(fields[1]) || !strings.HasSuffix(fields[2], ".json") {
			return nil
		}
		backup := strings.TrimSuffix(fields[2], ".json")
		if ValidID(backup) {
			history[backup] = true
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cannot establish absence of signed recovery point history: %w", err)
	}
	return history, nil
}

var errSignedHistory = errors.New("signed recovery point history exists; use signed recovery with independent --trust")
var errSignedHistoryPresent = errors.New("found exact signed point name")

func scopedSignedHistory(ctx context.Context, bucket *restoreinput.Bucket, scope LegacyScope, backup string) (bool, error) {
	if !ValidID(scope.InstallationID) || !ValidID(scope.OrgID) || !ValidID(backup) {
		return false, errors.New("invalid independent legacy recovery scope")
	}
	key := (Trust{InstallationID: scope.InstallationID, OrgID: scope.OrgID}).prefix() + backup + ".json"
	err := bucket.Versions(ctx, key, 4096, func(object minio.ObjectInfo) error {
		if object.Key == key {
			return errSignedHistoryPresent
		}
		return nil
	})
	if errors.Is(err, errSignedHistoryPresent) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot establish absence of signed recovery point history: %w", err)
	}
	return false, nil
}

// ConfirmUnsigned is the last admission check before a historical recovery
// becomes visible. A signed point may have appeared while the disks assembled.
func ConfirmUnsigned(ctx context.Context, bucket *restoreinput.Bucket, backup string, scope *LegacyScope) error {
	var present bool
	var err error
	if scope != nil {
		present, err = scopedSignedHistory(ctx, bucket, *scope, backup)
	} else {
		var history map[string]bool
		history, err = signedPointHistory(ctx, bucket)
		present = history[backup]
	}
	if err != nil {
		return err
	}
	if present {
		return errSignedHistory
	}
	return nil
}

func eachLegacy(ctx context.Context, bucket *restoreinput.Bucket, query Query, scanner objectScanner, visit func(Item, Plan) error) error {
	prefix := "vnbui-owned/v1/"
	if query.OrgID != "" {
		prefix += hash([]byte(query.OrgID)) + "/"
	}
	if query.GenerationKey != "" {
		if !legacyKeyPattern.MatchString(query.GenerationKey) || !strings.HasPrefix(query.GenerationKey, prefix) {
			return errors.New("invalid legacy generation object key or organization scope")
		}
		prefix = query.GenerationKey
	}
	const maxCatalogRead = 96 << 20
	var budget int64 = maxCatalogRead
	seen := map[string]bool{}
	var history map[string]bool
	var historyErr error
	historyLoaded := false
	return scanner(ctx, bucket, prefix, func(object minio.ObjectInfo) error {
		if !legacyKeyPattern.MatchString(object.Key) || (query.GenerationKey != "" && object.Key != query.GenerationKey) ||
			(query.VersionID == "" && !object.IsLatest) || (query.VersionID != "" && query.VersionID != object.VersionID) {
			return nil
		}
		if seen[object.Key] {
			return errors.New("ambiguous legacy generation version listing")
		}
		seen[object.Key] = true
		if object.IsDeleteMarker {
			return nil
		}
		item := objectItem(object, "unsigned-legacy")
		if strings.HasSuffix(object.Key, "/chain.json") {
			item.Status = "identity-only"
			return visit(item, Plan{})
		}
		if !restoreinput.ValidVersion(object.VersionID) {
			item.Status = "unversioned"
			return visit(item, Plan{})
		}
		if object.Size > budget {
			return errors.New("legacy discovery reached its metadata budget; select --org-id or --generation-key")
		}
		raw, err := readExact(ctx, bucket, restoreinput.ObjectPin(object), maxGeneration)
		if err != nil {
			return fmt.Errorf("read legacy generation %q: %w", object.Key, err)
		}
		budget -= int64(len(raw))
		g, scopes, plan, err := parseGeneration(raw, object.Key, bucket)
		switch {
		case errors.Is(err, errIncompleteLegacy):
			item.Status = "identity-only"
		case err != nil:
			if query.GenerationKey != "" {
				return err
			}
			item.Status = "invalid"
		default:
			if query.LegacyScope != nil && (g.InstallationID != query.LegacyScope.InstallationID || g.OrgID != query.LegacyScope.OrgID) {
				if query.GenerationKey != "" {
					return errors.New("legacy generation does not match the independently supplied source installation and organization")
				}
				return nil
			}
			if query.BackupID != "" && g.BackupID != query.BackupID {
				return nil
			}
			last := scopes[len(scopes)-1]
			item.BackupID, item.Name, item.Provider = g.BackupID, last.Name, last.Provider
			var present bool
			if query.LegacyScope != nil {
				present, err = scopedSignedHistory(ctx, bucket, *query.LegacyScope, g.BackupID)
				if err != nil {
					return err
				}
			} else {
				if !historyLoaded {
					history, historyErr = signedPointHistory(ctx, bucket)
					historyLoaded = true
				}
				if historyErr != nil {
					return historyErr
				}
				present = history[g.BackupID]
			}
			if present {
				item.Trust = "signed-recovery-requires-trust"
				item.Status = "signed-point-present"
				return visit(item, Plan{})
			}
		}
		return visit(item, plan)
	})
}

func ListLegacy(ctx context.Context, b *restoreinput.Bucket, q Query, options PageOptions) (CatalogPage, error) {
	var result CatalogPage
	err := eachLegacy(ctx, b, q, pageScanner(&result, options), func(item Item, _ Plan) error {
		result.Items = append(result.Items, item)
		result.Incomplete = result.Incomplete || item.Status == "invalid"
		return nil
	})
	return result, err
}

func FindLegacy(ctx context.Context, b *restoreinput.Bucket, q Query) (Item, Plan, error) {
	var selected Item
	var plan Plan
	scanner := scan
	if q.GenerationKey != "" && q.VersionID != "" {
		scanner = exactVersion(q.VersionID)
	}
	err := eachLegacy(ctx, b, q, scanner, func(item Item, p Plan) error {
		if item.Status == "signed-point-present" && item.BackupID == q.BackupID {
			return errSignedHistory
		}
		if q.GenerationKey != "" && item.Status != "complete" {
			return fmt.Errorf("selected legacy object cannot restore disks: %s", item.Status)
		}
		if item.Status != "complete" || item.BackupID != q.BackupID {
			return nil
		}
		if selected.BackupID != "" {
			return errors.New("multiple legacy generations match this backup; select --generation-key and --version-id")
		}
		selected, plan = item, p
		return nil
	})
	if err != nil {
		return Item{}, Plan{}, err
	}
	if selected.BackupID == "" {
		return Item{}, Plan{}, errors.New("no matching complete versioned legacy generation; old identity-only manifests cannot recover disks")
	}
	return selected, plan, nil
}

func fileObjects(ctx context.Context, bucket *restoreinput.Bucket, hostPrefix, set string, query Query, scanner objectScanner, visit func(Item, minio.ObjectInfo) error) error {
	if !safeFilePrefix.MatchString(hostPrefix) || !restoreinput.ValidObjectKey(hostPrefix) ||
		(set != "" && !fileSet.MatchString(set)) {
		return errors.New("invalid managed file host prefix or set name")
	}
	root := hostPrefix + "/managed-files/"
	prefix := root
	if set != "" {
		prefix += set + "/"
		if query.BackupID != "" {
			prefix += query.BackupID + "/archive.age"
		}
	}
	return scanner(ctx, bucket, prefix, func(object minio.ObjectInfo) error {
		parts := strings.Split(strings.TrimPrefix(object.Key, root), "/")
		if len(parts) != 3 || !fileSet.MatchString(parts[0]) || !ValidID(parts[1]) || parts[2] != "archive.age" ||
			object.IsDeleteMarker || !restoreinput.ValidVersion(object.VersionID) ||
			(set != "" && parts[0] != set) || (query.BackupID != "" && parts[1] != query.BackupID) ||
			(query.VersionID != "" && object.VersionID != query.VersionID) {
			return nil
		}
		item := objectItem(object, "s3-file-object")
		item.BackupID, item.Name, item.Provider = parts[1], parts[0], "files"
		item.Status = "archive-authentication-pending"
		return visit(item, object)
	})
}

func ListFiles(ctx context.Context, b *restoreinput.Bucket, prefix, set string, options PageOptions) (CatalogPage, error) {
	var result CatalogPage
	err := fileObjects(ctx, b, prefix, set, Query{}, pageScanner(&result, options), func(item Item, _ minio.ObjectInfo) error {
		result.Items = append(result.Items, item)
		return nil
	})
	return result, err
}

func FindFile(ctx context.Context, b *restoreinput.Bucket, prefix, set string, q Query) (Item, models.StorageObjectReceipt, error) {
	var selected Item
	var pin models.StorageObjectReceipt
	scanner := scan
	if set != "" && q.VersionID != "" {
		scanner = exactVersion(q.VersionID)
	}
	err := fileObjects(ctx, b, prefix, set, q, scanner, func(item Item, object minio.ObjectInfo) error {
		if selected.BackupID != "" {
			return errors.New("ambiguous archive; select its --set and exact --version-id")
		}
		selected, pin = item, restoreinput.ObjectPin(object)
		return nil
	})
	if err != nil {
		return Item{}, pin, err
	}
	if selected.BackupID == "" {
		return Item{}, pin, errors.New("named file archive version was not found")
	}
	return selected, pin, nil
}

func exactVersion(version string) objectScanner {
	return func(ctx context.Context, b *restoreinput.Bucket, key string, visit func(minio.ObjectInfo) error) error {
		object, err := b.VersionInfo(ctx, key, version)
		if err != nil {
			return err
		}
		return visit(object)
	}
}
