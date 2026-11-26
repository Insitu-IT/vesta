package storagerestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

const maxManifestBytes = 16 << 20

// These wire fields match backup/kubevirt's transactionInputs. In particular,
// zero extents have no payload_offset and full-backup holes are omitted.
type storedExtent struct {
	DiskOffset    uint64  `json:"disk_offset"`
	Length        uint64  `json:"length"`
	PayloadOffset *uint64 `json:"payload_offset,omitempty"`
	ZeroFill      bool    `json:"zero_fill,omitempty"`
}

type volumeManifest struct {
	VMNamespace   string         `json:"vm_namespace"`
	VMUID         string         `json:"vm_uid"`
	Format        string         `json:"format"`
	BackupType    string         `json:"backup_type"`
	Checkpoint    string         `json:"checkpoint"`
	Volume        string         `json:"volume"`
	VirtualSize   uint64         `json:"virtual_size"`
	Encrypted     *bool          `json:"encrypted"`
	PayloadKey    string         `json:"payload_key"`
	StoredExtents []storedExtent `json:"stored_extents"`
	VMDefinition  string         `json:"vm_definition,omitempty"`
}

func readManifest(ctx context.Context, member validatedMember, volume models.StorageVolume, pair objectPair, open ObjectOpener) (_ volumeManifest, err error) {
	var manifest volumeManifest
	if pair.manifest.PlaintextBytes > maxManifestBytes {
		return manifest, errors.New("manifest exceeds supported size")
	}
	body, close, err := openObject(ctx, member.Request.Plan.Target, pair.manifest, open)
	if err != nil {
		return manifest, err
	}
	defer func() { err = errors.Join(err, close()) }()
	data, err := io.ReadAll(body)
	if err != nil {
		return manifest, err
	}
	if err = body.verify(pair.manifest.CiphertextBytes, pair.manifest.CiphertextSHA256); err != nil {
		return manifest, err
	}
	if err = decodeManifest(data, &manifest); err != nil {
		return manifest, err
	}
	plan := member.Request.Plan
	if manifest.Format != "vnbui-kubevirt-cbt-v1" || manifest.BackupType != plan.BackupType ||
		manifest.VMNamespace != plan.Source.Namespace || manifest.VMUID != plan.Source.VMUID ||
		manifest.Volume != volume.Name || manifest.VirtualSize == 0 || manifest.VirtualSize > uint64(volume.CapacityBytes) ||
		manifest.Encrypted == nil || *manifest.Encrypted != (plan.Encryption.Format != "none") ||
		manifest.PayloadKey != pair.payload.Key || manifest.Checkpoint == "" || len(manifest.Checkpoint) > 256 ||
		strings.TrimSpace(manifest.Checkpoint) != manifest.Checkpoint || manifest.StoredExtents == nil ||
		len(manifest.StoredExtents) > storageupload.MaxExportRanges {
		return manifest, errors.New("manifest does not match transaction source, payload or format")
	}
	var end, position uint64
	for _, extent := range manifest.StoredExtents {
		if extent.Length == 0 || extent.DiskOffset < end || extent.DiskOffset > manifest.VirtualSize || extent.Length > manifest.VirtualSize-extent.DiskOffset {
			return manifest, errors.New("manifest has overlapping, unordered or out-of-bounds extents")
		}
		end = extent.DiskOffset + extent.Length
		if extent.ZeroFill {
			if plan.BackupType != "incremental" || extent.PayloadOffset != nil {
				return manifest, errors.New("invalid zero-fill extent")
			}
		} else {
			if extent.PayloadOffset == nil || *extent.PayloadOffset != position {
				return manifest, errors.New("payload offsets must be contiguous and ordered")
			}
			position += extent.Length // Disjoint ranges are bounded by virtual_size.
		}
	}
	if position != uint64(pair.payload.PlaintextBytes) {
		return manifest, errors.New("extent data length does not match payload receipt")
	}
	return manifest, nil
}

func decodeManifest(data []byte, dst *volumeManifest) error {
	if len(data) > maxManifestBytes || !utf8.Valid(data) {
		return errors.New("invalid manifest encoding or length")
	}
	// The producer uses omitted optional fields, so the exact-shape receipt
	// codec cannot parse this format. Reject duplicate keys before normal strict
	// decoding to avoid two readers assigning different meanings to one object.
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := uniqueJSON(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing manifest data")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return fmt.Errorf("decode extent manifest: %w", err)
	}
	return nil
}

func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 8 {
		return errors.New("manifest nesting exceeds supported format")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("null is not part of the extent manifest format")
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return nil
	}
	count := 0
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return errors.New("invalid or duplicate manifest field")
			}
			seen[name] = true
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
			count++
			if count > 16 {
				return errors.New("too many manifest fields")
			}
		}
		required := []string{}
		allowed := map[string]bool{}
		if depth == 0 {
			required = []string{"vm_namespace", "vm_uid", "format", "backup_type", "checkpoint", "volume", "virtual_size", "encrypted", "payload_key", "stored_extents"}
			allowed["vm_definition"] = true
		} else if depth == 2 {
			required = []string{"disk_offset", "length"}
			allowed["payload_offset"], allowed["zero_fill"] = true, true
		}
		for _, field := range required {
			allowed[field] = true
			if !seen[field] {
				return fmt.Errorf("manifest missing %s", field)
			}
		}
		for field := range seen {
			if !allowed[field] {
				return fmt.Errorf("unknown manifest field %s", field)
			}
		}
	case '[':
		for d.More() {
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
			count++
			if count > storageupload.MaxExportRanges {
				return errors.New("too many manifest extents")
			}
		}
	default:
		return errors.New("invalid manifest delimiter")
	}
	_, err = d.Token()
	return err
}
