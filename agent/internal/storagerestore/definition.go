package storagerestore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

// ReadVMDefinition reads the selected restore point's receipt-bound capture.
// A definition is not inferred from today's VM or from the first chain member.
// The complete captured spec may contain cloud-init data; encrypted backups
// carry it as authenticated VNBU ciphertext, not plaintext manifest metadata.
func ReadVMDefinition(ctx context.Context, members []Member, open ObjectOpener, keys KeyResolver) (map[string]interface{}, error) {
	chain, err := validateChain(members)
	if err != nil {
		return nil, err
	}
	member := chain[len(chain)-1]
	encoded := ""
	for _, volume := range member.Request.Plan.Source.Volumes {
		manifest, err := readManifest(ctx, member, volume, member.objects[volume.PVCUID], open)
		if err != nil {
			return nil, err
		}
		if manifest.VMDefinition == "" || (encoded != "" && manifest.VMDefinition != encoded) {
			return nil, errors.New("selected backup lacks a consistent captured VM definition")
		}
		encoded = manifest.VMDefinition
	}
	if len(encoded) > 4<<20 {
		return nil, errors.New("captured VM definition exceeds size limit")
	}
	return decodeVMDefinition(ctx, member, encoded, keys)
}

// decodeVMDefinition is shared by restore inspection and read-only scrub. Its
// encoded input must come from an already receipt-verified volume manifest.
func decodeVMDefinition(ctx context.Context, member validatedMember, encoded string, keys KeyResolver) (map[string]interface{}, error) {
	if encoded == "" || len(encoded) > 4<<20 {
		return nil, errors.New("captured VM definition missing or exceeds size limit")
	}
	body, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, errors.New("invalid captured VM definition encoding")
	}
	var reader io.Reader = bytes.NewReader(body)
	if member.Request.Plan.Encryption.Format != "none" {
		if keys == nil {
			return nil, errors.New("captured VM definition requires this member's DEK")
		}
		key, err := keys(ctx, member.Member)
		if err != nil {
			return nil, errors.New("captured VM key unavailable")
		}
		defer clear(key)
		reader, err = decryptReader(reader, key)
		if err != nil {
			return nil, err
		}
	}
	plain, err := io.ReadAll(io.LimitReader(reader, (2<<20)+1))
	if err != nil || len(plain) > 2<<20 {
		return nil, errors.New("captured VM definition authentication or length failed")
	}
	var result map[string]interface{}
	if err := json.Unmarshal(plain, &result); err != nil {
		return nil, errors.New("invalid captured VM definition")
	}
	metadata, _ := result["metadata"].(map[string]interface{})
	spec, _ := result["spec"].(map[string]interface{})
	source := member.Request.Plan.Source
	if len(result) != 4 || result["apiVersion"] != "kubevirt.io/v1" || result["kind"] != "VirtualMachine" || spec == nil ||
		metadata["namespace"] != source.Namespace || metadata["name"] != member.Request.Plan.VMName || metadata["uid"] != source.VMUID || metadata["resourceVersion"] == nil {
		return nil, errors.New("captured VM identity differs from accepted source")
	}
	return result, ctx.Err()
}
