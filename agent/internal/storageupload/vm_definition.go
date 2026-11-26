package storageupload

import (
	"bytes"
	"encoding/base64"

	"vnbui/agent/internal/encryption"
	"vnbui/agent/internal/models"
)

const MaxVMDefinitionBytes = 1024 * 1024

func validVMDefinition(n *NativeState, r *models.StorageTransactionRequest) bool {
	if n.VMDefinition == "" {
		return n.EncodedVMDefinition == ""
	}
	doc, err := models.DecodeStorageControlJSON([]byte(n.VMDefinition))
	if err != nil || len(doc) != 4 || doc["apiVersion"] != "kubevirt.io/v1" || doc["kind"] != "VirtualMachine" {
		return false
	}
	meta, ok := doc["metadata"].(map[string]any)
	spec, specOK := doc["spec"].(map[string]any)
	version, versionOK := meta["resourceVersion"].(string)
	if !ok || len(meta) != 4 || !specOK || len(spec) == 0 || !versionOK || version == "" ||
		meta["namespace"] != r.Plan.Source.Namespace || meta["name"] != r.Plan.VMName || meta["uid"] != r.Plan.Source.VMUID {
		return false
	}
	if n.EncodedVMDefinition == "" {
		return true
	}
	if len(n.EncodedVMDefinition) > base64.StdEncoding.EncodedLen(MaxVMDefinitionBytes+37) {
		return false
	}
	data, err := base64.StdEncoding.Strict().DecodeString(n.EncodedVMDefinition)
	if err != nil {
		return false
	}
	if r.Plan.Encryption.Format == "none" {
		return bytes.Equal(data, []byte(n.VMDefinition))
	}
	return len(data) == len(n.VMDefinition)+37 && bytes.HasPrefix(data, []byte{'V', 'N', 'B', 'U', 1})
}

// SealVMDefinition freezes the manifest representation before any S3 object is
// written. Random encryption framing is generated once, never recreated on
// retry. The private journal holds the captured VM definition, never the DEK.
func (j *Journal) SealVMDefinition(key []byte) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	n := j.state.Native
	if n == nil || n.VMDefinition == "" || j.state.Phase != "uploading" || !validVMDefinition(n, &j.state.Request) {
		return ErrHeld
	}
	encrypted := j.state.Request.Plan.Encryption.Format != "none"
	if (encrypted && len(key) != 32) || (!encrypted && len(key) != 0) {
		return ErrHeld
	}
	if n.EncodedVMDefinition != "" {
		return nil
	}
	for _, o := range j.state.Objects {
		if o.Phase != "planned" {
			return ErrHeld
		}
	}
	data := []byte(n.VMDefinition)
	if encrypted {
		var output bytes.Buffer
		if encryption.EncryptStreamChunked(bytes.NewReader(data), &output, key, 5242880) != nil {
			return ErrHeld
		}
		data = output.Bytes()
	}
	n.EncodedVMDefinition = base64.StdEncoding.EncodeToString(data)
	return j.save()
}
