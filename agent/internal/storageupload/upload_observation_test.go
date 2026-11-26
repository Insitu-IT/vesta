package storageupload

import (
	"bytes"
	"testing"

	"vnbui/agent/internal/encryption"
	"vnbui/agent/internal/models"
)

func TestPayloadObservationCountsSavedPartsAndActualEncryptedExtentBytes(t *testing.T) {
	const size = 5<<20 + 17
	s := State{Maps: []ExportMap{{Ranges: []ExportRange{
		{Length: size}, {Length: 1 << 30, ZeroFill: true},
	}}}, Objects: []ObjectState{
		{Artifact: models.StorageArtifact{Role: "volume_payload"}, Parts: []Part{{Bytes: 123}}, PendingPart: &Part{Bytes: 456}},
		{Artifact: models.StorageArtifact{Role: "volume_manifest"}, Parts: []Part{{Bytes: 789}}},
	}}
	s.Request.Plan.Encryption.Format = "vnbu1-aes256gcm-chunk5242880"
	var wire bytes.Buffer
	if err := encryption.EncryptStreamChunked(bytes.NewReader(make([]byte, size)), &wire, make([]byte, 32), 5242880); err != nil {
		t.Fatal(err)
	}
	p := payloadProgress(&s)
	if p.BytesTransferred != 123 || p.TotalBytes != int64(wire.Len()) {
		t.Fatal("pending/metadata/zero ranges or framing miscounted", p, wire.Len())
	}
}
