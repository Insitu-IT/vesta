//go:build linux

package backup

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

//go:embed native_write_fence.py
var nativeFenceHelper string

const nativeFenceInspectEntry = `
if __name__ == "__main__":
    envelope = json.loads(sys.stdin.buffer.read(MAX_JSON + 1))
    require(set(envelope) == {"action", "request"} and envelope["action"] == "inspect-fence-receipt", "read-only action required")
    value = envelope["request"]
    require(set(value) == {"receipt_root", "producer"}, "invalid inspection request")
    print(canonical({"proof": read_fence_receipt(value["receipt_root"], value["producer"])}).decode())
`

type nativeFencedArtifact struct {
	Target       string `json:"target"`
	Device       uint64 `json:"device"`
	Inode        uint64 `json:"inode"`
	Size         int64  `json:"size"`
	VeritySHA256 string `json:"verity_sha256"`
}

type nativeFencedFailure struct {
	Schema              string                 `json:"schema"`
	RequestSHA256       string                 `json:"request_sha256"`
	TargetBindingSHA256 string                 `json:"target_binding_sha256"`
	Artifacts           []nativeFencedArtifact `json:"artifacts"`
	Directory           []uint64               `json:"directory"`
	DataDirectory       []uint64               `json:"data_directory"`
}

func (r *nativeRunner) readFencedFailure(ctx context.Context, work *nativeWork) (*nativeFencedFailure, error) {
	if r.staging == nil {
		return nil, nil
	}
	request := nativeProducerRequest(work.request, r.attemptPath(work.request.Intent.AttemptID))
	// Receipt directory is protected and separate from allocation accounting.
	root := filepath.Join(filepath.Dir(r.staging.Root), "fence-receipts")
	if _, err := os.Lstat(filepath.Join(root, request.AttemptID+".json")); os.IsNotExist(err) {
		return nil, nil // Not a closure fact; existing producer guards still apply.
	} else if err != nil {
		return nil, ErrNativeUncertain
	}
	if _, err := os.Lstat(filepath.Join(r.root, "uploads", request.AttemptID)); !os.IsNotExist(err) {
		return nil, ErrNativeUncertain
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var response struct {
		Proof *nativeFencedFailure `json:"proof"`
	}
	err := runNativeHelperSource(ctx, nativeFenceHelper+nativeFenceInspectEntry, "inspect-fence-receipt",
		map[string]any{"receipt_root": root, "producer": request}, &response)
	if err != nil || response.Proof == nil {
		return nil, ErrNativeUncertain // A disappearing/malformed receipt holds.
	}
	body, err := models.StorageCanonical(request)
	if err != nil {
		return nil, ErrNativeUncertain
	}
	digest := sha256.Sum256(body)
	if response.Proof.Schema != "libvirt-failed-output-fence/1" || response.Proof.RequestSHA256 != hex.EncodeToString(digest[:]) {
		return nil, ErrNativeUncertain
	}
	return response.Proof, nil
}

func (r *nativeRunner) finishFencedFailure(ctx context.Context, work *nativeWork, proof *nativeFencedFailure) {
	intent, e1 := models.StorageCanonical(work.request.Intent)
	fence, e2 := models.StorageCanonical(proof)
	if e1 != nil || e2 != nil {
		r.retain(work)
		return
	}
	digest := sha256.Sum256(fence)
	binding := map[string]string{"intent_canonical": string(intent), "intent_sha256": work.request.IntentSHA256,
		"fence_canonical": string(fence), "fence_sha256": hex.EncodeToString(digest[:])}
	settle := r.settleFenced
	if settle == nil {
		settle = storageupload.SettleNativeFencedFailure
	}
	r.finishNativeFailureWith(ctx, work, binding, settle,
		"native failed output fenced; capacity released; partial output retained; fresh full required")
}
