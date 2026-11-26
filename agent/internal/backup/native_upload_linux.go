//go:build linux

package backup

import (
	"context"
	"net/http"
	"path/filepath"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

// UploadClosedNative is the transaction producer entry for an already closed,
// attested native job. Path-only StartUpload is not an authority source for it.
// The HTTP activation hold remains: native launch/capture must be admitted under
// the separate host-actor contract before an external caller can reach this.
// Prepared acceptance deliberately emits no completed event or local deletion.
func (e *Executor) UploadClosedNative(ctx context.Context, org, tree string, admission []byte, backend, provider *http.Client, credential func(context.Context) (string, error)) (*models.StorageAcceptance, error) {
	if e.cfg == nil || e.cfg.KeyFilePath == "" || e.cfg.AgentID == "" {
		return nil, storageupload.ErrHeld
	}
	root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
	// The operator provisions this durable private directory. Missing/unwritable
	// state is not silently recreated after restart or treated as historical proof.
	return storageupload.UploadClosedNative(ctx, root, tree, org, e.cfg.AgentID, e.cfg.OrchestratorURL, admission, backend, provider, credential)
}
