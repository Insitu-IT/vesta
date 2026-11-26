//go:build linux

package storageupload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"vnbui/agent/internal/models"
)

// SettleNativeFencedFailure releases only failed original custody, never data.
func SettleNativeFencedFailure(ctx context.Context, base, backup string, binding map[string]string, client *http.Client, agentKey func(context.Context) (string, error)) error {
	if len(binding) != 4 {
		return ErrHeld
	}
	for _, pair := range [][2]string{{"intent_canonical", "intent_sha256"}, {"fence_canonical", "fence_sha256"}} {
		digest := sha256.Sum256([]byte(binding[pair[0]]))
		if binding[pair[0]] == "" || binding[pair[1]] != hex.EncodeToString(digest[:]) {
			return ErrHeld
		}
	}
	var intent struct {
		AttemptID string `json:"attempt_id"`
		BackupID  string `json:"backup_id"`
	}
	if json.Unmarshal([]byte(binding["intent_canonical"]), &intent) != nil || intent.AttemptID == "" || intent.BackupID != backup {
		return ErrHeld
	}
	body, err := json.Marshal(binding)
	if err != nil || len(body) > 512<<10 {
		return ErrHeld
	}
	response, err := nativeControl(ctx, base, client, agentKey, backup, "native-fenced-failure", body)
	if err != nil {
		return err
	}
	var result struct {
		Settled      bool   `json:"settled"`
		AttemptID    string `json:"attempt_id"`
		IntentSHA256 string `json:"intent_sha256"`
		FenceSHA256  string `json:"fence_sha256"`
		CapacityID   string `json:"capacity_id"`
	}
	if models.DecodeStorageValue(response, &result, 4096) != nil || !result.Settled || result.AttemptID != intent.AttemptID ||
		result.IntentSHA256 != binding["intent_sha256"] || result.FenceSHA256 != binding["fence_sha256"] || result.CapacityID == "" {
		return ErrHeld
	}
	return nil
}
