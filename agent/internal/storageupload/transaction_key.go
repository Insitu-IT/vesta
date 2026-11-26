package storageupload

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"time"

	"vnbui/agent/internal/models"
)

// ResolveKey uses only the admitted transaction surface. The returned bytes
// are memory-only; caller clears them after the synchronous stream completes.
// There is no environment/heartbeat/static-provider credential fallback.
func (s *ControlledS3) ResolveKey(ctx context.Context) ([]byte, error) {
	binding := map[string]any{"reservation_id": s.reservation, "attempt_id": s.attempt, "plan_sha256": s.planHash, "key_ref": s.encryption.KeyRef}
	body, err := json.Marshal(binding)
	if err != nil {
		return nil, ErrHeld
	}
	credential, err := s.agentKey(ctx)
	if err != nil || credential == "" {
		return nil, ErrHeld
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/api/v1/agents/backups/"+s.backup+"/transaction-key", bytes.NewReader(body))
	if err != nil {
		return nil, ErrHeld
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Key", credential)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, ErrHeld
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		return nil, ErrHeld
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(data) > 4096 {
		return nil, ErrHeld
	}
	defer clear(data)
	value, err := models.DecodeStorageControlJSON(data)
	if err != nil || len(value) != 6 {
		return nil, ErrHeld
	}
	var result struct {
		ReservationID string  `json:"reservation_id"`
		AttemptID     string  `json:"attempt_id"`
		PlanSHA256    string  `json:"plan_sha256"`
		KeyRef        *string `json:"key_ref"`
		Format        string  `json:"format"`
		DEK           *string `json:"dek"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil || d.Decode(new(any)) != io.EOF || result.ReservationID != s.reservation || result.AttemptID != s.attempt || result.PlanSHA256 != s.planHash || !reflect.DeepEqual(result.KeyRef, s.encryption.KeyRef) || result.Format != s.encryption.Format {
		return nil, ErrHeld
	}
	if result.Format == "none" {
		if result.DEK != nil {
			return nil, ErrHeld
		}
		return nil, nil
	}
	if result.DEK == nil {
		return nil, ErrHeld
	}
	key, err := base64.StdEncoding.Strict().DecodeString(*result.DEK)
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, ErrHeld
	}
	return key, nil
}
