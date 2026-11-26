package storageupload

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"vnbui/agent/internal/models"
)

func TestKubevirtNamingPinnedBeforeNativeAndReopened(t *testing.T) {
	for _, prefix := range []string{"vnbui", "vesta"} {
		t.Run(prefix, func(t *testing.T) {
			root := t.TempDir()
			body := request(t, false)
			j, err := CreateWithKubevirtPrefix(root, body, prefix)
			if err != nil {
				t.Fatal(err)
			}
			state, err := j.Snapshot()
			if err != nil || state.ResourcePrefix != prefix || state.Native != nil {
				t.Fatal(state.ResourcePrefix, err)
			}
			if err = j.Close(); err != nil {
				t.Fatal(err)
			}
			j, err = Open(root, body)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			state, err = j.Snapshot()
			if err != nil || state.ResourcePrefix != prefix {
				t.Fatal(state.ResourcePrefix, err)
			}
		})
	}
}

func TestKubevirtLegacyJournalPrefixAbsentPreservesChecksum(t *testing.T) {
	root := t.TempDir()
	body := request(t, false)
	j, err := Create(root, body)
	if err != nil {
		t.Fatal(err)
	}
	state, err := j.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	path := j.path
	j.Close()
	// Exact pre-extension schema5 image, with no prefix or compensation fields.
	raw, _ := json.Marshal(state)
	var old map[string]any
	json.Unmarshal(raw, &old)
	delete(old, "resource_prefix")
	delete(old, "compensation")
	canonical, err := models.StorageCanonical(old)
	if err != nil {
		t.Fatal(err)
	}
	disk, _ := json.Marshal(map[string]any{"sha256": digest(canonical), "state": old})
	if err = os.WriteFile(path, disk, 0600); err != nil {
		t.Fatal(err)
	}
	j, err = Open(root, body)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	state, err = j.Snapshot()
	if err != nil || state.ResourcePrefix != "" {
		t.Fatal("old journal adopted nonlegacy prefix", state.ResourcePrefix, err)
	}
	current, err := os.ReadFile(filepath.Join(filepath.Dir(path), "transaction.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]json.RawMessage
	json.Unmarshal(current, &saved)
	var checksum string
	json.Unmarshal(saved["sha256"], &checksum)
	if checksum != digest(canonical) {
		t.Fatal("legacy checksum changed without effects")
	}
}
