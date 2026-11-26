//go:build linux && nativepg

package storageupload

// This bridge runs only under the restricted PostgreSQL acceptance driver.
// It replaces HTTP transport, not backend handlers, signing, or custody state.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"vnbui/agent/internal/encryption"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
)

func TestNativeMountedBridge(t *testing.T) {
	decoder, encoder := json.NewDecoder(os.Stdin), json.NewEncoder(os.Stdout)
	var input struct {
		Org, Agent, Key string
		Admission       ClosedNativeAdmission
	}
	if err := decoder.Decode(&input); err != nil {
		t.Fatal(err)
	}
	tree, journal := t.TempDir(), t.TempDir()
	expected := map[string][]byte{}
	for _, member := range input.Admission.Inventory.Files {
		path := filepath.Join(tree, member.Path)
		// The backend fixture's current push manifest binds these exact bytes.
		// This exercises closed upload/ciphertext handling, not a libvirt job.
		content := []byte(member.Path)
		if member.Role == "backup_metadata" {
			var err error
			content, err = models.StorageCanonical(input.Admission.PushResult.Manifest)
			if err != nil {
				t.Fatal(err)
			}
		}
		expected[member.ArtifactID] = content
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	input.Admission.Inventory, err = nativefileset.Capture(tree, input.Admission.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := json.Marshal(input.Admission)
	if err != nil {
		t.Fatal(err)
	}
	transport := func(channel string) *http.Client {
		return &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			if err = encoder.Encode(map[string]interface{}{"channel": channel, "method": r.Method, "url": r.URL.String(), "headers": r.Header, "body": body}); err != nil {
				return nil, err
			}
			var response struct {
				Status  int
				Headers http.Header
				Body    []byte
				Error   string
			}
			if err = decoder.Decode(&response); err != nil {
				return nil, err
			}
			if response.Error != "" {
				return nil, errors.New(response.Error)
			}
			headers := http.Header{}
			for name, values := range response.Headers {
				for _, value := range values {
					headers.Add(name, value)
				}
			}
			return &http.Response{StatusCode: response.Status, Header: headers, Body: io.NopCloser(bytes.NewReader(response.Body))}, nil
		})}
	}
	backend, provider := transport("backend"), transport("provider")
	credential := func(context.Context) (string, error) { return input.Key, nil }
	if _, err = UploadClosedNative(context.Background(), journal, tree, input.Org, input.Agent, "https://backend.test", admission, backend, provider, credential); err == nil {
		t.Fatal("lost acceptance did not hold")
	}
	if err = encoder.Encode(map[string]string{"channel": "replay"}); err != nil {
		t.Fatal(err)
	}
	var replayReady struct{}
	if err = decoder.Decode(&replayReady); err != nil {
		t.Fatal(err)
	}
	accepted, err := UploadClosedNative(context.Background(), journal, filepath.Join(tree, "absent"), input.Org, input.Agent, "https://backend.test", admission, backend, provider, credential)
	if err != nil || accepted == nil || !accepted.Accepted {
		t.Fatal("durable acceptance replay", err)
	}
	if err = encoder.Encode(map[string]string{"channel": "verify"}); err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Key     []byte
		Objects map[string][]byte
	}
	if err = decoder.Decode(&stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.Objects) != len(expected) {
		t.Fatal("missing objects")
	}
	for id, want := range expected {
		got, ok := stored.Objects[id]
		if !ok {
			t.Fatal("missing member", id)
		}
		if len(stored.Key) > 0 {
			dir := t.TempDir()
			encrypted, decrypted := filepath.Join(dir, "encrypted"), filepath.Join(dir, "decrypted")
			if err = os.WriteFile(encrypted, got, 0600); err != nil {
				t.Fatal(err)
			}
			if err = encryption.DecryptFile(encrypted, decrypted, stored.Key); err != nil {
				t.Fatal(err)
			}
			got, err = os.ReadFile(decrypted)
			if err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(got, want) {
			t.Fatal("stored member mismatch", id)
		}
	}
	fmt.Println(`{"channel":"done"}`)
}
