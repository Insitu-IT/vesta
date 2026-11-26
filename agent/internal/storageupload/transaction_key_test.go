package storageupload

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"vnbui/agent/internal/models"
)

func TestControlledTransactionKeyExactBindingAndRefusal(t *testing.T) {
	for _, mode := range []string{"accepted", "none", "reservation", "attempt", "digest", "key-ref", "format", "missing", "extra", "duplicate", "length", "no-store", "denied", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			body := request(t, mode != "none")
			r, err := models.DecodeStorageTransaction(body)
			if err != nil {
				t.Fatal(err)
			}
			var material any = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{73}, 32))
			if mode == "none" {
				material = nil
			}
			binding := map[string]any{"reservation_id": r.ReservationID, "attempt_id": r.Plan.AttemptID, "plan_sha256": r.PlanSHA256, "key_ref": r.Plan.Encryption.KeyRef}
			value := map[string]any{}
			for k, v := range binding {
				value[k] = v
			}
			value["format"] = r.Plan.Encryption.Format
			value["dek"] = material
			switch mode {
			case "reservation":
				value["reservation_id"] = "foreign"
			case "attempt":
				value["attempt_id"] = "foreign"
			case "digest":
				value["plan_sha256"] = "foreign"
			case "key-ref":
				value["key_ref"] = "foreign"
			case "format":
				value["format"] = "unknown"
			case "missing":
				delete(value, "dek")
			case "extra":
				value["authority"] = "unexpected"
			case "length":
				value["dek"] = ""
			}
			data, _ := json.Marshal(value)
			if mode == "duplicate" {
				data = append([]byte(`{"dek":null,`), data[1:]...)
			}
			if mode == "oversized" {
				data = bytes.Repeat([]byte{'x'}, 4097)
			}
			calls := 0
			client := &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != "POST" || req.URL.Path != "/api/v1/agents/backups/"+r.BackupID+"/transaction-key" || req.Header.Get("X-Agent-Key") != "registered-fixture" {
					t.Fatal("authenticated key route")
				}
				wire, _ := io.ReadAll(req.Body)
				expected, _ := json.Marshal(binding)
				var got, want any
				_ = json.Unmarshal(wire, &got)
				_ = json.Unmarshal(expected, &want)
				if !reflect.DeepEqual(got, want) {
					t.Fatal("key request binding")
				}
				header := http.Header{"Cache-Control": {"no-store"}}
				if mode == "no-store" {
					header = nil
				}
				status := 200
				if mode == "denied" {
					status = 403
				}
				return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(data))}, nil
			})}
			provider := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
				t.Fatal("key resolution invoked provider")
				return nil, ErrHeld
			})}
			store, err := NewControlledS3(body, "https://backend.example", client, provider, func(context.Context) (string, error) { return "registered-fixture", nil })
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			key, err := store.ResolveKey(context.Background())
			defer clear(key)
			if mode == "accepted" {
				if err != nil || !bytes.Equal(key, bytes.Repeat([]byte{73}, 32)) {
					t.Fatal("exact key refused")
				}
			} else if mode == "none" {
				if err != nil || key != nil {
					t.Fatal("unencrypted key")
				}
			} else if err == nil || key != nil || strings.Contains(err.Error(), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{73}, 32))) {
				t.Fatal("invalid key response admitted or leaked")
			}
			if calls != 1 {
				t.Fatal("key retry")
			}
		})
	}
}
