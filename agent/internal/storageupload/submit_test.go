package storageupload

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"vnbui/agent/internal/models"
)

func TestPreparedSubmissionRefusalRetainsExactEvidence(t *testing.T) {
	for _, mode := range []string{"400", "409", "500", "redirect", "empty", "duplicate", "unknown", "false", "hash", "reservation", "missing-object", "duplicate-object", "version", "assurance", "scrub", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			b := request(t, false)
			root := t.TempDir()
			j, e := Create(root, b)
			if e != nil {
				t.Fatal(e)
			}
			s := store(t, b)
			n := 0
			in := inputs(s.r, 0, &n)
			if e = j.UploadAll(context.Background(), s, in, nil); e != nil {
				t.Fatal(e)
			}
			good := ack(t, j)
			response := append([]byte{}, good...)
			status := 200
			var value map[string]any
			_ = json.Unmarshal(good, &value)
			switch mode {
			case "400":
				status = 400
			case "409":
				status = 409
			case "500":
				status = 500
			case "redirect":
				status = 307
			case "empty":
				value = map[string]any{}
			case "unknown":
				value["private"] = "private-provider-body"
			case "false":
				value["accepted"] = false
			case "hash":
				value["receipt_sha256"] = strings.Repeat("0", 64)
			case "reservation":
				value["reservation_id"] = "foreign"
			case "scrub":
				value["scrub_required"] = false
			case "missing-object":
				value["verification"] = []any{}
			case "duplicate-object":
				v := value["verification"].([]any)
				v[1] = v[0]
			case "version":
				value["verification"].([]any)[0].(map[string]any)["version_id"] = "foreign"
			case "assurance":
				value["verification"].([]any)[0].(map[string]any)["assurance"] = "provider_checksum_verified"
			}
			response, _ = json.Marshal(value)
			if mode == "duplicate" {
				response = append([]byte(`{"accepted":true,`), response[1:]...)
			}
			if mode == "oversize" {
				response = bytes.Repeat([]byte(" "), models.MaxStorageReceiptBytes+1)
			}
			calls, credentials := 0, 0
			client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://foreign.invalid"}}, Body: io.NopCloser(bytes.NewReader(response))}, nil
			})}
			credential := func(context.Context) (string, error) {
				credentials++
				data, err := j.read()
				if err != nil || !bytes.Contains(data, []byte(`"phase":"submitting"`)) {
					t.Fatal("credential lookup before durable intent")
				}
				return "fixture-private-key", nil
			}
			before := len(s.calls)
			if a, err := j.Submit(context.Background(), "https://backend.test", client, credential); a != nil || err != ErrHeld {
				t.Fatal("refused acceptance became success or disclosed details")
			}
			if calls != 1 || credentials != 1 || j.state.Acceptance != nil || j.state.Phase != "submitting" || len(s.calls) != before {
				t.Fatal("uncertain response changed producer authority")
			}
			_ = j.Close()
			j, e = Open(root, b)
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			if j.state.Receipt == nil || j.state.Acceptance != nil {
				t.Fatal("lost receipt evidence")
			}
			data, _ := os.ReadFile(j.path)
			for _, forbidden := range []string{"fixture-private-key", "private-provider-body"} {
				if bytes.Contains(data, []byte(forbidden)) {
					t.Fatal("secret/error body persisted")
				}
			}
			// A conflicting reply never overwrites the identical prepared receipt.
			if !bytes.Equal(good, ack(t, j)) {
				t.Fatal("receipt changed after refusal/restart")
			}
		})
	}
}

func TestUnwritableReceiptIntentPrecedesCredentialAndHTTP(t *testing.T) {
	b := request(t, false)
	j, e := Create(t.TempDir(), b)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	s := store(t, b)
	n := 0
	if e = j.UploadAll(context.Background(), s, inputs(s.r, 0, &n), nil); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(j.path); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(j.path, 0700); e != nil {
		t.Fatal(e)
	}
	client := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		t.Fatal("HTTP after journal refusal")
		return nil, ErrHeld
	})}
	key := func(context.Context) (string, error) { t.Fatal("credential after journal refusal"); return "", ErrHeld }
	if _, e = j.Submit(context.Background(), "https://backend.test", client, key); e == nil {
		t.Fatal("journal error accepted")
	}
}
