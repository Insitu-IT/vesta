package storageupload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestControlledPartDiagnosticsNeverExposeAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, fail, stage string
		status            int
		mutate            func(*signedPart)
	}{
		{name: "backend transport", fail: "part", stage: "backend_transport"},
		{name: "backend status", stage: "backend_response", status: 400},
		{name: "backend shape", stage: "backend_shape"},
		{name: "authority validation", stage: "authority_validation", mutate: func(a *signedPart) { a.Headers["private"] = "PRIVATE_SIGNED_HEADER" }},
		{name: "provider transport", fail: "provider", stage: "provider_transport"},
		{name: "provider status", stage: "provider_response", status: 403},
		{name: "provider checksum", stage: "provider_checksum"},
		{name: "provider etag", stage: "provider_etag"},
		{name: "lost acknowledgment", fail: "part_ack", stage: "backend_transport"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
			t.Cleanup(func() { slog.SetDefault(previous) })
			b := request(t, false)
			s := store(t, b)
			p := controlledFixture(t, b, s, tc.fail, tc.mutate)
			defer p.Close()
			a := s.r.Plan.Artifacts[0]
			id, err := p.Begin(context.Background(), a.Key, metadata(&s.r, a))
			if err != nil {
				t.Fatal(err)
			}
			if tc.stage == "backend_response" || tc.stage == "backend_shape" {
				p.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
					status := tc.status
					if status == 0 {
						status = http.StatusOK
					}
					return &http.Response{StatusCode: status, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(strings.NewReader("PRIVATE_BACKEND_BODY"))}, nil
				})
			}
			if tc.stage == "provider_response" || tc.stage == "provider_checksum" || tc.stage == "provider_etag" {
				p.provider.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
					status := tc.status
					if status == 0 {
						status = http.StatusOK
					}
					header := http.Header{"Etag": {`"fixture"`}}
					if tc.stage == "provider_checksum" {
						header.Set("X-Amz-Checksum-Sha256", "PRIVATE_CHECKSUM")
					}
					if tc.stage == "provider_etag" {
						header.Set("ETag", "PRIVATE_ETAG")
					}
					return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader("PRIVATE_PROVIDER_BODY"))}, nil
				})
			}
			data := []byte("PRIVATE_PAYLOAD")
			hash := sha256.Sum256(data)
			checksum := base64.StdEncoding.EncodeToString(hash[:])
			if _, err = p.Part(context.Background(), a.Key, id, 1, data, checksum); err != ErrHeld {
				t.Fatalf("failure did not retain its original hold: %v", err)
			}
			output := logs.String()
			if !strings.Contains(output, `"stage":"`+tc.stage+`"`) {
				t.Fatalf("missing safe stage %s: %s", tc.stage, output)
			}
			if tc.status != 0 && !strings.Contains(output, `"http_status":`+strconv.Itoa(tc.status)) {
				t.Fatalf("missing numeric response status: %s", output)
			}
			for _, forbidden := range []string{"PRIVATE", "https://", "X-Amz", "registered-fixture", "example-secret", a.Key, id} {
				if forbidden != "" && strings.Contains(output, forbidden) {
					t.Fatalf("diagnostic exposed private provider material: %s", forbidden)
				}
			}
		})
	}
}
