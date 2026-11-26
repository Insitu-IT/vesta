package storageupload

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync"
	"testing"
)

// Unlike a rejection before dispatch, a successful operation with a lost reply
// leaves remote effects that must not be blindly repeated after reopening.
func TestControlledAcceptedOperationLostReplyRetainsIntent(t *testing.T) {
	for _, phase := range []string{"create", "part", "provider", "part_ack", "complete", "head"} {
		t.Run(phase, func(t *testing.T) {
			b := request(t, true)
			s := store(t, b)
			p := controlledFixture(t, b, s, "", nil)
			defer p.Close()
			control := p.client.Transport
			provider := p.provider.Transport
			lost := 0
			p.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					return nil, err
				}
				r.Body = io.NopCloser(bytes.NewReader(body))
				var call struct {
					Operation string `json:"operation"`
				}
				if json.Unmarshal(body, &call) != nil {
					t.Fatal("invalid control request")
				}
				response, err := control.RoundTrip(r)
				if err == nil && call.Operation == phase {
					lost++
					response.Body.Close()
					return nil, io.ErrUnexpectedEOF
				}
				return response, err
			})
			p.provider.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
				response, err := provider.RoundTrip(r)
				if err == nil && phase == "provider" {
					lost++
					response.Body.Close()
					return nil, io.ErrUnexpectedEOF
				}
				return response, err
			})
			root := t.TempDir()
			j, err := Create(root, b)
			if err != nil {
				t.Fatal(err)
			}
			opens := 0
			in := inputs(s.r, 8, &opens)
			if err = j.UploadAll(context.Background(), p, in, make([]byte, 32)); err == nil || lost != 1 {
				t.Fatal("accepted operation's lost reply was not observed", err, lost)
			}
			wantCalls := map[string][]string{
				"create": {"begin"}, "part": {"begin"},
				"provider": {"begin", "part"}, "part_ack": {"begin", "part"},
				"complete": {"begin", "part", "complete"},
				"head":     {"begin", "part", "complete", "head"},
			}[phase]
			if !reflect.DeepEqual(s.calls, wantCalls) {
				t.Fatal("fault fired before its operation succeeded", s.calls)
			}
			original, err := os.ReadFile(j.path)
			if err != nil {
				t.Fatal(err)
			}
			if err = j.Close(); err != nil {
				t.Fatal(err)
			}
			j, err = Open(root, b)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			state, err := j.Snapshot()
			intent := map[string]string{"create": "create_intent", "part": "part_intent", "provider": "part_intent", "part_ack": "part_intent", "complete": "complete_intent", "head": "complete_intent"}[phase]
			if err != nil || state.Phase != "held" || state.Acceptance != nil || state.Objects[0].Phase != intent {
				t.Fatal("durable pre-call custody lost", err)
			}
			if phase != "create" && state.Objects[0].UploadID == "" {
				t.Fatal("acknowledged upload identity lost")
			}
			if (phase == "complete" || phase == "head") && state.Objects[0].Receipt == nil {
				t.Fatal("completion intent lost hashes")
			}
			if phase == "head" && state.Objects[0].Receipt.ETag == "" {
				t.Fatal("acknowledged completion identity lost")
			}
			if err = j.UploadAll(context.Background(), p, in, make([]byte, 32)); err == nil || lost != 1 || !reflect.DeepEqual(s.calls, wantCalls) {
				t.Fatal("reopen repeated an uncertain remote effect")
			}
			after, err := os.ReadFile(j.path)
			if err != nil || !bytes.Equal(original, after) {
				t.Fatal("refused replay rewrote held evidence", err)
			}
		})
	}
}

// Exercise a real trusted TLS connection that disappears after the receiver
// has accepted the exact receipt, rather than a transport stub's early error.
func TestPreparedAcceptanceLostTLSReplyRetriesIdenticallyAfterRestart(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, versioned := range []bool{false, true} {
			t.Run(fmt.Sprintf("encrypted=%t/version=%t", encrypted, versioned), func(t *testing.T) {
				b := request(t, encrypted)
				s := store(t, b)
				s.version = versioned
				root := t.TempDir()
				j, err := Create(root, b)
				if err != nil {
					t.Fatal(err)
				}
				opens := 0
				in := inputs(s.r, 8, &opens)
				if err = j.UploadAll(context.Background(), s, in, make([]byte, 32)); err != nil {
					t.Fatal(err)
				}
				response := ack(t, j)
				var mu sync.Mutex
				var receipts [][]byte
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agents/backups/"+s.r.BackupID+"/prepared-receipt" || r.Header.Get("X-Agent-Key") != "registered-fixture" {
						t.Error("receipt transport binding changed")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
					if err != nil {
						t.Error(err)
						return
					}
					mu.Lock()
					defer mu.Unlock()
					receipts = append(receipts, body)
					if len(receipts) == 1 {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						conn.Close()
						return
					}
					w.Header().Set("Content-Type", "application/json")
					w.Write(response)
				}))
				defer server.Close()
				client := server.Client() // trusts only this fixture's certificate
				defer client.CloseIdleConnections()
				key := func(context.Context) (string, error) { return "registered-fixture", nil }
				if _, err = j.Submit(context.Background(), server.URL, client, key); err == nil {
					t.Fatal("lost TLS response inferred acceptance")
				}
				if err = j.Close(); err != nil {
					t.Fatal(err)
				}
				j, err = Open(root, b)
				if err != nil {
					t.Fatal(err)
				}
				defer j.Close()
				if j.state.Phase != "submitting" || j.state.Acceptance != nil || j.state.Receipt == nil {
					t.Fatal("restart lost the exact pending receipt")
				}
				calls := append([]string(nil), s.calls...)
				if err = j.UploadAll(context.Background(), s, in, make([]byte, 32)); err != nil {
					t.Fatal(err)
				}
				a, err := j.Submit(context.Background(), server.URL, client, key)
				if err != nil || a == nil || j.state.Phase != "accepted" {
					t.Fatal("identical receipt retry did not recover", err)
				}
				if _, err = j.Submit(context.Background(), server.URL, client, key); err != nil {
					t.Fatal(err)
				}
				mu.Lock()
				defer mu.Unlock()
				if len(receipts) != 2 || !bytes.Equal(receipts[0], receipts[1]) || !reflect.DeepEqual(calls, s.calls) || opens != 2 {
					t.Fatal("restart reuploaded, changed receipt, or resent accepted work")
				}
			})
		}
	}
}
