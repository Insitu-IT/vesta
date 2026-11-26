//go:build linux

package nativestaging

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDisabledProfileCannotForgetEnrollment(t *testing.T) {
	journal := t.TempDir()
	p, err := NewProfile(journal, "", "")
	if p != nil || err != nil {
		t.Fatal(p, err)
	}
	marker := filepath.Join(journal, "staging-profile.json")
	if err = os.WriteFile(marker, []byte(`{"original":"retained"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = NewProfile(journal, "", ""); err == nil {
		t.Fatal("forgot enrolled profile")
	}
	got, _ := os.ReadFile(marker)
	if string(got) != `{"original":"retained"}` {
		t.Fatal("changed old profile")
	}
}

func TestUnsafeProfileLeavesJournalUnchanged(t *testing.T) {
	for _, roots := range [][2]string{{"relative", "/tmp/socket"}, {"/tmp", ""}, {"", "/tmp/socket"}, {"/tmp", "/tmp/socket"}} {
		t.Run(roots[0]+roots[1], func(t *testing.T) {
			journal := t.TempDir()
			old := filepath.Join(journal, "original")
			_ = os.WriteFile(old, []byte("custody"), 0600)
			if _, err := NewProfile(journal, roots[0], roots[1]); err == nil {
				t.Fatal("unsafe profile accepted")
			}
			if _, err := os.Stat(filepath.Join(journal, "staging-profile.json")); !os.IsNotExist(err) {
				t.Fatal("wrote profile on refusal")
			}
			if got, _ := os.ReadFile(old); string(got) != "custody" {
				t.Fatal("changed old custody")
			}
		})
	}
}

func TestInvalidAttemptCannotEscape(t *testing.T) {
	p := &Profile{Root: "/protected"}
	for _, value := range []string{"", "../other", "/other", "ABC", "11111111-1111-4111-8111-111111111111/other"} {
		if _, err := p.Path(value); err == nil {
			t.Fatal("invalid attempt", value)
		}
	}
}

func TestExchangeExactReplyAndMalformedFrames(t *testing.T) {
	body := []byte(`{"attempt_id":"11111111-1111-4111-8111-111111111111"}`)
	h := sha256.Sum256(body)
	valid, _ := json.Marshal(map[string]string{"schema": "libvirt-staging-reply/1", "status": "allocated", "request_sha256": hex.EncodeToString(h[:])})
	for _, test := range []struct {
		name     string
		response []byte
		size     uint32
		ok       bool
	}{
		{"exact", valid, uint32(len(valid)), true}, {"oversized", nil, maxFrame + 1, false},
		{"empty", nil, 0, false}, {"wrong digest", []byte(`{"schema":"libvirt-staging-reply/1","status":"allocated","request_sha256":"wrong"}`), 0, false},
		{"truncated", valid, uint32(len(valid) + 1), false},
		{"unknown field", append(append([]byte{}, valid[:len(valid)-1]...), []byte(`,"extra":true}`)...), 0, false},
		{"trailing bytes", append(append([]byte{}, valid...), []byte(`{}`)...), 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "broker.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				server, e := listener.AcceptUnix()
				if e != nil {
					done <- e
					return
				}
				defer server.Close()
				_ = server.SetDeadline(time.Now().Add(2 * time.Second))
				header := make([]byte, 4)
				if _, e = io.ReadFull(server, header); e != nil {
					done <- e
					return
				}
				n := binary.BigEndian.Uint32(header)
				if n > maxFrame {
					done <- ErrHeld
					return
				}
				request := make([]byte, n)
				if _, e = io.ReadFull(server, request); e != nil {
					done <- e
					return
				}
				var envelope struct {
					Action  string          `json:"action"`
					Request json.RawMessage `json:"request"`
				}
				if json.Unmarshal(request, &envelope) != nil || envelope.Action != "allocate" || !json.Valid(envelope.Request) {
					done <- ErrHeld
					return
				}
				size := test.size
				if size == 0 && test.name != "empty" {
					size = uint32(len(test.response))
				}
				binary.BigEndian.PutUint32(header, size)
				_, e = server.Write(header)
				if e == nil && len(test.response) > 0 {
					for _, b := range test.response {
						if _, e = server.Write([]byte{b}); e != nil {
							break
						}
					}
				}
				done <- e
			}()
			client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			_ = client.SetDeadline(time.Now().Add(2 * time.Second))
			err = exchange(client, body, uint32(os.Geteuid()))
			_ = client.Close()
			<-done
			if (err == nil) != test.ok {
				t.Fatal("unexpected frame verdict", err)
			}
		})
	}
}

func TestExchangeRejectsWrongPeerBeforeSending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broker.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if exchange(client, []byte(`{}`), uint32(os.Geteuid()+1)) == nil {
		t.Fatal("wrong peer accepted")
	}
	_ = server.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	one := make([]byte, 1)
	if n, _ := server.Read(one); n != 0 {
		t.Fatal("request leaked to wrong peer")
	}
}
