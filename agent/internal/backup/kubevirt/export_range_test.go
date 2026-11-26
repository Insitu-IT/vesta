//go:build kubevirt

package kubevirt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"vnbui/agent/internal/encryption"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

// An idle route can truncate an unfinished response while the caller uploads
// to another service. Advance time at the sink, without a wall-clock race.
type idleRangeBody struct {
	*bytes.Reader
	clock    *controlledClock
	lastRead time.Time
	closed   bool
}

func (b *idleRangeBody) Read(p []byte) (int, error) {
	if b.closed || b.clock.Now().Sub(b.lastRead) > 30*time.Second {
		return 0, io.ErrUnexpectedEOF
	}
	b.lastRead = b.clock.Now()
	return b.Reader.Read(p)
}
func (b *idleRangeBody) Close() error { b.closed = true; return nil }

type slowRangeSink struct {
	clock  *controlledClock
	bytes  int
	part   int
	onPart func()
}

func (w *slowRangeSink) Write(p []byte) (int, error) {
	before := w.bytes / w.part
	w.bytes += len(p)
	for i := before; i < w.bytes/w.part; i++ {
		w.onPart()
		w.clock.Advance(55 * time.Second)
	}
	return len(p), nil
}

func TestRangeReaderSlowSinkDoesNotIdleSourceResponse(t *testing.T) {
	// A short first extent offsets later source boundaries from 32 MiB parts,
	// including for plaintext streams. Encryption adds its own 5 MiB framing.
	data := bytes.Repeat([]byte{0, 3, 1, 2}, (70<<20)/4)
	for _, profile := range []string{"", models.KubevirtTransfer32} {
		for _, encrypted := range []bool{false, true} {
			t.Run(fmt.Sprintf("profile=%s/encrypted=%t", profile, encrypted), func(t *testing.T) {
				limit, err := models.StorageSourceRangeBytes(profile)
				if err != nil {
					t.Fatal(err)
				}
				clock := &controlledClock{current: time.Unix(1, 0)}
				var bodies []*idleRangeBody
				checks, requests, pauses, openAtPause := 0, 0, 0, 0
				x := &transactionExport{ctx: context.Background(), token: "fixture", validate: func() error { checks++; return nil }}
				x.client = &http.Client{Transport: exportTransport(func(req *http.Request) (*http.Response, error) {
					requests++
					offset, _ := strconv.Atoi(req.URL.Query().Get("offset"))
					n, _ := strconv.Atoi(req.URL.Query().Get("length"))
					if n <= 0 || uint64(n) > limit || offset < 0 || n > len(data)-offset {
						t.Fatal("unbounded source request")
					}
					b := &idleRangeBody{Reader: bytes.NewReader(data[offset : offset+n]), clock: clock, lastRead: clock.Now()}
					bodies = append(bodies, b)
					return &http.Response{StatusCode: 200, Body: b}, nil
				})}
				r := &rangeReader{source: x, endpoint: "https://export.example/exports/data/data", ranges: []storageupload.ExportRange{{Length: 3 << 20}, {Offset: 3 << 20, Length: uint64(len(data) - (3 << 20))}}, rangeBytes: limit}
				defer r.Close()
				sink := &slowRangeSink{clock: clock, part: 32 << 20, onPart: func() {
					pauses++
					for _, b := range bodies {
						if !b.closed {
							openAtPause++
						}
					}
				}}
				hash := sha256.New()
				input := io.TeeReader(r, hash)
				if encrypted {
					err = encryption.EncryptStreamChunked(input, sink, bytes.Repeat([]byte{9}, 32), 5<<20)
				} else {
					_, err = io.CopyBuffer(sink, input, make([]byte, 5<<20))
				}
				if err != nil {
					t.Fatalf("slow sink truncated source: %v", err)
				}
				want := sha256.Sum256(data)
				if !bytes.Equal(hash.Sum(nil), want[:]) || pauses != 2 || openAtPause != 0 {
					t.Fatal("source changed or response remained open during upload", pauses, openAtPause)
				}
				if requests != 1+(len(data)-(3<<20)+int(limit)-1)/int(limit) || checks != requests {
					t.Fatal("source request admission changed", requests, checks)
				}
				wantBytes := len(data)
				if encrypted {
					wantBytes += 5 + 32*((len(data)+(5<<20)-1)/(5<<20))
				}
				if sink.bytes != wantBytes {
					t.Fatal("wire size changed")
				}
			})
		}
	}
}

func TestRangeReaderRejectsIncompleteRangeBeforeDelivery(t *testing.T) {
	for _, length := range []int{63, 65} {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			clock := &controlledClock{current: time.Unix(1, 0)}
			body := &idleRangeBody{Reader: bytes.NewReader(bytes.Repeat([]byte{7}, length)), clock: clock, lastRead: clock.Now()}
			x := &transactionExport{ctx: context.Background(), validate: func() error { return nil }, client: &http.Client{Transport: exportTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: body}, nil
			})}}
			r := &rangeReader{source: x, endpoint: "https://export.example/exports/data/data", ranges: []storageupload.ExportRange{{Length: 64}}}
			defer r.Close()
			if n, err := r.Read(make([]byte, 1)); n != 0 || !errors.Is(err, storageupload.ErrHeld) || !body.closed {
				t.Fatal("invalid range exposed bytes or kept its response", n, err)
			}
			if n, err := r.Read(make([]byte, 1)); n != 0 || !errors.Is(err, storageupload.ErrHeld) {
				t.Fatal("failed reader resumed", n, err)
			}
		})
	}
}

func TestRangeReaderCancellationAfterPartialConsumption(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	x := &transactionExport{ctx: ctx, validate: func() error { return nil }, client: &http.Client{Transport: exportTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))}, nil
	})}}
	r := &rangeReader{source: x, endpoint: "https://export.example/exports/data/data", ranges: []storageupload.ExportRange{{Length: 64}}}
	defer r.Close()
	if n, err := r.Read(make([]byte, 1)); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	cancel()
	if n, err := r.Read(make([]byte, 1)); n != 0 || !errors.Is(err, storageupload.ErrHeld) || calls != 1 {
		t.Fatal("canceled buffered source continued", n, err, calls)
	}
}

// A real TLS response models a routed connection's finite write window. The
// consumer waits until the handler stops writing before asking for more bytes.
func TestRangeReaderDrainsHTTPResponseBeforeConsumerWait(t *testing.T) {
	data := bytes.Repeat([]byte{7}, 32<<20)
	finished := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer func() { finished <- struct{}{} }()
		if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		_, _ = w.Write(data)
	}))
	defer server.Close()
	x := &transactionExport{ctx: context.Background(), client: server.Client(), validate: func() error { return nil }}
	r := &rangeReader{source: x, endpoint: server.URL + "/exports/data/data", ranges: []storageupload.ExportRange{{Length: uint64(len(data))}}, rangeBytes: 32 << 20}
	defer r.Close()
	first := make([]byte, 1)
	if _, err := io.ReadFull(r, first); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("source response remained blocked on the consumer")
	}
	hash := sha256.New()
	_, _ = hash.Write(first)
	n, err := io.Copy(hash, r)
	want := sha256.Sum256(data)
	if err != nil || n != int64(len(data)-1) || !bytes.Equal(hash.Sum(nil), want[:]) {
		t.Fatal("routed response truncated after consumer wait", n, err)
	}
}

func TestRangeReaderRefusesNextRangeAfterAdmissionDrift(t *testing.T) {
	allowed, requests := true, 0
	x := &transactionExport{ctx: context.Background(), validate: func() error {
		if !allowed {
			return storageupload.ErrHeld
		}
		return nil
	}, client: &http.Client{Transport: exportTransport(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader([]byte{7, 7}))}, nil
	})}}
	r := &rangeReader{source: x, endpoint: "https://export.example/exports/data/data", ranges: []storageupload.ExportRange{{Length: 2}, {Offset: 4, Length: 2}}}
	defer r.Close()
	if n, err := r.Read(make([]byte, 1)); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	allowed = false
	// Already admitted bytes can be consumed, but no subsequent request is
	// allowed. Provider admission separately protects every upload boundary.
	if n, err := io.Copy(io.Discard, r); n != 1 || !errors.Is(err, storageupload.ErrHeld) || requests != 1 {
		t.Fatal("drift reached another source range", n, err, requests)
	}
}
