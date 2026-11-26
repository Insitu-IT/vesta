//go:build kubevirt

package kubevirt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
)

var errSourceIdle = errors.New("source idle deadline exceeded")

type controlledClock struct{ current time.Time }

func (c *controlledClock) Now() time.Time                 { return c.current }
func (c *controlledClock) Advance(duration time.Duration) { c.current = c.current.Add(duration) }

type idleDeadlineReader struct {
	remaining int64
	deadline  time.Duration
	clock     *controlledClock
	lastRead  time.Time
	started   bool
}

func (r *idleDeadlineReader) Read(p []byte) (int, error) {
	if r.started && r.clock.Now().Sub(r.lastRead) > r.deadline {
		return 0, errSourceIdle
	}
	r.started = true
	r.lastRead = r.clock.Now()
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > r.remaining {
		n = r.remaining
	}
	r.remaining -= n
	return int(n), nil
}

type timedMultipartClient struct {
	clock     *controlledClock
	perMiB    time.Duration
	active    bool
	aborted   bool
	completed bool
	parts     []minio.CompletePart
	written   int64
}

func (c *timedMultipartClient) PutObject(_ context.Context, _, _ string, reader io.Reader, size int64, _, _ string, _ minio.PutObjectOptions) (minio.UploadInfo, error) {
	n, err := io.Copy(io.Discard, reader)
	if err != nil {
		return minio.UploadInfo{}, err
	}
	if n != size {
		return minio.UploadInfo{}, io.ErrUnexpectedEOF
	}
	c.completed = true
	return minio.UploadInfo{Size: n}, nil
}

func (c *timedMultipartClient) NewMultipartUpload(context.Context, string, string, minio.PutObjectOptions) (string, error) {
	c.active = true
	return "upload-1", nil
}

func (c *timedMultipartClient) PutObjectPart(_ context.Context, _, _, _ string, partID int, reader io.Reader, size int64, _ minio.PutObjectPartOptions) (minio.ObjectPart, error) {
	n, err := io.Copy(io.Discard, reader)
	if err != nil {
		return minio.ObjectPart{}, err
	}
	if n != size {
		return minio.ObjectPart{}, io.ErrUnexpectedEOF
	}
	c.clock.Advance(time.Duration(size/(1024*1024)) * c.perMiB)
	c.written += n
	return minio.ObjectPart{PartNumber: partID, ETag: "etag"}, nil
}

func (c *timedMultipartClient) CompleteMultipartUpload(_ context.Context, _, _, _ string, parts []minio.CompletePart, _ minio.PutObjectOptions) (minio.UploadInfo, error) {
	c.active = false
	c.completed = true
	c.parts = append([]minio.CompletePart(nil), parts...)
	return minio.UploadInfo{Size: c.written}, nil
}

func (c *timedMultipartClient) AbortMultipartUpload(context.Context, string, string, string) error {
	c.active = false
	c.aborted = true
	return nil
}

func TestPullMultipartPartSizeKeepsSlowSinkInsideSourceIdleDeadline(t *testing.T) {
	const payloadSize = 70 * 1024 * 1024

	t.Run("previous 64 MiB part exceeds deadline and aborts", func(t *testing.T) {
		clock := &controlledClock{current: time.Unix(0, 0)}
		client := &timedMultipartClient{clock: clock, perMiB: time.Second}
		source := &idleDeadlineReader{remaining: payloadSize, deadline: 10 * time.Second, clock: clock}
		_, err := uploadPullStream(context.Background(), client, "bucket", "key", source, 64*1024*1024, clock.Now)
		if !errors.Is(err, errSourceIdle) {
			t.Fatalf("error = %v, want source idle deadline", err)
		}
		if !client.aborted || client.active || client.completed {
			t.Fatalf("failed upload state: aborted=%v active=%v completed=%v", client.aborted, client.active, client.completed)
		}
	})

	t.Run("5 MiB parts complete inside deadline", func(t *testing.T) {
		clock := &controlledClock{current: time.Unix(0, 0)}
		client := &timedMultipartClient{clock: clock, perMiB: time.Second}
		source := &idleDeadlineReader{remaining: payloadSize, deadline: 10 * time.Second, clock: clock}
		written, err := uploadPullStream(context.Background(), client, "bucket", "key", source, pullMultipartPartSize, clock.Now)
		if err != nil {
			t.Fatal(err)
		}
		if written != payloadSize || !client.completed || client.active || client.aborted {
			t.Fatalf("written=%d completed=%v active=%v aborted=%v", written, client.completed, client.active, client.aborted)
		}
		if len(client.parts) != 14 {
			t.Fatalf("parts=%d, want 14", len(client.parts))
		}
	})
}

func TestPullMultipartUploadsEmptyObjectWithoutOrphan(t *testing.T) {
	clock := &controlledClock{current: time.Unix(0, 0)}
	client := &timedMultipartClient{clock: clock}
	written, err := uploadPullStream(context.Background(), client, "bucket", "key", bytes.NewReader(nil), pullMultipartPartSize, clock.Now)
	if err != nil || written != 0 || !client.completed || client.active {
		t.Fatalf("written=%d completed=%v active=%v err=%v", written, client.completed, client.active, err)
	}
}

func TestPullPartSizeUsesMinimumAndKeepsWithinPartLimit(t *testing.T) {
	partSize, err := pullPartSize(100 * 1024 * 1024)
	if err != nil || partSize != pullMultipartPartSize {
		t.Fatalf("100 MiB part size = %d, err=%v", partSize, err)
	}

	payload := uint64(100 * 1024 * 1024 * 1024)
	partSize, err = pullPartSize(payload)
	if err != nil {
		t.Fatal(err)
	}
	parts := (payload + uint64(partSize) - 1) / uint64(partSize)
	if partSize <= pullMultipartPartSize || parts >= pullMultipartMaxParts {
		t.Fatalf("100 GiB part size=%d parts=%d", partSize, parts)
	}
}
