package backup

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestPollUntilImmediateSuccess(t *testing.T) {
	err := PollUntil(context.Background(), 10*time.Millisecond, 1*time.Second, func() (bool, error) {
		return true, nil
	})
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestPollUntilEventualSuccess(t *testing.T) {
	calls := 0
	err := PollUntil(context.Background(), 10*time.Millisecond, 1*time.Second, func() (bool, error) {
		calls++
		return calls >= 3, nil
	})
	if err != nil {
		t.Fatalf("expected success after %d calls, got: %v", calls, err)
	}
	if calls < 3 {
		t.Fatalf("expected at least 3 calls, got %d", calls)
	}
}

func TestPollUntilTimeout(t *testing.T) {
	err := PollUntil(context.Background(), 10*time.Millisecond, 50*time.Millisecond, func() (bool, error) {
		return false, nil
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if got := err.Error(); got != "timed out after 50ms" {
		t.Fatalf("unexpected error: %s", got)
	}
}

func TestPollUntilContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	err := PollUntil(ctx, 10*time.Millisecond, 5*time.Second, func() (bool, error) {
		return false, nil
	})
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

func TestPollUntilTransientErrors(t *testing.T) {
	calls := 0
	err := PollUntil(context.Background(), 10*time.Millisecond, 1*time.Second, func() (bool, error) {
		calls++
		if calls < 3 {
			return false, fmt.Errorf("transient error %d", calls)
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("expected success after transient errors, got: %v", err)
	}
}

func TestPollUntilTimeoutWithLastError(t *testing.T) {
	err := PollUntil(context.Background(), 10*time.Millisecond, 50*time.Millisecond, func() (bool, error) {
		return false, fmt.Errorf("api unavailable")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); got != "timed out after 50ms (last error: api unavailable)" {
		t.Fatalf("unexpected error: %s", got)
	}
}
