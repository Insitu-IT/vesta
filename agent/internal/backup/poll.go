package backup

import (
	"context"
	"fmt"
	"time"
)

// PollUntil polls fn every interval until it returns true, context is cancelled,
// or timeout is reached. If fn returns an error, polling continues (transient errors
// are retried). Only context cancellation and timeout are fatal.
func PollUntil(ctx context.Context, interval, timeout time.Duration, fn func() (bool, error)) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			if lastErr != nil {
				return fmt.Errorf("timed out after %v (last error: %w)", timeout, lastErr)
			}
			return fmt.Errorf("timed out after %v", timeout)
		case <-ticker.C:
			done, err := fn()
			if err != nil {
				lastErr = err
				continue // retry on transient errors
			}
			if done {
				return nil
			}
		}
	}
}
