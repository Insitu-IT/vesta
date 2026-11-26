package operationbudget

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"time"

	"golang.org/x/sys/unix"
)

// ScratchSample is produced by a read-only filesystem probe. It contains no
// paths or guest data and does not claim underlying storage-pool capacity.
type ScratchSample struct {
	At             time.Time `json:"at"`
	AvailableBytes int64     `json:"available_bytes"`
	CapacityBytes  int64     `json:"capacity_bytes"`
}

func SampleScratch(path string) (ScratchSample, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return ScratchSample{}, err
	}
	unit := stat.Frsize
	if unit <= 0 {
		unit = stat.Bsize
	}
	if unit <= 0 || stat.Bavail > stat.Blocks || stat.Blocks > uint64(math.MaxInt64/unit) {
		return ScratchSample{}, ErrEstimate
	}
	return ScratchSample{At: time.Now().UTC(), AvailableBytes: int64(stat.Bavail) * unit, CapacityBytes: int64(stat.Blocks) * unit}, nil
}

// ProbeScratch runs without API credentials and never opens a guest disk. The
// caller obtains one recent, bounded log record from the original probe Pod.
func ProbeScratch(ctx context.Context, path string, output io.Writer) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		s, err := SampleScratch(path)
		if err != nil {
			return err
		}
		if err = json.NewEncoder(output).Encode(s); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
