package storagerestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Destination is a fresh, exclusively owned PVC supplied by the restore
// controller. Block=true permits writes to an existing block device, never a
// regular file. This API cannot establish Kubernetes ownership: callers MUST
// fence the PVC until success and retain failed destinations as unusable.
type Destination struct {
	VolumeName string `json:"volume_name"`
	Path       string `json:"path"`
	Block      bool   `json:"block"`
}

// AssembleTo reconstructs directly onto isolated PVC destinations. Filesystem
// files use O_EXCL. Block devices are fully zero-initialized before baseline
// extents, including full-backup holes; no prior contents can survive. Any
// failure leaves partial private destinations, never a bootable/usable result.
// Kubernetes Jobs using this function must have backoffLimit=0/restartPolicy=Never.
func AssembleTo(ctx context.Context, members []Member, destinations []Destination, open ObjectOpener, keys KeyResolver) ([]Disk, error) {
	if ctx == nil || open == nil {
		return nil, errors.New("restore requires context and object reader")
	}
	chain, err := validateChain(members)
	if err != nil {
		return nil, err
	}
	volumes := chain[0].Request.Plan.Source.Volumes
	if len(destinations) != len(volumes) {
		return nil, errors.New("exactly one destination per protected volume is required")
	}
	byName := map[string]Destination{}
	paths := map[string]bool{}
	for _, d := range destinations {
		if d.VolumeName == "" || !filepath.IsAbs(d.Path) || filepath.Clean(d.Path) != d.Path || paths[d.Path] || byName[d.VolumeName].Path != "" {
			return nil, errors.New("duplicate or invalid restore destination")
		}
		byName[d.VolumeName], paths[d.Path] = d, true
	}
	disks := make([]Disk, len(volumes))
	// Validate all mappings before opening the first destination.
	for i, v := range volumes {
		d, ok := byName[v.Name]
		if !ok {
			return nil, errors.New("destination volume is not in the accepted source")
		}
		disks[i] = Disk{Volume: v, Path: d.Path, SizeBytes: v.CapacityBytes}
	}
	for _, disk := range disks {
		d := byName[disk.Volume.Name]
		flags := os.O_RDWR | os.O_CREATE | os.O_EXCL
		if d.Block {
			flags = os.O_RDWR
		}
		f, err := os.OpenFile(d.Path, flags, 0600)
		if err != nil {
			return nil, fmt.Errorf("open fresh destination: %w", err)
		}
		info, err := f.Stat()
		if err == nil && d.Block && (info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice != 0) {
			err = errors.New("block destination is not a block device")
		}
		if err == nil && d.Block {
			var capacity int64
			capacity, err = f.Seek(0, io.SeekEnd)
			if err == nil && capacity < disk.SizeBytes {
				err = errors.New("block PVC is smaller than source capacity")
			}
			if err == nil {
				_, err = f.Seek(0, io.SeekStart)
			}
			if err == nil {
				err = zeroDestination(ctx, f, capacity)
			}
		} else if err == nil {
			err = f.Truncate(disk.SizeBytes)
		}
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
	}
	previous := ""
	seen := map[string]bool{}
	for _, member := range chain {
		checkpoint, err := applyMember(ctx, member, disks, previous, open, keys)
		if err != nil {
			return nil, err
		}
		if seen[checkpoint] {
			return nil, errors.New("chain repeats a checkpoint")
		}
		seen[checkpoint], previous = true, checkpoint
	}
	for i := range disks {
		f, err := os.Open(disks[i].Path)
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		n, err := io.CopyBuffer(h, io.LimitReader(&contextReader{ctx: ctx, reader: f}, disks[i].SizeBytes), make([]byte, copyBufferBytes))
		closeErr := f.Close()
		if err != nil || closeErr != nil || n != disks[i].SizeBytes {
			return nil, errors.Join(errors.New("restored destination checksum read failed"), err, closeErr)
		}
		disks[i].SHA256 = hex.EncodeToString(h.Sum(nil))
	}
	return disks, ctx.Err()
}

func zeroDestination(ctx context.Context, file *os.File, remaining int64) error {
	zeroes := make([]byte, copyBufferBytes)
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := file.Write(zeroes[:min(int64(len(zeroes)), remaining)])
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		remaining -= int64(n)
	}
	return file.Sync()
}
