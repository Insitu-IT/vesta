package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Both providers finish verifying staged output before invoking this function.
// Sync each file before its directory, then commit the new tree and sync both
// sides of the rename before emitting a recovery receipt.
func publishVerifiedDisks(ctx context.Context, stage, output string, syncFile func(*os.File) error) error {
	root, err := os.OpenRoot(stage)
	if err != nil {
		return err
	}
	err = syncVerifiedEntry(ctx, root, ".", syncFile)
	if err := errors.Join(err, root.Close()); err != nil {
		return fmt.Errorf("sync staged recovery output: %w", err)
	}
	source, err := os.OpenFile(filepath.Dir(stage), os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.OpenFile(filepath.Dir(output), os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer destination.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.Renameat2(int(source.Fd()), filepath.Base(stage), int(destination.Fd()), filepath.Base(output), unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("publish verified disks in the new output directory: %w", err)
	}
	// Once the rename succeeds, attempt both directory syncs even on
	// cancellation. A sync error leaves the verified tree for inspection.
	sourceErr := syncFile(source)
	destinationErr := syncFile(destination)
	if err := errors.Join(sourceErr, destinationErr); err != nil {
		return fmt.Errorf("verified disks were renamed to the output directory; durability could not be confirmed: %w", err)
	}
	return nil
}

func syncVerifiedEntry(ctx context.Context, root *os.Root, name string, syncFile func(*os.File) error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	switch {
	case info.IsDir():
		entries, err := f.ReadDir(-1)
		if err != nil {
			return err
		}
		for _, child := range entries {
			if err := syncVerifiedEntry(ctx, root, filepath.Join(name, child.Name()), syncFile); err != nil {
				return err
			}
		}
	case !info.Mode().IsRegular():
		return errors.New("staged recovery output contains an unsupported file type")
	}
	return syncFile(f)
}
