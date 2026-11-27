package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func publishFixture(t *testing.T) (parent, stage, output string) {
	t.Helper()
	parent = t.TempDir()
	stage = filepath.Join(parent, "scratch", "verified")
	output = filepath.Join(parent, "recovered")
	writeFile(t, filepath.Join(stage, "members", "000", "disk.qcow2"), []byte("durable fixture"))
	return parent, stage, output
}

func TestPublishVerifiedDisksSyncOrder(t *testing.T) {
	parent, stage, output := publishFixture(t)
	var calls []string
	err := publishVerifiedDisks(context.Background(), stage, output, func(f *os.File) error {
		name := filepath.Base(filepath.Clean(f.Name()))
		if f.Name() == parent {
			name = "destination-parent"
		}
		calls = append(calls, name)
		_, foundErr := os.Stat(filepath.Join(output, "members", "000", "disk.qcow2"))
		if name == "scratch" || name == "destination-parent" {
			if foundErr != nil {
				t.Fatalf("rename has not published before %s sync: %v", name, foundErr)
			}
		} else if !os.IsNotExist(foundErr) {
			t.Fatalf("output published before staged sync of %s: %v", name, foundErr)
		}
		return f.Sync()
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"disk.qcow2", "000", "members", "verified", "scratch", "destination-parent"}
	if !slices.Equal(calls, want) {
		t.Fatalf("durability order %v want %v", calls, want)
	}
}

func TestPublishVerifiedDisksSyncFailures(t *testing.T) {
	for _, phase := range []string{"file", "staged-directory", "source-parent", "destination-parent"} {
		t.Run(phase, func(t *testing.T) {
			parent, stage, output := publishFixture(t)
			syncErr := errors.New("fixture fsync error")
			parentCalled := false
			err := publishVerifiedDisks(context.Background(), stage, output, func(f *os.File) error {
				if f.Name() == parent {
					parentCalled = true
				}
				if (phase == "file" && filepath.Base(f.Name()) == "disk.qcow2") ||
					(phase == "staged-directory" && filepath.Base(f.Name()) == "members") ||
					(phase == "source-parent" && f.Name() == filepath.Dir(stage)) ||
					(phase == "destination-parent" && f.Name() == parent) {
					return syncErr
				}
				return f.Sync()
			})
			if !errors.Is(err, syncErr) {
				t.Fatalf("publication failed to propagate sync error: %v", err)
			}
			_, outputErr := os.Stat(output)
			postRename := phase == "source-parent" || phase == "destination-parent"
			if postRename && (!parentCalled || outputErr != nil) {
				t.Fatalf("post-rename failure lost output or skipped final parent sync: %v", outputErr)
			}
			if !postRename && (parentCalled || !os.IsNotExist(outputErr)) {
				t.Fatalf("output advanced despite staged sync failure: %v", outputErr)
			}
		})
	}
}

func TestPublishVerifiedDisksRefusesReplacement(t *testing.T) {
	parent, stage, output := publishFixture(t)
	sentinel := filepath.Join(output, "already-there")
	writeFile(t, sentinel, []byte("existing"))
	parentCalled := false
	err := publishVerifiedDisks(context.Background(), stage, output, func(f *os.File) error {
		parentCalled = parentCalled || f.Name() == parent
		return f.Sync()
	})
	if !errors.Is(err, os.ErrExist) || parentCalled {
		t.Fatalf("existing output did not stop publication: %v", err)
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "existing" {
		t.Fatalf("existing output changed: %q %v", data, err)
	}
}
