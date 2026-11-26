package security

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// safeNameRe matches valid VM names, disk names, checkpoint names.
	safeNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
	// safePathComponentRe matches safe path components.
	safePathComponentRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
)

// ValidateVMName validates a VM name.
func ValidateVMName(name string) error {
	if name == "" {
		return fmt.Errorf("VM name cannot be empty")
	}
	if len(name) > 255 {
		return fmt.Errorf("VM name too long: %d chars", len(name))
	}
	if !safeNameRe.MatchString(name) {
		slog.Warn("validation: rejected VM name", "name", name)
		return fmt.Errorf("invalid VM name: must match %s", safeNameRe.String())
	}
	return nil
}

// ValidateDiskName validates a disk target name (e.g., vda, sda).
func ValidateDiskName(name string) error {
	if name == "" {
		return fmt.Errorf("disk name cannot be empty")
	}
	if !safeNameRe.MatchString(name) {
		slog.Warn("validation: rejected disk name", "name", name)
		return fmt.Errorf("invalid disk name: %q", name)
	}
	return nil
}

// ValidateCheckpointName validates a checkpoint name.
func ValidateCheckpointName(name string) error {
	if name == "" {
		return nil // optional
	}
	if !safeNameRe.MatchString(name) {
		return fmt.Errorf("invalid checkpoint name: %q", name)
	}
	return nil
}

// ValidateTargetName validates a restore target VM name.
func ValidateTargetName(name string) error {
	if name == "" {
		return nil // optional
	}
	return ValidateVMName(name)
}

// ValidatePath validates a file path for safety.
func ValidatePath(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	// Must be absolute
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path must be absolute: %q", path)
	}

	// Reject raw ".." in the original path (before Clean resolves it)
	if strings.Contains(path, "..") {
		slog.Warn("validation: path traversal attempt", "path", path)
		return fmt.Errorf("path traversal detected: %q", path)
	}

	return nil
}

// ValidateCompression validates the compression level string.
func ValidateCompression(comp string) error {
	if comp == "" {
		return nil
	}
	valid := map[string]bool{"1": true, "2": true, "3": true, "4": true, "5": true,
		"6": true, "7": true, "8": true, "9": true}
	if !valid[comp] {
		return fmt.Errorf("invalid compression level: %q (must be 1-9)", comp)
	}
	return nil
}

// ValidateWorkers validates the worker count.
func ValidateWorkers(workers int) error {
	if workers < 1 || workers > 8 {
		return fmt.Errorf("workers must be 1-8, got %d", workers)
	}
	return nil
}
