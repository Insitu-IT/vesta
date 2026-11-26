package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"vnbui/agent/internal/models"
)

// NativePushFormat is deliberately distinct from the full-only virtnbdbackup
// native-fileset transaction. The catalog must authorize a parent manifest;
// a local path, matching checkpoint name, or old receipt is not that authority.
const NativePushFormat = "libvirt-push-qcow2/1"

//go:embed libvirt_push.py
var nativePushHelper string

// ErrNativeUncertain means no backup may be published or output reclaimed.
// Cancellation stops only our observer, not a possibly replaced domain job.
var ErrNativeUncertain = errors.New("native attempt uncertain; retain custody and output")

type NativeSourceDisk = models.NativeSourceDisk
type NativePushDisk = models.NativePushDisk
type NativePushManifest = models.NativePushManifest
type NativePushResult = models.NativePushResult

type NativePushRequest struct {
	Schema         string             `json:"schema"`
	URI            string             `json:"uri"`
	BackupID       string             `json:"backup_id"`
	AttemptID      string             `json:"attempt_id"`
	DomainUUID     string             `json:"domain_uuid"`
	Disks          []NativeSourceDisk `json:"disks"`
	Exclusions     []string           `json:"exclusions"`
	Parent         *NativePushResult  `json:"parent"`
	OutputPath     string             `json:"output_path"`
	TimeoutSeconds int                `json:"timeout_seconds"`
}

type NativeRestoreMember struct {
	Manifest       NativePushManifest `json:"manifest"`
	ManifestSHA256 string             `json:"manifest_sha256"`
	Directory      string             `json:"directory"`
}

type NativeRestoredDisk struct {
	Target    string `json:"target"`
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

// RunNativePush executes one durable, fresh-attempt push. The caller must have
// persisted source/parent authorization and reserved capacity before this call.
// It produces sealed local images, NOT a storage receipt or completed backup.
// This is intentionally not wired to the old path-only /backups endpoint.
func RunNativePush(ctx context.Context, request NativePushRequest) (*NativePushResult, error) {
	var result NativePushResult
	if err := runNativeHelper(ctx, "backup", request, &result); err != nil {
		return nil, err
	}
	manifest := result.Manifest
	canonical, err := models.StorageCanonical(manifest)
	digest := sha256.Sum256(canonical)
	if err != nil || manifest.Schema != NativePushFormat || manifest.BackupID != request.BackupID ||
		manifest.AttemptID != request.AttemptID || manifest.DomainUUID != request.DomainUUID ||
		result.ManifestSHA256 != hex.EncodeToString(digest[:]) {
		return nil, fmt.Errorf("%w: helper result identity/digest mismatch", ErrNativeUncertain)
	}
	return &result, nil
}

// RestoreNativePush reconstructs accepted, ordered members into fresh raw
// disks, never alters the source files, and never defines/starts a live VM.
// Downloaded inputs must first pass their storage receipt/decryption checks.
func RestoreNativePush(ctx context.Context, members []NativeRestoreMember, outputPath string) ([]NativeRestoredDisk, error) {
	request := struct {
		Members    []NativeRestoreMember `json:"members"`
		OutputPath string                `json:"output_path"`
	}{members, outputPath}
	var result []NativeRestoredDisk
	if err := runNativeHelper(ctx, "restore", request, &result); err != nil {
		return nil, err
	}
	return result, nil
}

type nativeOutput struct {
	bytes.Buffer
	limit int
}

func (b *nativeOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("native helper output exceeds bound")
	}
	return b.Buffer.Write(p)
}

func runNativeHelper(ctx context.Context, action string, request, result any) error {
	return runNativeHelperSource(ctx, nativePushHelper, action, request, result)
}

func runNativeHelperSource(ctx context.Context, source, action string, request, result any) error {
	body, err := json.Marshal(struct {
		Action  string `json:"action"`
		Request any    `json:"request"`
	}{action, request})
	if err != nil || len(body) > 4*1024*1024 {
		return fmt.Errorf("%w: invalid native request", ErrNativeUncertain)
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", source)
	cmd.Stdin = bytes.NewReader(body)
	configureNativeHelperProcess(cmd)
	stdout := &nativeOutput{limit: 4 * 1024 * 1024}
	stderr := &nativeOutput{limit: 4096}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 5 * time.Second
	if err := runNativeHelperCommand(cmd); err != nil {
		return fmt.Errorf("%w: %v: %s", ErrNativeUncertain, err, stderr.String())
	}
	if err := models.DecodeStorageValue(stdout.Bytes(), result, 4*1024*1024); err != nil {
		return fmt.Errorf("%w: invalid helper response", ErrNativeUncertain)
	}
	return nil
}
