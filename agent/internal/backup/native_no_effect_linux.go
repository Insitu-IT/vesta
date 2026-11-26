//go:build linux

package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"
	"unicode/utf8"

	"vnbui/agent/internal/models"
)

type nativePreBeginRefusal struct {
	Schema        string `json:"schema"`
	RequestSHA256 string `json:"request_sha256"`
	BackupID      string `json:"backup_id"`
	AttemptID     string `json:"attempt_id"`
	DomainUUID    string `json:"domain_uuid"`
	Reason        string `json:"reason"`
}

// Missing evidence never means no effect. Only the helper's positive terminal
// refusal may settle, and any begin/admission/upload evidence contradicts it.
func readNativeNoEffect(path, uploadPath string, request NativePushRequest) (*nativePreBeginRefusal, error) {
	body, err := readNativeFile(filepath.Join(path, "prebegin-refusal.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrNativeUncertain
	}
	for _, name := range []string{filepath.Join(path, "begin-intent.json"), filepath.Join(path, "begin-returned.json"), filepath.Join(path, "producer-closed-failure.json"), filepath.Join(path, "producer-sealed.json"), filepath.Join(path, "admission.json"), filepath.Join(path, "data", "manifest.json"), uploadPath} {
		if _, err := os.Lstat(name); !os.IsNotExist(err) {
			return nil, ErrNativeUncertain
		}
	}
	intent, err := readNativeFile(filepath.Join(path, "intent.json"))
	var original NativePushRequest
	if err != nil || models.DecodeStorageValue(intent, &original, 4<<20) != nil || !reflect.DeepEqual(original, request) {
		return nil, ErrNativeUncertain
	}
	canonical, err := models.StorageCanonical(request)
	if err != nil || !bytes.Equal(intent, canonical) {
		return nil, ErrNativeUncertain
	}
	digest := sha256.Sum256(canonical)
	var proof nativePreBeginRefusal
	if models.DecodeStorageValue(body, &proof, 16<<10) != nil || proof.Schema != "libvirt-prebegin-refusal/1" ||
		proof.BackupID != request.BackupID || proof.AttemptID != request.AttemptID || proof.DomainUUID != request.DomainUUID ||
		proof.RequestSHA256 != hex.EncodeToString(digest[:]) || !utf8.ValidString(proof.Reason) || len([]rune(proof.Reason)) == 0 || len([]rune(proof.Reason)) > 2048 {
		return nil, ErrNativeUncertain
	}
	canonical, err = models.StorageCanonical(proof)
	if err != nil || !bytes.Equal(body, canonical) {
		return nil, ErrNativeUncertain
	}
	// A helper can fail after writing complete bytes but before its directory
	// fsync succeeds. Confirm durability ourselves before releasing remote
	// capacity, so restart cannot lose the fact which prevents producer replay.
	if syncNativeNoEffectFile(filepath.Join(path, "intent.json"), intent) != nil ||
		syncNativeNoEffectFile(filepath.Join(path, "prebegin-refusal.json"), body) != nil ||
		syncNativeDirectory(filepath.Dir(path)) != nil {
		return nil, ErrNativeUncertain
	}
	return &proof, nil
}

func syncNativeNoEffectFile(path string, expected []byte) error {
	file, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return ErrNativeUncertain
	}
	body, err := io.ReadAll(io.LimitReader(file, int64(len(expected))+1))
	if err != nil || !bytes.Equal(body, expected) {
		return ErrNativeUncertain
	}
	if err = file.Sync(); err != nil {
		return err
	}
	return syncNativeDirectory(filepath.Dir(path))
}

func (r *nativeRunner) finishNoEffect(ctx context.Context, work *nativeWork, proof *nativePreBeginRefusal) {
	intent, e1 := models.StorageCanonical(work.request.Intent)
	refusal, e2 := models.StorageCanonical(proof)
	if e1 != nil || e2 != nil {
		r.retain(work)
		return
	}
	digest := sha256.Sum256(refusal)
	binding := map[string]string{"intent_canonical": string(intent), "intent_sha256": work.request.IntentSHA256,
		"refusal_canonical": string(refusal), "refusal_sha256": hex.EncodeToString(digest[:])}
	r.finishNativeFailure(ctx, work, binding, false)
}

func (r *nativeRunner) finishNativeFailure(ctx context.Context, work *nativeWork, binding map[string]string, closed bool) {
	settle := r.settle
	message := "native pre-begin refusal settled; capacity released; local evidence retained"
	if closed {
		settle = r.settleClosed
		message = "native failed writer closure settled; capacity released; partial output retained; fresh full recommended"
	}
	r.finishNativeFailureWith(ctx, work, binding, settle, message)
}

func (r *nativeRunner) finishNativeFailureWith(ctx context.Context, work *nativeWork, binding map[string]string,
	settle func(context.Context, string, string, map[string]string, *http.Client, func(context.Context) (string, error)) error, message string) {
	credential := func(ctx context.Context) (string, error) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return r.executor.cfg.AgentAPIKey, nil
	}
	for ctx.Err() == nil {
		if settle != nil && settle(ctx, r.executor.cfg.OrchestratorURL, work.request.Intent.BackupID, binding, r.backend, credential) == nil {
			r.mu.Lock()
			work.finished, work.held = true, false
			r.mu.Unlock()
			r.progress(work, models.TaskStatusFailed, message)
			return
		}
		// Lost acknowledgements retry only this exact negative fact. This never
		// re-enters producer admission, libvirt or provider operations.
		delay := r.retry
		if delay >= time.Second {
			delay = 30 * time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			r.retain(work)
			return
		case <-timer.C:
		}
	}
	r.retain(work)
}
