//go:build linux

package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"vnbui/agent/internal/models"
)

type nativeFailureArtifact struct {
	Path    string `json:"path"`
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
	Size    int64  `json:"size"`
	MtimeNS int64  `json:"mtime_ns"`
	CtimeNS int64  `json:"ctime_ns"`
}

type nativeFailureEvent struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func (r *nativeRunner) finishClosedFailure(ctx context.Context, work *nativeWork, proof *nativeClosedFailure) {
	intent, e1 := models.StorageCanonical(work.request.Intent)
	closure, e2 := models.StorageCanonical(proof)
	if e1 != nil || e2 != nil {
		r.retain(work)
		return
	}
	digest := sha256.Sum256(closure)
	binding := map[string]string{"intent_canonical": string(intent), "intent_sha256": work.request.IntentSHA256,
		"closure_canonical": string(closure), "closure_sha256": hex.EncodeToString(digest[:])}
	r.finishNativeFailure(ctx, work, binding, true)
}

type nativeClosedFailure struct {
	Schema         string                  `json:"schema"`
	RequestSHA256  string                  `json:"request_sha256"`
	BackupID       string                  `json:"backup_id"`
	AttemptID      string                  `json:"attempt_id"`
	DomainUUID     string                  `json:"domain_uuid"`
	InvocationID   string                  `json:"invocation_id"`
	BeginAckSHA256 string                  `json:"begin_ack_sha256"`
	JobIDs         []string                `json:"job_ids"`
	TerminalEvents []nativeFailureEvent    `json:"terminal_events"`
	Artifacts      []nativeFailureArtifact `json:"artifacts"`
}

type nativeBeginReturned struct {
	Schema        string              `json:"schema"`
	RequestSHA256 string              `json:"request_sha256"`
	JobIDs        []string            `json:"job_ids"`
	Targets       map[string][]uint64 `json:"targets"`
}

// validNativeFailureEvents proves terminal writers, not successful image data.
// A reused pinned ID or incomplete cycle cannot become failure settlement.
func validNativeFailureEvents(jobs []string, events []nativeFailureEvent) bool {
	if len(jobs) == 0 || len(jobs) > 128 || len(events) == 0 || len(events) > 8192 || !sort.StringsAreSorted(jobs) {
		return false
	}
	states := map[string]string{}
	for _, id := range jobs {
		if id == "" || len(id) > 512 {
			return false
		}
		if _, ok := states[id]; ok {
			return false
		}
		states[id] = ""
	}
	transitions := map[string][]string{
		"": {"created"}, "created": {"running", "aborting"},
		"running": {"paused", "waiting", "pending", "aborting", "concluded"},
		"paused":  {"running", "aborting"}, "waiting": {"pending", "aborting", "concluded"},
		"pending": {"aborting", "concluded"}, "aborting": {"concluded"}, "concluded": {"null"},
	}
	for _, event := range events {
		old, ok := states[event.ID]
		if !ok {
			return false
		}
		allowed := false
		for _, next := range transitions[old] {
			if event.Status == next {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
		states[event.ID] = event.Status
	}
	for _, state := range states {
		if state != "null" {
			return false
		}
	}
	return true
}

// readNativeClosedFailure never relaunches a producer, mutates libvirt, uploads
// partial data or releases capacity. It confirms only the original acknowledged
// begin and continuously observed terminal cycles, with private output retained.
func readNativeClosedFailure(path, uploadPath string, request NativePushRequest) (*nativeClosedFailure, error) {
	body, err := readNativeFile(filepath.Join(path, "producer-closed-failure.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || len(body) > models.MaxStorageRequestBytes {
		return nil, ErrNativeUncertain
	}
	for _, directory := range []string{path, filepath.Join(path, "data")} {
		resolved, err := filepath.EvalSymlinks(directory)
		if err != nil || resolved != directory {
			return nil, ErrNativeUncertain
		}
	}
	for _, name := range []string{filepath.Join(path, "prebegin-refusal.json"), filepath.Join(path, "producer-sealed.json"), filepath.Join(path, "admission.json"), filepath.Join(path, "published.json"), uploadPath} {
		if _, err := os.Lstat(name); !os.IsNotExist(err) {
			return nil, ErrNativeUncertain
		}
	}
	canonical, err := models.StorageCanonical(request)
	if err != nil {
		return nil, ErrNativeUncertain
	}
	intent, err := readNativeFile(filepath.Join(path, "intent.json"))
	if err != nil || !bytes.Equal(intent, canonical) {
		return nil, ErrNativeUncertain
	}
	hash := sha256.Sum256(canonical)
	requestSHA := hex.EncodeToString(hash[:])
	begin, err := readNativeFile(filepath.Join(path, "begin-intent.json"))
	expectedBegin, _ := models.StorageCanonical(map[string]string{"schema": "libvirt-begin-intent/1", "request_sha256": requestSHA})
	if err != nil || !bytes.Equal(begin, expectedBegin) {
		return nil, ErrNativeUncertain
	}
	uncertain, err := readNativeFile(filepath.Join(path, "uncertain.json"))
	var failure struct {
		State  string `json:"state"`
		Reason string `json:"reason"`
	}
	if err != nil || models.DecodeStorageValue(uncertain, &failure, 16<<10) != nil || failure.State != "uncertain" {
		return nil, ErrNativeUncertain
	}
	var proof nativeClosedFailure
	if models.DecodeStorageValue(body, &proof, models.MaxStorageRequestBytes) != nil || proof.Schema != "libvirt-closed-failure/1" || proof.RequestSHA256 != requestSHA ||
		proof.BackupID != request.BackupID || proof.AttemptID != request.AttemptID || proof.DomainUUID != request.DomainUUID ||
		!regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(proof.InvocationID) || !validNativeFailureEvents(proof.JobIDs, proof.TerminalEvents) {
		return nil, ErrNativeUncertain
	}
	saved, err := models.StorageCanonical(proof)
	if err != nil || !bytes.Equal(body, saved) {
		return nil, ErrNativeUncertain
	}
	ack, err := readNativeFile(filepath.Join(path, "begin-returned.json"))
	if err != nil {
		return nil, ErrNativeUncertain
	}
	var returned nativeBeginReturned
	if models.DecodeStorageValue(ack, &returned, models.MaxStorageRequestBytes) != nil || returned.Schema != "libvirt-begin-returned/1" || returned.RequestSHA256 != requestSHA || !reflect.DeepEqual(returned.JobIDs, proof.JobIDs) {
		return nil, ErrNativeUncertain
	}
	saved, err = models.StorageCanonical(returned)
	ackHash := sha256.Sum256(ack)
	if err != nil || !bytes.Equal(ack, saved) || hex.EncodeToString(ackHash[:]) != proof.BeginAckSHA256 {
		return nil, ErrNativeUncertain
	}
	selected := map[string]bool{}
	excluded := map[string]bool{}
	for _, name := range request.Exclusions {
		excluded[name] = true
	}
	for _, disk := range request.Disks {
		if !excluded[disk.Target] {
			selected[disk.Target] = true
		}
	}
	if len(selected) == 0 || len(returned.Targets) != len(selected) || len(proof.Artifacts) != len(selected) || len(proof.JobIDs) != len(selected) {
		return nil, ErrNativeUncertain
	}
	seen := map[string]bool{}
	for _, artifact := range proof.Artifacts {
		target := strings.TrimSuffix(artifact.Path, ".qcow2")
		identity := returned.Targets[target]
		if !selected[target] || artifact.Path != target+".qcow2" || seen[target] || len(identity) != 2 || artifact.Device != identity[0] || artifact.Inode != identity[1] || artifact.Inode == 0 || artifact.Size < 0 {
			return nil, ErrNativeUncertain
		}
		seen[target] = true
		file, err := os.OpenFile(filepath.Join(path, "data", artifact.Path), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, ErrNativeUncertain
		}
		info, statErr := file.Stat()
		valid := statErr == nil && info.Mode().IsRegular()
		if valid {
			st, ok := info.Sys().(*syscall.Stat_t)
			valid = ok && st.Nlink == 1 && uint64(st.Dev) == artifact.Device && st.Ino == artifact.Inode && st.Size == artifact.Size && st.Mtim.Nano() == artifact.MtimeNS && st.Ctim.Nano() == artifact.CtimeNS
		}
		if valid {
			valid = file.Sync() == nil
		}
		closeErr := file.Close()
		if !valid || closeErr != nil {
			return nil, ErrNativeUncertain
		}
	}
	for name, content := range map[string][]byte{"intent.json": intent, "begin-intent.json": begin, "begin-returned.json": ack, "uncertain.json": uncertain, "producer-closed-failure.json": body} {
		if syncNativeNoEffectFile(filepath.Join(path, name), content) != nil {
			return nil, ErrNativeUncertain
		}
	}
	if syncNativeDirectory(filepath.Join(path, "data")) != nil || syncNativeDirectory(filepath.Dir(path)) != nil {
		return nil, ErrNativeUncertain
	}
	return &proof, nil
}
