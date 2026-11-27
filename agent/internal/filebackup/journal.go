package filebackup

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"vnbui/agent/internal/filearchive"
)

func (r *Runner) loadQueue() error {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return err
	}
	var queue []job
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".journal-") {
			if err := os.Remove(filepath.Join(r.dir, entry.Name())); err != nil {
				return err
			}
			continue
		}
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !validID(id) {
			continue
		}
		j, err := r.read(id)
		if err != nil {
			return fmt.Errorf("read managed file backup journal for %s: %w", id, err)
		}
		if j.terminal() {
			r.cleanup(id)
			continue
		}
		queue = append(queue, j)
	}
	slices.SortFunc(queue, func(a, b job) int {
		return cmp.Or(a.AcceptedAt.Compare(b.AcceptedAt), strings.Compare(a.BackupID, b.BackupID))
	})
	for _, j := range queue {
		r.queue = append(r.queue, j.BackupID)
		if !j.RetryAt.IsZero() {
			r.retries[j.BackupID] = j.RetryAt
		}
	}
	return nil
}

func (r *Runner) read(id string) (job, error) {
	f, err := os.Open(filepath.Join(r.dir, id+".json"))
	if err != nil {
		return job{}, err
	}
	defer f.Close()
	var j job
	decoder := json.NewDecoder(io.LimitReader(f, 64<<10))
	if err := decoder.Decode(&j); err != nil || decoder.Decode(new(any)) != io.EOF ||
		j.BackupID != id || !ValidName(j.FileSet) || j.AcceptedAt.IsZero() || j.ArchiveFormat != filearchive.Format {
		return job{}, errors.New("invalid managed file backup journal record")
	}
	if (j.PutPhase != "" && j.PutPhase != putReady && j.PutPhase != putPossible) ||
		(j.PutPhase != "" && (j.ArchiveSize <= 0 || j.ArchiveSHA == "")) ||
		(j.PutVersion != "" && (j.PutPhase != putPossible || !validVersion(j.PutVersion))) ||
		j.RetryCount > maxRetryCount || (j.RetryAt.IsZero() != (j.RetryCount == 0)) {
		return job{}, errors.New("invalid managed file backup custody state in journal")
	}
	switch j.Status {
	case "pending", "running", "completed", "failed":
		return j, nil
	default:
		return job{}, errors.New("invalid managed file backup status in journal")
	}
}

func (r *Runner) save(j job) error {
	f, err := os.CreateTemp(r.dir, ".journal-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := json.NewEncoder(f).Encode(j); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(r.dir, j.BackupID+".json")); err != nil {
		return err
	}
	return r.syncJournal()
}

func (r *Runner) syncJournal() error {
	dir, err := os.Open(r.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
