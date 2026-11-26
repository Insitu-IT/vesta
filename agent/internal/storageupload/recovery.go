package storageupload

import (
	"encoding/json"
	"os"
	"path/filepath"

	"vnbui/agent/internal/models"
)

// RecoverRequests reads current journals for a process that exclusively owns
// the journal root. It validates each complete durable record before returning
// its original request. It does not adopt older formats or infer work from S3.
func RecoverRequests(root string) ([][]byte, error) {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrHeld
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, ErrHeld
	}
	requests := make([][]byte, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, ErrHeld
		}
		j, err := lock(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, ErrHeld
		}
		request, err := recoveredRequest(j, entry.Name())
		var isRetired bool
		if err == nil {
			isRetired, _, err = retired(j)
		}
		closeErr := j.Close()
		if err != nil || closeErr != nil {
			return nil, ErrHeld
		}
		if !isRetired {
			requests = append(requests, request)
		}
	}
	return requests, nil
}

func recoveredRequest(j *Journal, reservation string) ([]byte, error) {
	data, err := j.read()
	if err != nil {
		return nil, err
	}
	var disk diskJournal
	// Recovery remains current-schema-only. decodeJournal also serves Open's
	// pre-existing migrations; those must not expand startup admission here.
	var header struct {
		State struct {
			Schema int `json:"schema"`
		} `json:"state"`
	}
	if json.Unmarshal(data, &header) != nil || header.State.Schema != 5 {
		return nil, ErrHeld
	}
	if decodeJournal(data, &disk) != nil || disk.State.Schema != 5 || disk.State.Request.ReservationID != reservation {
		return nil, ErrHeld
	}
	canonical, err := models.StorageCanonical(disk.State)
	if err != nil || digest(canonical) != disk.SHA256 {
		return nil, ErrHeld
	}
	j.state = disk.State
	if err := j.validate(); err != nil {
		return nil, err
	}
	j.last = data
	return json.Marshal(disk.State.Request)
}
