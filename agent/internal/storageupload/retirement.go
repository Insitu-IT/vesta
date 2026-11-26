package storageupload

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"vnbui/agent/internal/models"
)

const retirementFile = "retirement.json"

// HeldJournalSHA256 reads the exact durable journal bytes that a reviewed
// release must name. It does not mutate or retire the attempt.
func HeldJournalSHA256(root string, request []byte) (string, error) {
	r, err := models.DecodeStorageTransaction(request)
	if err != nil {
		return "", ErrHeld
	}
	j, err := lock(filepath.Join(root, r.ReservationID))
	if err != nil {
		return "", ErrHeld
	}
	defer j.Close()
	original, err := recoveredRequest(j, r.ReservationID)
	if err != nil || !bytes.Equal(original, request) || !retirementEligible(&j.state) {
		return "", ErrHeld
	}
	if exists, _, err := retired(j); err != nil || exists {
		return "", ErrHeld
	}
	journal, err := j.read()
	if err != nil {
		return "", ErrHeld
	}
	return digest(journal), nil
}

// RetirementProof is nonsecret evidence of a separately authorized database
// release. The caller must verify that release against the original backup and
// capacity before invoking Retire; this primitive grants no review authority.
type RetirementProof struct {
	Schema        int    `json:"schema"`
	OrgID         string `json:"org_id"`
	BackupID      string `json:"backup_id"`
	ReservationID string `json:"reservation_id"`
	AttemptID     string `json:"attempt_id"`
	PlanSHA256    string `json:"plan_sha256"`
	OperationID   string `json:"operation_id"`
	CapacityID    string `json:"capacity_id"`
	JournalSHA256 string `json:"journal_sha256"`
	ReleaseSHA256 string `json:"release_sha256"`
}

type retirementRecord struct {
	Proof         RetirementProof `json:"proof"`
	JournalSHA256 string          `json:"journal_sha256"`
}

type diskRetirement struct {
	SHA256 string           `json:"sha256"`
	Record retirementRecord `json:"record"`
}

func validRetirement(record retirementRecord, state State, journal []byte) bool {
	p, r := record.Proof, state.Request
	return retirementEligible(&state) &&
		p.Schema == 1 && p.OrgID == r.OrgID && p.BackupID == r.BackupID &&
		p.ReservationID == r.ReservationID && p.AttemptID == r.Plan.AttemptID &&
		p.PlanSHA256 == r.PlanSHA256 && validHash(p.PlanSHA256) &&
		validCanonicalUUID(p.OperationID) && validCanonicalUUID(p.CapacityID) &&
		validHash(p.ReleaseSHA256) && validHash(p.JournalSHA256) &&
		p.JournalSHA256 == record.JournalSHA256 && record.JournalSHA256 == digest(journal)
}

// Receipt acceptance is not publication. An irreversible, settled pre-finalize
// abort can obtain a separate owner-reviewed release without discarding its
// accepted receipt. Ordinary accepted/finalizing attempts remain ineligible.
func retirementEligible(state *State) bool {
	if state.Phase != "held" {
		return false
	}
	if state.Acceptance == nil {
		return state.Compensation == nil
	}
	return state.Compensation != nil && state.Compensation.S3Absent && validCompensation(state)
}

func validCanonicalUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}

// retired validates both the immutable original journal and a complete
// append-only tombstone. Missing means active; malformed means hold the entire
// journal root rather than silently making an old attempt runnable again.
func retired(j *Journal) (bool, retirementRecord, error) {
	path := filepath.Join(filepath.Dir(j.path), retirementFile)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, retirementRecord{}, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 16<<10 {
		return false, retirementRecord{}, ErrHeld
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 16<<10 {
		return false, retirementRecord{}, ErrHeld
	}
	var disk diskRetirement
	if models.DecodeStorageValue(data, &disk, 16<<10) != nil {
		return false, retirementRecord{}, ErrHeld
	}
	canonical, err := models.StorageCanonical(disk.Record)
	journal, readErr := j.read()
	if err != nil || readErr != nil || disk.SHA256 != digest(canonical) ||
		!validRetirement(disk.Record, j.state, journal) {
		return false, retirementRecord{}, ErrHeld
	}
	return true, disk.Record, nil
}

// Retire appends a durable tombstone without deleting or rewriting the held
// journal. Recovery skips it; an old attempt ID still cannot be created again.
// Only a caller that has verified a reviewed terminal database release may
// supply proof. It must also ensure no producer is concurrently active.
func Retire(root string, request []byte, proof RetirementProof) error {
	r, err := models.DecodeStorageTransaction(request)
	if err != nil {
		return ErrHeld
	}
	j, err := lock(filepath.Join(root, r.ReservationID))
	if err != nil {
		return ErrHeld
	}
	defer j.Close()
	original, err := recoveredRequest(j, r.ReservationID)
	if err != nil || !bytes.Equal(original, request) {
		return ErrHeld
	}
	return writeRetirement(j, proof)
}

func writeRetirement(j *Journal, proof RetirementProof) error {
	journal, err := j.read()
	if err != nil {
		return ErrHeld
	}
	record := retirementRecord{Proof: proof, JournalSHA256: digest(journal)}
	if !validRetirement(record, j.state, journal) {
		return ErrHeld
	}
	if exists, prior, err := retired(j); err != nil {
		return ErrHeld
	} else if exists {
		if prior == record {
			return nil
		}
		return ErrHeld
	}
	canonical, err := models.StorageCanonical(record)
	if err != nil {
		return ErrHeld
	}
	data, err := json.Marshal(diskRetirement{SHA256: digest(canonical), Record: record})
	if err != nil || len(data) > 16<<10 {
		return ErrHeld
	}
	file, err := os.CreateTemp(filepath.Dir(j.path), ".retirement-")
	if err != nil {
		return ErrHeld
	}
	defer os.Remove(file.Name())
	if _, err = io.Copy(file, bytes.NewReader(data)); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return ErrHeld
	}
	path := filepath.Join(filepath.Dir(j.path), retirementFile)
	if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return ErrHeld
	}
	if err = os.Rename(file.Name(), path); err != nil || j.dir.Sync() != nil {
		return ErrHeld
	}
	return nil
}
