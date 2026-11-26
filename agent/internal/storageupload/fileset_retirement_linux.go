//go:build linux

package storageupload

import (
	"os"
	"path/filepath"

	"vnbui/agent/internal/models"
)

// nativeRetirementJournal validates the complete native journal without
// reopening it through the resumable-upload path or changing a single byte.
func nativeRetirementJournal(root, attempt string) (*FileSetJournal, error) {
	if !validCanonicalUUID(attempt) {
		return nil, ErrHeld
	}
	s, err := lock(filepath.Join(root, attempt))
	if err != nil {
		return nil, ErrHeld
	}
	fail := func() (*FileSetJournal, error) { _ = s.Close(); return nil, ErrHeld }
	data, err := s.read()
	if err != nil {
		return fail()
	}
	var disk struct {
		SHA256 string       `json:"sha256"`
		State  fileSetState `json:"state"`
	}
	if models.DecodeStorageValue(data, &disk, MaxJournalBytes) != nil {
		return fail()
	}
	canonical, err := models.StorageCanonical(disk.State)
	j := &FileSetJournal{store: s, state: disk.State}
	if err != nil || disk.SHA256 != digest(canonical) || j.validate() != nil ||
		j.state.Request.ReservationID != attempt ||
		!((j.state.Phase == "held" && j.state.Acceptance == nil) ||
			(j.state.Phase == "accepted" && j.state.Acceptance != nil)) {
		return fail()
	}
	// The public runner requires stopped held work and a backend-verified owner
	// release. Receipt acceptance is not generation publication. Adapt only the
	// non-persisted retirement view; validate and preserve the full original
	// native representation, including any accepted receipt, above.
	r := j.state.Request
	s.state = State{Phase: "held", Request: models.StorageTransactionRequest{
		OrgID: r.OrgID, BackupID: r.BackupID, ReservationID: r.ReservationID,
		PlanSHA256: r.PlanSHA256, Plan: models.StorageTransactionPlan{AttemptID: r.Plan.AttemptID},
	}}
	return j, nil
}

// NativeHeldJournalIdentity supplies only non-secret binding for a reviewed
// backend proof. It grants no release or retry authority.
func NativeHeldJournalIdentity(root, attempt, org, agent, backup string) (RetirementProof, error) {
	j, err := nativeRetirementJournal(root, attempt)
	if err != nil {
		return RetirementProof{}, ErrHeld
	}
	defer j.Close()
	if r := j.state.Request; r.OrgID != org || r.AgentID != agent || r.BackupID != backup {
		return RetirementProof{}, ErrHeld
	}
	if exists, _, err := retired(j.store); err != nil || exists {
		return RetirementProof{}, ErrHeld
	}
	data, err := j.store.read()
	if err != nil {
		return RetirementProof{}, ErrHeld
	}
	r := j.state.Request
	return RetirementProof{Schema: 1, OrgID: r.OrgID, BackupID: r.BackupID,
		ReservationID: r.ReservationID, AttemptID: r.Plan.AttemptID,
		PlanSHA256: r.PlanSHA256, JournalSHA256: digest(data)}, nil
}

func RetireNativeFileSet(root, attempt string, proof RetirementProof) error {
	j, err := nativeRetirementJournal(root, attempt)
	if err != nil {
		return ErrHeld
	}
	defer j.Close()
	return writeRetirement(j.store, proof)
}

// NativeFileSetRetired checks an append-only tombstone and its original held
// journal. Corruption is an error, never permission to run the attempt again.
func NativeFileSetRetired(root, attempt, org, agent, backup string) (bool, RetirementProof, error) {
	if !validCanonicalUUID(attempt) {
		return false, RetirementProof{}, ErrHeld
	}
	path := filepath.Join(root, attempt, retirementFile)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return false, RetirementProof{}, nil
	} else if err != nil {
		return false, RetirementProof{}, ErrHeld
	}
	j, err := nativeRetirementJournal(root, attempt)
	if err != nil {
		return false, RetirementProof{}, ErrHeld
	}
	defer j.Close()
	if r := j.state.Request; r.OrgID != org || r.AgentID != agent || r.BackupID != backup {
		return false, RetirementProof{}, ErrHeld
	}
	exists, record, err := retired(j.store)
	return exists, record.Proof, err
}
