package storageupload

import "time"

// BorrowedUtility is a read-only observation of an embedded VMI attachment.
// It conveys neither Kubernetes object ownership nor detach/delete authority.
// ReadOnly is the controller's PVC mount flag, not agent mutation permission.
type BorrowedUtility struct {
	VMIUID     string `json:"vmi_uid"`
	TrackerUID string `json:"tracker_uid"`
	BackupUID  string `json:"backup_uid"`
	ScratchUID string `json:"scratch_uid"`
	Name       string `json:"name"`
	ClaimName  string `json:"claim_name"`
	Type       string `json:"type"`
	ReadOnly   bool   `json:"read_only"`
	StartedAt  string `json:"started_at"`
	BackupType string `json:"backup_type"`
}

func validUtility(u *BorrowedUtility, s *State) bool {
	if s.Native == nil || s.Request.Plan.Source.VMIUID == nil || len(s.Native.Objects) != 3 {
		return false
	}
	n := s.Native
	stamp, err := time.Parse(time.RFC3339Nano, u.StartedAt)
	if err != nil || stamp.IsZero() || stamp.UTC().Format(time.RFC3339Nano) != u.StartedAt || u.BackupType != s.Request.Plan.BackupType {
		return false
	}
	return n.Objects[0].Phase == "observed" && n.Objects[1].Phase == "observed" &&
		u.VMIUID == *s.Request.Plan.Source.VMIUID && u.TrackerUID == n.Objects[0].UID &&
		u.BackupUID == n.Objects[1].UID && u.ScratchUID == n.ScratchUID &&
		u.ClaimName == n.ScratchName && nativeID(u.Name) && u.Name == n.Objects[1].Name+"-backup-target-pvc" && u.Type == "Backup" && !u.ReadOnly
}

// BindUtility commits the first admitted projection before another unsafe
// operation. Re-observation is idempotent; no replacement/reset is permitted.
func (j *Journal) BindUtility(u BorrowedUtility) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned || j.state.Phase != "uploading" || !validUtility(&u, &j.state) {
		return ErrHeld
	}
	if j.state.Utility != nil && *j.state.Utility != u {
		return ErrHeld
	}
	j.state.Utility = &u
	return j.save()
}
