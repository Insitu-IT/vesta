package storageupload

import (
	"bytes"
	"path/filepath"

	"vnbui/agent/internal/models"
)

// HoldStoppedPreNative seals a pristine KubeVirt payload journal after its
// caller has durably stopped the original producer before native preparation.
// It records local custody only. It does not prove remote absence or authorize
// release or retirement. A true eligibility result with an error means the
// original attempt must remain held even though this write was not confirmed.
func HoldStoppedPreNative(root string, request []byte) (eligible bool, err error) {
	r, err := models.DecodeStorageTransaction(request)
	if err != nil || r.Plan.Provider != "kubevirt" {
		return false, ErrHeld
	}
	j, err := lock(filepath.Join(root, r.ReservationID))
	if err != nil {
		return false, ErrHeld
	}
	defer j.Close()
	return holdStoppedPreNative(j, r.ReservationID, request)
}

func holdStoppedPreNative(j *Journal, reservation string, request []byte) (bool, error) {
	original, err := recoveredRequest(j, reservation)
	if err != nil || !bytes.Equal(original, request) || !pristinePreNative(&j.state) {
		return false, ErrHeld
	}
	if exists, _, err := retired(j); err != nil || exists {
		return false, ErrHeld
	}
	if j.state.Phase == "held" {
		return true, nil
	}
	j.state.Phase = "held"
	return true, j.save()
}

func pristinePreNative(s *State) bool {
	if s.Request.Plan.Provider != "kubevirt" || (s.Phase != "uploading" && s.Phase != "held") ||
		s.Native != nil || s.Utility != nil || s.Export != nil || len(s.Maps) != 0 ||
		s.Receipt != nil || s.Acceptance != nil || s.Finalize != nil || s.Compensation != nil {
		return false
	}
	for _, object := range s.Objects {
		if object.Phase != "planned" || object.UploadID != "" || len(object.Parts) != 0 ||
			object.PendingPart != nil || object.Receipt != nil || object.Provider != nil || object.Assurance != "" {
			return false
		}
	}
	return true
}
