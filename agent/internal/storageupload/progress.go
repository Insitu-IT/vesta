package storageupload

import "vnbui/agent/internal/models"

// validateProgress checks the durable multipart state independently of the
// representation's ownership identity (validated by its enclosing journal).
func validateProgress(o ObjectState) error {
	size, err := plannedPartSize(o.Artifact, "")
	if err != nil || o.PartSize != size || o.Parts == nil || len(o.Parts) > 10000 || len(o.UploadID) > 2048 {
		return ErrHeld
	}
	switch o.Phase {
	case "planned", "create_intent", "uploading", "part_intent", "complete_intent", "complete":
	default:
		return ErrHeld
	}
	for n, p := range o.Parts {
		if p.Number != n+1 || p.Bytes < 0 || p.Bytes > int64(o.PartSize) || !validHash(p.SHA256) || p.ETag == "" || len(p.ETag) > 1024 {
			return ErrHeld
		}
	}
	if o.Phase == "planned" || o.Phase == "create_intent" {
		if o.UploadID != "" || len(o.Parts) != 0 || o.PendingPart != nil || o.Receipt != nil || o.Provider != nil {
			return ErrHeld
		}
	} else if o.UploadID == "" {
		return ErrHeld
	}
	if (o.Phase == "part_intent") != (o.PendingPart != nil) {
		return ErrHeld
	}
	if p := o.PendingPart; p != nil && (p.Number != len(o.Parts)+1 || p.Number > 10000 || p.Bytes < 0 || p.Bytes > int64(o.PartSize) || !validHash(p.SHA256) || p.ETag != "") {
		return ErrHeld
	}
	if (o.Phase == "complete_intent" || o.Phase == "complete") != (o.Receipt != nil) {
		return ErrHeld
	}
	if o.Receipt != nil {
		candidate := *o.Receipt
		if o.Phase == "complete_intent" && candidate.ETag == "" {
			candidate.ETag = "unconfirmed"
		}
		if models.ValidateStorageObject(o.Artifact, candidate) != nil {
			return ErrHeld
		}
		var total int64
		for _, p := range o.Parts {
			total += p.Bytes
		}
		if len(o.Parts) == 0 || total != candidate.CiphertextBytes {
			return ErrHeld
		}
	}
	if o.Phase == "complete" {
		if o.Receipt == nil || o.Provider == nil || o.UploadID == "" {
			return ErrHeld
		}
	} else if o.Assurance != "" {
		return ErrHeld
	}
	return nil
}
