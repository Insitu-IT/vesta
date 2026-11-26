//go:build linux

package storageupload

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
)

// FileSetJournal is an explicit native representation using the same exclusive
// checksum/fsync journal and streaming engine. It grants no native job launch,
// completion, checkpoint or deletion authority.
type FileSetJournal struct {
	store *Journal
	state fileSetState
}

type fileSetObject struct {
	Artifact    models.NativeStorageArtifact       `json:"artifact"`
	Phase       string                             `json:"phase"`
	PartSize    int                                `json:"part_size"`
	UploadID    string                             `json:"upload_id"`
	Parts       []Part                             `json:"parts"`
	PendingPart *Part                              `json:"pending_part"`
	Receipt     *models.NativeStorageObjectReceipt `json:"receipt"`
	Provider    *ObjectInfo                        `json:"provider"`
	Assurance   string                             `json:"assurance"`
}

type fileSetState struct {
	Schema     int                             `json:"schema"`
	Request    models.NativeTransactionRequest `json:"request"`
	Phase      string                          `json:"phase"`
	Objects    []fileSetObject                 `json:"objects"`
	Receipt    *models.NativeStorageReceipt    `json:"receipt"`
	Acceptance *models.StorageAcceptance       `json:"acceptance"`
}

func fileBounds(a models.NativeStorageArtifact) models.StorageArtifact {
	// Internal stream bounds only, never a wire plan or persisted identity.
	return models.StorageArtifact{Key: a.Key, Role: a.Role, PlaintextMin: a.PlaintextMin,
		PlaintextMax: a.PlaintextMax, CiphertextMin: a.CiphertextMin, CiphertextMax: a.CiphertextMax}
}

func fileMetadata(r *models.NativeTransactionRequest, a models.NativeStorageArtifact) map[string]string {
	return map[string]string{"vnbui-protocol": "1", "vnbui-org-id": r.OrgID,
		"vnbui-backup-id": r.BackupID, "vnbui-reservation-id": r.ReservationID,
		"vnbui-plan-sha256": r.PlanSHA256, "vnbui-artifact-id": a.ArtifactID}
}

func (o fileSetObject) progress() ObjectState {
	p := ObjectState{Artifact: fileBounds(o.Artifact), Phase: o.Phase, PartSize: o.PartSize,
		UploadID: o.UploadID, Parts: o.Parts, PendingPart: o.PendingPart, Provider: o.Provider, Assurance: o.Assurance}
	if r := o.Receipt; r != nil {
		p.Receipt = &models.StorageObjectReceipt{Key: r.Key, Role: r.Role, VersionID: r.VersionID,
			ETag: r.ETag, PlaintextBytes: r.PlaintextBytes, CiphertextBytes: r.CiphertextBytes,
			PlaintextSHA256: r.PlaintextSHA256, CiphertextSHA256: r.CiphertextSHA256}
	}
	return p
}

func (o *fileSetObject) record(p ObjectState) {
	o.Phase = p.Phase
	o.PartSize = p.PartSize
	o.UploadID = p.UploadID
	o.Parts = p.Parts
	o.PendingPart = p.PendingPart
	o.Provider = p.Provider
	o.Assurance = p.Assurance
	if r := p.Receipt; r != nil {
		o.Receipt = &models.NativeStorageObjectReceipt{ArtifactID: o.Artifact.ArtifactID, DiskID: o.Artifact.DiskID,
			Role: o.Artifact.Role, Key: r.Key, VersionID: r.VersionID, ETag: r.ETag, PlaintextBytes: r.PlaintextBytes,
			CiphertextBytes: r.CiphertextBytes, PlaintextSHA256: r.PlaintextSHA256, CiphertextSHA256: r.CiphertextSHA256}
	}
}

func NewNativeControlledS3(request []byte, base string, client, provider *http.Client, agentKey func(context.Context) (string, error)) (*ControlledS3, error) {
	r, err := nativefileset.DecodeTransaction(request)
	if err != nil {
		return nil, ErrHeld
	}
	s, err := newControlledS3(base, client, provider, agentKey)
	if err != nil {
		return nil, err
	}
	s.reservation = r.ReservationID
	s.attempt = r.Plan.AttemptID
	s.planHash = r.PlanSHA256
	s.backup = r.BackupID
	s.target = r.Plan.Target
	s.encryption = r.Plan.Encryption
	for _, a := range r.Plan.Artifacts {
		s.keys[a.Key] = fileBounds(a)
		s.metadata[a.Key] = fileMetadata(r, a)
	}
	return s, nil
}

func CreateFileSet(root string, request []byte) (*FileSetJournal, error) {
	r, err := nativefileset.DecodeTransaction(request)
	if err != nil {
		return nil, ErrHeld
	}
	dir := filepath.Join(root, r.ReservationID)
	if os.Mkdir(dir, 0700) != nil {
		return nil, ErrHeld
	}
	parent, err := os.Open(root)
	if err != nil {
		return nil, ErrHeld
	}
	err = parent.Sync()
	closeErr := parent.Close()
	if err != nil || closeErr != nil {
		return nil, ErrHeld
	}
	s, err := lock(dir)
	if err != nil {
		return nil, err
	}
	j := &FileSetJournal{store: s, state: fileSetState{Schema: 6, Request: *r, Phase: "uploading", Objects: []fileSetObject{}}}
	for _, a := range r.Plan.Artifacts {
		size, e := plannedPartSize(fileBounds(a), "")
		if e != nil {
			_ = s.Close()
			return nil, e
		}
		j.state.Objects = append(j.state.Objects, fileSetObject{Artifact: a, Phase: "planned", PartSize: size, Parts: []Part{}})
	}
	if err = j.save(); err != nil {
		_ = s.Close()
		return nil, err
	}
	return j, nil
}

func OpenFileSet(root string, request []byte) (*FileSetJournal, error) {
	r, err := nativefileset.DecodeTransaction(request)
	if err != nil {
		return nil, ErrHeld
	}
	return openFileSet(root, r.ReservationID, func(got models.NativeTransactionRequest) bool { return reflect.DeepEqual(got, *r) })
}

func openFileSet(root, attempt string, bound func(models.NativeTransactionRequest) bool) (*FileSetJournal, error) {
	s, err := lock(filepath.Join(root, attempt))
	if err != nil {
		return nil, err
	}
	fail := func() (*FileSetJournal, error) { _ = s.Close(); return nil, ErrHeld }
	data, err := s.read()
	if err != nil {
		return fail()
	}
	var d struct {
		SHA256 string       `json:"sha256"`
		State  fileSetState `json:"state"`
	}
	if models.DecodeStorageValue(data, &d, MaxJournalBytes) != nil || !bound(d.State.Request) {
		return fail()
	}
	b, err := models.StorageCanonical(d.State)
	if err != nil || digest(b) != d.SHA256 {
		return fail()
	}
	j := &FileSetJournal{store: s, state: d.State}
	s.last = data
	if j.validate() != nil {
		return fail()
	}
	for _, o := range j.state.Objects {
		if o.Phase != "planned" && o.Phase != "complete" {
			j.state.Phase = "held"
		}
	}
	if j.save() != nil {
		return fail()
	}
	return j, nil
}

func (j *FileSetJournal) Close() error { return j.store.Close() }
func (j *FileSetJournal) save() error  { return j.store.persist(j.state, j.validate) }

func (j *FileSetJournal) Submit(ctx context.Context, base string, client *http.Client, agentKey func(context.Context) (string, error)) (*models.StorageAcceptance, error) {
	j.store.mu.Lock()
	defer j.store.mu.Unlock()
	if j.store.poisoned || (j.state.Phase != "prepared" && j.state.Phase != "submitting" && j.state.Phase != "accepted") {
		return nil, ErrHeld
	}
	if j.state.Phase == "accepted" {
		if j.save() != nil {
			return nil, ErrHeld
		}
		return copyAcceptance(j.state.Acceptance), nil
	}
	body, _, err := j.canonicalReceipt()
	if err != nil {
		return nil, ErrHeld
	}
	j.state.Phase = "submitting"
	if j.save() != nil {
		return nil, ErrHeld
	}
	response, err := submitReceipt(ctx, base, client, agentKey, j.state.Request.BackupID, body)
	if err != nil {
		return nil, err
	}
	a, err := j.acceptance(response)
	if err != nil {
		return nil, ErrHeld
	}
	j.state.Acceptance = a
	j.state.Phase = "accepted"
	if j.save() != nil {
		return nil, ErrHeld
	}
	return copyAcceptance(a), nil
}

func (j *FileSetJournal) canonicalReceipt() ([]byte, string, error) {
	if j.state.Receipt == nil {
		return nil, "", ErrHeld
	}
	r := j.state.Request
	return nativefileset.CanonicalReceipt(*j.state.Receipt, r.Plan.Artifacts, r.BackupID, r.ReservationID, r.Plan.Target, r.Plan.Encryption)
}

func (j *FileSetJournal) acceptance(body []byte) (*models.StorageAcceptance, error) {
	_, hash, err := j.canonicalReceipt()
	if err != nil {
		return nil, ErrHeld
	}
	objects := map[string]*string{}
	for _, o := range j.state.Receipt.Objects {
		objects[o.Key] = o.VersionID
	}
	return models.DecodeReceiptAcceptance(body, j.state.Request.ReservationID, hash, j.state.Request.Plan.CapabilityProfile, objects)
}

func (j *FileSetJournal) validate() error {
	s := &j.state
	body, _ := json.Marshal(s.Request)
	if _, err := nativefileset.DecodeTransaction(body); err != nil || s.Schema != 6 || len(s.Objects) != len(s.Request.Plan.Artifacts) {
		return ErrHeld
	}
	switch s.Phase {
	case "uploading", "prepared", "submitting", "accepted", "held":
	default:
		return ErrHeld
	}
	for i, o := range s.Objects {
		if !reflect.DeepEqual(o.Artifact, s.Request.Plan.Artifacts[i]) {
			return ErrHeld
		}
		p := o.progress()
		if validateProgress(p) != nil {
			return ErrHeld
		}
		if o.Receipt != nil && (o.Receipt.ArtifactID != o.Artifact.ArtifactID || !reflect.DeepEqual(o.Receipt.DiskID, o.Artifact.DiskID)) {
			return ErrHeld
		}
		if o.Phase == "complete" && (!validObjectHead(p, fileMetadata(&s.Request, o.Artifact)) || o.Assurance != assurance(s.Request.Plan.CapabilityProfile, *o.Provider)) {
			return ErrHeld
		}
	}
	if s.Receipt != nil {
		if _, _, err := j.canonicalReceipt(); err != nil {
			return ErrHeld
		}
		for i, o := range s.Objects {
			if o.Phase != "complete" || !reflect.DeepEqual(*o.Receipt, s.Receipt.Objects[i]) {
				return ErrHeld
			}
		}
	}
	if (s.Phase == "prepared" || s.Phase == "submitting" || s.Phase == "accepted") && s.Receipt == nil {
		return ErrHeld
	}
	if s.Acceptance != nil {
		b, _ := json.Marshal(s.Acceptance)
		if _, err := j.acceptance(b); err != nil {
			return ErrHeld
		}
	}
	if s.Phase == "accepted" && s.Acceptance == nil {
		return ErrHeld
	}
	return nil
}

// UploadClosedTree never launches a job. A descriptor is pinned before the
// first mutation and validates its committed custody at EOF. Completed objects
// and accepted/prepared replay never reopen an artifact body.
func (j *FileSetJournal) UploadClosedTree(ctx context.Context, p Provider, root string, key []byte) (err error) {
	j.store.mu.Lock()
	defer j.store.mu.Unlock()
	if j.store.poisoned || j.state.Phase == "held" || !reflect.DeepEqual(p.Target(), j.state.Request.Plan.Target) {
		return ErrHeld
	}
	if j.state.Phase == "prepared" || j.state.Phase == "submitting" || j.state.Phase == "accepted" {
		return j.save()
	}
	encrypted := j.state.Request.Plan.Encryption.Format != "none"
	if encrypted && len(key) != 32 || !encrypted && len(key) != 0 {
		return ErrHeld
	}
	inventory := j.state.Request.Plan.Source.Inventory
	if nativefileset.CheckTree(root, inventory) != nil {
		return ErrHeld
	}
	files := map[string]models.NativeFile{}
	for _, f := range inventory.Files {
		files[f.ArtifactID] = f
	}
	defer func() {
		if err != nil {
			j.state.Phase = "held"
			_ = j.save()
		}
	}()
	for i := range j.state.Objects {
		o := &j.state.Objects[i]
		if o.Phase == "complete" {
			continue
		}
		if o.Phase != "planned" {
			return ErrHeld
		}
		if nativefileset.CheckTree(root, inventory) != nil || j.save() != nil {
			return ErrHeld
		}
		f, e := nativefileset.OpenForUpload(root, files[o.Artifact.ArtifactID])
		if e != nil {
			return ErrHeld
		}
		progress := o.progress()
		e = streamObject(ctx, p, &progress, f, key, encrypted, fileMetadata(&j.state.Request, o.Artifact), j.state.Request.Plan.CapabilityProfile, func() error { o.record(progress); return j.save() })
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			return ErrHeld
		}
	}
	if nativefileset.CheckTree(root, inventory) != nil {
		return ErrHeld
	}
	r := models.NativeStorageReceipt{Protocol: models.StorageProtocol, Schema: 2, Representation: models.NativeFileSetFormat,
		ReservationID: j.state.Request.ReservationID, BackupID: j.state.Request.BackupID, Endpoint: p.Target().Endpoint, Bucket: p.Target().Bucket, Objects: []models.NativeStorageObjectReceipt{}}
	for _, o := range j.state.Objects {
		r.Objects = append(r.Objects, *o.Receipt)
	}
	j.state.Receipt = &r
	j.state.Phase = "prepared"
	return j.save()
}
