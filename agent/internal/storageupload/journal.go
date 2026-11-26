// Package storageupload is the held transaction/1 uploader primitive shared by
// future KubeVirt and local-file producers. It never starts a backup or finalizes
// a checkpoint. The legacy offset-resume journal is deliberately not adopted.
package storageupload

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"time"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/metrics"
	"vnbui/agent/internal/models"
)

const MaxJournalBytes = 16 * 1024 * 1024

var ErrHeld = errors.New("storage transaction held; retain journal for exact reconciliation")

type Part struct {
	Number int    `json:"number"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	ETag   string `json:"etag"`
}

type ObjectState struct {
	Artifact    models.StorageArtifact       `json:"artifact"`
	Phase       string                       `json:"phase"`
	PartSize    int                          `json:"part_size"`
	UploadID    string                       `json:"upload_id"`
	Parts       []Part                       `json:"parts"`
	PendingPart *Part                        `json:"pending_part"`
	Receipt     *models.StorageObjectReceipt `json:"receipt"`
	Provider    *ObjectInfo                  `json:"provider"`
	Assurance   string                       `json:"assurance"`
}

type State struct {
	Schema         int                              `json:"schema"`
	ResourcePrefix string                           `json:"resource_prefix,omitempty"`
	Request        models.StorageTransactionRequest `json:"request"`
	Phase          string                           `json:"phase"`
	Objects        []ObjectState                    `json:"objects"`
	Receipt        *models.StorageReceipt           `json:"receipt"`
	Acceptance     *models.StorageAcceptance        `json:"acceptance"`
	Native         *NativeState                     `json:"native"`
	Utility        *BorrowedUtility                 `json:"utility"`
	Export         *ExportState                     `json:"export"`
	Maps           []ExportMap                      `json:"maps"`
	Finalize       *FinalizeState                   `json:"finalize"`
	Compensation   *CompensationState               `json:"compensation,omitempty"`
}

type diskJournal struct {
	SHA256 string `json:"sha256"`
	State  State  `json:"state"`
}

type Journal struct {
	mu       sync.Mutex
	dir      *os.File
	path     string
	last     []byte
	state    State
	poisoned bool
	syncFile func(*os.File) error
}

func digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

// Create requires a previously unused attempt directory. Missing state after
// an earlier creation is never permission to start again; use Open and hold.
func Create(root string, request []byte) (*Journal, error) { return create(root, request, "") }
func create(root string, request []byte, resourcePrefix string) (*Journal, error) {
	r, err := models.DecodeStorageTransaction(request)
	if err != nil {
		return nil, err
	}
	if resourcePrefix != "" && r.Plan.Provider != "kubevirt" {
		return nil, ErrHeld
	}
	dir := filepath.Join(root, r.ReservationID)
	if err = os.Mkdir(dir, 0700); err != nil {
		return nil, ErrHeld
	}
	parent, err := os.Open(root)
	if err != nil {
		return nil, ErrHeld
	}
	err = parent.Sync()
	_ = parent.Close()
	if err != nil {
		return nil, ErrHeld
	}
	j, err := lock(dir)
	if err != nil {
		return nil, err
	}
	j.state = State{ResourcePrefix: resourcePrefix, Schema: 5, Request: *r, Phase: "uploading", Objects: []ObjectState{}, Maps: []ExportMap{}}
	for _, a := range r.Plan.Artifacts {
		size, err := plannedPartSize(a, r.Plan.TransferProfile)
		if err != nil {
			_ = j.Close()
			return nil, err
		}
		j.state.Objects = append(j.state.Objects, ObjectState{Artifact: a, Phase: "planned", PartSize: size, Parts: []Part{}})
	}
	if err = j.save(); err != nil {
		_ = j.Close()
		return nil, err
	}
	return j, nil
}

func lock(dir string) (*Journal, error) {
	s, err := os.Lstat(dir)
	if err != nil || !s.IsDir() || s.Mode().Perm()&0077 != 0 {
		return nil, ErrHeld
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil, ErrHeld
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, ErrHeld
	}
	return &Journal{dir: f, path: filepath.Join(dir, "transaction.json"), syncFile: (*os.File).Sync}, nil
}

func Open(root string, request []byte) (*Journal, error) {
	r, err := models.DecodeStorageTransaction(request)
	if err != nil {
		return nil, err
	}
	j, err := lock(filepath.Join(root, r.ReservationID))
	if err != nil {
		return nil, err
	}
	fail := func() (*Journal, error) { _ = j.Close(); return nil, ErrHeld }
	data, err := j.read()
	if err != nil {
		return fail()
	}
	var d diskJournal
	if decodeJournal(data, &d) != nil || !reflect.DeepEqual(d.State.Request, *r) {
		return fail()
	}
	j.state = d.State
	j.last = data
	if err = j.validate(); err != nil {
		return fail()
	}
	// Internal streaming hash state is never serialized. An interrupted object
	// cannot resume or allocate another MPU at this key after process loss.
	for _, o := range j.state.Objects {
		if o.Phase != "planned" && o.Phase != "complete" {
			j.state.Phase = "held"
		}
	}
	if j.state.Native != nil {
		for _, o := range j.state.Native.Objects {
			if o.Phase == "create_intent" {
				j.state.Phase = "held"
			}
		}
	}
	if err = j.save(); err != nil {
		return fail()
	}
	return j, nil
}

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.dir == nil {
		return nil
	}
	e := j.dir.Close()
	j.dir = nil
	return e
}

// Snapshot is detached evidence for the later producer/reconciler. It cannot
// mutate this journal or confer permission to repeat an uncertain operation.
func (j *Journal) Snapshot() (State, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.save(); err != nil {
		return State{}, err
	}
	data, err := json.Marshal(j.state)
	if err != nil {
		return State{}, ErrHeld
	}
	var copy State
	// This is our own validated in-memory state, not untrusted wire input.
	// omitempty preserves the original schema-5 checksum until an abort exists.
	if err = json.Unmarshal(data, &copy); err != nil {
		return State{}, ErrHeld
	}
	return copy, nil
}

func (j *Journal) read() ([]byte, error) {
	s, e := os.Lstat(j.path)
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0 || s.Size() > MaxJournalBytes {
		return nil, ErrHeld
	}
	f, e := os.Open(j.path)
	if e != nil {
		return nil, ErrHeld
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, MaxJournalBytes+1))
	if e != nil || len(b) > MaxJournalBytes {
		return nil, ErrHeld
	}
	return b, nil
}

func (j *Journal) validate() error {
	s := &j.state
	if _, err := config.NormalizeKubevirtResourcePrefix(s.ResourcePrefix); err != nil {
		return ErrHeld
	}
	if !validFinalize(s) {
		return ErrHeld
	}
	if !validCompensation(s) {
		return ErrHeld
	}
	if (s.Export != nil && !validExport(s.Export, s)) || (len(s.Maps) > 0 && !validExportMaps(s.Maps, s)) {
		return ErrHeld
	}
	if s.Utility != nil && !validUtility(s.Utility, s) {
		return ErrHeld
	}
	if s.Native != nil && !validNative(s.Native, &s.Request) {
		return ErrHeld
	}
	request, _ := json.Marshal(s.Request)
	if _, e := models.DecodeStorageTransaction(request); e != nil || s.Schema != 5 || len(s.Objects) != len(s.Request.Plan.Artifacts) {
		return ErrHeld
	}
	switch s.Phase {
	case "uploading", "prepared", "submitting", "accepted", "compensating", "held":
	default:
		return ErrHeld
	}
	for i, o := range s.Objects {
		size, err := plannedPartSize(o.Artifact, s.Request.Plan.TransferProfile)
		if err != nil || o.PartSize != size {
			return ErrHeld
		}
		if !reflect.DeepEqual(o.Artifact, s.Request.Plan.Artifacts[i]) || o.Parts == nil || len(o.Parts) > 10000 || len(o.UploadID) > 2048 {
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
		if o.Phase == "complete" && (o.Receipt == nil || o.Provider == nil || o.UploadID == "") {
			return ErrHeld
		}
		if o.Phase == "complete" {
			if !validHead(&s.Request, o) || o.Assurance != assurance(s.Request.Plan.CapabilityProfile, *o.Provider) {
				return ErrHeld
			}
		} else if o.Assurance != "" {
			return ErrHeld
		}
	}
	if s.Receipt != nil {
		if _, _, e := models.CanonicalReceipt(&s.Request, *s.Receipt); e != nil {
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
		body, _ := json.Marshal(s.Acceptance)
		if s.Receipt == nil {
			return ErrHeld
		}
		if _, e := models.DecodeStorageAcceptance(body, &s.Request, *s.Receipt); e != nil {
			return ErrHeld
		}
	}
	if s.Phase == "accepted" && s.Acceptance == nil {
		return ErrHeld
	}
	return nil
}

// save checks the previous on-disk image before replacement. Any failure poisons
// this handle; no subsequent external side effect may follow a failed fsync.
func (j *Journal) save() (err error) {
	return j.persist(j.state, j.validate)
}

// persist is shared by the two explicit journal representations. Neither
// representation is converted into the other to acquire upload authority.
func (j *Journal) persist(state any, validate func() error) (err error) {
	started := time.Now()
	defer func() {
		metrics.StorageStepSeconds.WithLabelValues("journal_persist").Observe(time.Since(started).Seconds())
	}()
	defer func() {
		if err != nil {
			j.poisoned = true
		}
	}()
	if j.poisoned || j.dir == nil {
		return ErrHeld
	}
	if j.last != nil {
		old, e := j.read()
		if e != nil || !bytes.Equal(old, j.last) {
			return ErrHeld
		}
	}
	if validate() != nil {
		return ErrHeld
	}
	canonical, e := models.StorageCanonical(state)
	if e != nil {
		return ErrHeld
	}
	data, e := json.Marshal(struct {
		SHA256 string `json:"sha256"`
		State  any    `json:"state"`
	}{digest(canonical), state})
	if e != nil || len(data) > MaxJournalBytes {
		return ErrHeld
	}
	f, e := os.CreateTemp(filepath.Dir(j.path), ".transaction-")
	if e != nil {
		return ErrHeld
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(data); e == nil {
		e = j.syncFile(f)
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return ErrHeld
	}
	if e = os.Rename(f.Name(), j.path); e != nil {
		return ErrHeld
	}
	if e = j.syncFile(j.dir); e != nil {
		return ErrHeld
	}
	j.last = data
	return nil
}
