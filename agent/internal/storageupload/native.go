package storageupload

import (
	"reflect"
	"strings"
	"time"

	"vnbui/agent/internal/models"
)

// NativeState is non-secret native preparation custody in the same exclusive,
// checksummed, fsync/rename journal as the accepted request and upload receipts.
// A create_intent is deliberately not resumable: a lost reply must not adopt a
// same-name object or issue a second create. D07 consumes that uncertainty.
type NativeState struct {
	ScratchName         string          `json:"scratch_name"`
	ScratchUID          string          `json:"scratch_uid"`
	Objects             []NativeObject  `json:"objects"`
	VMDefinition        string          `json:"vm_definition"`
	EncodedVMDefinition string          `json:"encoded_vm_definition"`
	Lifetime            *NativeLifetime `json:"lifetime,omitempty"`
}

type NativeObject struct {
	Role     string `json:"role"`
	Name     string `json:"name"`
	UID      string `json:"uid"`
	OwnerUID string `json:"owner_uid"`
	Phase    string `json:"phase"`
	Created  bool   `json:"created"`
}

func nativeID(s string) bool {
	return s != "" && len(s) <= 253 && !strings.ContainsAny(s, "/\\\x00\r\n\t ")
}

func validNative(n *NativeState, r *models.StorageTransactionRequest) bool {
	if r.Plan.Provider != "kubevirt" || !nativeID(n.ScratchName) || !nativeID(n.ScratchUID) || len(n.Objects) != 3 || !validVMDefinition(n, r) {
		return false
	}
	if n.Lifetime != nil && (!n.Lifetime.Valid() || (n.Objects[1].Phase == "observed") != (n.Lifetime.CreatedAt != "")) {
		return false
	}
	roles := []string{"tracker", "backup", "export_token"}
	for i, o := range n.Objects {
		if o.Role != roles[i] || !nativeID(o.Name) {
			return false
		}
		switch o.Phase {
		case "planned":
			if o.UID != "" || o.OwnerUID != "" || o.Created {
				return false
			}
		case "create_intent", "observed":
			if !nativeID(o.OwnerUID) || (o.Phase == "observed") != nativeID(o.UID) {
				return false
			}
			if i == 0 {
				if o.OwnerUID != r.Plan.Source.VMUID {
					return false
				}
			} else if n.Objects[i-1].Phase != "observed" || o.OwnerUID != n.Objects[i-1].UID {
				return false
			}
			if o.Phase == "create_intent" && (!o.Created || o.UID != "") {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (j *Journal) PrepareNative(n NativeState) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.state.Native != nil || j.state.Phase != "uploading" || !validNative(&n, &j.state.Request) {
		return ErrHeld
	}
	for _, o := range n.Objects {
		if o.Phase != "planned" {
			return ErrHeld
		}
	}
	for _, o := range j.state.Objects {
		if o.Phase != "planned" {
			return ErrHeld
		}
	}
	copy := n
	copy.Objects = append([]NativeObject(nil), n.Objects...)
	if n.Lifetime != nil {
		lifetime := *n.Lifetime
		copy.Lifetime = &lifetime
	}
	j.state.Native = &copy
	return j.save()
}

// HoldPreNativeSourceDrift stops a definitively invalid source from retrying
// forever before native preparation. It preserves the request and reservation;
// this is not a no-effect release proof or cleanup authorization.
func (j *Journal) HoldPreNativeSourceDrift() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.state.Request.Plan.Provider != "kubevirt" || j.state.Request.Plan.Parent == nil ||
		j.state.Phase != "uploading" || j.state.Native != nil || j.state.Acceptance != nil ||
		j.state.Receipt != nil || j.state.Utility != nil || j.state.Export != nil ||
		len(j.state.Maps) != 0 || j.state.Finalize != nil || j.state.Compensation != nil {
		return ErrHeld
	}
	for _, object := range j.state.Objects {
		if object.Phase != "planned" || object.UploadID != "" || len(object.Parts) != 0 ||
			object.PendingPart != nil || object.Receipt != nil || object.Provider != nil {
			return ErrHeld
		}
	}
	j.state.Phase = "held"
	return j.save()
}

// HoldNativeDrift makes a confirmed loss or replacement of an observed native
// resource reviewable without granting any retry or cleanup authority. The
// caller must establish the drift from an authoritative provider read.
func (j *Journal) HoldNativeDrift() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.state.Phase != "uploading" || j.state.Native == nil || j.state.Acceptance != nil {
		return ErrHeld
	}
	observed := false
	for _, object := range j.state.Native.Objects {
		observed = observed || object.Phase == "observed"
	}
	if !observed {
		return ErrHeld
	}
	j.state.Phase = "held"
	return j.save()
}

// BeginNativeCreate commits an exact owner-bound intent before the API call.
// Even identical repetition refuses; no lease or process restart resets it.
func (j *Journal) BeginNativeCreate(role, owner string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.state.Native == nil || j.state.Phase != "uploading" {
		return ErrHeld
	}
	for i, o := range j.state.Native.Objects {
		if o.Role != role {
			continue
		}
		if o.Phase != "planned" {
			return ErrHeld
		}
		o.Phase, o.OwnerUID, o.Created = "create_intent", owner, true
		j.state.Native.Objects[i] = o
		if !validNative(j.state.Native, &j.state.Request) {
			j.poisoned = true
			return ErrHeld
		}
		return j.save()
	}
	return ErrHeld
}

// ObserveNative binds only the successful response to this handle's create, or
// an existing source tracker admitted before any native preparation. It never
// changes an already bound UID, and is not an uncertain-create recovery API.
func (j *Journal) ObserveNative(role, uid, owner string, created bool) error {
	return j.observeNative(role, uid, owner, created, "")
}

// ObserveNativeBackup binds creation time atomically with the successful create
// response's UID. A restart never invents or extends that original deadline.
func (j *Journal) ObserveNativeBackup(uid, owner string, createdAt time.Time) error {
	if createdAt.IsZero() {
		return ErrHeld
	}
	return j.observeNative("backup", uid, owner, true, createdAt.UTC().Format(time.RFC3339Nano))
}

func (j *Journal) observeNative(role, uid, owner string, created bool, createdAt string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.state.Native == nil || j.state.Phase != "uploading" {
		return ErrHeld
	}
	for i, o := range j.state.Native.Objects {
		if o.Role != role {
			continue
		}
		candidate := NativeObject{Role: role, Name: o.Name, UID: uid, OwnerUID: owner, Phase: "observed", Created: created}
		if role == "backup" && j.state.Native.Lifetime != nil {
			if createdAt == "" || (o.Phase == "observed" && j.state.Native.Lifetime.CreatedAt != createdAt) {
				return ErrHeld
			}
		}
		if o.Phase == "observed" {
			if !reflect.DeepEqual(o, candidate) {
				return ErrHeld
			}
			return j.save()
		}
		if created {
			if o.Phase != "create_intent" || o.OwnerUID != owner {
				return ErrHeld
			}
		} else if role != "tracker" || o.Phase != "planned" {
			return ErrHeld
		}
		j.state.Native.Objects[i] = candidate
		if role == "backup" && j.state.Native.Lifetime != nil {
			j.state.Native.Lifetime.CreatedAt = createdAt
		}
		if !validNative(j.state.Native, &j.state.Request) {
			j.poisoned = true
			return ErrHeld
		}
		return j.save()
	}
	return ErrHeld
}
