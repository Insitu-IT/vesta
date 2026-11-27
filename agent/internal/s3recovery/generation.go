package s3recovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
	"vnbui/agent/internal/nativerestore"
	"vnbui/agent/internal/restoreinput"
	"vnbui/agent/internal/storagerestore"
)

var errIncompleteLegacy = errors.New("historical identity-only manifest has no complete recoverable generation")

type generation struct {
	Protocol       string               `json:"protocol"`
	InstallationID string               `json:"installation_id"`
	OrgID          string               `json:"org_id"`
	GenerationID   string               `json:"generation_id"`
	PredecessorID  *string              `json:"predecessor_id"`
	RootBackupID   string               `json:"root_backup_id"`
	BackupID       string               `json:"backup_id"`
	Source         json.RawMessage      `json:"source"`
	Target         models.StorageTarget `json:"target"`
	Members        []generationMember   `json:"members"`
}

type generationMember struct {
	Request         json.RawMessage `json:"request"`
	Receipt         json.RawMessage `json:"receipt"`
	ReceiptSHA256   string          `json:"receipt_sha256"`
	Acceptance      json.RawMessage `json:"acceptance"`
	Wrapped         json.RawMessage `json:"wrapped_attempt_key"`
	Checkpoint      json.RawMessage `json:"checkpoint"`
	CheckpointProof json.RawMessage `json:"checkpoint_proof"`
	NativeResult    json.RawMessage `json:"native_result"`
}

type requestScope struct {
	OrgID, BackupID, ReservationID, AttemptID, PlanSHA256 string
	Provider, Name                                        string
	Source                                                any
	Target                                                models.StorageTarget
	Encryption                                            models.StorageEncryption
	Parent                                                *models.StorageParent
}

type Plan struct {
	VM      []storagerestore.Member
	Native  nativerestore.Bundle
	wrapped map[string]wrappedKey
}

func fields(value map[string]any, required, optional string) bool {
	expected := strings.Fields(required)
	extra := strings.Fields(optional)
	for _, name := range expected {
		if _, found := value[name]; !found {
			return false
		}
	}
	for name := range value {
		if !slices.Contains(expected, name) && !slices.Contains(extra, name) {
			return false
		}
	}
	return true
}

func parseGeneration(raw []byte, key string, bucket *restoreinput.Bucket) (generation, []requestScope, Plan, error) {
	var record generation
	var plan Plan
	wire, err := models.DecodeStorageControlJSONBounded(raw, maxGeneration)
	if err != nil {
		return record, nil, plan, ErrMetadata
	}
	if wire["protocol"] != "vnbui-storage-generation/1" || wire["members"] == nil {
		return record, nil, plan, errIncompleteLegacy
	}
	if !fields(wire, "protocol installation_id org_id generation_id predecessor_id root_backup_id backup_id source target members", "") ||
		json.Unmarshal(raw, &record) != nil || len(record.Members) == 0 || len(record.Members) > 256 ||
		!ValidID(record.InstallationID) || !ValidID(record.OrgID) || !ValidID(record.GenerationID) ||
		!ValidID(record.RootBackupID) || !ValidID(record.BackupID) ||
		(record.PredecessorID != nil && (!ValidID(*record.PredecessorID) || *record.PredecessorID == record.GenerationID)) ||
		key != generationKey(record.OrgID, record.RootBackupID, record.GenerationID) {
		return record, nil, plan, ErrMetadata
	}
	var exactTarget models.StorageTarget
	targetBytes, err := json.Marshal(wire["target"])
	if err != nil || models.DecodeStorageValue(targetBytes, &exactTarget, 4096) != nil || !bucket.Matches(exactTarget) ||
		!models.ValidStorageTarget(exactTarget) {
		return record, nil, plan, errors.New("generation destination does not match the private S3 configuration")
	}
	canonical, err := models.StorageCanonical(wire)
	if err != nil || !bytes.Equal(canonical, raw) {
		return record, nil, plan, errors.New("generation is not in the published canonical encoding")
	}
	plan.wrapped = make(map[string]wrappedKey)
	entries := wire["members"].([]any)
	scopes := make([]requestScope, 0, len(entries))
	for i, entry := range record.Members {
		obj, ok := entries[i].(map[string]any)
		if !ok || !fields(obj, "request receipt receipt_sha256 acceptance wrapped_attempt_key checkpoint checkpoint_proof", "native_result") ||
			!checksum.MatchString(entry.ReceiptSHA256) {
			return record, nil, Plan{}, ErrMetadata
		}
		var scope requestScope
		if _, native := obj["native_result"]; native {
			member, nativeScope, readErr := decodeNative(entry)
			if readErr != nil {
				return record, nil, Plan{}, readErr
			}
			scope = nativeScope
			plan.Native.Members = append(plan.Native.Members, member)
		} else {
			member, kubeScope, readErr := decodeKubeVirt(entry)
			if readErr != nil {
				return record, nil, Plan{}, readErr
			}
			scope = kubeScope
			plan.VM = append(plan.VM, member)
		}
		if scope.OrgID != record.OrgID || scope.Target != record.Target ||
			(i == 0 && scope.BackupID != record.RootBackupID) ||
			(i == len(entries)-1 && scope.BackupID != record.BackupID) {
			return record, nil, Plan{}, ErrMetadata
		}
		if scope.Encryption.Format == "none" {
			if !bytes.Equal(entry.Wrapped, []byte("null")) {
				return record, nil, Plan{}, ErrMetadata
			}
		} else {
			if scope.Encryption.KeyRef == nil {
				return record, nil, Plan{}, ErrMetadata
			}
			expected := wrappedKey{Schema: 1, OrgID: scope.OrgID, BackupID: scope.BackupID,
				ReservationID: scope.ReservationID, AttemptID: scope.AttemptID, PlanSHA256: scope.PlanSHA256,
				KeyRef: *scope.Encryption.KeyRef, Format: scope.Encryption.Format, Wrapping: "aes256-keywrap/1"}
			wrapped, err := decodeWrapped(entry.Wrapped, expected)
			if err != nil {
				return record, nil, Plan{}, err
			}
			plan.wrapped[scope.BackupID] = wrapped
		}
		scopes = append(scopes, scope)
	}
	last := scopes[len(scopes)-1]
	source, marshalErr := models.StorageCanonical(last.Source)
	if marshalErr != nil || !bytes.Equal(record.Source, source) ||
		(last.Parent != nil && (record.PredecessorID == nil || *record.PredecessorID != last.Parent.GenerationID)) {
		return record, nil, Plan{}, ErrMetadata
	}
	switch {
	case len(plan.VM) == len(entries):
		err = storagerestore.ValidateMembers(plan.VM)
	case len(plan.Native.Members) == len(entries):
		plan.Native.Schema = nativerestore.BundleSchema
		err = nativerestore.Validate(plan.Native)
	default:
		err = errors.New("generation mixes incompatible provider profiles")
	}
	return record, scopes, plan, err
}

func decodeKubeVirt(entry generationMember) (storagerestore.Member, requestScope, error) {
	var member storagerestore.Member
	r, err := models.DecodeStorageTransaction(entry.Request)
	if err != nil || models.DecodeStorageValue(entry.Receipt, &member.Receipt, models.MaxStorageReceiptBytes) != nil {
		return member, requestScope{}, ErrMetadata
	}
	member.Request = *r
	_, digest, err := models.CanonicalReceipt(r, member.Receipt)
	if err != nil || digest != entry.ReceiptSHA256 {
		return member, requestScope{}, errors.New("generation receipt digest mismatch")
	}
	acceptance, err := models.DecodeStorageAcceptance(entry.Acceptance, r, member.Receipt)
	if err != nil {
		return member, requestScope{}, errors.New("generation lacks matching receipt acceptance")
	}
	checkpoint, err := models.DecodeStorageControlJSON(entry.Checkpoint)
	if err != nil || checkpoint["reservation_id"] != r.ReservationID || checkpoint["attempt_id"] != r.Plan.AttemptID ||
		checkpoint["plan_sha256"] != r.PlanSHA256 || checkpoint["receipt_sha256"] != digest ||
		checkpoint["acceptance_id"] != acceptance.AcceptanceID {
		return member, requestScope{}, errors.New("missing or mismatched KubeVirt generation checkpoint binding")
	}
	if _, err = models.DecodeStorageControlJSON(entry.CheckpointProof); err != nil {
		return member, requestScope{}, errors.New("missing KubeVirt generation checkpoint proof")
	}
	return member, requestScope{r.OrgID, r.BackupID, r.ReservationID, r.Plan.AttemptID, r.PlanSHA256,
		r.Plan.Provider, r.Plan.VMName, r.Plan.Source, r.Plan.Target, r.Plan.Encryption, r.Plan.Parent}, nil
}

func decodeNative(entry generationMember) (nativerestore.Member, requestScope, error) {
	var member nativerestore.Member
	r, err := nativefileset.DecodeTransaction(entry.Request)
	if err != nil || models.DecodeStorageValue(entry.Receipt, &member.Receipt, models.MaxStorageReceiptBytes) != nil ||
		models.DecodeStorageValue(entry.NativeResult, &member.PushResult, models.MaxStorageRequestBytes) != nil ||
		!bytes.Equal(entry.Checkpoint, []byte("null")) || !bytes.Equal(entry.CheckpointProof, []byte("null")) {
		return member, requestScope{}, ErrMetadata
	}
	member.Request = *r
	_, digest, err := nativefileset.CanonicalReceipt(member.Receipt, r.Plan.Artifacts, r.BackupID, r.ReservationID, r.Plan.Target, r.Plan.Encryption)
	if err != nil || digest != entry.ReceiptSHA256 {
		return member, requestScope{}, errors.New("generation native receipt digest mismatch")
	}
	objects := make(map[string]*string, len(member.Receipt.Objects))
	for _, object := range member.Receipt.Objects {
		objects[object.Key] = object.VersionID
	}
	_, err = models.DecodeReceiptAcceptance(entry.Acceptance, r.ReservationID, digest, r.Plan.CapabilityProfile, objects)
	if err != nil {
		return member, requestScope{}, fmt.Errorf("generation lacks matching native receipt acceptance: %w", err)
	}
	return member, requestScope{r.OrgID, r.BackupID, r.ReservationID, r.Plan.AttemptID, r.PlanSHA256,
		r.Plan.Provider, member.PushResult.Manifest.DomainUUID, r.Plan.Source, r.Plan.Target, r.Plan.Encryption, r.Plan.Parent}, nil
}
