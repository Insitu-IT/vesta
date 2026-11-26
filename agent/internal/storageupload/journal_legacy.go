package storageupload

import (
	"encoding/json"

	"vnbui/agent/internal/models"
)

// This is the exact D03 journal image, not a legacy backup/offset-resume
// request. Its checksum is verified before upgrading; no native object or
// ownership is inferred. Unknown shapes/schemas continue to hold.
type priorState struct {
	Schema     int                              `json:"schema"`
	Request    models.StorageTransactionRequest `json:"request"`
	Phase      string                           `json:"phase"`
	Objects    []ObjectState                    `json:"objects"`
	Receipt    *models.StorageReceipt           `json:"receipt"`
	Acceptance *models.StorageAcceptance        `json:"acceptance"`
}

func decodeJournal(data []byte, d *diskJournal) error {
	// The empty compatibility array is only a strict-parser aid. Preserve the
	// historical in-memory projection as well as its omitted canonical bytes.
	defer func() {
		if d.State.Export != nil && len(d.State.Export.NativeVolumes) == 0 {
			d.State.Export.NativeVolumes = nil
		}
	}()
	// The strict wire decoder still requires every struct field. Supply null
	// only for the two explicitly optional journal extensions, in memory. The
	// original checksum below is checked against the omitempty representation;
	// no lifetime is inferred, saved, or added to a historical journal.
	shape, err := models.DecodeStorageControlJSONBounded(data, MaxJournalBytes)
	if err != nil {
		return ErrHeld
	}
	if state, ok := shape["state"].(map[string]any); ok {
		changed := false
		for _, field := range []string{"native", "export"} {
			if object, ok := state[field].(map[string]any); ok {
				if field == "export" {
					if _, present := object["native_volumes"]; !present {
						object["native_volumes"] = []any{}
						changed = true
					}
				}
				if _, present := object["lifetime"]; !present {
					object["lifetime"] = nil
					changed = true
				}
			}
		}
		if changed {
			data, err = json.Marshal(shape)
			if err != nil {
				return ErrHeld
			}
		}
	}
	if models.DecodeStorageValue(data, d, MaxJournalBytes) == nil {
		canonical, err := models.StorageCanonical(d.State)
		if err != nil || d.State.Schema != 5 || digest(canonical) != d.SHA256 {
			return ErrHeld
		}
		return nil
	}
	// Schema-5 journals before explicit naming retain their exact original
	// checksum and derive legacy names, irrespective of the current process config.
	var namingNoCompensation struct {
		SHA256 string `json:"sha256"`
		State  struct {
			Schema         int                              `json:"schema"`
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
			ResourcePrefix string                           `json:"resource_prefix"`
		} `json:"state"`
	}
	if models.DecodeStorageValue(data, &namingNoCompensation, MaxJournalBytes) == nil {
		canonical, err := models.StorageCanonical(namingNoCompensation.State)
		if err != nil || namingNoCompensation.State.Schema != 5 || digest(canonical) != namingNoCompensation.SHA256 {
			return ErrHeld
		}
		s := namingNoCompensation.State
		d.SHA256 = namingNoCompensation.SHA256
		d.State = State{Schema: 5, Request: s.Request, Phase: s.Phase, Objects: s.Objects, Receipt: s.Receipt, Acceptance: s.Acceptance, Native: s.Native, Utility: s.Utility, Export: s.Export, Maps: s.Maps, Finalize: s.Finalize, ResourcePrefix: s.ResourcePrefix}
		return nil
	}
	var namingLegacy struct {
		SHA256 string `json:"sha256"`
		State  struct {
			Schema       int                              `json:"schema"`
			Request      models.StorageTransactionRequest `json:"request"`
			Phase        string                           `json:"phase"`
			Objects      []ObjectState                    `json:"objects"`
			Receipt      *models.StorageReceipt           `json:"receipt"`
			Acceptance   *models.StorageAcceptance        `json:"acceptance"`
			Native       *NativeState                     `json:"native"`
			Utility      *BorrowedUtility                 `json:"utility"`
			Export       *ExportState                     `json:"export"`
			Maps         []ExportMap                      `json:"maps"`
			Finalize     *FinalizeState                   `json:"finalize"`
			Compensation *CompensationState               `json:"compensation"`
		} `json:"state"`
	}
	if models.DecodeStorageValue(data, &namingLegacy, MaxJournalBytes) == nil {
		canonical, err := models.StorageCanonical(namingLegacy.State)
		if err != nil || namingLegacy.State.Schema != 5 || digest(canonical) != namingLegacy.SHA256 {
			return ErrHeld
		}
		s := namingLegacy.State
		d.SHA256 = namingLegacy.SHA256
		d.State = State{Schema: 5, Request: s.Request, Phase: s.Phase, Objects: s.Objects, Receipt: s.Receipt, Acceptance: s.Acceptance, Native: s.Native, Utility: s.Utility, Export: s.Export, Maps: s.Maps, Finalize: s.Finalize, Compensation: s.Compensation}
		return nil
	}
	// Schema-5 journals created before the optional compensation extension have
	// exactly this shape. Verify their ORIGINAL checksum before projection; no
	// forward/native/abort evidence is invented during read or restart recovery.
	var original5 struct {
		SHA256 string `json:"sha256"`
		State  struct {
			Schema     int                              `json:"schema"`
			Request    models.StorageTransactionRequest `json:"request"`
			Phase      string                           `json:"phase"`
			Objects    []ObjectState                    `json:"objects"`
			Receipt    *models.StorageReceipt           `json:"receipt"`
			Acceptance *models.StorageAcceptance        `json:"acceptance"`
			Native     *NativeState                     `json:"native"`
			Utility    *BorrowedUtility                 `json:"utility"`
			Export     *ExportState                     `json:"export"`
			Maps       []ExportMap                      `json:"maps"`
			Finalize   *FinalizeState                   `json:"finalize"`
		} `json:"state"`
	}
	if models.DecodeStorageValue(data, &original5, MaxJournalBytes) == nil {
		canonical, err := models.StorageCanonical(original5.State)
		if err != nil || original5.State.Schema != 5 || digest(canonical) != original5.SHA256 {
			return ErrHeld
		}
		s := original5.State
		d.SHA256 = original5.SHA256
		d.State = State{Schema: 5, Request: s.Request, Phase: s.Phase, Objects: s.Objects, Receipt: s.Receipt, Acceptance: s.Acceptance, Native: s.Native, Utility: s.Utility, Export: s.Export, Maps: s.Maps, Finalize: s.Finalize}
		return nil
	}
	var v4 struct {
		SHA256 string `json:"sha256"`
		State  struct {
			Schema     int                              `json:"schema"`
			Request    models.StorageTransactionRequest `json:"request"`
			Phase      string                           `json:"phase"`
			Objects    []ObjectState                    `json:"objects"`
			Receipt    *models.StorageReceipt           `json:"receipt"`
			Acceptance *models.StorageAcceptance        `json:"acceptance"`
			Native     *NativeState                     `json:"native"`
			Utility    *BorrowedUtility                 `json:"utility"`
			Export     *ExportState                     `json:"export"`
			Maps       []ExportMap                      `json:"maps"`
		} `json:"state"`
	}
	if models.DecodeStorageValue(data, &v4, MaxJournalBytes) == nil {
		canonical, err := models.StorageCanonical(v4.State)
		if err != nil || v4.State.Schema != 4 || digest(canonical) != v4.SHA256 {
			return ErrHeld
		}
		s := v4.State
		d.State = State{Schema: 5, Request: s.Request, Phase: s.Phase, Objects: s.Objects, Receipt: s.Receipt, Acceptance: s.Acceptance, Native: s.Native, Utility: s.Utility, Export: s.Export, Maps: s.Maps}
		return nil
	}
	var v3 struct {
		SHA256 string `json:"sha256"`
		State  struct {
			Schema     int                              `json:"schema"`
			Request    models.StorageTransactionRequest `json:"request"`
			Phase      string                           `json:"phase"`
			Objects    []ObjectState                    `json:"objects"`
			Receipt    *models.StorageReceipt           `json:"receipt"`
			Acceptance *models.StorageAcceptance        `json:"acceptance"`
			Native     *NativeState                     `json:"native"`
			Utility    *BorrowedUtility                 `json:"utility"`
		} `json:"state"`
	}
	if models.DecodeStorageValue(data, &v3, MaxJournalBytes) == nil {
		canonical, err := models.StorageCanonical(v3.State)
		if err != nil || v3.State.Schema != 3 || digest(canonical) != v3.SHA256 {
			return ErrHeld
		}
		s := v3.State
		d.State = State{Schema: 5, Request: s.Request, Phase: s.Phase, Objects: s.Objects, Receipt: s.Receipt, Acceptance: s.Acceptance, Native: s.Native, Utility: s.Utility, Maps: []ExportMap{}}
		return nil
	}
	var v2 struct {
		SHA256 string `json:"sha256"`
		State  struct {
			Schema     int                              `json:"schema"`
			Request    models.StorageTransactionRequest `json:"request"`
			Phase      string                           `json:"phase"`
			Objects    []ObjectState                    `json:"objects"`
			Receipt    *models.StorageReceipt           `json:"receipt"`
			Acceptance *models.StorageAcceptance        `json:"acceptance"`
			Native     *NativeState                     `json:"native"`
		} `json:"state"`
	}
	if models.DecodeStorageValue(data, &v2, MaxJournalBytes) == nil {
		canonical, err := models.StorageCanonical(v2.State)
		if err != nil || v2.State.Schema != 2 || digest(canonical) != v2.SHA256 {
			return ErrHeld
		}
		s := v2.State
		d.State = State{Schema: 5, Request: s.Request, Phase: s.Phase, Objects: s.Objects, Receipt: s.Receipt, Acceptance: s.Acceptance, Native: s.Native, Maps: []ExportMap{}}
		return nil
	}
	var old struct {
		SHA256 string     `json:"sha256"`
		State  priorState `json:"state"`
	}
	if models.DecodeStorageValue(data, &old, MaxJournalBytes) != nil || old.State.Schema != 1 {
		return ErrHeld
	}
	canonical, err := models.StorageCanonical(old.State)
	if err != nil || digest(canonical) != old.SHA256 {
		return ErrHeld
	}
	s := old.State
	d.State = State{Schema: 5, Request: s.Request, Phase: s.Phase, Objects: s.Objects, Receipt: s.Receipt, Acceptance: s.Acceptance, Maps: []ExportMap{}}
	return nil
}
