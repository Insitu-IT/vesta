package nativerestore

import (
	"context"
	"errors"
	"fmt"
	"io"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
	"vnbui/agent/internal/storagerestore"
)

// Verify checks every exact native artifact against the admitted receipt and
// push manifest. Unlike Materialize/RestoreNativePush it creates no local disk,
// runs no qemu/libvirt operation, and confers no import or publication authority.
func Verify(ctx context.Context, bundle Bundle, open storagerestore.ObjectOpener, keys KeyResolver) (*storagerestore.VerificationResult, error) {
	if ctx == nil || open == nil {
		return nil, errors.New("verification requires context and exact-object reader")
	}
	if err := Validate(bundle); err != nil {
		return nil, err
	}
	first := bundle.Members[0].Request
	result := &storagerestore.VerificationResult{
		Schema: storagerestore.VerificationSchema, Provider: "libvirt", OrgID: first.OrgID,
		AgentID: first.AgentID,
		VMID:    first.Plan.Source.VMID, Members: make([]storagerestore.VerifiedMember, 0, len(bundle.Members)),
	}
	for _, member := range bundle.Members {
		if err := verifyMember(ctx, member, open, keys); err != nil {
			return nil, fmt.Errorf("backup %s verification: %w", member.Request.BackupID, err)
		}
		r := member.Request
		_, digest, err := nativefileset.CanonicalReceipt(member.Receipt, r.Plan.Artifacts, r.BackupID, r.ReservationID, r.Plan.Target, r.Plan.Encryption)
		if err != nil {
			return nil, err
		}
		result.Members = append(result.Members, storagerestore.VerifiedMember{
			BackupID: r.BackupID, ReservationID: r.ReservationID, PlanSHA256: r.PlanSHA256,
			ReceiptSHA256: digest, Objects: len(member.Receipt.Objects),
		})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func verifyMember(ctx context.Context, member Member, open storagerestore.ObjectOpener, keys KeyResolver) error {
	encrypted := member.Request.Plan.Encryption.Format != "none"
	var key []byte
	if encrypted {
		if keys == nil {
			return errors.New("native member DEK resolver unavailable")
		}
		var err error
		key, err = keys(ctx, member)
		defer clear(key)
		if err != nil || len(key) != 32 {
			return errors.New("native member DEK unavailable")
		}
	}
	for _, o := range member.Receipt.Objects {
		object := models.StorageObjectReceipt{
			Key: o.Key, VersionID: o.VersionID, ETag: o.ETag,
			PlaintextBytes: o.PlaintextBytes, CiphertextBytes: o.CiphertextBytes,
			PlaintextSHA256: o.PlaintextSHA256, CiphertextSHA256: o.CiphertextSHA256,
		}
		if err := storagerestore.WriteVerifiedObject(ctx, member.Request.Plan.Target, object, encrypted, key, open, io.Discard); err != nil {
			return fmt.Errorf("artifact %s: %w", o.ArtifactID, err)
		}
	}
	return nil
}
