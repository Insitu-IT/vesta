package storagerestore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
)

const VerificationSchema = "vnbui-chain-verification/1"

// VerifiedMember binds a successful full artifact read to the caller-admitted
// request and receipt. It does not establish catalog trust or publication.
type VerifiedMember struct {
	BackupID      string `json:"backup_id"`
	ReservationID string `json:"reservation_id"`
	PlanSHA256    string `json:"plan_sha256"`
	ReceiptSHA256 string `json:"receipt_sha256"`
	Objects       int    `json:"objects"`
}

// VerificationResult is returned only after all bytes and metadata pass. It is
// not a durable backend status, a guest boot proof, or authority to adopt data.
type VerificationResult struct {
	Schema   string           `json:"schema"`
	Provider string           `json:"provider"`
	OrgID    string           `json:"org_id"`
	AgentID  string           `json:"agent_id"`
	VMID     string           `json:"vm_id"`
	Members  []VerifiedMember `json:"members"`
}

// Verify performs an exact-object streaming scrub of a catalog-admitted chain.
// It creates no disks/files/VMs and authorizes no object-store mutation. The
// caller supplies the same anchored inventory and version-fenced opener as
// restore. A self-consistent bundle alone does not establish provenance.
func Verify(ctx context.Context, members []Member, open ObjectOpener, keys KeyResolver) (*VerificationResult, error) {
	if ctx == nil || open == nil {
		return nil, errors.New("verification requires context and exact-object reader")
	}
	chain, err := validateChain(members)
	if err != nil {
		return nil, err
	}
	result := &VerificationResult{
		Schema: VerificationSchema, Provider: "kubevirt", OrgID: chain[0].Request.OrgID,
		AgentID: chain[0].Request.AgentID,
		VMID:    chain[0].Request.Plan.Source.VMID, Members: make([]VerifiedMember, 0, len(chain)),
	}
	previous := ""
	seen := map[string]bool{}
	for _, member := range chain {
		checkpoint, err := verifyMember(ctx, member, previous, open, keys)
		if err != nil {
			return nil, fmt.Errorf("backup %s verification: %w", member.Request.BackupID, err)
		}
		if seen[checkpoint] {
			return nil, errors.New("verification chain repeats a checkpoint")
		}
		seen[checkpoint] = true
		previous = checkpoint
		result.Members = append(result.Members, VerifiedMember{
			BackupID: member.Request.BackupID, ReservationID: member.Request.ReservationID,
			PlanSHA256: member.Request.PlanSHA256, ReceiptSHA256: member.digest,
			Objects: len(member.Receipt.Objects),
		})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func verifyMember(ctx context.Context, member validatedMember, previous string, open ObjectOpener, keys KeyResolver) (string, error) {
	if parent := member.Request.Plan.Parent; parent != nil && parent.Checkpoint != previous {
		return "", errors.New("parent checkpoint does not match preceding manifest")
	}
	encrypted := member.Request.Plan.Encryption.Format != "none"
	var key []byte
	if encrypted {
		if keys == nil {
			return "", errors.New("encrypted verification requires a per-member DEK resolver")
		}
		var err error
		key, err = keys(ctx, member.Member)
		defer clear(key)
		if err != nil || len(key) != 32 {
			return "", errors.New("could not resolve the backup's 32-byte DEK")
		}
	}
	checkpoint, definition := "", ""
	for _, volume := range member.Request.Plan.Source.Volumes {
		pair := member.objects[volume.PVCUID]
		manifest, err := readManifest(ctx, member, volume, pair, open)
		if err != nil {
			return "", fmt.Errorf("volume %s manifest: %w", volume.Name, err)
		}
		if checkpoint != "" && checkpoint != manifest.Checkpoint {
			return "", errors.New("volume manifests disagree on checkpoint")
		}
		if manifest.VMDefinition == "" || (definition != "" && definition != manifest.VMDefinition) {
			return "", errors.New("backup lacks a consistent captured VM definition")
		}
		checkpoint, definition = manifest.Checkpoint, manifest.VMDefinition
		if err := WriteVerifiedObject(ctx, member.Request.Plan.Target, pair.payload, encrypted, key, open, io.Discard); err != nil {
			return "", fmt.Errorf("volume %s payload: %w", volume.Name, err)
		}
	}
	// Share restore's definition authentication/identity checks, without resolving
	// the DEK a second time or letting its private copy clear this member's key.
	definitionKeys := func(context.Context, Member) ([]byte, error) { return bytes.Clone(key), nil }
	if _, err := decodeVMDefinition(ctx, member, definition, definitionKeys); err != nil {
		return "", err
	}
	return checkpoint, nil
}
