// Package verification runs read-only, receipt-bound scrubs with durable results.
package verification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/google/uuid"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
	"vnbui/agent/internal/nativerestore"
	"vnbui/agent/internal/restoreinput"
	"vnbui/agent/internal/storagerestore"
)

const Schema = "vnbui-backup-verification/1"
const ProgressSchema = "vnbui-backup-verification-progress/1"
const MaxRequestBytes = 32 << 20

var ErrPlan = errors.New("invalid verification plan or read credentials")
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Plan is nonsecret original custody. AuthoritySHA256 binds the backend's
// persisted initiating principal/scope; it is not an independent agent grant.
type Plan struct {
	Schema          string          `json:"schema"`
	VerificationID  string          `json:"verification_id"`
	OrgID           string          `json:"org_id"`
	AgentID         string          `json:"agent_id"`
	Provider        string          `json:"provider"`
	AuthoritySHA256 string          `json:"authority_sha256"`
	Bundle          json.RawMessage `json:"bundle"`
}

// Request carries ephemeral read credentials. Only Plan may enter the journal.
type Request struct {
	Plan Plan                     `json:"plan"`
	S3   models.KubeVirtRestoreS3 `json:"s3"`
	Keys map[string]string        `json:"keys"`
}

type kubevirtBundle struct {
	Schema  string                  `json:"schema"`
	Members []storagerestore.Member `json:"members"`
}

func decodeDocument(body []byte, destination any, limit int) error {
	if _, err := models.DecodeStorageControlJSONBounded(body, limit); err != nil {
		return ErrPlan
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(destination) != nil {
		return ErrPlan
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrPlan
	}
	return nil
}

func DecodeRequest(body []byte) (Request, error) {
	var req Request
	if decodeDocument(body, &req, MaxRequestBytes) != nil {
		return Request{}, ErrPlan
	}
	return req, nil
}

func validID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

// ExpectedResult validates static custody and derives exact result bindings.
// This is an expectation, NOT proof that any artifact has been read.
func ExpectedResult(plan Plan) (*storagerestore.VerificationResult, string, error) {
	if plan.Schema != Schema || !validID(plan.VerificationID) || !validID(plan.OrgID) || !validID(plan.AgentID) ||
		!digestPattern.MatchString(plan.AuthoritySHA256) || len(plan.Bundle) == 0 || len(plan.Bundle) > MaxRequestBytes {
		return nil, "", ErrPlan
	}
	result := &storagerestore.VerificationResult{Schema: storagerestore.VerificationSchema, Provider: plan.Provider, OrgID: plan.OrgID, AgentID: plan.AgentID, Members: []storagerestore.VerifiedMember{}}
	switch plan.Provider {
	case "kubevirt":
		var bundle kubevirtBundle
		if models.DecodeStorageValue(plan.Bundle, &bundle, MaxRequestBytes) != nil || bundle.Schema != "vnbui-kubevirt-restore/1" || storagerestore.ValidateMembers(bundle.Members) != nil {
			return nil, "", ErrPlan
		}
		for _, member := range bundle.Members {
			r := member.Request
			if r.OrgID != plan.OrgID || r.AgentID != plan.AgentID {
				return nil, "", ErrPlan
			}
			_, digest, err := models.CanonicalReceipt(&r, member.Receipt)
			if err != nil {
				return nil, "", ErrPlan
			}
			result.VMID = r.Plan.Source.VMID
			result.Members = append(result.Members, storagerestore.VerifiedMember{BackupID: r.BackupID, ReservationID: r.ReservationID, PlanSHA256: r.PlanSHA256, ReceiptSHA256: digest, Objects: len(member.Receipt.Objects)})
		}
	case "libvirt":
		bundle, err := nativerestore.DecodeBundle(plan.Bundle)
		if err != nil {
			return nil, "", ErrPlan
		}
		for _, member := range bundle.Members {
			r := member.Request
			if r.OrgID != plan.OrgID || r.AgentID != plan.AgentID {
				return nil, "", ErrPlan
			}
			_, digest, err := nativefileset.CanonicalReceipt(member.Receipt, r.Plan.Artifacts, r.BackupID, r.ReservationID, r.Plan.Target, r.Plan.Encryption)
			if err != nil {
				return nil, "", ErrPlan
			}
			result.VMID = r.Plan.Source.VMID
			result.Members = append(result.Members, storagerestore.VerifiedMember{BackupID: r.BackupID, ReservationID: r.ReservationID, PlanSHA256: r.PlanSHA256, ReceiptSHA256: digest, Objects: len(member.Receipt.Objects)})
		}
	default:
		return nil, "", ErrPlan
	}
	body, err := models.StorageCanonical(plan)
	if err != nil {
		return nil, "", ErrPlan
	}
	sum := sha256.Sum256(body)
	return result, hex.EncodeToString(sum[:]), nil
}

func validateCredentials(req Request) error {
	var members []struct {
		Request struct {
			BackupID string `json:"backup_id"`
			Plan     struct {
				Target     models.StorageTarget     `json:"target"`
				Encryption models.StorageEncryption `json:"encryption"`
			} `json:"plan"`
		} `json:"request"`
	}
	var bundle struct {
		Members json.RawMessage `json:"members"`
	}
	if json.Unmarshal(req.Plan.Bundle, &bundle) != nil || json.Unmarshal(bundle.Members, &members) != nil || req.Keys == nil {
		return ErrPlan
	}
	expected := 0
	for _, m := range members {
		target := m.Request.Plan.Target
		if req.S3.Endpoint != target.Endpoint || req.S3.Bucket != target.Bucket || req.S3.Region != target.Region || target.Region == "" || req.S3.AccessKey == "" || req.S3.SecretKey == "" {
			return ErrPlan
		}
		if m.Request.Plan.Encryption.Format != "none" {
			expected++
			key, err := base64.StdEncoding.Strict().DecodeString(req.Keys[m.Request.BackupID])
			valid := err == nil && len(key) == 32
			clear(key)
			if !valid {
				return ErrPlan
			}
		}
	}
	if len(req.Keys) != expected {
		return ErrPlan
	}
	return nil
}

func run(ctx context.Context, req Request, caFile string) (*storagerestore.VerificationResult, error) {
	s3 := req.S3
	open, close, err := restoreinput.S3SourceConfig(restoreinput.S3Configuration{Endpoint: s3.Endpoint, Bucket: s3.Bucket, Region: s3.Region, AccessKey: s3.AccessKey, SecretKey: s3.SecretKey, SessionToken: s3.SessionToken, CAFile: caFile})
	if err != nil {
		return nil, err
	}
	defer close()
	keys := func(_ context.Context, m storagerestore.Member) ([]byte, error) {
		return base64.StdEncoding.Strict().DecodeString(req.Keys[m.Request.BackupID])
	}
	if req.Plan.Provider == "libvirt" {
		bundle, err := nativerestore.DecodeBundle(req.Plan.Bundle)
		if err != nil {
			return nil, err
		}
		return nativerestore.Verify(ctx, bundle, open, func(ctx context.Context, m nativerestore.Member) ([]byte, error) {
			return keys(ctx, storagerestore.Member{Request: models.StorageTransactionRequest{BackupID: m.Request.BackupID}})
		})
	}
	var bundle kubevirtBundle
	if models.DecodeStorageValue(req.Plan.Bundle, &bundle, MaxRequestBytes) != nil {
		return nil, ErrPlan
	}
	return storagerestore.Verify(ctx, bundle.Members, open, keys)
}
