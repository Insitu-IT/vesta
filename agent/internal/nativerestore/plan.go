package nativerestore

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"slices"

	"vnbui/agent/internal/models"
)

var uuidName = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var macName = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)

func ValidatePlan(request *models.NativeRestoreRequest, requireCredentials bool) (Bundle, string, error) {
	var bundle Bundle
	if request == nil || request.Schema != models.NativeRestoreSchema || !uuidName.MatchString(request.RestoreID) ||
		!uuidName.MatchString(request.Target.VMUUID) || !safeName.MatchString(request.Target.VMName) || len(request.Bundle) > 4<<20 {
		return bundle, "", ErrBundle
	}
	if models.DecodeStorageValue(request.Bundle, &bundle, 4<<20) != nil || Validate(bundle) != nil {
		return bundle, "", ErrBundle
	}
	first, last := bundle.Members[0], bundle.Members[len(bundle.Members)-1]
	if request.OrgID != first.Request.OrgID || request.AgentID != first.Request.AgentID || request.Target.VMUUID == last.PushResult.Manifest.DomainUUID {
		return bundle, "", ErrBundle
	}
	disks := []string{}
	for _, d := range last.PushResult.Manifest.Disks {
		disks = append(disks, d.Target)
	}
	if !slices.Equal(disks, request.Target.Disks) || !slices.Equal(last.PushResult.Manifest.Exclusions, request.Target.DropExcludedDisks) {
		return bundle, "", ErrBundle
	}
	seen := map[string]bool{}
	for _, network := range request.Target.Networks {
		if !macName.MatchString(network.SourceMAC) || !safeName.MatchString(network.Network) || seen[network.SourceMAC] {
			return bundle, "", ErrBundle
		}
		seen[network.SourceMAC] = true
	}
	if requireCredentials {
		s3 := request.S3
		target := first.Request.Plan.Target
		if s3.Endpoint != target.Endpoint || s3.Bucket != target.Bucket || s3.Region != target.Region || s3.Region == "" || s3.AccessKey == "" || s3.SecretKey == "" {
			return bundle, "", ErrBundle
		}
		expected := 0
		for _, m := range bundle.Members {
			if m.Request.Plan.Encryption.Format != "none" {
				expected++
				key, err := base64.StdEncoding.Strict().DecodeString(request.Keys[m.Request.BackupID])
				if err != nil || len(key) != 32 {
					return bundle, "", ErrBundle
				}
			}
		}
		if len(request.Keys) != expected {
			return bundle, "", ErrBundle
		}
	}
	copy := *request
	copy.S3 = models.KubeVirtRestoreS3{}
	copy.Keys = nil
	body, err := models.StorageCanonical(copy)
	if err != nil {
		return bundle, "", err
	}
	return bundle, hash(body), nil
}

func DecodeBundle(body []byte) (Bundle, error) {
	var bundle Bundle
	if models.DecodeStorageValue(body, &bundle, 4<<20) != nil {
		return bundle, ErrBundle
	}
	return bundle, Validate(bundle)
}

func MarshalBundle(bundle Bundle) json.RawMessage { body, _ := json.Marshal(bundle); return body }
