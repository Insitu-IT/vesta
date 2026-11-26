package nativerestore

import (
	"bytes"
	"context"
	"errors"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storagerestore"
)

// ReadDomainXML verifies the selected immutable domain artifact, not disk data.
func ReadDomainXML(ctx context.Context, bundle Bundle, open storagerestore.ObjectOpener, keys KeyResolver) ([]byte, error) {
	if err := Validate(bundle); err != nil {
		return nil, err
	}
	m := bundle.Members[len(bundle.Members)-1]
	for _, o := range m.Receipt.Objects {
		if o.Role != "domain_config" {
			continue
		}
		if o.PlaintextBytes > 1<<20 {
			return nil, ErrBundle
		}
		encrypted := m.Request.Plan.Encryption.Format != "none"
		var key []byte
		if encrypted {
			if keys == nil {
				return nil, errors.New("native member DEK resolver unavailable")
			}
			var err error
			key, err = keys(ctx, m)
			if err != nil {
				return nil, err
			}
		}
		obj := models.StorageObjectReceipt{Key: o.Key, VersionID: o.VersionID, ETag: o.ETag, PlaintextBytes: o.PlaintextBytes, CiphertextBytes: o.CiphertextBytes, PlaintextSHA256: o.PlaintextSHA256, CiphertextSHA256: o.CiphertextSHA256}
		var output bytes.Buffer
		if err := storagerestore.WriteVerifiedObject(ctx, m.Request.Plan.Target, obj, encrypted, key, open, &output); err != nil {
			return nil, err
		}
		return output.Bytes(), nil
	}
	return nil, errors.New("captured native domain definition unavailable")
}
