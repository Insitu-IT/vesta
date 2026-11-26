package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativerestore"
	"vnbui/agent/internal/storagerestore"
)

func runNativeBundle(ctx context.Context, raw []byte, output, definition string, open storagerestore.ObjectOpener, keys storagerestore.KeyResolver, stdout io.Writer) error {
	bundle, err := nativerestore.DecodeBundle(raw)
	if err != nil {
		return err
	}
	resolve := func(ctx context.Context, m nativerestore.Member) ([]byte, error) {
		return keys(ctx, storagerestore.Member{Request: models.StorageTransactionRequest{BackupID: m.Request.BackupID}})
	}
	if definition != "" {
		xml, err := nativerestore.ReadDomainXML(ctx, bundle, open, resolve)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(definition, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = f.Write(xml)
		if err == nil {
			err = f.Sync()
		}
		err = errors.Join(err, f.Close())
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(map[string]string{"definition_path": definition})
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return err
	}
	if err = os.Mkdir(output, 0700); err != nil {
		return err
	}
	members, err := nativerestore.Materialize(ctx, bundle, filepath.Join(output, "members"), open, resolve)
	if err != nil {
		return err
	}
	disks, err := backup.RestoreNativePush(ctx, members, filepath.Join(output, "disks"))
	if err != nil {
		return err
	}
	// Standalone recovery never defines or starts a VM. API admission owns that
	// separate operation and its explicit mappings, restart journal and custody.
	return json.NewEncoder(stdout).Encode(map[string]interface{}{"disks": disks})
}
