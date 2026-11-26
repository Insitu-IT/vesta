package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"vnbui/agent/internal/models"
	kubevirtrestore "vnbui/agent/internal/restore/kubevirt"
	"vnbui/agent/internal/restoreinput"
	"vnbui/agent/internal/storagerestore"
	"io"
	"os"
)

func runWorker(ctx context.Context, path, caPath string, stdout io.Writer) error {
	var req models.KubeVirtRestoreRequest
	// Projected Secret files use mode 0440 and the install-authorized qemu
	// group, not a local operator's 0600 credential-file convention.
	if err := readJSONFile(path, &req, 900<<10, false); err != nil {
		return fmt.Errorf("cannot read private worker input")
	}
	bundle, _, err := kubevirtrestore.ValidatePlan(&req)
	if err != nil {
		return err
	}
	cfg := req.S3
	open, close, err := restoreinput.S3SourceConfig(restoreinput.S3Configuration{Endpoint: cfg.Endpoint, Bucket: cfg.Bucket, Region: cfg.Region, AccessKey: cfg.AccessKey, SecretKey: cfg.SecretKey, SessionToken: cfg.SessionToken, CAFile: caPath})
	if err != nil {
		return err
	}
	defer close()
	keys := func(ctx context.Context, member storagerestore.Member) ([]byte, error) {
		return base64.StdEncoding.Strict().DecodeString(req.Keys[member.Request.BackupID])
	}
	definition, err := storagerestore.ReadVMDefinition(ctx, bundle.Members, open, keys)
	if err != nil {
		return err
	}
	if _, err = kubevirtrestore.RenderVM(definition, req.Target, bundle.Members[len(bundle.Members)-1].Request.Plan.Source); err != nil {
		return err
	}
	destinations := make([]storagerestore.Destination, len(req.Target.Disks))
	for i, disk := range req.Target.Disks {
		path := fmt.Sprintf("/restore/disk-%03d/disk.img", i)
		block := disk.VolumeMode == "Block"
		if block {
			path = fmt.Sprintf("/dev/restore/disk-%03d", i)
		}
		destinations[i] = storagerestore.Destination{VolumeName: disk.VolumeName, Path: path, Block: block}
	}
	disks, err := storagerestore.AssembleTo(ctx, bundle.Members, destinations, open, keys)
	if err != nil {
		return err
	}
	for _, destination := range destinations {
		if !destination.Block {
			if err = os.Chmod(destination.Path, 0660); err != nil {
				return err
			}
		}
	}
	// Only disk identities/digests appear in logs. VM definition, S3 secrets
	// and DEKs are never printed or written to a termination message.
	return json.NewEncoder(stdout).Encode(map[string]interface{}{"status": "verified", "disks": disks})
}
