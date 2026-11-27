package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
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
	final, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	folder, err := os.MkdirTemp(filepath.Dir(final), ".vesta-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(folder)
	stage := filepath.Join(folder, "verified")
	disks, err := restoreNativeDisks(ctx, bundle, stage, open, keys, false)
	if err != nil {
		return err
	}
	for i := range disks {
		disks[i].Path, err = publishedPath(stage, final, disks[i].Path)
		if err != nil {
			return err
		}
	}
	if err := publishVerifiedDisks(ctx, stage, final, (*os.File).Sync); err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]interface{}{"disks": disks})
}

func restoreNativeDisks(ctx context.Context, bundle nativerestore.Bundle, output string, open storagerestore.ObjectOpener, keys storagerestore.KeyResolver, bucketInput bool) ([]backup.NativeRestoredDisk, error) {
	resolve := func(ctx context.Context, m nativerestore.Member) ([]byte, error) {
		return keys(ctx, storagerestore.Member{Request: models.StorageTransactionRequest{BackupID: m.Request.BackupID}})
	}
	work, err := os.MkdirTemp(filepath.Dir(output), ".vesta-native-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	members, err := nativerestore.Materialize(ctx, bundle, filepath.Join(work, "members"), open, resolve)
	if err != nil {
		return nil, err
	}
	if bucketInput {
		for _, member := range members {
			for _, disk := range member.Manifest.Disks {
				if err := standaloneQCOW(filepath.Join(member.Directory, disk.File)); err != nil {
					return nil, err
				}
			}
		}
	}
	return stageNativeOutput(ctx, members, filepath.Join(work, "reconstruction"), output, backup.RestoreNativePush)
}

// The native helper needs private copies of every historical member and
// rewritten QCOW overlays. Transfer only the checked top-level raw results
// into the directory that the standalone caller will publish.
func stageNativeOutput(ctx context.Context, members []backup.NativeRestoreMember, reconstruction, stage string,
	convert func(context.Context, []backup.NativeRestoreMember, string) ([]backup.NativeRestoredDisk, error)) ([]backup.NativeRestoredDisk, error) {
	if len(members) == 0 {
		return nil, errors.New("native recovery requires a verified chain")
	}
	disks, err := convert(ctx, members, reconstruction)
	if err != nil {
		return nil, err
	}
	expected := members[len(members)-1].Manifest.Disks
	if len(disks) == 0 || len(disks) != len(expected) {
		return nil, errors.New("native recovery returned an incomplete disk set")
	}
	if err := os.Mkdir(stage, 0700); err != nil {
		return nil, err
	}
	out := filepath.Join(stage, "disks")
	if err := os.Mkdir(out, 0700); err != nil {
		return nil, err
	}
	for i, disk := range disks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := disk.Target + ".raw"
		verified := filepath.Join(reconstruction, name)
		if !filepath.IsLocal(name) || filepath.Base(name) != name || disk.Path != verified ||
			disk.Target != expected[i].Target || disk.SizeBytes != expected[i].VirtualSize {
			return nil, errors.New("native recovery returned a disk outside its expected identity")
		}
		info, err := os.Lstat(verified)
		if err != nil || !info.Mode().IsRegular() || info.Size() != disk.SizeBytes {
			return nil, fmt.Errorf("invalid reconstructed raw disk %q", disk.Target)
		}
		if err := os.Chmod(verified, 0600); err != nil {
			return nil, err
		}
		destination := filepath.Join(out, name)
		if err := os.Rename(verified, destination); err != nil {
			return nil, err
		}
		disks[i].Path = destination
	}
	return disks, nil
}

// Check the fixed qcow2 header before giving bucket-sourced images to qemu-img.
// The supported native profile publishes self-contained images for every
// member; the restore tool adds the local backing references itself.
func standaloneQCOW(name string) error {
	file, err := os.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	var header [80]byte
	if _, err := io.ReadFull(file, header[:]); err != nil {
		return err
	}
	version := binary.BigEndian.Uint32(header[4:8])
	if string(header[:4]) != "QFI\xfb" || (version != 2 && version != 3) ||
		binary.BigEndian.Uint64(header[8:16]) != 0 || binary.BigEndian.Uint32(header[16:20]) != 0 ||
		(version == 3 && binary.BigEndian.Uint64(header[72:80])&(1<<2) != 0) {
		return errors.New("native bucket disk is not a self-contained qcow2 image")
	}
	return nil
}
