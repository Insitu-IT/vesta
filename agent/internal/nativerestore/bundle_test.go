package nativerestore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"vnbui/agent/internal/encryption"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
)

func bundleFixture(t *testing.T, encrypted bool) (Bundle, map[string][]byte, []byte) {
	t.Helper()
	body, err := os.ReadFile("../../contracts/native_storage_examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var examples []struct {
		Request models.NativeTransactionRequest
		Receipt models.NativeStorageReceipt
	}
	if json.Unmarshal(body, &examples) != nil {
		t.Fatal("fixture")
	}
	e := examples[0]
	if encrypted {
		e = examples[1]
	}
	p := &e.Request.Plan
	inv := &p.Source.Inventory
	inv.Disks = []models.NativeDisk{{ID: "vda", Target: "vda", Bus: "virtio", Serial: ""}, {ID: "vdb", Target: "vdb", Bus: "virtio", Serial: ""}}
	plain := map[string][]byte{"domain.xml": []byte("<domain>captured</domain>"), "checkpoint.xml": []byte("<domaincheckpoint/>"), "vda.qcow2": []byte("disk-one"), "vdb.qcow2": []byte("disk-two")}
	manifest := models.NativePushManifest{Schema: "libvirt-push-qcow2/1", BackupID: e.Request.BackupID, AttemptID: p.AttemptID, DomainUUID: inv.DomainUUID, Checkpoint: inv.Checkpoint, CheckpointSHA256: hash(plain["checkpoint.xml"]), DomainXMLSHA256: hash(plain["domain.xml"]), Exclusions: []string{}, Source: []models.NativeSourceDisk{{Target: "vda", Bus: "virtio", Source: "/source/a", Format: "qcow2"}, {Target: "vdb", Bus: "virtio", Source: "/source/b", Format: "qcow2"}}, Disks: []models.NativePushDisk{{Target: "vda", File: "vda.qcow2", SizeBytes: 8, VirtualSize: 4096, SHA256: hash(plain["vda.qcow2"])}, {Target: "vdb", File: "vdb.qcow2", SizeBytes: 8, VirtualSize: 8192, SHA256: hash(plain["vdb.qcow2"])}}}
	canonical, _ := models.StorageCanonical(manifest)
	plain["manifest.json"] = canonical
	inv.Files = nil
	names := []string{"domain.xml", "checkpoint.xml", "manifest.json", "vda.qcow2", "vdb.qcow2"}
	roles := []string{"domain_config", "checkpoint", "backup_metadata", "disk_payload", "disk_payload"}
	for i, name := range names {
		file := models.NativeFile{MemberBackupID: inv.BackupID, MemberCheckpoint: inv.Checkpoint, Path: name, Role: roles[i], Device: 1, Inode: uint64(i + 1), Size: int64(len(plain[name])), MtimeNS: 1, CtimeNS: 1}
		if i >= 3 {
			target := inv.Disks[i-3].Target
			file.DiskID = &target
		}
		file.ArtifactID = nativefileset.ArtifactID(*inv, file)
		inv.Files = append(inv.Files, file)
	}
	inventory, _ := models.StorageCanonical(*inv)
	p.Source.InventorySHA256 = hash(inventory)
	p.Artifacts, err = nativefileset.BuildArtifacts(p.Source, e.Request.OrgID, e.Request.BackupID, e.Request.ReservationID, p.Encryption)
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := models.StorageCanonical(*p)
	e.Request.PlanSHA256 = hash(plan)
	e.Receipt.Objects = nil
	stored := map[string][]byte{}
	key := bytes.Repeat([]byte{7}, 32)
	for _, a := range p.Artifacts {
		var data []byte
		for _, file := range inv.Files {
			if file.ArtifactID == a.ArtifactID {
				data = plain[file.Path]
			}
		}
		cipher := data
		if encrypted {
			var b bytes.Buffer
			if err := encryption.EncryptStream(bytes.NewReader(data), &b, key); err != nil {
				t.Fatal(err)
			}
			cipher = b.Bytes()
		}
		stored[a.Key] = cipher
		e.Receipt.Objects = append(e.Receipt.Objects, models.NativeStorageObjectReceipt{ArtifactID: a.ArtifactID, DiskID: a.DiskID, Role: a.Role, Key: a.Key, ETag: `"immutable"`, PlaintextBytes: int64(len(data)), CiphertextBytes: int64(len(cipher)), PlaintextSHA256: hash(data), CiphertextSHA256: hash(cipher)})
	}
	bundle := Bundle{Schema: BundleSchema, Members: []Member{{Request: e.Request, Receipt: e.Receipt, PushResult: models.NativePushResult{Manifest: manifest, ManifestSHA256: hash(canonical)}}}}
	if err := Validate(bundle); err != nil {
		t.Fatal("fixture validation", err)
	}
	return bundle, stored, key
}

func TestMaterializeExactMultiDiskObjectsPlainAndEncrypted(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[encrypted], func(t *testing.T) {
			bundle, store, key := bundleFixture(t, encrypted)
			open := func(_ context.Context, _ models.StorageTarget, o models.StorageObjectReceipt) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(store[o.Key])), nil
			}
			keys := func(context.Context, Member) ([]byte, error) { return key, nil }
			path := filepath.Join(t.TempDir(), "inputs")
			members, err := Materialize(context.Background(), bundle, path, open, keys)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"vda.qcow2", "vdb.qcow2", "domain.xml", "checkpoint.xml", "manifest.json"} {
				info, err := os.Stat(filepath.Join(members[0].Directory, name))
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatal(name, info, err)
				}
			}
			if _, err = Materialize(context.Background(), bundle, path, open, keys); err == nil {
				t.Fatal("overwrote input custody")
			}
			xml, err := ReadDomainXML(context.Background(), bundle, open, keys)
			if err != nil || string(xml) != "<domain>captured</domain>" {
				t.Fatal(string(xml), err)
			}
			obj := bundle.Members[0].Receipt.Objects[0]
			store[obj.Key][len(store[obj.Key])-1] ^= 1
			if _, err = Materialize(context.Background(), bundle, filepath.Join(t.TempDir(), "bad"), open, keys); err == nil {
				t.Fatal("corruption accepted")
			}
		})
	}
}

func TestNativeRestoreRefusesMembershipAndDestinationDrift(t *testing.T) {
	bundle, _, key := bundleFixture(t, true)
	m := bundle.Members[0]
	request := models.NativeRestoreRequest{Schema: models.NativeRestoreSchema, OrgID: m.Request.OrgID, AgentID: m.Request.AgentID, RestoreID: "99999999-9999-4999-8999-999999999999", Target: models.NativeRestoreTarget{VMName: "fresh-vm", VMUUID: "88888888-8888-4888-8888-888888888888", Disks: []string{"vda", "vdb"}, DropExcludedDisks: []string{}, Networks: []models.NativeRestoreNetwork{}}, Bundle: MarshalBundle(bundle), S3: models.KubeVirtRestoreS3{Endpoint: m.Request.Plan.Target.Endpoint, Bucket: m.Request.Plan.Target.Bucket, Region: m.Request.Plan.Target.Region, AccessKey: "read", SecretKey: "private"}, Keys: map[string]string{m.Request.BackupID: base64.StdEncoding.EncodeToString(key)}}
	if _, _, err := ValidatePlan(&request, true); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"tenant", "agent", "source", "disks", "network", "key", "target"} {
		t.Run(fault, func(t *testing.T) {
			body, _ := json.Marshal(request)
			var wrong models.NativeRestoreRequest
			_ = json.Unmarshal(body, &wrong)
			switch fault {
			case "tenant":
				wrong.OrgID = "other"
			case "agent":
				wrong.AgentID = "other"
			case "source":
				wrong.Target.VMUUID = m.PushResult.Manifest.DomainUUID
			case "disks":
				wrong.Target.Disks = []string{"vda"}
			case "network":
				wrong.Target.Networks = []models.NativeRestoreNetwork{{SourceMAC: "../../bad", Network: "default"}}
			case "key":
				wrong.Keys = nil
			case "target":
				wrong.S3.Bucket = "other"
			}
			if _, _, err := ValidatePlan(&wrong, true); err == nil {
				t.Fatal("unsafe request admitted")
			}
		})
	}
	for _, fault := range []string{"hash", "role", "source", "parent"} {
		t.Run(fault, func(t *testing.T) {
			body, _ := json.Marshal(bundle)
			var wrong Bundle
			_ = json.Unmarshal(body, &wrong)
			switch fault {
			case "hash":
				wrong.Members[0].Receipt.Objects[0].PlaintextSHA256 = string(bytes.Repeat([]byte("0"), 64))
			case "role":
				wrong.Members[0].Receipt.Objects[0].Role = "autostart"
			case "source":
				wrong.Members[0].PushResult.Manifest.Source[0].Source = "/different"
			case "parent":
				wrong.Members = append(wrong.Members, wrong.Members[0])
			}
			if Validate(wrong) == nil {
				t.Fatal("changed accepted chain admitted")
			}
		})
	}
}
