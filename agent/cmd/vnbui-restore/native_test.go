package main

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/models"
)

func TestNativeMultiGenerationPublishesOnlyFinalRawImages(t *testing.T) {
	parent := t.TempDir()
	scratch := filepath.Join(parent, "scratch")
	reconstruction := filepath.Join(scratch, "native-work")
	stage := filepath.Join(scratch, "verified")
	output := filepath.Join(parent, "recovered")
	expected := []models.NativePushDisk{{Target: "vda", File: "vda.qcow2", VirtualSize: 5},
		{Target: "vdb", File: "vdb.qcow2", VirtualSize: 6}}
	fullID := "full"
	members := []backup.NativeRestoreMember{
		{Manifest: models.NativePushManifest{BackupID: fullID, Disks: expected}, Directory: filepath.Join(scratch, "full")},
		{Manifest: models.NativePushManifest{BackupID: "incremental", ParentBackupID: &fullID, Disks: expected},
			Directory: filepath.Join(scratch, "incremental")},
	}
	for _, member := range members {
		writeFile(t, filepath.Join(member.Directory, "domain.xml"), []byte("private-definition"))
		writeFile(t, filepath.Join(member.Directory, "vda.qcow2"), []byte("historical-overlay"))
	}
	outputs := map[string][]byte{"vda": []byte("final"), "vdb": []byte("final!")}
	disks, err := stageNativeOutput(context.Background(), members, reconstruction, stage,
		func(_ context.Context, chain []backup.NativeRestoreMember, work string) ([]backup.NativeRestoredDisk, error) {
			if len(chain) != 2 || *chain[1].Manifest.ParentBackupID != chain[0].Manifest.BackupID ||
				work != reconstruction || filepath.Dir(work) != filepath.Dir(stage) {
				t.Fatal("native conversion did not receive both generations in separate scratch")
			}
			writeFile(t, filepath.Join(work, "restored.json"), []byte("stale paths"))
			writeFile(t, filepath.Join(work, "0-vda.qcow2"), []byte("decrypted historical data"))
			writeFile(t, filepath.Join(work, "1-vda.qcow2"), []byte("decrypted incremental data"))
			results := make([]backup.NativeRestoredDisk, 0, len(expected))
			for _, disk := range expected {
				p := filepath.Join(work, disk.Target+".raw")
				writeFile(t, p, outputs[disk.Target])
				results = append(results, backup.NativeRestoredDisk{Target: disk.Target, Path: p, SizeBytes: disk.VirtualSize,
					SHA256: checksum(outputs[disk.Target])})
			}
			return results, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	for i := range disks {
		disks[i].Path, err = publishedPath(stage, output, disks[i].Path)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := publishVerifiedDisks(context.Background(), stage, output, (*os.File).Sync); err != nil {
		t.Fatal(err)
	}
	var actual []string
	if err := filepath.WalkDir(output, func(path string, _ fs.DirEntry, err error) error {
		if err == nil {
			relative, relErr := filepath.Rel(output, path)
			if relErr != nil {
				return relErr
			}
			actual = append(actual, relative)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{".", "disks", "disks/vda.raw", "disks/vdb.raw"}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("native output exposed scratch: %v", actual)
	}
	for _, disk := range disks {
		data, err := os.ReadFile(disk.Path)
		if err != nil || checksum(data) != disk.SHA256 || string(data) != string(outputs[disk.Target]) {
			t.Fatalf("wrong final raw disk or stale receipt path: %v", err)
		}
	}
}
