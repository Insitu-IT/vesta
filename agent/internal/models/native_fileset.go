package models

import (
	"encoding/json"
	"reflect"
)

// NativeFileSetFormat is independent of KubeVirt's per-volume extent format.
const NativeFileSetFormat = "libvirt-native-fileset/1"

// DecodeNativeFileSet establishes bounded exact wire shape, not persisted
// authority or filesystem custody. Callers must perform semantic admission.
func DecodeNativeFileSet(body []byte) (*NativeFileSet, error) {
	v, err := DecodeStorageControlJSON(body)
	if err != nil || !exactShape(v, reflect.TypeOf(NativeFileSet{})) {
		return nil, ErrStorageRequest
	}
	var s NativeFileSet
	if json.Unmarshal(body, &s) != nil || s.Format != NativeFileSetFormat {
		return nil, ErrStorageRequest
	}
	return &s, nil
}

// NativeFileSet contains no credentials or pre-upload content hashes. A backend
// must admit job/source ownership before accepting this local inventory.
type NativeFileSet struct {
	Format     string       `json:"format"`
	DomainUUID string       `json:"domain_uuid"`
	BackupID   string       `json:"backup_id"`
	AttemptID  string       `json:"attempt_id"`
	JobID      string       `json:"job_id"`
	Checkpoint string       `json:"checkpoint"`
	Disks      []NativeDisk `json:"disks"`
	Files      []NativeFile `json:"files"`
}

type NativeDisk struct {
	ID     string `json:"id"`
	Target string `json:"target"`
	Bus    string `json:"bus"`
	Serial string `json:"serial"`
}

type NativeFile struct {
	MemberBackupID   string  `json:"member_backup_id"`
	MemberCheckpoint string  `json:"member_checkpoint"`
	ArtifactID       string  `json:"artifact_id"`
	Path             string  `json:"path"`
	Role             string  `json:"role"`
	DiskID           *string `json:"disk_id"`
	Device           uint64  `json:"device"`
	Inode            uint64  `json:"inode"`
	Size             int64   `json:"size"`
	MtimeNS          int64   `json:"mtime_ns"`
	CtimeNS          int64   `json:"ctime_ns"`
}
