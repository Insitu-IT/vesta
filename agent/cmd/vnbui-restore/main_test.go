package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storagerestore"
)

func checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, data)
}

func offlineFixture(t *testing.T) (chainFile, objectsDir string, payloadPath string) {
	t.Helper()
	root := t.TempDir()
	objectsDir = filepath.Join(root, "objects")
	template, err := os.ReadFile("../../contracts/storage_semantic_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	members := make([]storagerestore.Member, 0, 2)
	previousDigest := ""
	for index := 0; index < 2; index++ {
		var request models.StorageTransactionRequest
		if err := json.Unmarshal(template, &request); err != nil {
			t.Fatal(err)
		}
		request.Plan.Target.Region = "us-east-1"
		request.Plan.Source.Volumes[0].CapacityBytes = 12
		payload := []byte("ABCDEFGH")
		extents := []map[string]any{{"disk_offset": 0, "length": 8, "payload_offset": 0}}
		if index == 1 {
			request.BackupID = "66666666-6666-4666-8666-666666666666"
			request.ReservationID = "77777777-7777-4777-8777-777777777777"
			request.Plan.AttemptID = request.ReservationID
			request.Plan.BackupType = "incremental"
			request.Plan.Parent = &models.StorageParent{
				BackupID: members[0].Request.BackupID, RootBackupID: members[0].Request.BackupID,
				ReceiptSHA256: previousDigest, GenerationID: "88888888-8888-4888-8888-888888888888",
				TrackerUID: "tracker", Checkpoint: "cp-0",
			}
			payload = []byte("xy")
			extents = []map[string]any{
				{"disk_offset": 2, "length": 2, "payload_offset": 0},
				{"disk_offset": 6, "length": 2, "zero_fill": true},
			}
		}
		payloadKey := ""
		for i := range request.Plan.Artifacts {
			a := &request.Plan.Artifacts[i]
			a.Key = "vnbui-owned/v1/" + checksum([]byte(request.OrgID)) + "/" + checksum([]byte(request.BackupID)) + "/payload/" + request.ReservationID + "/" + checksum([]byte(a.VolumeID)) + "/" + a.Role
			if a.Role == "volume_payload" {
				a.PlaintextMax, a.CiphertextMax = 12, 12
				payloadKey = a.Key
			}
		}
		manifest, err := json.Marshal(map[string]any{
			"format": "vnbui-kubevirt-cbt-v1", "vm_namespace": request.Plan.Source.Namespace,
			"vm_uid": request.Plan.Source.VMUID, "backup_type": request.Plan.BackupType,
			"checkpoint": fmt.Sprintf("cp-%d", index), "volume": "data", "virtual_size": 12,
			"encrypted": false, "payload_key": payloadKey, "stored_extents": extents,
		})
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := models.StorageCanonical(request.Plan)
		if err != nil {
			t.Fatal(err)
		}
		request.PlanSHA256 = checksum(canonical)
		receipt := models.StorageReceipt{
			Protocol: models.StorageProtocol, Schema: 2, ReservationID: request.ReservationID,
			BackupID: request.BackupID, Endpoint: request.Plan.Target.Endpoint, Bucket: request.Plan.Target.Bucket,
		}
		for _, artifact := range request.Plan.Artifacts {
			data := manifest
			if artifact.Role == "volume_payload" {
				data = payload
			}
			objectPath := filepath.Join(objectsDir, receipt.Bucket, filepath.FromSlash(artifact.Key))
			writeFile(t, objectPath, data)
			if artifact.Role == "volume_payload" {
				payloadPath = objectPath
			}
			receipt.Objects = append(receipt.Objects, models.StorageObjectReceipt{
				Key: artifact.Key, ETag: `"fixture-etag"`, PlaintextBytes: int64(len(data)), CiphertextBytes: int64(len(data)),
				PlaintextSHA256: checksum(data), CiphertextSHA256: checksum(data), VolumeID: artifact.VolumeID, Role: artifact.Role,
			})
		}
		_, previousDigest, err = models.CanonicalReceipt(&request, receipt)
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, storagerestore.Member{Request: request, Receipt: receipt})
	}
	chainFile = filepath.Join(root, "chain.json")
	writeJSON(t, chainFile, map[string]any{"schema": "vnbui-kubevirt-restore/1", "members": members})
	return chainFile, objectsDir, payloadPath
}

func TestOfflineFullAndIncrementalCLI(t *testing.T) {
	chain, objects, _ := offlineFixture(t)
	output := filepath.Join(t.TempDir(), "new-disks")
	var stdout bytes.Buffer
	if err := run(context.Background(), []string{"-chain", chain, "-objects-dir", objects, "-output", output}, &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Disks []storagerestore.Disk `json:"disks"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || len(result.Disks) != 1 {
		t.Fatalf("result: %s, %v", stdout.Bytes(), err)
	}
	expected := append([]byte("ABxyEF"), make([]byte, 6)...)
	actual, err := os.ReadFile(result.Disks[0].Path)
	if err != nil || !bytes.Equal(actual, expected) || result.Disks[0].SizeBytes != 12 || result.Disks[0].SHA256 != checksum(expected) {
		t.Fatalf("restored disk: %x, %v, %+v", actual, err, result.Disks)
	}
	if err := run(context.Background(), []string{"-chain", chain, "-objects-dir", objects, "-output", output}, io.Discard, io.Discard); err == nil {
		t.Fatal("existing output was overwritten")
	}
	unchanged, _ := os.ReadFile(result.Disks[0].Path)
	if !bytes.Equal(unchanged, expected) {
		t.Fatal("refused restore changed existing output")
	}
}

func TestOfflineCorruptionDoesNotPublishOutput(t *testing.T) {
	chain, objects, payload := offlineFixture(t)
	writeFile(t, payload, []byte("zz")) // Correct length, different content.
	output := filepath.Join(t.TempDir(), "new-disks")
	var stdout bytes.Buffer
	if err := run(context.Background(), []string{"-chain", chain, "-objects-dir", objects, "-output", output}, &stdout, io.Discard); err == nil {
		t.Fatal("corrupt payload accepted")
	}
	if stdout.Len() != 0 {
		t.Fatal("failure emitted successful output")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("failed restore left output directory", err)
	}
}

func TestSnapshotCannotEscapeRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	writeFile(t, outside, []byte("outside"))
	if err := os.Mkdir(filepath.Join(root, "bucket"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "bucket", "object")); err != nil {
		t.Fatal(err)
	}
	open, closeSource, err := localSource(root)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSource()
	target := models.StorageTarget{Endpoint: "https://s3.example.net", Bucket: "bucket", Region: "us-east-1"}
	for _, key := range []string{"object", "../../secret", "/secret"} {
		if body, err := open(context.Background(), target, models.StorageObjectReceipt{Key: key, CiphertextBytes: 7}); err == nil {
			body.Close()
			t.Fatal("snapshot escape accepted", key)
		}
	}
}

func TestDEKsArePrivateAndPerBackup(t *testing.T) {
	directory := t.TempDir()
	firstID, secondID := "first-backup", "second-backup"
	first, second := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	writeFile(t, filepath.Join(directory, firstID+".key"), []byte(base64.StdEncoding.EncodeToString(first)))
	writeFile(t, filepath.Join(directory, secondID+".key"), []byte(base64.StdEncoding.EncodeToString(second)))
	keys, closeKeys, err := fileKeys(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer closeKeys()
	for id, expected := range map[string][]byte{firstID: first, secondID: second} {
		key, err := keys(context.Background(), storagerestore.Member{Request: models.StorageTransactionRequest{BackupID: id}})
		if err != nil || !bytes.Equal(key, expected) {
			t.Fatal("wrong per-backup DEK", err)
		}
	}
	if err := os.Chmod(filepath.Join(directory, firstID+".key"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := keys(context.Background(), storagerestore.Member{Request: models.StorageTransactionRequest{BackupID: firstID}}); err == nil {
		t.Fatal("world-readable key accepted")
	}
	if _, err := keys(context.Background(), storagerestore.Member{Request: models.StorageTransactionRequest{BackupID: "../escape"}}); err == nil {
		t.Fatal("invalid backup key path accepted")
	}
}

func TestS3PinnedGETAndTrust(t *testing.T) {
	for _, variant := range []string{"versioned", "unversioned", "wrong-etag", "wrong-version", "wrong-size", "untrusted-tls", "redirect"} {
		t.Run(variant, func(t *testing.T) {
			var calls atomic.Int32
			payload := "stored-bytes"
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/bucket/object" || r.Header.Get("If-Match") != `"expected-etag"` || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
					t.Error("GET did not use the exact signed receipt identity")
				}
				if variant == "unversioned" {
					if r.URL.Query().Has("versionId") {
						t.Error("unversioned object acquired an invented version")
					}
				} else if r.URL.Query().Get("versionId") != "expected-version" {
					t.Error("versionId missing from request")
				}
				if variant == "redirect" {
					w.Header().Set("Location", "https://outside.invalid/object")
					w.WriteHeader(http.StatusTemporaryRedirect)
					return
				}
				w.Header().Set("Last-Modified", "Thu, 01 Oct 2026 00:00:00 GMT")
				w.Header().Set("ETag", `"expected-etag"`)
				if variant != "unversioned" {
					w.Header().Set("X-Amz-Version-Id", "expected-version")
				}
				if variant == "wrong-etag" {
					w.Header().Set("ETag", `"different-etag"`)
				}
				if variant == "wrong-version" {
					w.Header().Set("X-Amz-Version-Id", "different-version")
				}
				body := payload
				if variant == "wrong-size" {
					body += "extra"
				}
				w.Header().Set("Content-Length", fmt.Sprint(len(body)))
				fmt.Fprint(w, body)
			}))
			defer server.Close()
			directory := t.TempDir()
			caPath := filepath.Join(directory, "ca.pem")
			writeFile(t, caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
			cfg := s3Configuration{Endpoint: server.URL, Bucket: "bucket", Region: "us-east-1", AccessKey: "fixture-access", SecretKey: "fixture-secret", CAFile: "ca.pem"}
			if variant == "untrusted-tls" {
				cfg.CAFile = ""
			}
			configPath := filepath.Join(directory, "s3.json")
			writeJSON(t, configPath, cfg)
			open, closeSource, err := s3Source(configPath)
			if err != nil {
				t.Fatal(err)
			}
			defer closeSource()
			target := models.StorageTarget{Endpoint: cfg.Endpoint, Bucket: cfg.Bucket, Region: cfg.Region}
			version := "expected-version"
			object := models.StorageObjectReceipt{Key: "object", ETag: `"expected-etag"`, VersionID: &version, CiphertextBytes: int64(len(payload))}
			if variant == "unversioned" {
				object.VersionID = nil
			}
			body, err := open(context.Background(), target, object)
			if variant == "versioned" || variant == "unversioned" {
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(body)
				body.Close()
				if err != nil || string(data) != payload {
					t.Fatal("GET body changed", err)
				}
			} else if err == nil {
				body.Close()
				t.Fatal("invalid S3 response accepted")
			}
			before := calls.Load()
			target.Bucket = "different-bucket"
			if _, err := open(context.Background(), target, object); err == nil || calls.Load() != before {
				t.Fatal("configuration scope mismatch reached S3")
			}
		})
	}
}

func TestCLIUsageAndInvalidBundle(t *testing.T) {
	if err := run(context.Background(), []string{"-help"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), nil, io.Discard, io.Discard); err == nil {
		t.Fatal("empty command accepted")
	}
	root := t.TempDir()
	bundle := filepath.Join(root, "chain.json")
	writeJSON(t, bundle, map[string]any{"schema": "unknown", "members": []any{}})
	if err := run(context.Background(), []string{"-chain", bundle, "-objects-dir", root, "-output", filepath.Join(root, "new")}, io.Discard, io.Discard); err == nil {
		t.Fatal("unsupported restore bundle accepted")
	}
}
