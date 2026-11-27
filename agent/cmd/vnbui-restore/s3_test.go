package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fernet/fernet-go"
	josecipher "github.com/go-jose/go-jose/v4/cipher"
	"vnbui/agent/internal/encryption"
	"vnbui/agent/internal/filearchive"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/s3recovery"
	"vnbui/agent/internal/storagerestore"
)

const testInstallation = "11111111-2222-4333-8444-555555555555"
const testKEKID = "88888888-9999-4aaa-8bbb-cccccccccccc"
const testFullGeneration = "88888888-8888-4888-8888-888888888888"
const testIncrementalGeneration = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

type versionedObject struct {
	Key     string
	Version string
	Body    []byte
	Latest  bool
	ETAG    string
}

func (o versionedObject) ETag() string {
	if o.ETAG != "" {
		return o.ETAG
	}
	return strconv.Quote(checksum(o.Body)[:32])
}

type fixtureObjects struct {
	mu                 sync.Mutex
	objects            map[string][]versionedObject
	denySignedHistory  bool
	denySignedPrefix   string
	signedDeleteMarker string
}

func (store *fixtureObjects) put(key string, body []byte) versionedObject {
	store.mu.Lock()
	defer store.mu.Unlock()
	history := store.objects[key]
	for i := range history {
		history[i].Latest = false
	}
	object := versionedObject{Key: key, Version: fmt.Sprintf("fixture-version-%d", len(history)+1), Body: body, Latest: true}
	store.objects[key] = append(history, object)
	return object
}

func (store *fixtureObjects) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		store.mu.Lock()
		defer store.mu.Unlock()
		if (req.Method != http.MethodGet && req.Method != http.MethodHead) || !strings.HasPrefix(req.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Error("fixture received a nonread or unscoped request")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if req.URL.Query().Has("versions") {
			prefix := req.URL.Query().Get("prefix")
			if (store.denySignedHistory && prefix == "vesta-recovery/v1/") ||
				(store.denySignedPrefix != "" && prefix == store.denySignedPrefix) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if req.URL.Path != "/bucket/" && req.URL.Path != "/bucket" {
				t.Errorf("invalid version listing path %s", req.URL.Path)
			}
			type version struct {
				Key          string
				VersionId    string
				IsLatest     bool
				LastModified string
				ETag         string
				Size         int
			}
			response := struct {
				XMLName             xml.Name `xml:"ListVersionsResult"`
				Name                string
				Version             []version
				IsTruncated         bool
				NextKeyMarker       string
				NextVersionIdMarker string
				DeleteMarker        []version
			}{Name: "bucket"}
			query := req.URL.Query()
			var candidates []version
			var keys []string
			for key := range store.objects {
				if strings.HasPrefix(key, query.Get("prefix")) {
					keys = append(keys, key)
				}
			}
			slices.Sort(keys)
			markerKey, markerVersion := query.Get("key-marker"), query.Get("version-id-marker")
			for _, key := range keys {
				if key < markerKey {
					continue
				}
				started := key != markerKey
				for _, object := range slices.Backward(store.objects[key]) {
					if !started {
						if object.Version == markerVersion {
							started = true
						}
						continue
					}
					candidates = append(candidates,
						version{key, object.Version, object.Latest, "2026-11-23T15:03:55Z", object.ETag(), len(object.Body)})
				}
			}
			maxKeys, _ := strconv.Atoi(query.Get("max-keys"))
			if maxKeys > 0 && len(candidates) > maxKeys {
				last := candidates[maxKeys-1]
				response.IsTruncated = true
				response.NextKeyMarker = last.Key
				response.NextVersionIdMarker = last.VersionId
				candidates = candidates[:maxKeys]
			}
			response.Version = candidates
			if store.signedDeleteMarker != "" && strings.HasPrefix(store.signedDeleteMarker, prefix) {
				response.DeleteMarker = []version{{Key: store.signedDeleteMarker, VersionId: "deleted", IsLatest: true,
					LastModified: "2026-11-23T15:03:55Z"}}
			}
			w.Header().Set("Content-Type", "application/xml")
			_ = xml.NewEncoder(w).Encode(response)
			return
		}
		key := strings.TrimPrefix(req.URL.Path, "/bucket/")
		for _, entry := range store.objects[key] {
			if req.URL.Query().Get("versionId") != entry.Version {
				continue
			}
			match := req.Header.Get("If-Match")
			if match != entry.ETag() && !(req.Method == http.MethodHead && match == "") {
				http.Error(w, "precondition failed", http.StatusPreconditionFailed)
				return
			}
			w.Header().Set("ETag", entry.ETag())
			w.Header().Set("X-Amz-Version-Id", entry.Version)
			w.Header().Set("Last-Modified", "Mon, 23 Nov 2026 15:03:55 GMT")
			w.Header().Set("Content-Length", strconv.Itoa(len(entry.Body)))
			if req.Method != http.MethodHead {
				_, _ = w.Write(entry.Body)
			}
			return
		}
		if req.Method == http.MethodHead {
			w.Header().Set("X-Minio-Error-Code", "NoSuchVersion")
		} else {
			t.Errorf("fixture version not specified or absent for %s", key)
		}
		http.NotFound(w, req)
	}
}

func makeVersionedBucket(t *testing.T) (*fixtureObjects, s3Configuration, string) {
	t.Helper()
	store := &fixtureObjects{objects: make(map[string][]versionedObject)}
	server := httptest.NewTLSServer(store.handler(t))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	cfg := s3Configuration{Endpoint: server.URL, Bucket: "bucket", Region: "us-east-1", AccessKey: "fixture-access", SecretKey: "fixture-secret", CAFile: "ca.pem"}
	file := filepath.Join(dir, "s3.json")
	writeJSON(t, file, cfg)
	return store, cfg, file
}

func canonicalFixture(t *testing.T, value any) []byte {
	t.Helper()
	data, err := models.StorageCanonical(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func keyExportFixture(t *testing.T, kek []byte, trust map[string]any, secret string) []byte {
	t.Helper()
	salt := []byte("fixture-salt-all")
	derived, err := pbkdf2.Key(sha256.New, secret, salt, 600000, 32)
	if err != nil {
		t.Fatal(err)
	}
	var key fernet.Key
	copy(key[:], derived)
	data := map[string]any{"version": 1, "format": "vnbui-key-export", "exported_at": "2026-04-10T07:16:32",
		"keys": []any{map[string]string{"id": testKEKID, "name": "fixture", "algorithm": "aes-256-gcm",
			"key_material": base64.StdEncoding.EncodeToString(kek), "key_hash": checksum(kek)[:16], "created_at": "2024-04-10T07:16:32"}}}
	if trust != nil {
		data["recovery_trust"] = trust
	}
	token, err := fernet.EncryptAndSignAtTime(canonicalFixture(t, data), &key, time.Date(2024, 4, 10, 7, 16, 32, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return append(salt, token...)
}

func putEncryptedGeneration(t *testing.T, put func(string, []byte) versionedObject, cfg s3Configuration, kek []byte, legacyMissingVersion bool) ([]storagerestore.Member, []versionedObject) {
	t.Helper()
	snapshot, objectsDir, _ := offlineFixture(t)
	var original struct {
		Schema  string                  `json:"schema"`
		Members []storagerestore.Member `json:"members"`
	}
	if err := readJSONFile(snapshot, &original, 4<<20, false); err != nil {
		t.Fatal(err)
	}
	accepted := make([]any, 0, len(original.Members))
	var previousDigest string
	versions := make([]versionedObject, 0, len(original.Members))
	keyRef := "kek:" + testKEKID + ":" + checksum(kek)[:16]
	destination := models.StorageTarget{Endpoint: cfg.Endpoint, Bucket: cfg.Bucket, Region: cfg.Region}
	for i := range original.Members {
		member := &original.Members[i]
		r := &member.Request
		r.Plan.Target = destination
		r.Plan.Encryption = models.StorageEncryption{Format: "vnbu1-aes256gcm-chunk5242880", KeyRef: &keyRef}
		if r.Plan.Parent != nil {
			r.Plan.Parent.ReceiptSHA256 = previousDigest
		}
		dek := bytes.Repeat([]byte{byte(i + 10)}, 32)
		receipt := &member.Receipt
		sourceBucket := receipt.Bucket
		receipt.Endpoint, receipt.Bucket = cfg.Endpoint, cfg.Bucket
		verification := make([]models.StorageVerification, len(receipt.Objects))
		for j := range receipt.Objects {
			obj := &receipt.Objects[j]
			old, err := os.ReadFile(filepath.Join(objectsDir, sourceBucket, filepath.FromSlash(obj.Key)))
			if err != nil {
				t.Fatal(err)
			}
			plain, encrypted := old, old
			a := &r.Plan.Artifacts[j]
			if obj.Role == "volume_payload" {
				var cipher bytes.Buffer
				if err := encryption.EncryptStream(bytes.NewReader(plain), &cipher, dek); err != nil {
					t.Fatal(err)
				}
				encrypted = cipher.Bytes()
				a.CiphertextMin, a.CiphertextMax = 5, 5+a.PlaintextMax+32
			} else {
				var manifest map[string]any
				if err := json.Unmarshal(old, &manifest); err != nil {
					t.Fatal(err)
				}
				manifest["encrypted"] = true
				plain = canonicalFixture(t, manifest)
				encrypted = plain
			}
			object := put(obj.Key, encrypted)
			obj.ETag, obj.VersionID = object.ETag(), &object.Version
			if legacyMissingVersion && j == 0 {
				obj.VersionID = nil
			}
			obj.PlaintextBytes, obj.CiphertextBytes = int64(len(plain)), int64(len(encrypted))
			obj.PlaintextSHA256, obj.CiphertextSHA256 = checksum(plain), checksum(encrypted)
			reason := "provider_full_object_sha256_unavailable"
			verification[j] = models.StorageVerification{Key: obj.Key, VersionID: obj.VersionID, Assurance: "identity_metadata_only", Reason: &reason}
		}
		r.PlanSHA256 = checksum(canonicalFixture(t, r.Plan))
		_, digest, err := models.CanonicalReceipt(r, *receipt)
		if err != nil {
			t.Fatal(err)
		}
		acceptance := models.StorageAcceptance{Protocol: models.StorageProtocol, ReservationID: r.ReservationID,
			ReceiptSHA256: digest, Accepted: true, AcceptanceID: fmt.Sprintf("fixture-acceptance-%d", i),
			ScrubRequired: true, Verification: verification}
		block, err := aes.NewCipher(kek)
		if err != nil {
			t.Fatal(err)
		}
		wrapped, err := josecipher.KeyWrap(block, dek)
		if err != nil {
			t.Fatal(err)
		}
		accepted = append(accepted, map[string]any{"request": r, "receipt": receipt, "receipt_sha256": digest,
			"acceptance": acceptance, "checkpoint_proof": map[string]any{},
			"checkpoint": map[string]string{"reservation_id": r.ReservationID, "attempt_id": r.Plan.AttemptID,
				"plan_sha256": r.PlanSHA256, "receipt_sha256": digest, "acceptance_id": acceptance.AcceptanceID},
			"wrapped_attempt_key": map[string]any{"schema": 1, "org_id": r.OrgID, "backup_id": r.BackupID,
				"reservation_id": r.ReservationID, "attempt_id": r.Plan.AttemptID, "plan_sha256": r.PlanSHA256,
				"key_ref": keyRef, "format": r.Plan.Encryption.Format, "wrapping": "aes256-keywrap/1",
				"ciphertext": base64.StdEncoding.EncodeToString(wrapped)}})
		previousDigest = digest
		generation, predecessor := testFullGeneration, any(nil)
		if i != 0 {
			generation, predecessor = testIncrementalGeneration, testFullGeneration
		}
		root := original.Members[0].Request.BackupID
		generationKey := "vnbui-owned/v1/" + checksum([]byte(r.OrgID)) + "/" + checksum([]byte(root)) + "/generations/" + generation + ".json"
		raw := canonicalFixture(t, map[string]any{"protocol": "vnbui-storage-generation/1", "installation_id": testInstallation,
			"org_id": r.OrgID, "generation_id": generation, "predecessor_id": predecessor, "root_backup_id": root,
			"backup_id": r.BackupID, "source": r.Plan.Source, "target": destination, "members": accepted})
		versions = append(versions, put(generationKey, raw))
	}
	return original.Members, versions
}

func signTestPoints(t *testing.T, store *fixtureObjects, cfg s3Configuration, members []storagerestore.Member, generations []versionedObject) (map[string]any, []versionedObject) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	org := members[0].Request.OrgID
	trust := map[string]any{"schema": "vesta-recovery-trust/1", "installation_id": testInstallation, "org_id": org,
		"key_id": checksum(pub), "public_key": encode(pub)}
	header := encode(canonicalFixture(t, map[string]string{"alg": "EdDSA", "kid": checksum(pub), "typ": "vesta-recovery-point+jws"}))
	var points []versionedObject
	for i, member := range members {
		object := generations[i]
		generation := strings.TrimSuffix(filepath.Base(object.Key), ".json")
		point := canonicalFixture(t, map[string]any{"format": "vesta-recovery-point/1", "installation_id": testInstallation,
			"org_id": org, "backup_id": member.Request.BackupID, "generation_id": generation,
			"root_backup_id": members[0].Request.BackupID, "provider": "kubevirt", "name": "Sample VM",
			"completed_at": fmt.Sprintf("2026-11-2%dT15:03:55Z", 3+i),
			"generation": map[string]any{"key": object.Key, "version_id": object.Version, "etag": object.ETag(),
				"bytes": len(object.Body), "sha256": checksum(object.Body), "endpoint": cfg.Endpoint, "bucket": cfg.Bucket, "region": cfg.Region}})
		input := header + "." + encode(point)
		jws := input + "." + encode(ed25519.Sign(private, []byte(input)))
		raw := canonicalFixture(t, map[string]string{"format": "vesta-recovery-envelope/1", "public_key": encode(pub), "jws": jws})
		key := "vesta-recovery/v1/" + testInstallation + "/" + org + "/" + member.Request.BackupID + ".json"
		points = append(points, store.put(key, raw))
	}
	return trust, points
}

func TestBucketFirstEncryptedFullAndIncremental(t *testing.T) {
	store, cfg, configPath := makeVersionedBucket(t)
	kek := bytes.Repeat([]byte{0x78}, 32)
	members, generations := putEncryptedGeneration(t, store.put, cfg, kek, true)
	trust, points := signTestPoints(t, store, cfg, members, generations)
	local := t.TempDir()
	trustPath, exportPath, passPath := filepath.Join(local, "trust.json"), filepath.Join(local, "keys.bin"), filepath.Join(local, "pass.txt")
	writeJSON(t, trustPath, trust)
	writeFile(t, exportPath, keyExportFixture(t, kek, trust, "8-char!!"))
	writeFile(t, passPath, []byte("8-char!!\n"))
	trusted := []string{"--s3-config", configPath, "--trust", trustPath}
	withKeys := []string{"--kek-export", exportPath, "--passphrase-file", passPath}
	var list bytes.Buffer
	if err := run(context.Background(), append([]string{"s3", "list"}, trusted...), &list, io.Discard); err != nil ||
		!strings.Contains(list.String(), "Sample VM") || !strings.Contains(list.String(), "2026-11-24T15:03:55Z") {
		t.Fatalf("signed catalog: %v, %s", err, &list)
	}
	testRestore := func(name string, index int, args []string, want []byte, wantError string) {
		t.Helper()
		output := filepath.Join(local, name)
		command := []string{"s3", "restore", "--backup", members[index].Request.BackupID, "--output", output}
		var result bytes.Buffer
		err := run(context.Background(), append(command, args...), &result, io.Discard)
		if wantError != "" {
			if err == nil || !strings.Contains(err.Error(), wantError) || result.Len() != 0 {
				t.Fatalf("%s: result=%s, err=%v", name, &result, err)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("%s: rejected recovery published a path: %v", name, err)
			}
			return
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		data, err := os.ReadFile(filepath.Join(output, "disk-000.raw"))
		if err != nil || !bytes.Equal(data, want) || !strings.Contains(result.String(), checksum(want)) {
			t.Fatalf("%s: bytes=%x, err=%v, result=%s", name, data, err, &result)
		}
	}
	full := append([]byte("ABCDEFGH"), make([]byte, 4)...)
	incremental := append([]byte("ABxyEF"), make([]byte, 6)...)
	testRestore("full", 0, append(slices.Clone(trusted), withKeys...), full, "")
	testRestore("incremental", 1, append([]string{"--s3-config", configPath}, withKeys...), incremental, "")
	testRestore("no-key", 1, trusted, nil, "--kek-export")
	testRestore("bucket-only", 1, []string{"--s3-config", configPath}, nil, "independent --trust")
	wrongExport := filepath.Join(local, "wrong-kek.bin")
	writeFile(t, wrongExport, keyExportFixture(t, bytes.Repeat([]byte{0xaa}, 32), trust, "8-char!!"))
	testRestore("wrong-key", 1, append(slices.Clone(trusted), "--kek-export", wrongExport, "--passphrase-file", passPath), nil, "--kek-export")
	legacy := append([]string{"--s3-config", configPath, "--allow-unsigned-legacy"}, withKeys...)
	oldIdentity := strings.TrimSuffix(generations[0].Key, "/generations/"+testFullGeneration+".json") + "/chain.json"
	store.put(oldIdentity, []byte(`{"backup_id":"historical-only"}`))
	list.Reset()
	if err := run(context.Background(), append([]string{"s3", "list"}, legacy...), &list, io.Discard); err != nil ||
		!strings.Contains(list.String(), "identity-only") || !strings.Contains(list.String(), "unsigned-legacy") {
		t.Fatalf("legacy catalog: %v, %s", err, &list)
	}
	testRestore("unsigned-signed-point", 1, append(slices.Clone(legacy), "--generation-key", generations[1].Key, "--version-id", generations[1].Version), nil, "signed recovery point history")
	testRestore("identity-only", 0, append(slices.Clone(legacy), "--generation-key", oldIdentity), nil, "identity-only")
	store.put(points[1].Key, []byte(`{"format":"vesta-recovery-envelope/1","public_key":"untrusted","jws":"bad"}`))
	testRestore("invalid-signature", 1, append(slices.Clone(trusted), withKeys...), nil, "verify recovery point")
	testRestore("unsigned-corrupt-signed-point", 1, append(slices.Clone(legacy), "--generation-key", generations[1].Key, "--version-id", generations[1].Version), nil, "signed recovery point history")
}

func TestBucketFirstFileArchiveSelection(t *testing.T) {
	store, _, config := makeVersionedBucket(t)
	folder := t.TempDir()
	identity := filepath.Join(folder, "identity")
	recipient, err := filearchive.CreateIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	archive := makeFileArchive(t, recipient)
	const backup = "00000000-7777-4888-9999-123456789abc"
	key := "qa/test-host/managed-files/reports/" + backup + "/archive.age"
	version := store.put(key, archive)
	store.put(key, []byte("other version"))
	base := []string{"--file-prefix", "qa/test-host", "--s3-config", config}
	var stdout bytes.Buffer
	if err := run(context.Background(), append([]string{"s3", "list"}, base...), &stdout, io.Discard); err != nil ||
		!strings.Contains(stdout.String(), version.Version) || !strings.Contains(stdout.String(), "archive-authentication-pending") {
		t.Fatalf("managed files catalog=%s, err=%v", &stdout, err)
	}
	output := filepath.Join(folder, "output")
	args := []string{"s3", "restore", "--backup", backup, "--output", output, "--identity", identity,
		"--set", "reports", "--version-id", version.Version, "--sha256", checksum(archive), "--select", "example.txt"}
	stdout.Reset()
	if err := run(context.Background(), append(args, base...), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(filepath.Join(output, "example.txt")); err != nil || string(raw) != "file archive fixture" ||
		!strings.Contains(stdout.String(), "archive-verified") {
		t.Fatalf("file output=%q, receipt=%s, err=%v", raw, &stdout, err)
	}
}

func TestBucketFirstHistoricalExactVersionAndSignedPrecedence(t *testing.T) {
	store, cfg, configPath := makeVersionedBucket(t)
	kek := bytes.Repeat([]byte{0x32}, 32)
	members, generations := putEncryptedGeneration(t, store.put, cfg, kek, true)
	backup := members[1].Request.BackupID
	g := generations[1]
	store.put(g.Key, []byte("newer malformed generation"))
	local := t.TempDir()
	exportPath, passPath := filepath.Join(local, "keys.bin"), filepath.Join(local, "pass.txt")
	writeFile(t, exportPath, keyExportFixture(t, kek, nil, "8-char!!"))
	writeFile(t, passPath, []byte("8-char!!"))
	pin := []string{"--s3-config", configPath, "--allow-unsigned-legacy", "--generation-key", g.Key, "--version-id", g.Version}
	var result bytes.Buffer
	if err := run(context.Background(), append([]string{"s3", "list"}, pin...), &result, io.Discard); err != nil ||
		!strings.Contains(result.String(), g.Version) || !strings.Contains(result.String(), backup) {
		t.Fatalf("exact legacy listing: %v, %s", err, &result)
	}
	withKey := append(slices.Clone(pin), "--kek-export", exportPath, "--passphrase-file", passPath)
	recover := func(name string, flags []string, wantError string) {
		t.Helper()
		disk := filepath.Join(local, name)
		result.Reset()
		err := run(context.Background(), append([]string{"s3", "restore", "--backup", backup, "--output", disk}, flags...), &result, io.Discard)
		if wantError != "" {
			if err == nil || !strings.Contains(err.Error(), wantError) || result.Len() != 0 {
				t.Fatalf("%s: %v %s", name, err, &result)
			}
			if _, err := os.Stat(disk); !os.IsNotExist(err) {
				t.Fatalf("refused recovery created an output: %v", err)
			}
			return
		}
		data, readErr := os.ReadFile(filepath.Join(disk, "disk-000.raw"))
		if err != nil || readErr != nil || !bytes.Equal(data, append([]byte("ABxyEF"), make([]byte, 6)...)) {
			t.Fatalf("historical encrypted disk: %v %v", err, readErr)
		}
	}
	recover("unsigned", withKey, "")
	store.mu.Lock()
	store.denySignedHistory = true
	store.mu.Unlock()
	recover("listing-denied", withKey, "cannot establish absence")
	store.mu.Lock()
	store.denySignedHistory = false
	store.mu.Unlock()
	store.put("vesta-recovery/v1/99999999-2222-4333-8444-555555555555/"+members[1].Request.OrgID+"/"+backup+".json", []byte("retained signed record"))
	recover("signed-history-in-another-installation", withKey, "signed recovery point history")
}

func TestBucketFirstCatalogContinuesPastHistoricalVersionLimit(t *testing.T) {
	store, cfg, configPath := makeVersionedBucket(t)
	kek := bytes.Repeat([]byte{0x42}, 32)
	members, generations := putEncryptedGeneration(t, store.put, cfg, kek, false)
	trust, points := signTestPoints(t, store, cfg, members, generations)
	local := t.TempDir()
	trustPath := filepath.Join(local, "trust.json")
	writeJSON(t, trustPath, trust)
	store.mu.Lock()
	oldHistory := make([]versionedObject, 4105)
	for i := range oldHistory {
		oldHistory[i] = versionedObject{Key: points[0].Key, Version: strconv.Itoa(i), Body: []byte("historical")}
	}
	store.objects[points[0].Key] = append(oldHistory, points[0])
	store.mu.Unlock()
	invalid := strings.Replace(points[1].Key, members[1].Request.BackupID,
		"44444444-1212-4433-8444-555555555555", 1)
	store.put(invalid, []byte("corrupt signed metadata"))
	scoped := []string{"--s3-config", configPath, "--trust", trustPath}
	cursor := ""
	var gotFirst, gotLate, gotIssue bool
	for i := 0; i < 6; i++ {
		args := append([]string{"s3", "list", "--limit", "1000"}, scoped...)
		if cursor != "" {
			args = append(args, "--cursor", cursor)
		}
		var result bytes.Buffer
		if err := run(context.Background(), args, &result, io.Discard); err != nil {
			t.Fatal(err)
		}
		var parsed s3recovery.CatalogPage
		if err := json.Unmarshal(result.Bytes(), &parsed); err != nil {
			t.Fatal(err)
		}
		for _, item := range parsed.Items {
			gotFirst = gotFirst || item.BackupID == members[0].Request.BackupID
			if item.BackupID == members[1].Request.BackupID {
				if i < 4 {
					t.Fatal("late signed record was reported before its genuine position")
				}
				gotLate = true
			}
		}
		for _, issue := range parsed.Issues {
			gotIssue = gotIssue || issue.ObjectKey == invalid
		}
		if !parsed.Incomplete {
			t.Fatal("partial or damaged listing claimed completeness")
		}
		if parsed.NextCursor == "" {
			break
		}
		cursor = parsed.NextCursor
	}
	if !gotFirst || !gotLate || !gotIssue {
		t.Fatalf("listing lose known point=%v late genuine point=%v invalid row=%v", gotFirst, gotLate, gotIssue)
	}
	err := run(context.Background(), append([]string{"s3", "restore", "--backup", members[0].Request.BackupID,
		"--output", filepath.Join(local, "missing-keys")}, scoped...), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--kek-export") {
		t.Fatalf("direct known backup was blocked by historical version count: %v", err)
	}
	err = run(context.Background(), append([]string{"s3", "restore", "--backup", members[0].Request.BackupID,
		"--version-id", points[0].Version, "--output", filepath.Join(local, "missing-pinned-keys")}, scoped...), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--kek-export") {
		t.Fatalf("explicit version did not read exact signed identity: %v", err)
	}
}

func TestBucketFirstRetiredSignedPointDoesNotAppearAvailable(t *testing.T) {
	store, cfg, configPath := makeVersionedBucket(t)
	members, generations := putEncryptedGeneration(t, store.put, cfg, bytes.Repeat([]byte{0x45}, 32), false)
	trust, _ := signTestPoints(t, store, cfg, members, generations)
	trustPath := filepath.Join(t.TempDir(), "trust.json")
	writeJSON(t, trustPath, trust)
	store.mu.Lock()
	delete(store.objects, generations[0].Key)
	store.mu.Unlock()
	var output bytes.Buffer
	if err := run(context.Background(), []string{"s3", "list", "--s3-config", configPath, "--trust", trustPath}, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	var view s3recovery.CatalogPage
	if err := json.Unmarshal(output.Bytes(), &view); err != nil || view.Incomplete || len(view.Items) != 2 {
		t.Fatalf("signed discovery: %v %s", err, &output)
	}
	for _, item := range view.Items {
		want := item.BackupID != members[0].Request.BackupID
		if item.Available == nil || *item.Available != want ||
			(want && item.Status != "available") || (!want && item.Status != "unavailable") {
			t.Fatalf("incorrect retirement status: %+v", item)
		}
	}
}

func TestBucketFirstLegacyIndependentScopeWithNarrowReader(t *testing.T) {
	store, cfg, configPath := makeVersionedBucket(t)
	kek := bytes.Repeat([]byte{0x65}, 32)
	members, generations := putEncryptedGeneration(t, store.put, cfg, kek, false)
	request := members[1].Request
	selected := generations[1]
	prefix := "vesta-recovery/v1/"
	exact := prefix + testInstallation + "/" + request.OrgID + "/" + request.BackupID + ".json"
	otherInstallation := "cccccccc-2222-4333-8444-555555555555"
	unrelated := prefix + otherInstallation + "/" + request.OrgID + "/" + request.BackupID + ".json"
	oldHistory := make([]versionedObject, 65537)
	for i := range oldHistory {
		oldHistory[i] = versionedObject{Key: unrelated, Version: strconv.Itoa(i), Body: []byte("disjoint history")}
	}
	store.mu.Lock()
	store.objects[unrelated] = oldHistory
	store.denySignedHistory = true
	store.mu.Unlock()

	local := t.TempDir()
	passPath, oldExport := filepath.Join(local, "pass"), filepath.Join(local, "old-kek")
	writeFile(t, passPath, []byte("8-char!!"))
	writeFile(t, oldExport, keyExportFixture(t, kek, nil, "8-char!!"))
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	trust := map[string]any{"schema": "vesta-recovery-trust/1", "installation_id": testInstallation,
		"org_id": request.OrgID, "key_id": checksum(public), "public_key": base64.RawURLEncoding.EncodeToString(public)}
	embedded, trustPath := filepath.Join(local, "embedded-kek"), filepath.Join(local, "trust.json")
	writeFile(t, embedded, keyExportFixture(t, kek, trust, "8-char!!"))
	writeJSON(t, trustPath, trust)
	flags := []string{"--s3-config", configPath, "--allow-unsigned-legacy", "--generation-key", selected.Key,
		"--version-id", selected.Version, "--passphrase-file", passPath}
	explicit := []string{"--kek-export", oldExport, "--installation-id", testInstallation, "--org-id", request.OrgID}
	check := func(name string, options []string, errorText string) {
		t.Helper()
		output := filepath.Join(local, name)
		args := []string{"s3", "restore", "--backup", request.BackupID, "--output", output}
		args = append(append(args, flags...), options...)
		var report bytes.Buffer
		err := run(context.Background(), args, &report, io.Discard)
		if errorText != "" {
			if err == nil || !strings.Contains(err.Error(), errorText) || report.Len() != 0 {
				t.Fatalf("%s: stderr=%v report=%s", name, err, &report)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("refused scoped recovery published output")
			}
			return
		}
		raw, readErr := os.ReadFile(filepath.Join(output, "disk-000.raw"))
		if err != nil || readErr != nil || !bytes.Equal(raw, append([]byte("ABxyEF"), make([]byte, 6)...)) {
			t.Fatalf("%s: err=%v read=%v", name, err, readErr)
		}
	}
	check("explicit", explicit, "")
	check("trusted-old-key", []string{"--kek-export", oldExport, "--trust", trustPath}, "")
	check("embedded", []string{"--kek-export", embedded}, "")
	check("without-independent-scope", []string{"--kek-export", oldExport}, "cannot establish absence")
	check("mismatched-generation", []string{"--kek-export", oldExport, "--installation-id", otherInstallation,
		"--org-id", request.OrgID}, "does not match the independently supplied")
	check("conflicting-local-sources", []string{"--kek-export", embedded, "--installation-id", otherInstallation,
		"--org-id", request.OrgID}, "differs from independent recovery trust")
	store.mu.Lock()
	store.denySignedPrefix = exact
	store.mu.Unlock()
	check("denied-exact", explicit, "cannot establish absence")
	store.mu.Lock()
	store.denySignedPrefix = ""
	store.mu.Unlock()
	store.put(exact, []byte("corrupt retained envelope"))
	check("corrupt-envelope", explicit, "signed recovery point history")
	store.mu.Lock()
	delete(store.objects, exact)
	store.signedDeleteMarker = exact
	store.mu.Unlock()
	check("delete-marker", explicit, "signed recovery point history")
}
