package storageupload

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"vnbui/agent/internal/models"
)

func request(t *testing.T, encrypted bool) []byte {
	t.Helper()
	b, e := os.ReadFile("../../contracts/storage_semantic_valid.json")
	if e != nil {
		t.Fatal(e)
	}
	var r models.StorageTransactionRequest
	if json.Unmarshal(b, &r) != nil {
		t.Fatal("fixture")
	}
	r.Plan.Source.Volumes[0].CapacityBytes = 32 * 1024 * 1024
	for i := range r.Plan.Artifacts {
		a := &r.Plan.Artifacts[i]
		if a.Role == "volume_payload" {
			a.PlaintextMax = 32 * 1024 * 1024
			a.CiphertextMax = a.PlaintextMax
		}
	}
	if encrypted {
		ref := "kek:66666666-6666-4666-8666-666666666666:aaaaaaaaaaaaaaaa"
		r.Plan.Encryption = models.StorageEncryption{Format: "vnbu1-aes256gcm-chunk5242880", KeyRef: &ref}
		for i := range r.Plan.Artifacts {
			a := &r.Plan.Artifacts[i]
			if a.Role == "volume_payload" {
				a.CiphertextMin = 5
				a.CiphertextMax = 5 + a.PlaintextMax + 32*((a.PlaintextMax+5242880-1)/5242880)
			}
		}
	}
	r.Plan.Target.Region = "eu-central"
	p, e := models.StorageCanonical(r.Plan)
	if e != nil {
		t.Fatal(e)
	}
	r.PlanSHA256 = digest(p)
	b, e = json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = models.DecodeStorageTransaction(b); e != nil {
		t.Fatal(e)
	}
	return b
}

type fakeStore struct {
	r        models.StorageTransactionRequest
	calls    []string
	data     map[string][]byte
	meta     map[string]map[string]string
	fail     string
	version  bool
	checksum string
	mutate   func()
}

func store(t *testing.T, b []byte) *fakeStore {
	r, e := models.DecodeStorageTransaction(b)
	if e != nil {
		t.Fatal(e)
	}
	return &fakeStore{r: *r, data: map[string][]byte{}, meta: map[string]map[string]string{}}
}
func (s *fakeStore) Target() models.StorageTarget { return s.r.Plan.Target }
func (s *fakeStore) event(name string) error {
	s.calls = append(s.calls, name)
	if s.mutate != nil {
		s.mutate()
	}
	if name == s.fail {
		return errors.New("provider-private-error")
	}
	return nil
}
func (s *fakeStore) Begin(ctx context.Context, key string, m map[string]string) (string, error) {
	if e := s.event("begin"); e != nil {
		return "", e
	}
	s.meta[key] = m
	return "upload-exact", nil
}
func (s *fakeStore) Part(ctx context.Context, key, id string, n int, data []byte, checksum string) (string, error) {
	if ctx == nil || id != "upload-exact" {
		return "", ErrHeld
	}
	raw, _ := hex.DecodeString(digest(data))
	if checksum != base64.StdEncoding.EncodeToString(raw) {
		return "", ErrHeld
	}
	if e := s.event("part"); e != nil {
		return "", e
	}
	s.data[key] = append(s.data[key], data...)
	return fmt.Sprintf("part-%d", n), nil
}
func (s *fakeStore) Complete(ctx context.Context, key, id string, parts []Part) (ObjectInfo, error) {
	if e := s.event("complete"); e != nil {
		return ObjectInfo{}, e
	}
	v := (*string)(nil)
	if s.version {
		x := "version-exact"
		v = &x
	}
	return ObjectInfo{ETag: "opaque-not-a-checksum", VersionID: v, Metadata: map[string]string{}}, nil
}
func (s *fakeStore) Head(ctx context.Context, key string, v *string, etag string) (ObjectInfo, error) {
	if e := s.event("head"); e != nil {
		return ObjectInfo{}, e
	}
	i := ObjectInfo{ETag: etag, VersionID: v, Bytes: int64(len(s.data[key])), Metadata: s.meta[key]}
	switch s.checksum {
	case "present":
		i.ChecksumType = "FULL_OBJECT"
		i.SHA256 = digest(s.data[key])
	case "mismatch":
		i.ChecksumType = "FULL_OBJECT"
		i.SHA256 = strings.Repeat("0", 64)
	case "metadata":
		i.Metadata = map[string]string{"foreign": "owner"}
	case "size":
		i.Bytes++
	case "etag":
		i.ETag = "replaced"
	case "version":
		v := "replaced"
		i.VersionID = &v
	}
	return i, nil
}
func inputs(r models.StorageTransactionRequest, payload int, opens *int) []Input {
	out := []Input{}
	for _, a := range r.Plan.Artifacts {
		a := a
		out = append(out, Input{Artifact: a, Open: func() (io.ReadCloser, error) {
			*opens++
			n := payload
			if a.Role == "volume_manifest" {
				n = 2
			}
			return io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{1}, n))), nil
		}})
	}
	return out
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func ack(t *testing.T, j *Journal) []byte {
	t.Helper()
	_, h, e := models.CanonicalReceipt(&j.state.Request, *j.state.Receipt)
	if e != nil {
		t.Fatal(e)
	}
	a := models.StorageAcceptance{Protocol: models.StorageProtocol, ReservationID: j.state.Request.ReservationID, ReceiptSHA256: h, Accepted: true, AcceptanceID: "durable-db-id", ScrubRequired: true, Verification: []models.StorageVerification{}}
	for _, o := range j.state.Receipt.Objects {
		reason := "provider_full_object_sha256_unavailable"
		a.Verification = append(a.Verification, models.StorageVerification{Key: o.Key, VersionID: o.VersionID, Assurance: "identity_metadata_only", Reason: &reason})
	}
	b, _ := json.Marshal(a)
	return b
}
func TestTwoArtifactsRestartIdenticalPreparedSubmission(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, versioned := range []bool{false, true} {
			t.Run(fmt.Sprintf("encrypted=%t/version=%t", encrypted, versioned), func(t *testing.T) {
				b := request(t, encrypted)
				root := t.TempDir()
				j, e := Create(root, b)
				if e != nil {
					t.Fatal(e)
				}
				s := store(t, b)
				s.version = versioned
				opens := 0
				in := inputs(s.r, 9*1024*1024, &opens)
				in[0], in[1] = in[1], in[0] // order is not artifact identity
				if e = j.UploadAll(context.Background(), s, in, make([]byte, 32)); e != nil {
					t.Fatal(e)
				}
				if opens != 2 || j.state.Phase != "prepared" {
					t.Fatal("not complete")
				}
				for _, o := range j.state.Receipt.Objects {
					plainBytes := 9 * 1024 * 1024
					if o.Role == "volume_manifest" {
						plainBytes = 2
					}
					if o.PlaintextBytes != int64(plainBytes) || o.PlaintextSHA256 != digest(bytes.Repeat([]byte{1}, plainBytes)) {
						t.Fatal("plaintext digest/count differs from single source traversal")
					}
					if o.CiphertextSHA256 != digest(s.data[o.Key]) || o.CiphertextBytes != int64(len(s.data[o.Key])) {
						t.Fatal("ciphertext hash")
					}
				}
				posted := [][]byte{}
				response := ack(t, j)
				client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
					if r.Method != "POST" || r.URL.Path != "/api/v1/agents/backups/"+s.r.BackupID+"/prepared-receipt" || r.Header.Get("X-Agent-Key") != "fixture-in-memory" {
						t.Fatal("wire")
					}
					body, _ := io.ReadAll(r.Body)
					posted = append(posted, body)
					if len(posted) == 1 {
						return nil, errors.New("lost acknowledgement")
					}
					return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(response)), Header: http.Header{}}, nil
				})}
				key := func(context.Context) (string, error) { return "fixture-in-memory", nil }
				if _, e = j.Submit(context.Background(), "https://backend.test", client, key); e == nil {
					t.Fatal("transport inferred acceptance")
				}
				calls := len(s.calls)
				_ = j.Close()
				j, e = Open(root, b)
				if e != nil {
					t.Fatal(e)
				}
				defer j.Close()
				if e = j.UploadAll(context.Background(), s, in, make([]byte, 32)); e != nil {
					t.Fatal(e)
				}
				if _, e = j.Submit(context.Background(), "https://backend.test", client, key); e != nil {
					t.Fatal(e)
				}
				if len(posted) != 2 || !bytes.Equal(posted[0], posted[1]) || len(s.calls) != calls || opens != 2 {
					t.Fatal("reuploaded/reinterpreted receipt")
				}
				if _, e = j.Submit(context.Background(), "https://backend.test", client, key); e != nil || len(posted) != 2 {
					t.Fatal("accepted replay")
				}
				data, e := os.ReadFile(j.path)
				if e != nil || bytes.Contains(data, []byte("fixture-in-memory")) {
					t.Fatal("credential custody")
				}
			})
		}
	}
}

func TestPartSizingHasFixedMemoryAndCountCeilings(t *testing.T) {
	for _, maximum := range []int64{0, 1, partSize, int64(partSize) * 10000, 1 << 40, 5 << 40, int64(maxPartSize) * 10000} {
		size, err := plannedPartSize(models.StorageArtifact{CiphertextMax: maximum}, "")
		if err != nil || size < partSize || size > maxPartSize || (maximum+int64(size)-1)/int64(size) > 10000 {
			t.Fatal("unsupported bounded part sizing", maximum, size, err)
		}
	}
	if _, err := plannedPartSize(models.StorageArtifact{CiphertextMax: int64(maxPartSize)*10000 + 1}, ""); err == nil {
		t.Fatal("accepted size beyond fixed-memory/count ceiling")
	}
}
func TestClosedSnapshotDoesNotAuthorizeOrMutate(t *testing.T) {
	b := request(t, false)
	j, err := Create(t.TempDir(), b)
	if err != nil {
		t.Fatal(err)
	}
	copy, err := j.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	copy.Request.Plan.Artifacts[0].Key = "foreign"
	if j.state.Request.Plan.Artifacts[0].Key == "foreign" {
		t.Fatal("snapshot aliases custody")
	}
	_ = j.Close()
	if _, err = j.Snapshot(); err == nil {
		t.Fatal("closed journal authorized next operation")
	}
}
func TestUncertainProviderPhasesHoldWithoutReplay(t *testing.T) {
	for _, phase := range []string{"begin", "part", "complete", "head"} {
		t.Run(phase, func(t *testing.T) {
			b := request(t, false)
			root := t.TempDir()
			j, e := Create(root, b)
			if e != nil {
				t.Fatal(e)
			}
			s := store(t, b)
			s.fail = phase
			n := 0
			in := inputs(s.r, 1, &n)
			if e = j.UploadAll(context.Background(), s, in, nil); e == nil {
				t.Fatal("accepted lost/rejected operation")
			}
			calls := len(s.calls)
			_ = j.Close()
			j, e = Open(root, b)
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			if j.state.Phase != "held" || j.UploadAll(context.Background(), s, in, nil) == nil || len(s.calls) != calls {
				t.Fatal("uncertain producer replay")
			}
		})
	}
}
func TestProviderMetadataAndChecksum(t *testing.T) {
	for _, mode := range []string{"", "present", "mismatch", "metadata", "size", "etag", "version"} {
		t.Run(mode, func(t *testing.T) {
			b := request(t, false)
			j, e := Create(t.TempDir(), b)
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			s := store(t, b)
			s.checksum = mode
			n := 0
			e = j.UploadAll(context.Background(), s, inputs(s.r, 0, &n), nil)
			if (e == nil) != (mode == "" || mode == "present") {
				t.Fatal("metadata verdict", e)
			}
		})
	}
}
func TestExactInputSetBeforeEffects(t *testing.T) {
	for _, kind := range []string{"missing", "extra", "duplicate", "key", "role", "volume", "bounds", "target"} {
		t.Run(kind, func(t *testing.T) {
			b := request(t, false)
			j, e := Create(t.TempDir(), b)
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			s := store(t, b)
			n := 0
			in := inputs(s.r, 1, &n)
			switch kind {
			case "missing":
				in = in[:1]
			case "extra":
				in = append(in, in[0])
			case "duplicate":
				in[1] = in[0]
			case "key":
				in[0].Artifact.Key += "x"
			case "role":
				in[0].Artifact.Role = "volume_payload"
			case "volume":
				in[0].Artifact.VolumeID = "foreign"
			case "bounds":
				in[0].Artifact.PlaintextMax++
			case "target":
				s.r.Plan.Target.Bucket = "foreign"
			}
			if j.UploadAll(context.Background(), s, in, nil) == nil || n != 0 || len(s.calls) != 0 {
				t.Fatal("side effect before complete identity admission")
			}
		})
	}
}
func TestJournalRefusalsAndExclusiveCustody(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "oversize", "symlink", "removed-during-call", "conflicting-request", "locked"} {
		t.Run(kind, func(t *testing.T) {
			b := request(t, false)
			root := t.TempDir()
			j, e := Create(root, b)
			if e != nil {
				t.Fatal(e)
			}
			path := j.path
			if kind == "locked" {
				if _, e = Open(root, b); e == nil {
					t.Fatal("two journal writers")
				}
				_ = j.Close()
				return
			}
			if kind == "removed-during-call" {
				s := store(t, b)
				s.mutate = func() { _ = os.Remove(path) }
				n := 0
				if j.UploadAll(context.Background(), s, inputs(s.r, 1, &n), nil) == nil || !reflect.DeepEqual(s.calls, []string{"begin"}) {
					t.Fatal("effects after missing journal")
				}
				_ = j.Close()
				return
			}
			_ = j.Close()
			switch kind {
			case "missing":
				_ = os.Remove(path)
			case "corrupt":
				_ = os.WriteFile(path, []byte(`{}`), 0600)
			case "oversize":
				f, _ := os.OpenFile(path, os.O_WRONLY, 0600)
				_ = f.Truncate(MaxJournalBytes + 1)
				_ = f.Close()
			case "symlink":
				_ = os.Remove(path)
				_ = os.Symlink(filepath.Join(root, "foreign"), path)
			case "conflicting-request":
				b = request(t, true)
			}
			if reopened, e := Open(root, b); e == nil {
				_ = reopened.Close()
				t.Fatal("invalid journal accepted")
			}
			if fresh, e := Create(root, b); e == nil {
				_ = fresh.Close()
				t.Fatal("reset absent/conflicting evidence")
			}
		})
	}
}
func TestEmptyEncryptedAndManifestBound(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprint(encrypted), func(t *testing.T) {
			b := request(t, encrypted)
			j, e := Create(t.TempDir(), b)
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			s := store(t, b)
			n := 0
			in := inputs(s.r, 0, &n)
			zeroManifest := []byte(`{"extents":[{"disk_offset":0,"length":33554432,"zero_fill":true}]}`)
			for i := range in {
				if in[i].Artifact.Role == "volume_manifest" {
					in[i].Open = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(zeroManifest)), nil }
				}
			}
			if e = j.UploadAll(context.Background(), s, in, make([]byte, 32)); e != nil {
				t.Fatal(e)
			}
			for _, o := range j.state.Receipt.Objects {
				if o.Role == "volume_payload" {
					expected := int64(0)
					if encrypted {
						expected = 5
					}
					if o.PlaintextBytes != 0 || o.CiphertextBytes != expected || o.PlaintextSHA256 != digest(nil) {
						t.Fatal("zero-only framing")
					}
				} else if o.PlaintextSHA256 != digest(zeroManifest) || !bytes.Equal(s.data[o.Key], zeroManifest) {
					t.Fatal("zero-fill metadata changed or materialized")
				}
			}
		})
	}
	b := request(t, false)
	j, e := Create(t.TempDir(), b)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	s := store(t, b)
	n := 0
	in := inputs(s.r, 1, &n)
	for i := range in {
		if in[i].Artifact.Role == "volume_manifest" {
			in[i].Open = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(make([]byte, maxManifest+1))), nil }
		}
	}
	if j.UploadAll(context.Background(), s, in, nil) == nil || len(s.calls) != 0 {
		t.Fatal("oversized manifest published")
	}
}
