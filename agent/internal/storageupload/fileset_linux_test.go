//go:build linux

package storageupload

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"vnbui/agent/internal/encryption"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
)

func nativeMemberBytes(path string) []byte {
	return bytes.Repeat([]byte("native member "+path+"\x00\xff\n"), 257+len(path))
}

func nativeRequest(t *testing.T, encrypted bool) ([]byte, string) {
	t.Helper()
	data, err := os.ReadFile("../../contracts/native_storage_examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var examples []struct {
		Request models.NativeTransactionRequest `json:"request"`
	}
	if err = json.Unmarshal(data, &examples); err != nil {
		t.Fatal(err)
	}
	r := examples[0].Request
	if encrypted {
		r = examples[1].Request
	}
	root := t.TempDir()
	for _, f := range r.Plan.Source.Inventory.Files {
		path := filepath.Join(root, f.Path)
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, nativeMemberBytes(f.Path), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r.Plan.Source.Inventory, err = nativefileset.Capture(root, r.Plan.Source.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	b, err := models.StorageCanonical(r.Plan.Source.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	r.Plan.Source.InventorySHA256 = digest(b)
	r.Plan.Artifacts, err = nativefileset.BuildArtifacts(r.Plan.Source, r.OrgID, r.BackupID, r.ReservationID, r.Plan.Encryption)
	if err != nil {
		t.Fatal(err)
	}
	b, err = models.StorageCanonical(r.Plan)
	if err != nil {
		t.Fatal(err)
	}
	r.PlanSHA256 = digest(b)
	b, err = json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = nativefileset.DecodeTransaction(b); err != nil {
		t.Fatal(err)
	}
	return b, root
}

func nativeStore(r models.NativeTransactionRequest) *fakeStore {
	return &fakeStore{r: models.StorageTransactionRequest{Plan: models.StorageTransactionPlan{Target: r.Plan.Target}}, data: map[string][]byte{}, meta: map[string]map[string]string{}}
}

func nativeAck(t *testing.T, j *FileSetJournal) []byte {
	t.Helper()
	_, hash, err := j.canonicalReceipt()
	if err != nil {
		t.Fatal(err)
	}
	a := models.StorageAcceptance{Protocol: models.StorageProtocol, Accepted: true, ReservationID: j.state.Request.ReservationID,
		AcceptanceID: "durable-acceptance", ReceiptSHA256: hash, ScrubRequired: true, Verification: []models.StorageVerification{}}
	reason := "provider_full_object_sha256_unavailable"
	for _, o := range j.state.Receipt.Objects {
		a.Verification = append(a.Verification, models.StorageVerification{Key: o.Key, VersionID: o.VersionID, Assurance: "identity_metadata_only", Reason: &reason})
	}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNativeClosedFilesLostAcceptanceReopen(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[encrypted], func(t *testing.T) {
			request, tree := nativeRequest(t, encrypted)
			root := t.TempDir()
			j, err := CreateFileSet(root, request)
			if err != nil {
				t.Fatal(err)
			}
			s := nativeStore(j.state.Request)
			var key []byte
			if encrypted {
				key = bytes.Repeat([]byte{9}, 32)
			}
			if err = j.UploadClosedTree(context.Background(), s, tree, key); err != nil {
				t.Fatal(err)
			}
			if len(j.state.Receipt.Objects) != 5 || j.state.Phase != "prepared" {
				t.Fatal("partial inventory")
			}
			if nativefileset.CheckTree(tree, j.state.Request.Plan.Source.Inventory) != nil {
				t.Fatal("local set changed")
			}
			for _, o := range j.state.Receipt.Objects {
				if digest(s.data[o.Key]) != o.CiphertextSHA256 || int64(len(s.data[o.Key])) != o.CiphertextBytes {
					t.Fatal("stored digest/count")
				}
				var expected []byte
				for _, member := range j.state.Request.Plan.Source.Inventory.Files {
					if member.ArtifactID == o.ArtifactID {
						expected = nativeMemberBytes(member.Path)
					}
				}
				if len(expected) == 0 || digest(expected) != o.PlaintextSHA256 || int64(len(expected)) != o.PlaintextBytes {
					t.Fatal("plaintext member digest/count")
				}
				actual := s.data[o.Key]
				if encrypted {
					dir := t.TempDir()
					input, output := filepath.Join(dir, "encrypted"), filepath.Join(dir, "decrypted")
					if err := os.WriteFile(input, actual, 0600); err != nil {
						t.Fatal(err)
					}
					if err := encryption.DecryptFile(input, output, key); err != nil {
						t.Fatal(err)
					}
					actual, err = os.ReadFile(output)
					if err != nil {
						t.Fatal(err)
					}
				}
				if !bytes.Equal(actual, expected) {
					t.Fatal("stored member differs from closed source")
				}
				if s.meta[o.Key]["vnbui-artifact-id"] != o.ArtifactID {
					t.Fatal("lost native identity")
				}
			}
			ack := nativeAck(t, j)
			var submitted [][]byte
			client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
				b, e := io.ReadAll(r.Body)
				if e != nil {
					t.Fatal(e)
				}
				submitted = append(submitted, b)
				if len(submitted) == 1 {
					return nil, errors.New("lost acknowledgement")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(ack))}, nil
			})}
			credential := func(context.Context) (string, error) { return "memory-only", nil }
			if _, err = j.Submit(context.Background(), "https://backend.test", client, credential); err != ErrHeld {
				t.Fatal("lost reply accepted")
			}
			calls := append([]string{}, s.calls...)
			if err = j.Close(); err != nil {
				t.Fatal(err)
			}
			j, err = OpenFileSet(root, request)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			// A nonexistent source root discriminates replay from a second source
			// lookup/read; the provider call ledger discriminates all remote effects.
			if err = j.UploadClosedTree(context.Background(), s, filepath.Join(tree, "not-present"), nil); err != nil {
				t.Fatal(err)
			}
			a, err := j.Submit(context.Background(), "https://backend.test", client, credential)
			if err != nil || a.AcceptanceID != "durable-acceptance" {
				t.Fatal("replay", err)
			}
			if len(submitted) != 2 || !bytes.Equal(submitted[0], submitted[1]) || !reflect.DeepEqual(s.calls, calls) {
				t.Fatal("replay changed receipt or reread provider")
			}
			if _, err = j.Submit(context.Background(), "https://backend.test", client, credential); err != nil || len(submitted) != 2 {
				t.Fatal("accepted replay resubmitted")
			}
			data, err := os.ReadFile(j.store.path)
			if err != nil || bytes.Contains(data, []byte("memory-only")) || bytes.Contains(data, key) && len(key) > 0 {
				t.Fatal("secret custody")
			}
		})
	}
}

func TestNativeJournalUncertainProviderCannotRestartUpload(t *testing.T) {
	for _, phase := range []string{"begin", "part", "complete", "head"} {
		t.Run(phase, func(t *testing.T) {
			request, tree := nativeRequest(t, false)
			root := t.TempDir()
			j, err := CreateFileSet(root, request)
			if err != nil {
				t.Fatal(err)
			}
			s := nativeStore(j.state.Request)
			s.fail = phase
			if err = j.UploadClosedTree(context.Background(), s, tree, nil); err != ErrHeld {
				t.Fatal("uncertainty not held")
			}
			calls := len(s.calls)
			_ = j.Close()
			j, err = OpenFileSet(root, request)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			s.fail = ""
			if err = j.UploadClosedTree(context.Background(), s, tree, nil); err != ErrHeld || len(s.calls) != calls {
				t.Fatal("uncertain producer repeated")
			}
		})
	}
}

func TestNativeHTTPControlEntryPlainEncryptedReplay(t *testing.T) {
	for _, profile := range []struct {
		encrypted bool
		state     string
	}{{false, "exited"}, {true, "exited"}, {false, "sealed"}, {true, "sealed"}} {
		t.Run(strconv.FormatBool(profile.encrypted)+"/"+profile.state, func(t *testing.T) {
			request, tree := nativeRequest(t, profile.encrypted)
			r, err := nativefileset.DecodeTransaction(request)
			if err != nil {
				t.Fatal(err)
			}
			admission := ClosedNativeAdmission{IntentSHA256: strings.Repeat("a", 64), Inventory: r.Plan.Source.Inventory}
			// This control-only test uses a mock backend; producer/manifest content
			// binding is exercised by the native capture and backend manifest tests.
			admission.PushResult.Manifest.Schema = "libvirt-push-qcow2/1"
			admission.PushResult.Manifest.Source = []models.NativeSourceDisk{}
			admission.PushResult.Manifest.Disks = []models.NativePushDisk{}
			admission.PushResult.Manifest.Exclusions = []string{}
			admission.ClosedJob.JobID = admission.Inventory.JobID
			admission.ClosedJob.AttemptID = r.ReservationID
			admission.ClosedJob.InvocationID = strings.Repeat("b", 32)
			admission.ClosedJob.State = profile.state
			body, _ := json.Marshal(admission)
			root := t.TempDir()
			s := nativeStore(*r)
			var order []string
			var receipts [][]byte
			var selectedKey, selectedID string
			var ack []byte
			backend := &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
				if req.Header.Get("X-Agent-Key") != "memory-agent" {
					t.Fatal("unauthenticated")
				}
				path := req.URL.Path
				op := path[strings.LastIndex(path, "/")+1:]
				order = append(order, op)
				input, e := io.ReadAll(req.Body)
				if e != nil {
					t.Fatal(e)
				}
				var result any
				switch op {
				case "native-inventory":
					if !bytes.Equal(input, body) {
						t.Fatal("inventory changed")
					}
					result = map[string]any{"accepted": true, "completed": false, "attempt_id": r.ReservationID, "inventory_sha256": r.Plan.Source.InventorySHA256}
				case "native-transaction":
					result = r
				case "transaction-key":
					data, e := os.ReadFile(filepath.Join(root, r.ReservationID, "transaction.json"))
					if e != nil || !bytes.Contains(data, []byte(r.PlanSHA256)) {
						t.Fatal("key before durable plan")
					}
					var key *string
					if profile.encrypted {
						k := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
						key = &k
					}
					result = map[string]any{"reservation_id": r.ReservationID, "attempt_id": r.ReservationID, "plan_sha256": r.PlanSHA256, "key_ref": r.Plan.Encryption.KeyRef, "format": r.Plan.Encryption.Format, "dek": key}
				case "storage-control":
					var q struct {
						Binding   map[string]any  `json:"binding"`
						Key       string          `json:"artifact_key"`
						Operation string          `json:"operation"`
						Args      json.RawMessage `json:"args"`
					}
					if json.Unmarshal(input, &q) != nil || q.Binding["plan_sha256"] != r.PlanSHA256 {
						t.Fatal("control binding")
					}
					c := controlResponse{Schema: 1}
					switch q.Operation {
					case "create":
						var a models.NativeStorageArtifact
						for _, v := range r.Plan.Artifacts {
							if v.Key == q.Key {
								a = v
							}
						}
						c.UploadID, e = s.Begin(req.Context(), q.Key, fileMetadata(r, a))
					case "part":
						var p struct {
							UploadID string `json:"upload_id"`
							Number   int    `json:"number"`
							Bytes    int    `json:"bytes"`
							SHA256   string `json:"sha256"`
						}
						_ = json.Unmarshal(q.Args, &p)
						raw, _ := hex.DecodeString(p.SHA256)
						selectedKey, selectedID = q.Key, p.UploadID
						c.Authority = fakeAuthority(s, q.Key, p.UploadID, p.Number, p.Bytes, p.SHA256, base64.StdEncoding.EncodeToString(raw))
					case "part_ack":
						c.Acknowledged = true
					case "complete":
						var p struct {
							UploadID string `json:"upload_id"`
							Parts    []Part `json:"parts"`
						}
						_ = json.Unmarshal(q.Args, &p)
						i, x := s.Complete(req.Context(), q.Key, p.UploadID, p.Parts)
						e = x
						i.ETag = strconv.Quote(i.ETag)
						c.Object = &i
					case "head":
						var p struct {
							Version *string `json:"version_id"`
							ETag    string  `json:"etag"`
						}
						_ = json.Unmarshal(q.Args, &p)
						i, x := s.Head(req.Context(), q.Key, p.Version, p.ETag)
						e = x
						c.Object = &i
					default:
						t.Fatal("unplanned operation")
					}
					result = c
				case "prepared-receipt":
					receipts = append(receipts, input)
					if len(receipts) == 1 {
						var receipt models.NativeStorageReceipt
						if json.Unmarshal(input, &receipt) != nil {
							t.Fatal("receipt")
						}
						_, hash, x := nativefileset.CanonicalReceipt(receipt, r.Plan.Artifacts, r.BackupID, r.ReservationID, r.Plan.Target, r.Plan.Encryption)
						if x != nil {
							t.Fatal(x)
						}
						a := models.StorageAcceptance{Protocol: models.StorageProtocol, Accepted: true, ReservationID: r.ReservationID, AcceptanceID: "durable", ReceiptSHA256: hash, ScrubRequired: true, Verification: []models.StorageVerification{}}
						reason := "provider_full_object_sha256_unavailable"
						for _, o := range receipt.Objects {
							a.Verification = append(a.Verification, models.StorageVerification{Key: o.Key, VersionID: o.VersionID, Assurance: "identity_metadata_only", Reason: &reason})
						}
						ack, _ = json.Marshal(a)
						return nil, errors.New("lost accepted response")
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(bytes.NewReader(ack))}, nil
				default:
					t.Fatal("unexpected route")
				}
				if e != nil {
					t.Fatal(e)
				}
				out, _ := json.Marshal(result)
				return &http.Response{StatusCode: 200, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(bytes.NewReader(out))}, nil
			})}
			provider := &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
				if req.Method != "PUT" || req.Header.Get("X-Agent-Key") != "" || req.URL.Query().Get("uploadId") != selectedID {
					t.Fatal("provider authority")
				}
				data, e := io.ReadAll(req.Body)
				if e != nil {
					t.Fatal(e)
				}
				n, _ := strconv.Atoi(req.URL.Query().Get("partNumber"))
				etag, e := s.Part(req.Context(), selectedKey, selectedID, n, data, req.Header.Get("X-Amz-Checksum-Sha256"))
				if e != nil {
					t.Fatal(e)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Etag": {strconv.Quote(etag)}}, Body: io.NopCloser(strings.NewReader(""))}, nil
			})}
			credential := func(context.Context) (string, error) { return "memory-agent", nil }
			if _, err = UploadClosedNative(context.Background(), root, tree, r.OrgID, r.AgentID, "https://backend.test", body, backend, provider, credential); err != ErrHeld {
				t.Fatal("lost reply accepted", err)
			}
			if len(order) < 4 || !reflect.DeepEqual(order[:3], []string{"native-inventory", "native-transaction", "transaction-key"}) {
				t.Fatal("wrong order", order)
			}
			calls, prior := len(s.calls), len(order)
			a, err := UploadClosedNative(context.Background(), root, filepath.Join(tree, "absent"), r.OrgID, r.AgentID, "https://backend.test", body, backend, provider, credential)
			if err != nil || a.AcceptanceID != "durable" || len(s.calls) != calls || len(order) != prior+1 || order[len(order)-1] != "prepared-receipt" || len(receipts) != 2 || !bytes.Equal(receipts[0], receipts[1]) {
				t.Fatal("non-exact restart", err)
			}
		})
	}
}

func TestNativeFileCustodyAndJournalFailureRefuse(t *testing.T) {
	for _, fault := range []string{"extra", "missing", "replace", "mutation-after-open", "fsync", "target", "foreign-agent", "corrupt"} {
		t.Run(fault, func(t *testing.T) {
			request, tree := nativeRequest(t, false)
			root := t.TempDir()
			j, err := CreateFileSet(root, request)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			s := nativeStore(j.state.Request)
			var file string
			for _, member := range j.state.Request.Plan.Source.Inventory.Files {
				if member.ArtifactID == j.state.Objects[0].Artifact.ArtifactID {
					file = filepath.Join(tree, member.Path)
				}
			}
			switch fault {
			case "extra":
				if err = os.WriteFile(filepath.Join(tree, "unplanned"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err = os.Remove(file); err != nil {
					t.Fatal(err)
				}
			case "replace":
				if err = os.Rename(file, file+".old"); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(file, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "mutation-after-open":
				// The first Begin follows descriptor capture, before the first read.
				s.mutate = func() {
					s.mutate = nil
					f, e := os.OpenFile(file, os.O_WRONLY|os.O_APPEND, 0)
					if e != nil {
						t.Fatal(e)
					}
					_, e = f.Write([]byte("changed"))
					_ = f.Close()
					if e != nil {
						t.Fatal(e)
					}
				}
			case "fsync":
				j.store.syncFile = func(*os.File) error { return errors.New("fsync failure") }
			case "target":
				s.r.Plan.Target.Bucket = "changed"
			case "foreign-agent":
				j.state.Request.AgentID = "11111111-1111-4111-8111-111111111111"
			case "corrupt":
				if err = os.WriteFile(j.store.path, []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err = j.UploadClosedTree(context.Background(), s, tree, nil); err == nil {
				t.Fatal("unsafe upload accepted")
			}
			for _, call := range s.calls {
				if call == "complete" {
					t.Fatal("unsafe completion")
				}
			}
			if fault != "mutation-after-open" && len(s.calls) != 0 {
				t.Fatal("effect before refusal")
			}
		})
	}
}
