package storagerestore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"
	"time"

	"vnbui/agent/internal/encryption"
	"vnbui/agent/internal/models"
)

func verificationFixture(t *testing.T, encrypted bool) ([]Member, *memoryStore, KeyResolver) {
	t.Helper()
	members, store, keys, _ := chainFixture(t, encrypted)
	for i := range members {
		m := &members[i]
		if i > 0 {
			_, digest, err := models.CanonicalReceipt(&members[i-1].Request, members[i-1].Receipt)
			if err != nil {
				t.Fatal(err)
			}
			m.Request.Plan.Parent.ReceiptSHA256 = digest
			rehash(t, m)
		}
		body, err := json.Marshal(definitionFor(*m))
		if err != nil {
			t.Fatal(err)
		}
		if encrypted {
			key, _ := keys(context.Background(), *m)
			var output bytes.Buffer
			if err := encryption.EncryptStream(bytes.NewReader(body), &output, key); err != nil {
				t.Fatal(err)
			}
			clear(key)
			body = output.Bytes()
		}
		attachDefinition(t, m, store, base64.StdEncoding.EncodeToString(body))
	}
	return members, store, keys
}

func TestVerifyExactFullIncrementalChainWithoutOutput(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprint(encrypted), func(t *testing.T) {
			members, store, keys := verificationFixture(t, encrypted)
			original, _ := json.Marshal(store.data)
			var returnedKeys [][]byte
			resolve := func(ctx context.Context, member Member) ([]byte, error) {
				key, err := keys(ctx, member)
				returnedKeys = append(returnedKeys, key)
				return key, err
			}
			result, err := Verify(context.Background(), members, store.open, resolve)
			if err != nil || result == nil {
				t.Fatal(result, err)
			}
			if result.Schema != VerificationSchema || result.Provider != "kubevirt" || result.OrgID != members[0].Request.OrgID || result.AgentID != members[0].Request.AgentID || result.VMID != members[0].Request.Plan.Source.VMID || len(result.Members) != 2 || store.reads != 4 {
				t.Fatalf("unexpected verification: %+v reads=%d", result, store.reads)
			}
			for i, m := range members {
				_, digest, _ := models.CanonicalReceipt(&m.Request, m.Receipt)
				want := VerifiedMember{BackupID: m.Request.BackupID, ReservationID: m.Request.ReservationID, PlanSHA256: m.Request.PlanSHA256, ReceiptSHA256: digest, Objects: len(m.Receipt.Objects)}
				if result.Members[i] != want {
					t.Fatalf("result not bound to admitted receipt: %+v", result.Members[i])
				}
			}
			if encrypted && len(returnedKeys) != 2 {
				t.Fatal("DEK resolved more than once per member")
			}
			for _, key := range returnedKeys {
				if !bytes.Equal(key, make([]byte, len(key))) {
					t.Fatal("DEK not cleared")
				}
			}
			after, _ := json.Marshal(store.data)
			if !bytes.Equal(original, after) {
				t.Fatal("scrub mutated provider objects")
			}
		})
	}
}

func TestVerifyRefusesInvalidChainBeforeObjectIO(t *testing.T) {
	for _, fault := range []string{"tenant", "target", "order", "missing", "duplicate", "overlong"} {
		t.Run(fault, func(t *testing.T) {
			members, store, keys := verificationFixture(t, false)
			switch fault {
			case "tenant":
				members[1].Request.OrgID = "different"
				rehash(t, &members[1])
			case "target":
				members[1].Request.Plan.Target.Bucket = "different-bucket"
				members[1].Receipt.Bucket = "different-bucket"
				rehash(t, &members[1])
			case "order":
				members[0], members[1] = members[1], members[0]
			case "missing":
				members = members[1:]
			case "duplicate":
				members = append(members, members[1])
			case "overlong":
				for len(members) <= 256 {
					members = append(members, members[1])
				}
			}
			if result, err := Verify(context.Background(), members, store.open, keys); result != nil || err == nil {
				t.Fatal("invalid chain returned proof", result, err)
			}
			if store.reads != 0 {
				t.Fatal("invalid chain reached provider")
			}
		})
	}
}

func TestVerifyCorruptionMissingObjectAndWrongKeyNeverReturnProof(t *testing.T) {
	for _, fault := range []string{"payload", "manifest", "missing", "wrong-key", "key-error", "no-key", "missing-definition", "wrong-definition", "checkpoint"} {
		t.Run(fault, func(t *testing.T) {
			members, store, keys := verificationFixture(t, true)
			m := &members[len(members)-1]
			switch fault {
			case "wrong-key":
				keys = func(context.Context, Member) ([]byte, error) { return bytes.Repeat([]byte{9}, 32), nil }
			case "key-error":
				keys = func(context.Context, Member) ([]byte, error) { return nil, errors.New("key unavailable") }
			case "no-key":
				keys = nil
			case "missing-definition":
				attachDefinition(t, m, store, "")
			case "wrong-definition":
				attachDefinition(t, m, store, base64.StdEncoding.EncodeToString([]byte(`{"kind":"wrong"}`)))
			case "checkpoint":
				m.Request.Plan.Parent.Checkpoint = "foreign"
				rehash(t, m)
			default:
				for _, object := range m.Receipt.Objects {
					if (fault == "manifest" && object.Role == "volume_manifest") || (fault != "manifest" && object.Role == "volume_payload") {
						if fault == "missing" {
							delete(store.data, object.Key)
						} else {
							store.data[object.Key][len(store.data[object.Key])-1] ^= 1
						}
					}
				}
			}
			if result, err := Verify(context.Background(), members, store.open, keys); result != nil || err == nil {
				t.Fatal("unverified chain returned proof", result, err)
			}
		})
	}
}

type closeFailure struct{ io.Reader }

func (closeFailure) Close() error { return errors.New("object close failed") }

func TestVerifyCancellationAndCloseFailureNeverReturnProof(t *testing.T) {
	members, store, keys := verificationFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := Verify(ctx, members, store.open, keys); result != nil || !errors.Is(err, context.Canceled) || store.reads != 0 {
		t.Fatal(result, err, store.reads)
	}
	open := func(ctx context.Context, target models.StorageTarget, object models.StorageObjectReceipt) (io.ReadCloser, error) {
		body, err := store.open(ctx, target, object)
		if err != nil {
			return nil, err
		}
		return closeFailure{body}, nil
	}
	if result, err := Verify(context.Background(), members, open, keys); result != nil || err == nil {
		t.Fatal("close failure returned proof", result, err)
	}
	first, _ := Verify(context.Background(), members, store.open, keys)
	second, _ := Verify(context.Background(), members, store.open, keys)
	if first == nil || !reflect.DeepEqual(first, second) {
		t.Fatal("same receipt verification result changed")
	}
}

func TestVerifyCancellationClosesBlockedObjectRead(t *testing.T) {
	members, _, keys := verificationFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	reader, writer := io.Pipe()
	defer writer.Close()
	open := func(context.Context, models.StorageTarget, models.StorageObjectReceipt) (io.ReadCloser, error) {
		close(started)
		return reader, nil
	}
	done := make(chan error, 1)
	go func() {
		result, err := Verify(ctx, members, open, keys)
		if result != nil {
			err = errors.New("cancelled scrub returned proof")
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("scrub did not reach object reader")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled scrub succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scrub did not close blocked reader")
	}
}
