package nativerestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
	"vnbui/agent/internal/storagerestore"
)

func TestNativeVerifyEveryArtifactWithoutMaterializing(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprint(encrypted), func(t *testing.T) {
			bundle, store, key := bundleFixture(t, encrypted)
			original, _ := json.Marshal(store)
			reads := 0
			open := func(_ context.Context, target models.StorageTarget, o models.StorageObjectReceipt) (io.ReadCloser, error) {
				if target != bundle.Members[0].Request.Plan.Target || o.ETag != `"immutable"` || o.VersionID != nil {
					t.Fatal("wrong provider identity")
				}
				reads++
				return io.NopCloser(bytes.NewReader(store[o.Key])), nil
			}
			var resolved []byte
			keys := func(context.Context, Member) ([]byte, error) { resolved = bytes.Clone(key); return resolved, nil }
			result, err := Verify(context.Background(), bundle, open, keys)
			if err != nil || result == nil {
				t.Fatal(result, err)
			}
			m := bundle.Members[0]
			_, digest, _ := nativefileset.CanonicalReceipt(m.Receipt, m.Request.Plan.Artifacts, m.Request.BackupID, m.Request.ReservationID, m.Request.Plan.Target, m.Request.Plan.Encryption)
			want := &storagerestore.VerificationResult{Schema: storagerestore.VerificationSchema, Provider: "libvirt", OrgID: m.Request.OrgID, AgentID: m.Request.AgentID, VMID: m.Request.Plan.Source.VMID, Members: []storagerestore.VerifiedMember{{BackupID: m.Request.BackupID, ReservationID: m.Request.ReservationID, PlanSHA256: m.Request.PlanSHA256, ReceiptSHA256: digest, Objects: 5}}}
			if !reflect.DeepEqual(result, want) || reads != 5 {
				t.Fatalf("unexpected result: %+v reads=%d", result, reads)
			}
			if !bytes.Equal(resolved, make([]byte, len(resolved))) {
				t.Fatal("DEK not cleared")
			}
			after, _ := json.Marshal(store)
			if !bytes.Equal(original, after) {
				t.Fatal("provider artifacts changed")
			}
			body, _ := json.Marshal(result)
			if bytes.Contains(body, []byte("captured")) || bytes.Contains(body, []byte("disk-one")) {
				t.Fatal("artifact contents leaked into result")
			}
		})
	}
}

func TestNativeVerifyCorruptionInEveryArtifactAndEncryptionMode(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, index := range []int{0, 1, 2, 3, 4} {
			for _, fault := range []string{"digest", "short", "extra", "read-error", "close-error"} {
				t.Run(fmt.Sprintf("%t/%d/%s", encrypted, index, fault), func(t *testing.T) {
					bundle, store, key := bundleFixture(t, encrypted)
					badKey := bundle.Members[0].Receipt.Objects[index].Key
					open := func(_ context.Context, _ models.StorageTarget, o models.StorageObjectReceipt) (io.ReadCloser, error) {
						data := bytes.Clone(store[o.Key])
						if o.Key == badKey {
							switch fault {
							case "digest":
								data[len(data)-1] ^= 1
							case "short":
								data = data[:len(data)-1]
							case "extra":
								data = append(data, 0)
							case "read-error":
								return nil, errors.New("exact object unavailable")
							case "close-error":
								return nativeCloseFailure{bytes.NewReader(data)}, nil
							}
						}
						return io.NopCloser(bytes.NewReader(data)), nil
					}
					keys := func(context.Context, Member) ([]byte, error) { return bytes.Clone(key), nil }
					if result, err := Verify(context.Background(), bundle, open, keys); result != nil || err == nil {
						t.Fatal("invalid artifact returned verification", result, err)
					}
				})
			}
		}
	}
}

type nativeCloseFailure struct{ io.Reader }

func (nativeCloseFailure) Close() error { return errors.New("object close failed") }

func TestNativeVerifyRejectsInvalidRequestKeyAndCancellation(t *testing.T) {
	for _, fault := range []string{"invalid", "missing-key", "wrong-key", "key-error", "cancelled", "nil-context", "nil-open"} {
		t.Run(fault, func(t *testing.T) {
			bundle, store, key := bundleFixture(t, true)
			reads := 0
			var open storagerestore.ObjectOpener = func(_ context.Context, _ models.StorageTarget, o models.StorageObjectReceipt) (io.ReadCloser, error) {
				reads++
				return io.NopCloser(bytes.NewReader(store[o.Key])), nil
			}
			var keys KeyResolver = func(context.Context, Member) ([]byte, error) { return bytes.Clone(key), nil }
			ctx := context.Background()
			switch fault {
			case "invalid":
				bundle.Members[0].Receipt.Objects[0].Key += "foreign"
			case "missing-key":
				keys = nil
			case "wrong-key":
				keys = func(context.Context, Member) ([]byte, error) { return bytes.Repeat([]byte{42}, 32), nil }
			case "key-error":
				keys = func(context.Context, Member) ([]byte, error) { return nil, errors.New("do-not-log-key-material") }
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-context":
				ctx = nil
			case "nil-open":
				open = nil
			}
			result, err := Verify(ctx, bundle, open, keys)
			if result != nil || err == nil {
				t.Fatal("invalid scrub returned proof", result, err)
			}
			if bytes.Contains([]byte(err.Error()), []byte("do-not-log-key-material")) {
				t.Fatal("resolver error leaked")
			}
			if fault != "wrong-key" && reads != 0 {
				t.Fatal("invalid admission reached provider", reads)
			}
		})
	}
}

func TestNativeVerifyFullAndIncrementalReadsAncestorsWithDistinctKeys(t *testing.T) {
	bundle, _, firstKey := bundleFixture(t, true)
	first, store := sealImageMember(t, bundle.Members[0], map[string][]byte{"vda": []byte("full-one"), "vdb": []byte("full-two")}, firstKey)
	body, _ := json.Marshal(first)
	var second Member
	if err := json.Unmarshal(body, &second); err != nil {
		t.Fatal(err)
	}
	second.Request.BackupID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	second.Request.ReservationID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	second.Request.Plan.AttemptID = second.Request.ReservationID
	_, receiptSHA, err := nativefileset.CanonicalReceipt(first.Receipt, first.Request.Plan.Artifacts, first.Request.BackupID, first.Request.ReservationID, first.Request.Plan.Target, first.Request.Plan.Encryption)
	if err != nil {
		t.Fatal(err)
	}
	second.Request.Plan.BackupType = "incremental"
	second.Request.Plan.Parent = &models.StorageParent{BackupID: first.Request.BackupID, RootBackupID: first.Request.BackupID, ReceiptSHA256: receiptSHA, GenerationID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", TrackerUID: first.PushResult.Manifest.DomainUUID, Checkpoint: first.PushResult.Manifest.Checkpoint}
	second.PushResult.Manifest.BackupID = second.Request.BackupID
	second.PushResult.Manifest.AttemptID = second.Request.ReservationID
	second.PushResult.Manifest.Checkpoint = "vnbui-" + second.Request.ReservationID
	second.PushResult.Manifest.ParentBackupID = &first.Request.BackupID
	second.PushResult.Manifest.ParentManifestSHA256 = &first.PushResult.ManifestSHA256
	secondKey := bytes.Repeat([]byte{42}, 32)
	second, more := sealImageMember(t, second, map[string][]byte{"vda": []byte("inc-one"), "vdb": []byte("inc-two")}, secondKey)
	for key, data := range more {
		store[key] = data
	}
	bundle.Members = []Member{first, second}
	seen := map[string]int{}
	open := func(_ context.Context, target models.StorageTarget, o models.StorageObjectReceipt) (io.ReadCloser, error) {
		if target != first.Request.Plan.Target {
			t.Fatal("changed target")
		}
		seen[o.Key]++
		return io.NopCloser(bytes.NewReader(store[o.Key])), nil
	}
	keys := func(_ context.Context, m Member) ([]byte, error) {
		if m.Request.BackupID == first.Request.BackupID {
			return bytes.Clone(firstKey), nil
		}
		if m.Request.BackupID == second.Request.BackupID {
			return bytes.Clone(secondKey), nil
		}
		return nil, errors.New("unadmitted member")
	}
	result, err := Verify(context.Background(), bundle, open, keys)
	if err != nil || result == nil || len(result.Members) != 2 || len(seen) != 10 {
		t.Fatal(result, err, len(seen))
	}
	for _, count := range seen {
		if count != 1 {
			t.Fatal("repeated artifact read", count)
		}
	}
	object := first.Receipt.Objects[0]
	store[object.Key][len(store[object.Key])-1] ^= 1
	if result, err = Verify(context.Background(), bundle, open, keys); result != nil || err == nil {
		t.Fatal("corrupt ancestor ignored", result, err)
	}
}
