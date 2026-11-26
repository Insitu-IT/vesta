package storageupload

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type lostReply struct {
	*fakeStore
	phase string
}

func (s *lostReply) Begin(ctx context.Context, key string, meta map[string]string) (string, error) {
	id, e := s.fakeStore.Begin(ctx, key, meta)
	if s.phase == "begin" && e == nil {
		return "", errors.New("lost begin acknowledgement")
	}
	return id, e
}
func (s *lostReply) Part(ctx context.Context, key, id string, n int, data []byte, checksum string) (string, error) {
	etag, e := s.fakeStore.Part(ctx, key, id, n, data, checksum)
	if s.phase == "part" && e == nil {
		return "", errors.New("lost part acknowledgement")
	}
	return etag, e
}
func (s *lostReply) Complete(ctx context.Context, key, id string, parts []Part) (ObjectInfo, error) {
	info, e := s.fakeStore.Complete(ctx, key, id, parts)
	if s.phase == "complete" && e == nil {
		return ObjectInfo{}, errors.New("lost completion acknowledgement")
	}
	return info, e
}
func (s *lostReply) Head(ctx context.Context, key string, version *string, etag string) (ObjectInfo, error) {
	info, e := s.fakeStore.Head(ctx, key, version, etag)
	if s.phase == "head" && e == nil {
		return ObjectInfo{}, errors.New("lost HEAD reply")
	}
	return info, e
}

func TestAcceptedProviderOperationLostReplyRetainsPreCallIntent(t *testing.T) {
	for _, phase := range []string{"begin", "part", "complete", "head"} {
		t.Run(phase, func(t *testing.T) {
			b := request(t, false)
			root := t.TempDir()
			j, err := Create(root, b)
			if err != nil {
				t.Fatal(err)
			}
			fake := store(t, b)
			fake.mutate = func() {
				data, e := os.ReadFile(j.path)
				if e != nil {
					t.Fatal(e)
				}
				var saved diskJournal
				if e = json.Unmarshal(data, &saved); e != nil {
					t.Fatal(e)
				}
				operation := fake.calls[len(fake.calls)-1]
				expected := map[string]string{"begin": "create_intent", "part": "part_intent", "complete": "complete_intent", "head": "complete_intent"}[operation]
				o := saved.State.Objects[0]
				if o.Phase != expected {
					t.Fatal("provider operation before exact durable intent")
				}
				if operation == "part" && (o.UploadID == "" || o.PendingPart == nil) {
					t.Fatal("missing upload/part intent")
				}
				if operation == "complete" && (o.Receipt == nil || o.Receipt.ETag != "" || len(o.Parts) == 0) {
					t.Fatal("missing final digest before complete")
				}
				if operation == "head" && (o.Receipt == nil || o.Receipt.ETag == "") {
					t.Fatal("missing exact completion identity before HEAD")
				}
			}
			s := &lostReply{fakeStore: fake, phase: phase}
			n := 0
			in := inputs(fake.r, 0, &n)
			if err = j.UploadAll(context.Background(), s, in, nil); err == nil {
				t.Fatal("lost acknowledgement accepted")
			}
			calls := len(fake.calls)
			_ = j.Close()
			j, err = Open(root, b)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			state, err := j.Snapshot()
			if err != nil || state.Phase != "held" || state.Acceptance != nil {
				t.Fatal("lost exact held evidence", err)
			}
			if phase != "begin" && state.Objects[0].UploadID == "" {
				t.Fatal("lost upload identity")
			}
			if phase == "complete" && state.Objects[0].Receipt == nil {
				t.Fatal("lost final hashes")
			}
			if phase == "head" && state.Objects[0].Receipt.ETag == "" {
				t.Fatal("lost acknowledged identity")
			}
			if j.UploadAll(context.Background(), s, in, nil) == nil || len(fake.calls) != calls {
				t.Fatal("blind redispatch after lost reply")
			}
		})
	}
}

func TestDurabilityFailurePoisonsBeforeNextSideEffect(t *testing.T) {
	for _, phase := range []string{"file-fsync", "directory-fsync", "after-create"} {
		t.Run(phase, func(t *testing.T) {
			b := request(t, false)
			j, err := Create(t.TempDir(), b)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			s := store(t, b)
			count := 0
			inject := func(f *os.File) error {
				count++
				if phase != "directory-fsync" || count == 2 {
					return errors.New("simulated durable I/O failure")
				}
				return f.Sync()
			}
			if phase == "after-create" {
				s.mutate = func() { j.syncFile = inject }
			} else {
				j.syncFile = inject
			}
			opens := 0
			in := inputs(s.r, 1, &opens)
			if j.UploadAll(context.Background(), s, in, nil) == nil || !j.poisoned {
				t.Fatal("fsync failure not held")
			}
			want := 0
			if phase == "after-create" {
				want = 1
			}
			if len(s.calls) != want {
				t.Fatal("provider side effect after failed durability")
			}
			if j.UploadAll(context.Background(), s, in, nil) == nil || len(s.calls) != want {
				t.Fatal("poisoned handle resumed")
			}
		})
	}
}

func TestCompletedObjectsSurviveReceiptJournalFailure(t *testing.T) {
	b := request(t, true)
	root := t.TempDir()
	j, err := Create(root, b)
	if err != nil {
		t.Fatal(err)
	}
	s := store(t, b)
	opens := 0
	in := inputs(s.r, 12, &opens)
	j.syncFile = func(f *os.File) error {
		if j.state.Phase == "prepared" {
			return errors.New("receipt fsync failure")
		}
		return f.Sync()
	}
	if j.UploadAll(context.Background(), s, in, make([]byte, 32)) == nil {
		t.Fatal("failed receipt persistence accepted")
	}
	if opens != 2 {
		t.Fatal("did not stream both artifacts")
	}
	calls := len(s.calls)
	_ = j.Close()
	j, err = Open(root, b)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if j.state.Phase != "uploading" || j.state.Receipt != nil {
		t.Fatal("wrong persisted crash boundary")
	}
	if err = j.UploadAll(context.Background(), s, in, nil); err != nil {
		t.Fatal(err)
	}
	if j.state.Receipt == nil || len(j.state.Receipt.Objects) != 2 || opens != 2 || len(s.calls) != calls {
		t.Fatal("receipt construction reuploaded completed objects")
	}
}
