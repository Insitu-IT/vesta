//go:build kubevirt

package kubevirt

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"vnbui/agent/internal/models"
)

func TestTransferProfileProductionStreamRequestReductionAndReopen(t *testing.T) {
	const size = 64<<20 + 513
	for _, incremental := range []bool{false, true} {
		for _, encrypted := range []bool{false, true} {
			t.Run(fmt.Sprintf("incremental=%t/encrypted=%t", incremental, encrypted), func(t *testing.T) {
				counts := map[string]int{}
				for _, profile := range []string{"", models.KubevirtTransfer32} {
					f := readyExportFixtureProfile(t, incremental, encrypted, size, 1, profile)
					dyn := f.e.dynamic.(*dynamicfake.FakeDynamicClient)
					dyn.ClearActions()
					if accepted, err := f.run(); err != nil || accepted == nil {
						t.Fatal("stream refused", err)
					}
					counts[profile] = len(dyn.Actions())
					d := f.disk(t)
					if d.Request.Plan.TransferProfile != profile || d.Phase != "accepted" {
						t.Fatal("profile/custody changed")
					}
					if d.Request.Plan.Source.Schema != 2 || len(d.Request.Plan.Source.Volumes) != 1 || len(d.Request.Plan.Source.NativeDisks()) != 2 {
						t.Fatal("fixture lost native/selected disk distinction")
					}
					unit, wantReads := 8<<20, 9
					if profile != "" {
						unit, wantReads = 32<<20, 3
					}
					if len(f.rangeSizes) != wantReads {
						t.Fatalf("ranges=%v", f.rangeSizes)
					}
					for _, n := range f.rangeSizes {
						if n <= 0 || n > unit {
							t.Fatal("unbounded source request", n)
						}
					}
					for _, o := range d.Objects {
						if o.Artifact.Role != "volume_payload" {
							continue
						}
						if o.PartSize != unit || len(o.Parts) != wantReads {
							t.Fatalf("parts=%d unit=%d", len(o.Parts), o.PartSize)
						}
						if o.Receipt.PlaintextBytes != size || o.Receipt.PlaintextSHA256 != nativeHash(bytes.Repeat([]byte{7}, size)) {
							t.Fatal("plaintext changed")
						}
						if o.Receipt.CiphertextSHA256 != nativeHash(f.data[o.Artifact.Key]) || o.Receipt.CiphertextBytes != int64(len(f.data[o.Artifact.Key])) {
							t.Fatal("ciphertext changed")
						}
					}
					calls, streams := len(f.calls), f.streams
					verifyAcceptedInSeparateProcess(t, f)
					if _, err := f.run(); err != nil || len(f.calls) != calls || f.streams != streams {
						t.Fatal("reopen repeated payload/provider IO", err)
					}
				}
				validationCalls := 14
				if incremental {
					validationCalls = 15
				}
				// Six fewer source requests and six fewer payload parts. Each
				// still executes the production validator at its own boundary,
				// with one consistent VMI observation for utility and mapping.
				// One selected disk now correctly retains two native disks;
				// the excluded native PVC adds one required identity read per
				// validation, so full/incremental cost 14/15 calls.
				if saved := counts[""] - counts[models.KubevirtTransfer32]; saved != 12*validationCalls {
					t.Fatalf("saved %d Kubernetes calls; counts=%v", saved, counts)
				}
			})
		}
	}
}

func TestTransferProfileProductionFaultsRetainCustody(t *testing.T) {
	for _, fault := range []string{"part_ack", "truncated", "extra", "drift_after_part", "uid_after_part", "token_after_part", "cancel_after_part"} {
		t.Run(fault, func(t *testing.T) {
			f := readyExportFixtureProfile(t, false, true, 65<<20, 1, models.KubevirtTransfer32)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			readsAtDrift := -1
			switch fault {
			case "part_ack":
				f.failControl, f.payloadControlOnly = fault, true
			case "truncated", "extra":
				f.sourceFault = fault
			case "drift_after_part", "uid_after_part", "token_after_part", "cancel_after_part":
				changed := false
				f.before = func(op string) {
					pendingPayload := false
					for _, o := range f.disk(t).Objects {
						if o.Artifact.Role == "volume_payload" && o.PendingPart != nil {
							pendingPayload = true
						}
					}
					if op == "part_ack" && pendingPayload && !changed {
						changed = true
						readsAtDrift = len(f.rangeSizes)
						if fault == "cancel_after_part" {
							cancel()
							return
						}
						if fault == "token_after_part" {
							mutateExportObject(t, f, coreV1Secret, f.state.Native.Objects[2].Name, func(o *unstructured.Unstructured) { o.SetUID("replacement") })
							return
						}
						mutateExportObject(t, f, exportServiceResource, "service-original", func(o *unstructured.Unstructured) {
							if fault == "uid_after_part" {
								o.SetUID("replacement")
							} else {
								_ = unstructured.SetNestedField(o.Object, "10.0.0.99", "spec", "clusterIP")
							}
						})
					}
				}
			}
			if _, err := f.e.AcceptStorageTransaction(ctx, f.body, f.backend, f.provider, func(context.Context) (string, error) { return "registered-agent-fixture", nil }); err == nil {
				t.Fatal("uncertain/drifted transfer accepted")
			}
			d := f.disk(t)
			if d.Phase != "held" || d.Acceptance != nil || d.Receipt != nil {
				t.Fatal("fault lost held custody")
			}
			for _, call := range f.calls {
				if call == "receipt" {
					t.Fatal("fault submitted receipt")
				}
			}
			if strings.HasSuffix(fault, "_after_part") && (readsAtDrift < 0 || len(f.rangeSizes) != readsAtDrift) {
				t.Fatal("drift reached next source request")
			}
			if fault == "part_ack" {
				for _, o := range d.Objects {
					if o.Artifact.Role == "volume_payload" && len(o.Parts) != 0 {
						t.Fatal("uncertain ACK counted")
					}
				}
			}
		})
	}
}

func TestTransferProfileSparseAndZeroOnlyStreams(t *testing.T) {
	for _, fault := range []string{"hole-zero", "zero"} {
		f := readyExportFixtureProfile(t, fault == "zero", true, 64, 1, models.KubevirtTransfer32)
		f.sourceFault = fault
		if _, err := f.run(); err != nil {
			t.Fatal(err)
		}
		d := f.disk(t)
		expected := int64(32)
		if fault == "zero" {
			expected = 0
		}
		for _, o := range d.Objects {
			if o.Artifact.Role == "volume_payload" && o.Receipt.PlaintextBytes != expected {
				t.Fatal("sparse source was expanded")
			}
		}
		for _, call := range f.calls {
			if fault == "zero" && strings.HasSuffix(call, "/data") {
				t.Fatal("zero-only source was read")
			}
		}
	}
}
