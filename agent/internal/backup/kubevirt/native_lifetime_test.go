//go:build kubevirt

package kubevirt

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"vnbui/agent/internal/models"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
)

func TestSizeDerivedNativeWindowSurvivesTwoHoursOfUsefulProgressAndReopen(t *testing.T) {
	e, body, request, _ := nativeFixtureConfigured(t, false, func(r *models.StorageTransactionRequest, objects []*unstructured.Unstructured) []*unstructured.Unstructured {
		v := &r.Plan.Source.Volumes[0]
		v.CapacityBytes = 50 << 30
		for i := range r.Plan.Artifacts {
			a := &r.Plan.Artifacts[i]
			if a.VolumeID == v.PVCUID && a.Role == "volume_payload" {
				a.PlaintextMax, a.CiphertextMax = v.CapacityBytes, v.CapacityBytes
			}
		}
		for _, o := range objects {
			if o.GetKind() == "PersistentVolumeClaim" && string(o.GetUID()) == v.PVCUID {
				_ = unstructured.SetNestedField(o.Object, strconv.FormatInt(v.CapacityBytes, 10), "status", "capacity", "storage")
			}
		}
		return objects
	})
	j, err := e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	state, _ := j.Snapshot()
	j.Close()
	root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
	g, err := openSafety(root, request)
	if err != nil {
		t.Fatal(err)
	}
	start := nativeNow()
	for minute := 1; minute <= 121; minute++ {
		now := start.Add(time.Duration(minute) * time.Minute)
		nativeNow = func() time.Time { return now }
		if err := checkSafety(context.WithValue(context.Background(), safetyContextKey{}, g)); err != nil {
			t.Fatal("progressing operation expired", err)
		}
		if err := g.advance("transferring", int64(minute)<<20); err != nil {
			t.Fatal(err)
		}
	}
	e.cfg.OperationBudget = g.snapshot().Policy
	e.cfg.OperationBudget.TimeCoefficient = 99 // Reopening must use the pinned policy.
	j, err = e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal("two-hour implicit cutoff returned", err)
	}
	defer j.Close()
	reopened, _ := j.Snapshot()
	if !reflect.DeepEqual(state.Native, reopened.Native) {
		t.Fatal("reopen extended native deadline")
	}
}

func TestNativeLifetimeRealPreparationReopenAndExpiry(t *testing.T) {
	for _, timeout := range []int{0, 3 * 3600} {
		t.Run(time.Duration(timeout*int(time.Second)).String(), func(t *testing.T) {
			e, body, r, dyn := nativeFixture(t, false)
			e.cfg.KubevirtNativeTTLSeconds = 4 * 3600
			e.cfg.KubevirtTransactionTimeoutSeconds = timeout
			start := nativeNow()
			j, err := e.PrepareStorageTransaction(context.Background(), body)
			if err != nil {
				t.Fatal(err)
			}
			s, err := j.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			j.Close()
			b, err := dyn.Resource(kvtypes.BackupResource).Namespace(r.Plan.Source.Namespace).Get(context.Background(), s.Native.Objects[1].Name, metav1.GetOptions{})
			if err != nil || textAt(b, "spec", "ttlDuration") != "1h0m0s" || s.Native.Lifetime.CreatedAt != start.Format(time.RFC3339Nano) {
				t.Fatal("real preparation did not bind the size-derived TTL and original creation", err)
			}
			// A new process/configuration cannot alter the attempt's original window.
			e.cfg.KubevirtNativeTTLSeconds = 8 * 3600
			e.cfg.KubevirtTransactionTimeoutSeconds = 0
			nativeNow = func() time.Time { return start.Add(30 * time.Second) }
			j, err = e.PrepareStorageTransaction(context.Background(), body)
			if err != nil {
				t.Fatal("valid preparation recovery within original budget", err)
			}
			reopened, err := j.Snapshot()
			j.Close()
			if err != nil || !reflect.DeepEqual(s.Native, reopened.Native) {
				t.Fatal("recovery changed lifetime", err)
			}
			dyn.ClearActions()
			expires := s.Native.Lifetime.Deadline()
			nativeNow = func() time.Time { return expires }
			if j, err := e.PrepareStorageTransaction(context.Background(), body); err == nil {
				j.Close()
				t.Fatal("expiry accepted")
			}
			for _, a := range dyn.Actions() {
				if a.GetVerb() != "get" && a.GetVerb() != "list" {
					t.Fatal("expiry mutated native custody", a.GetVerb())
				}
			}
		})
	}
}

func TestNativeLifetimeInvalidConfigBeforePreparationEffects(t *testing.T) {
	for _, ttl := range []int{0, -1, 3599, 2592001} {
		e, body, _, dyn := nativeFixture(t, false)
		e.cfg.KubevirtNativeTTLSeconds = ttl
		if j, err := e.PrepareStorageTransaction(context.Background(), body); err == nil {
			j.Close()
			t.Fatal("invalid TTL accepted", ttl)
		}
		if len(dyn.Actions()) != 0 {
			t.Fatal("invalid policy reached Kubernetes")
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")); !os.IsNotExist(err) {
			t.Fatal("invalid policy created a journal", err)
		}
	}
}

func TestNativeLifetimeRefusesShortExporterBeforePayload(t *testing.T) {
	for _, fault := range []string{"rotation", "export-ttl", "missing-deadline", "duplicate-deadline", "value-from"} {
		t.Run(fault, func(t *testing.T) {
			f := readyExportFixture(t, false, false, 32)
			if fault == "export-ttl" {
				mutateExportObject(t, f, kvtypes.ExportResource, "export-original", func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, "30m", "spec", "ttlDuration")
				})
			} else {
				mutateExportObject(t, f, exportPodResource, "pod-original", func(o *unstructured.Unstructured) {
					entry := map[string]interface{}{"name": "DEADLINE", "value": nativeNow().Add(30 * time.Minute).Format(time.RFC3339Nano)}
					env := []interface{}{entry}
					switch fault {
					case "missing-deadline":
						env = []interface{}{}
					case "duplicate-deadline":
						env = append(env, entry)
					case "value-from":
						entry["valueFrom"] = map[string]interface{}{"fieldRef": map[string]interface{}{"fieldPath": "metadata.name"}}
					}
					_ = unstructured.SetNestedSlice(o.Object, []interface{}{map[string]interface{}{"name": "exporter", "env": env}}, "spec", "containers")
				})
			}
			if _, err := f.run(); err == nil {
				t.Fatal("unsupported exporter window accepted")
			}
			s := f.disk(t)
			if s.Phase != "held" || s.Export != nil || s.Acceptance != nil || len(f.calls) != 0 || f.streams != 0 {
				t.Fatal("unsafe window produced payload or acceptance", s.Phase, f.calls)
			}
			for _, o := range s.Objects {
				if o.Phase != "planned" || o.UploadID != "" {
					t.Fatal("multipart custody created")
				}
			}
		})
	}
}

func TestNativeLifetimeDefaultFitsHCOTwelveHourExporter(t *testing.T) {
	for _, incremental := range []bool{false, true} {
		for _, encrypted := range []bool{false, true} {
			f := readyExportFixture(t, incremental, encrypted, 32)
			deadline := nativeNow().Add(12 * time.Hour).Format(time.RFC3339Nano)
			mutateExportObject(t, f, exportPodResource, "pod-original", func(o *unstructured.Unstructured) {
				_ = unstructured.SetNestedSlice(o.Object, []interface{}{map[string]interface{}{"name": "exporter", "env": []interface{}{map[string]interface{}{"name": "DEADLINE", "value": deadline}}}}, "spec", "containers")
			})
			if _, err := f.run(); err != nil {
				t.Fatalf("default lifetime cannot use HCO's 12h exporter: %v", err)
			}
			s := f.disk(t)
			if s.Export == nil || s.Acceptance == nil || f.streams == 0 {
				t.Fatal("default HCO path did not produce and accept payload")
			}
		}
	}
}

func TestNativeLifetimeMetadataDriftNeverExtendsAttempt(t *testing.T) {
	for _, field := range []string{"ttl", "created"} {
		t.Run(field, func(t *testing.T) {
			f := readyExportFixture(t, false, false, 1)
			s := f.disk(t)
			mutateExportObject(t, f, kvtypes.BackupResource, s.Native.Objects[1].Name, func(b *unstructured.Unstructured) {
				if field == "ttl" {
					_ = unstructured.SetNestedField(b.Object, "48h", "spec", "ttlDuration")
				} else {
					b.SetCreationTimestamp(metav1.NewTime(nativeNow().Add(time.Hour)))
				}
			})
			if _, err := f.run(); err == nil || len(f.calls) != 0 {
				t.Fatal("drift extended or produced", err)
			}
		})
	}
}

func TestNativeLifetimeExportWindowCannotChangeOnReceiptRecovery(t *testing.T) {
	for _, field := range []string{"creation", "pod-deadline"} {
		t.Run(field, func(t *testing.T) {
			f := readyExportFixture(t, false, false, 1)
			if _, err := f.run(); err != nil {
				t.Fatal(err)
			}
			calls, streams := len(f.calls), f.streams
			if field == "creation" {
				mutateExportObject(t, f, kvtypes.ExportResource, "export-original", func(o *unstructured.Unstructured) {
					o.SetCreationTimestamp(metav1.NewTime(o.GetCreationTimestamp().Add(time.Second)))
				})
			} else {
				mutateExportObject(t, f, exportPodResource, "pod-original", func(o *unstructured.Unstructured) {
					later := f.disk(t).Native.Lifetime.Deadline().Add(time.Second)
					_ = unstructured.SetNestedSlice(o.Object, []interface{}{map[string]interface{}{"name": "exporter", "env": []interface{}{map[string]interface{}{"name": "DEADLINE", "value": later.Format(time.RFC3339Nano)}}}}, "spec", "containers")
				})
			}
			if _, err := f.run(); err == nil || len(f.calls) != calls || f.streams != streams {
				t.Fatal("receipt recovery adopted changed export lifetime or repeated effects", err)
			}
		})
	}
}
