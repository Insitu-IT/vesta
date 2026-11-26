//go:build kubevirt

package kubevirt

import (
	"context"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktesting "k8s.io/client-go/testing"

	dynamicfake "k8s.io/client-go/dynamic/fake"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/operationbudget"
	"vnbui/agent/internal/storageupload"
)

func TestExportValidationRequestBudgetOneDiskFull(t *testing.T) {
	f := readyExportFixtureVolumes(t, false, false, 1024, 1)
	// The fixture has controller objects attached, but the producer must still
	// admit and durably bind the borrowed utility before inspecting its export.
	journal, err := f.e.PrepareStorageTransaction(context.Background(), f.body)
	if err != nil {
		t.Fatal(err)
	}
	s, err := journal.Snapshot()
	closeErr := journal.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	export, err := f.e.inspectExport(context.Background(), &s)
	if err != nil {
		t.Fatal(err)
	}
	s.Export = export
	dyn := f.e.dynamic.(*dynamicfake.FakeDynamicClient)
	dyn.ClearActions()
	if err := f.e.revalidateExport(context.Background(), &s); err != nil {
		t.Fatal(err)
	}
	// One selected disk is backed by a two-native-disk controller projection.
	// The excluded PVC still participates in CBW and needs its own identity read.
	if s.Request.Plan.Source.Schema != 2 || len(s.Request.Plan.Source.Volumes) != 1 || len(s.Request.Plan.Source.NativeDisks()) != 2 {
		t.Fatal("fixture lost native/selected disk distinction")
	}
	if calls := len(dyn.Actions()); calls != 14 {
		t.Fatalf("one validation made %d calls; expected 14 (28 per read/upload cycle)", calls)
	}
	got := map[string]int{}
	for _, action := range dyn.Actions() {
		if action.GetVerb() != "get" && action.GetVerb() != "list" {
			t.Fatal("validation mutated Kubernetes")
		}
		key := action.GetVerb() + " " + action.GetResource().Resource
		if action.GetVerb() == "get" {
			key += "/" + action.(ktesting.GetAction).GetName()
		}
		got[key]++
	}
	want := map[string]int{
		"get virtualmachinebackuptrackers/" + s.Native.Objects[0].Name: 1,
		"get virtualmachinebackups/" + s.Native.Objects[1].Name:        2,
		"get persistentvolumeclaims/" + s.Native.ScratchName:           1,
		"get virtualmachines/" + s.Request.Plan.VMName:                 1,
		"get virtualmachineinstances/" + s.Request.Plan.VMName:         2,
		"list virtualmachineexports":                                   1,
		"get services/service-original":                                1,
		"list pods":                                                    1,
		"list endpointslices":                                          1,
		"get secrets/" + s.Native.Objects[2].Name:                      1,
	}
	excluded := ""
	for _, v := range s.Request.Plan.Source.NativeDisks() {
		want["get persistentvolumeclaims/"+v.PVCName] = 1
		if v.PVCUID != s.Request.Plan.Source.Volumes[0].PVCUID {
			excluded = v.PVCName
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("validation budget contains unexpected or duplicate reads: got=%v want=%v", got, want)
	}
	// Prove the additional read enforces the excluded disk's safety boundary.
	pvc, err := dyn.Resource(pvcResource).Namespace(s.Request.Plan.Source.Namespace).Get(context.Background(), excluded, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pvc.SetUID("replacement-excluded-pvc")
	if err := dyn.Tracker().Update(pvcResource, pvc, s.Request.Plan.Source.Namespace); err != nil {
		t.Fatal(err)
	}
	err = f.e.revalidateExport(context.Background(), &s)
	if err == nil || faultOf(err).Reason != "source_volume_identity_changed" || faultOf(err).Disposition != "refused" {
		t.Fatal("excluded native disk identity read was not enforced", err)
	}
}

func TestTransactionUploadSnapshotsStayImmutableAndNonterminal(t *testing.T) {
	e, _, request := runnerFixture(t)
	r := &transactionRunner{executor: e, work: map[string]*transactionWork{request.BackupID: {request: request}}}
	e.storageRunner = r
	r.progress(r.work[request.BackupID], models.TaskStatusRunning, "preparing", false)
	initial := e.GetProgress(request.BackupID)
	e.observeTransactionUpload(request, storageupload.UploadProgress{BytesTransferred: 8, TotalBytes: 64})
	current := e.GetProgress(request.BackupID)
	if initial.ProgressPercent != 0 || current.ProgressPercent != 12 || current.StartedAt != initial.StartedAt {
		t.Fatal("mutated snapshot/start or wrong progress")
	}
	first := e.StorageProgressEvents()
	if !reflect.DeepEqual(first, e.StorageProgressEvents()) || len(first) != 1 || first[0]["phase"] != "uploading" {
		t.Fatal("heartbeat lost snapshot")
	}
	e.observeTransactionUpload(request, storageupload.UploadProgress{BytesTransferred: 64, TotalBytes: 64})
	e.observeTransactionFinalizing(request)
	finalizing := e.GetProgress(request.BackupID)
	if finalizing.ProgressPercent != 99 || *finalizing.CheckpointCommitted || e.StorageProgressEvents()[0]["phase"] != "finalizing" {
		t.Fatal("upload inferred completion")
	}
	r.retain(r.work[request.BackupID], "retained")
	if len(e.StorageProgressEvents()) != 0 || len(e.StorageHoldEvents()) != 1 || e.GetProgress(request.BackupID).BytesTransferred != 64 {
		t.Fatal("hold regressed/lost progress")
	}
}

func TestLongBackupUsesSizeEstimateWithinProviderCeiling(t *testing.T) {
	p := operationbudget.DefaultPolicy()
	small, err := p.Estimate(1<<30, 32<<20, 0, 10*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	large, err := p.Estimate(100<<30, 32<<20, 0, 24*time.Hour)
	if err != nil || large.RunSeconds <= 2*3600 || large.RunSeconds <= small.RunSeconds {
		t.Fatal("backup size did not determine its budget", large, err)
	}
	if _, err := p.Estimate(100<<30, 32<<20, 0, time.Hour); err == nil {
		t.Fatal("operator ceiling silently truncated required work")
	}
}

func TestUploadProgressMatchesDurablePartsAndSparseDenominator(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		f := readyExportFixtureVolumes(t, true, encrypted, 16<<20, 1)
		if _, err := f.run(); err != nil {
			t.Fatal(err)
		}
		s := f.disk(t)
		var bytes int64
		for _, object := range s.Objects {
			if object.Artifact.Role == "volume_payload" {
				bytes += object.Receipt.CiphertextBytes
			}
		}
		p := f.e.GetProgress(s.Request.BackupID)
		if p == nil || p.BytesTransferred != bytes || *p.TotalBytes != bytes || p.ProgressPercent != 99 || *p.CheckpointCommitted {
			t.Fatal("progress disagrees with saved payload receipts", p, bytes)
		}
	}
}

func TestLostPartAcknowledgmentDoesNotAdvanceProgress(t *testing.T) {
	f := readyExportFixtureVolumes(t, false, true, 16<<20, 1)
	f.failControl = "part_ack"
	if _, err := f.run(); err == nil {
		t.Fatal("uncertain acknowledgment accepted")
	}
	p := f.e.GetProgress(f.state.Request.BackupID)
	if p == nil || p.BytesTransferred != 0 || p.ProgressPercent != 0 || *p.CheckpointCommitted {
		t.Fatal("uncertain bytes counted as uploaded", p)
	}
	if f.disk(t).Phase != "held" {
		t.Fatal("uncertain attempt lost custody")
	}
}
