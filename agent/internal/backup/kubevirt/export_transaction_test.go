//go:build kubevirt

package kubevirt

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	k8stest "k8s.io/client-go/testing"
	"vnbui/agent/internal/models"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/storageupload"
)

type exportTransport func(*http.Request) (*http.Response, error)

func (f exportTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func exportResponse(value any) *http.Response {
	b, _ := json.Marshal(value)
	return &http.Response{StatusCode: 200, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(bytes.NewReader(b))}
}

type exportFixture struct {
	e                  *Executor
	body               []byte
	state              storageupload.State
	backend, provider  *http.Client
	calls              []string
	streams            int
	rangeSizes         []int
	receipt            []byte
	lost               bool
	corruptAck         bool
	data               map[string][]byte
	info               map[string]storageupload.ObjectInfo
	before             func(string)
	sourceFault        string
	failControl        string
	payloadControlOnly bool
	versioned          bool
}

func (f *exportFixture) disk(t *testing.T) storageupload.State {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(filepath.Dir(f.e.cfg.KeyFilePath), "storage-transactions", f.state.Request.ReservationID, "transaction.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		SHA256 string              `json:"sha256"`
		State  storageupload.State `json:"state"`
	}
	if json.Unmarshal(b, &d) != nil {
		t.Fatal("disk")
	}
	canonical, _ := models.StorageCanonical(d.State)
	if nativeHash(canonical) != d.SHA256 {
		t.Fatal("disk checksum")
	}
	for _, s := range []string{"native-token-fixture", "registered-agent-fixture", "X-Amz-Signature", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{91}, 32))} {
		if bytes.Contains(b, []byte(s)) {
			t.Fatal("secret custody")
		}
	}
	return d.State
}
func readyExportFixture(t *testing.T, incremental, encrypted bool, size int) *exportFixture {
	return readyExportFixtureVolumes(t, incremental, encrypted, size, 2)
}
func readyExportFixtureVolumes(t *testing.T, incremental, encrypted bool, size, count int) *exportFixture {
	return readyExportFixtureProfile(t, incremental, encrypted, size, count, "")
}
func readyExportFixtureProfile(t *testing.T, incremental, encrypted bool, size, count int, profile string) *exportFixture {
	t.Helper()
	configure := func(r *models.StorageTransactionRequest, objects []*unstructured.Unstructured) []*unstructured.Unstructured {
		r.Plan.TransferProfile = profile
		if count == 1 {
			r.Plan.Source.Schema = 2
			r.Plan.Source.NativeVolumes = append([]models.StorageVolume(nil), r.Plan.Source.Volumes...)
			r.Plan.Source.Volumes = r.Plan.Source.Volumes[:1]
			r.Plan.Exclusions = []string{"data-two", "seed"}
		} else if count == 3 {
			v := r.Plan.Source.Volumes[0]
			v.Name = "data-three"
			v.PVCName = v.Name
			v.PVCUID = v.Name + "-uid"
			v.Mapping.DiskName = v.Name
			r.Plan.Source.Volumes = append(r.Plan.Source.Volumes, v)
			pvc := objects[0].DeepCopy()
			pvc.SetName(v.Name)
			pvc.SetUID(types.UID(v.PVCUID))
			objects = append(objects, pvc)
			for _, o := range objects {
				if o.GetKind() != "VirtualMachine" && o.GetKind() != "VirtualMachineInstance" {
					continue
				}
				prefix := []string{"spec"}
				if o.GetKind() == "VirtualMachine" {
					prefix = []string{"spec", "template", "spec"}
				}
				path := append(append([]string{}, prefix...), "volumes")
				vols, _, _ := unstructured.NestedSlice(o.Object, path...)
				vols = append(vols, map[string]interface{}{"name": v.Name, "persistentVolumeClaim": map[string]interface{}{"claimName": v.PVCName}})
				_ = unstructured.SetNestedSlice(o.Object, vols, path...)
				path = append(append([]string{}, prefix...), "domain", "devices", "disks")
				disks, _, _ := unstructured.NestedSlice(o.Object, path...)
				disks = append(disks, map[string]interface{}{"name": v.Name, "disk": map[string]interface{}{"bus": "virtio"}})
				_ = unstructured.SetNestedSlice(o.Object, disks, path...)
			}
		}
		r.Plan.Artifacts = nil
		root := "vnbui-owned/v1/" + nativeHash([]byte(r.OrgID)) + "/" + nativeHash([]byte(r.BackupID)) + "/payload/" + r.Plan.AttemptID + "/"
		for _, v := range r.Plan.Source.Volumes {
			for _, role := range []string{"volume_payload", "volume_manifest"} {
				max := int64(size)
				if role == "volume_manifest" {
					max = 16 << 20
				}
				r.Plan.Artifacts = append(r.Plan.Artifacts, models.StorageArtifact{VolumeID: v.PVCUID, Role: role, Key: root + nativeHash([]byte(v.PVCUID)) + "/" + role, PlaintextMax: max, CiphertextMax: max})
			}
		}
		sort.Slice(r.Plan.Artifacts, func(i, j int) bool { return r.Plan.Artifacts[i].Key < r.Plan.Artifacts[j].Key })
		for i := range r.Plan.Source.Volumes {
			r.Plan.Source.Volumes[i].CapacityBytes = int64(size)
			for _, o := range objects {
				if o.GetKind() == "PersistentVolumeClaim" && o.GetName() == r.Plan.Source.Volumes[i].PVCName {
					_ = unstructured.SetNestedField(o.Object, strconv.Itoa(size), "status", "capacity", "storage")
				}
			}
		}
		if r.Plan.Source.Schema == 2 {
			for i := range r.Plan.Source.NativeVolumes {
				for _, selected := range r.Plan.Source.Volumes {
					if selected.Name == r.Plan.Source.NativeVolumes[i].Name {
						r.Plan.Source.NativeVolumes[i] = selected
					}
				}
			}
		}
		if encrypted {
			ref := "kek:66666666-6666-4666-8666-666666666666:aaaaaaaaaaaaaaaa"
			r.Plan.Encryption = models.StorageEncryption{Format: "vnbu1-aes256gcm-chunk5242880", KeyRef: &ref}
		}
		for i := range r.Plan.Artifacts {
			a := &r.Plan.Artifacts[i]
			if a.Role == "volume_payload" {
				a.PlaintextMax = int64(size)
				a.CiphertextMax = int64(size)
				if encrypted {
					a.CiphertextMin = 5
					a.CiphertextMax = 5 + int64(size) + 32*((int64(size)+5242880-1)/5242880)
				}
			}
		}
		return objects
	}
	e, body, dyn, s := attachedFixtureConfigured(t, incremental, configure)
	e.cfg.OrchestratorURL = "https://backend.example"
	f := &exportFixture{e: e, body: body, state: s, data: map[string][]byte{}, info: map[string]storageupload.ObjectInfo{}}
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(exportTokenHeader) != "native-token-fixture-of-at-least-32-bytes" {
			t.Error("native token binding")
		}
		f.streams++
		f.calls = append(f.calls, "source:"+r.URL.Path)
		if f.before != nil {
			f.before("source")
		}
		d := f.disk(t)
		if d.Export == nil {
			t.Error("source before durable attribution")
		}
		if f.sourceFault == "redirect" {
			http.Redirect(w, r, "https://foreign.example", 302)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/map") {
			description := "data"
			if incremental {
				description = "dirty"
			}
			if f.sourceFault == "allocation-data" {
				description = "data"
			}
			if f.sourceFault == "zero" {
				if incremental {
					description = "dirty,zero"
				} else {
					description = "zero"
				}
			}
			page := mapPage{Extents: []mapExtent{{Offset: 0, Length: uint64(size), Description: description}}}
			if f.sourceFault == "hole-zero" {
				page.Extents = []mapExtent{
					{Offset: 0, Length: 16, Type: 0, Description: "data"},
					{Offset: 16, Length: 32, Type: 3, Description: "hole,zero"},
					{Offset: 48, Length: 16, Type: 0, Description: "data"},
				}
			}
			if f.sourceFault == "missing" {
				page.Extents[0].Offset = 1
			}
			if f.sourceFault == "oversized" {
				w.Write(bytes.Repeat([]byte{'x'}, (1<<20)+1))
				return
			}
			_ = json.NewEncoder(w).Encode(page)
			return
		}
		if len(d.Maps) != count {
			t.Error("payload before durable complete maps")
		}
		n, _ := strconv.Atoi(r.URL.Query().Get("length"))
		f.rangeSizes = append(f.rangeSizes, n)
		if f.sourceFault == "truncated" {
			n--
		}
		if f.sourceFault == "extra" {
			n++
		}
		w.Write(bytes.Repeat([]byte{7}, n))
	}))
	t.Cleanup(source.Close)
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: source.Certificate().Raw}))
	controller := true
	obj := func(api, kind, name, uid, ownerKind, ownerName, ownerUID, ownerAPI string) *unstructured.Unstructured {
		o := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": api, "kind": kind, "metadata": map[string]interface{}{"name": name, "namespace": "ns", "uid": uid}}}
		o.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: ownerAPI, Kind: ownerKind, Name: ownerName, UID: types.UID(ownerUID), Controller: &controller}})
		return o
	}
	b, _ := dyn.Resource(kvtypes.BackupResource).Namespace("ns").Get(context.Background(), s.Native.Objects[1].Name, metav1.GetOptions{})
	ex := obj("export.kubevirt.io/v1beta1", "VirtualMachineExport", "export-original", "export-uid", "VirtualMachineBackup", b.GetName(), string(b.GetUID()), "backup.kubevirt.io/v1alpha1")
	ex.Object["spec"] = map[string]interface{}{"source": map[string]interface{}{"apiGroup": "backup.kubevirt.io", "kind": "VirtualMachineBackup", "name": b.GetName()}, "tokenSecretRef": s.Native.Objects[2].Name}
	ex.SetCreationTimestamp(b.GetCreationTimestamp())
	_ = unstructured.SetNestedField(ex.Object, s.Native.BackupTTL().String(), "spec", "ttlDuration")
	volumes, links, status := []interface{}{}, []interface{}{}, []interface{}{}
	for i, v := range s.Request.Plan.Source.NativeDisks() {
		data, mapURL := source.URL+"/exports/"+v.Name+"/data", source.URL+"/exports/"+v.Name+"/map"
		target := fmt.Sprintf("vd%c", 'a'+i)
		volumes = append(volumes, map[string]interface{}{"volumeName": v.Name, "diskTarget": target, "dataEndpoint": data, "mapEndpoint": mapURL})
		links = append(links, map[string]interface{}{"name": v.Name, "endpoints": []interface{}{map[string]interface{}{"endpoint": "data", "url": data}, map[string]interface{}{"endpoint": "map", "url": mapURL}}})
		status = append(status, map[string]interface{}{"name": v.Name, "target": target})
	}
	_ = unstructured.SetNestedSlice(b.Object, volumes, "status", "includedVolumes")
	_ = unstructured.SetNestedField(b.Object, ca, "status", "endpointCert")
	_ = unstructured.SetNestedField(b.Object, "expected-child", "status", "checkpointName")
	_ = unstructured.SetNestedSlice(b.Object, []interface{}{
		map[string]interface{}{"type": "Progressing", "status": "True"},
		map[string]interface{}{"type": "Done", "status": "False"},
		map[string]interface{}{"type": "ExportInitiated", "status": "True"},
		map[string]interface{}{"type": "ExportReady", "status": "True"},
	}, "status", "conditions")
	_ = dyn.Tracker().Update(kvtypes.BackupResource, b, "ns")
	ex.Object["status"] = map[string]interface{}{"phase": "Ready", "serviceName": "service-original", "links": map[string]interface{}{"internal": map[string]interface{}{"cert": ca, "backups": links}}}
	service := obj("v1", "Service", "service-original", "service-uid", "VirtualMachineExport", ex.GetName(), "export-uid", "export.kubevirt.io/v1")
	service.Object["spec"] = map[string]interface{}{"type": "ClusterIP", "clusterIP": "10.0.0.1", "ports": []interface{}{map[string]interface{}{"name": "export", "protocol": "TCP", "port": int64(443), "targetPort": int64(8443)}}}
	_ = unstructured.SetNestedStringMap(service.Object, map[string]string{"routing": "fixture"}, "spec", "selector")
	pod := obj("v1", "Pod", "pod-original", "pod-uid", "VirtualMachineExport", ex.GetName(), "export-uid", "export.kubevirt.io/v1")
	pod.Object["spec"] = map[string]interface{}{"containers": []interface{}{map[string]interface{}{"name": "exporter", "env": []interface{}{map[string]interface{}{"name": "DEADLINE", "value": b.GetCreationTimestamp().Add(s.Native.BackupTTL()).UTC().Format(time.RFC3339Nano)}}}}}
	pod.Object["status"] = map[string]interface{}{"phase": "Running", "podIPs": []interface{}{map[string]interface{}{"ip": "10.0.0.2"}}}
	pod.SetLabels(map[string]string{"routing": "fixture"})
	_ = unstructured.SetNestedSlice(pod.Object, []interface{}{map[string]interface{}{"type": "Ready", "status": "True"}}, "status", "conditions")
	slice := obj("discovery.k8s.io/v1", "EndpointSlice", "slice-original", "slice-uid", "Service", service.GetName(), "service-uid", "v1")
	slice.Object["addressType"] = "IPv4"
	slice.Object["ports"] = []interface{}{map[string]interface{}{"name": "export", "protocol": "TCP", "port": int64(8443)}}
	slice.Object["endpoints"] = []interface{}{map[string]interface{}{"addresses": []interface{}{"10.0.0.2"}, "conditions": map[string]interface{}{"ready": true}, "targetRef": map[string]interface{}{"kind": "Pod", "name": pod.GetName(), "namespace": "ns", "uid": "pod-uid"}}}
	for _, o := range []*unstructured.Unstructured{ex, service, pod, slice} {
		if err := dyn.Tracker().Add(o); err != nil {
			t.Fatal(err)
		}
	}
	// Fake dynamic clients need list kinds registered for dynamically added GVRs.
	dyn.PrependReactor("list", "*", func(a k8stest.Action) (bool, runtime.Object, error) {
		var kind string
		switch a.GetResource() {
		case kvtypes.ExportResource:
			kind = "VirtualMachineExport"
		case exportPodResource:
			kind = "Pod"
		case exportSliceResource:
			kind = "EndpointSlice"
		default:
			return false, nil, nil
		}
		v, err := dyn.Tracker().List(a.GetResource(), schema.GroupVersionKind{Group: a.GetResource().Group, Version: a.GetResource().Version, Kind: kind}, "ns")
		return true, v, err
	})
	vmi, _ := dyn.Resource(kvtypes.VMIResource).Namespace("ns").Get(context.Background(), s.Request.Plan.VMName, metav1.GetOptions{})
	_ = unstructured.SetNestedSlice(vmi.Object, status, "status", "volumeStatus")
	_ = dyn.Tracker().Update(kvtypes.VMIResource, vmi, "ns")
	secret, _ := dyn.Resource(coreV1Secret).Namespace("ns").Get(context.Background(), s.Native.Objects[2].Name, metav1.GetOptions{})
	secret.Object["data"] = map[string]interface{}{"token": base64.StdEncoding.EncodeToString([]byte("native-token-fixture-of-at-least-32-bytes"))}
	_ = dyn.Tracker().Update(coreV1Secret, secret, "ns")
	f.backend = &http.Client{Transport: exportTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-Agent-Key") != "registered-agent-fixture" {
			t.Fatal("agent authentication")
		}
		data, _ := io.ReadAll(r.Body)
		d := f.disk(t)
		if d.Export == nil {
			t.Fatal("authority before export journal")
		}
		if strings.HasSuffix(r.URL.Path, "transaction-key") {
			f.calls = append(f.calls, "key")
			var dek any
			if encrypted {
				dek = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{91}, 32))
			}
			return exportResponse(map[string]any{"reservation_id": s.Request.ReservationID, "attempt_id": s.Request.Plan.AttemptID, "plan_sha256": s.Request.PlanSHA256, "key_ref": s.Request.Plan.Encryption.KeyRef, "format": s.Request.Plan.Encryption.Format, "dek": dek}), nil
		}
		if strings.HasSuffix(r.URL.Path, "prepared-receipt") {
			f.calls = append(f.calls, "receipt")
			if d.Phase != "submitting" || d.Receipt == nil {
				t.Fatal("receipt before durable phase")
			}
			if f.receipt != nil && !bytes.Equal(f.receipt, data) {
				t.Fatal("receipt changed on replay")
			}
			f.receipt = append([]byte{}, data...)
			_, hash, err := models.CanonicalReceipt(&s.Request, *d.Receipt)
			if err != nil {
				t.Fatal(err)
			}
			ack := models.StorageAcceptance{Protocol: models.StorageProtocol, ReservationID: s.Request.ReservationID, ReceiptSHA256: hash, Accepted: true, AcceptanceID: "durable-acceptance", ScrubRequired: true, Verification: []models.StorageVerification{}}
			for _, o := range d.Receipt.Objects {
				reason := "provider_full_object_sha256_unavailable"
				ack.Verification = append(ack.Verification, models.StorageVerification{Key: o.Key, VersionID: o.VersionID, Assurance: "identity_metadata_only", Reason: &reason})
			}
			if f.lost {
				f.lost = false
				return nil, errors.New("lost acceptance response")
			}
			if f.corruptAck {
				ack.ReceiptSHA256 = strings.Repeat("0", 64)
			}
			return exportResponse(ack), nil
		}
		var c struct {
			Schema      int
			Binding     map[string]any
			ArtifactKey string `json:"artifact_key"`
			Operation   string
			Args        map[string]any
		}
		if json.Unmarshal(data, &c) != nil || c.Binding["plan_sha256"] != s.Request.PlanSHA256 {
			t.Fatal("control binding")
		}
		f.calls = append(f.calls, c.Operation)
		if f.failControl == c.Operation && c.Operation != "create" && c.Operation != "complete" && (!f.payloadControlOnly || strings.HasSuffix(c.ArtifactKey, "/volume_payload")) {
			return nil, errors.New("uncertain control response")
		}
		if f.before != nil {
			f.before(c.Operation)
		}
		if len(d.Maps) != count {
			t.Fatal("provider before durable maps")
		}
		var artifact *models.StorageArtifact
		for i := range s.Request.Plan.Artifacts {
			if s.Request.Plan.Artifacts[i].Key == c.ArtifactKey {
				artifact = &s.Request.Plan.Artifacts[i]
			}
		}
		if artifact == nil {
			t.Fatal("unplanned key")
		}
		switch c.Operation {
		case "create":
			if _, exists := f.data[c.ArtifactKey]; exists {
				t.Fatal("second logical upload")
			}
			f.data[c.ArtifactKey] = []byte{}
			if f.failControl == "create" {
				return nil, errors.New("lost create acknowledgment")
			}
			return exportResponse(map[string]any{"schema": 1, "upload_id": "upload-" + nativeHash([]byte(c.ArtifactKey))}), nil
		case "part":
			now := time.Now().UTC().Truncate(time.Second)
			hash := c.Args["sha256"].(string)
			raw, _ := hex.DecodeString(hash)
			number := int(c.Args["number"].(float64))
			size := int(c.Args["bytes"].(float64))
			q := url.Values{"uploadId": {c.Args["upload_id"].(string)}, "partNumber": {strconv.Itoa(number)}, "X-Amz-Algorithm": {"AWS4-HMAC-SHA256"}, "X-Amz-Credential": {"EXAMPLE/" + now.Format("20060102") + "/" + s.Request.Plan.Target.Region + "/s3/aws4_request"}, "X-Amz-Date": {now.Format("20060102T150405Z")}, "X-Amz-Expires": {"60"}, "X-Amz-SignedHeaders": {"content-length;host;x-amz-checksum-sha256;x-amz-content-sha256"}, "X-Amz-Signature": {strings.Repeat("a", 64)}}
			return exportResponse(map[string]any{"schema": 1, "authority": map[string]any{"method": "PUT", "url": s.Request.Plan.Target.Endpoint + "/" + s.Request.Plan.Target.Bucket + "/" + c.ArtifactKey + "?" + q.Encode(), "headers": map[string]string{"content-length": strconv.Itoa(size), "x-amz-checksum-sha256": base64.StdEncoding.EncodeToString(raw), "x-amz-content-sha256": hash}, "expires_at": now.Unix() + 60}}), nil
		case "part_ack":
			return exportResponse(map[string]any{"schema": 1, "acknowledged": true}), nil
		case "complete":
			info := storageupload.ObjectInfo{ETag: "opaque-object", Bytes: int64(len(f.data[c.ArtifactKey])), Metadata: map[string]string{"vnbui-protocol": "1", "vnbui-org-id": s.Request.OrgID, "vnbui-backup-id": s.Request.BackupID, "vnbui-reservation-id": s.Request.ReservationID, "vnbui-plan-sha256": s.Request.PlanSHA256, "vnbui-artifact-id": nativeHash([]byte(artifact.VolumeID + ":" + artifact.Role))}}
			if f.versioned {
				version := "immutable-" + nativeHash([]byte(c.ArtifactKey))
				info.VersionID = &version
			}
			info.ETag = strconv.Quote(info.ETag)
			f.info[c.ArtifactKey] = info
			if f.failControl == "complete" {
				return nil, errors.New("lost complete acknowledgment")
			}
			return exportResponse(map[string]any{"schema": 1, "object": info}), nil
		case "head":
			return exportResponse(map[string]any{"schema": 1, "object": f.info[c.ArtifactKey]}), nil
		default:
			t.Fatal("unexpected control")
		}
		return nil, errors.New("control")
	})}
	f.provider = &http.Client{Transport: exportTransport(func(r *http.Request) (*http.Response, error) {
		f.calls = append(f.calls, "upload")
		data, _ := io.ReadAll(r.Body)
		key := strings.TrimPrefix(r.URL.Path, "/"+s.Request.Plan.Target.Bucket+"/")
		if r.Method != "PUT" || r.Header.Get("X-Agent-Key") != "" || nativeHash(data) != r.Header.Get("X-Amz-Content-Sha256") {
			t.Fatal("signed payload identity")
		}
		f.data[key] = append(f.data[key], data...)
		return &http.Response{StatusCode: 200, Header: http.Header{"Etag": {strconv.Quote("part-" + r.URL.Query().Get("partNumber"))}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	return f
}
func (f *exportFixture) run() (*models.StorageAcceptance, error) {
	return f.e.AcceptStorageTransaction(context.Background(), f.body, f.backend, f.provider, func(context.Context) (string, error) { return "registered-agent-fixture", nil })
}

func TestHCOFilesystemPVCMapUsesGuestVisibleVirtualSize(t *testing.T) {
	const pvcBytes, guestBytes = uint64(128 << 20), uint64(120 << 20)
	client := &http.Client{Transport: exportTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("offset") != "0" || r.URL.Query().Get("page_size") != "512" {
			t.Fatal("unexpected map request")
		}
		return exportResponse(map[string]any{"extents": []any{map[string]any{"offset": 0, "length": guestBytes, "type": 0, "description": "data"}}, "next_offset": nil}), nil
	})}
	reader := &transactionExport{ctx: context.Background(), client: client, token: "fixture-token", validate: func() error { return nil }}
	got, _, err := reader.extents(storageupload.ExportVolume{VolumeID: "pvc-uid", MapURL: "https://export.example/exports/data/map"}, pvcBytes, "full", 10)
	if err != nil || got.VirtualSize != guestBytes || len(got.Ranges) != 1 || got.Ranges[0].Length != guestBytes {
		t.Fatalf("filesystem overhead map refused or mis-sized: %+v %v", got, err)
	}
}

func TestExportReadDeadlineExcludesSlowUploadBetweenReads(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Length", "2")
		_, _ = w.Write([]byte("a"))
		w.(http.Flusher).Flush()
		select {
		case <-release:
			_, _ = w.Write([]byte("b"))
		case <-request.Context().Done():
		}
	}))
	defer server.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	reader := &transactionExport{ctx: context.Background(), client: server.Client(), token: "fixture-token", validate: func() error { return nil }}
	body, err := reader.getWithTimeout(server.URL+"/exports/data/data", nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	first := make([]byte, 1)
	if _, err := io.ReadFull(body, first); err != nil || string(first) != "a" {
		t.Fatalf("first read: %q, %v", first, err)
	}
	// The consumer may spend longer than a read deadline uploading the first
	// chunk. No export read is active during that interval.
	time.Sleep(1100 * time.Millisecond)
	close(release)
	second := make([]byte, 1)
	if _, err := io.ReadFull(body, second); err != nil || string(second) != "b" {
		t.Fatalf("read after slow upload: %q, %v", second, err)
	}
}

func TestExportReadDeadlineCancelsStalledBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Length", "2")
		_, _ = w.Write([]byte("a"))
		w.(http.Flusher).Flush()
		<-request.Context().Done()
	}))
	defer server.Close()
	reader := &transactionExport{ctx: context.Background(), client: server.Client(), token: "fixture-token", validate: func() error { return nil }}
	body, err := reader.getWithTimeout(server.URL+"/exports/data/data", nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	first := make([]byte, 1)
	if _, err := io.ReadFull(body, first); err != nil || string(first) != "a" {
		t.Fatalf("first read: %q, %v", first, err)
	}
	started := time.Now()
	_, err = io.ReadFull(body, make([]byte, 1))
	if err == nil || time.Since(started) > 3*time.Second {
		t.Fatalf("stalled body was not promptly canceled: %v", err)
	}
}

func verifyAcceptedInSeparateProcess(t *testing.T, f *exportFixture) {
	t.Helper()
	request := filepath.Join(t.TempDir(), "request.json")
	if os.WriteFile(request, f.body, 0600) != nil {
		t.Fatal("request fixture")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestProductionAcceptedJournalProcessReopen$", "-test.timeout=15s")
	cmd.Env = append(os.Environ(), "D04_REOPEN_REQUEST="+request, "D04_REOPEN_ROOT="+filepath.Join(filepath.Dir(f.e.cfg.KeyFilePath), "storage-transactions"))
	if result, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("separate process reopen failed: %v (%d output bytes)", err, len(result))
	}
}
func TestProductionAcceptedJournalProcessReopen(t *testing.T) {
	path := os.Getenv("D04_REOPEN_REQUEST")
	if path == "" {
		return
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	j, err := storageupload.Open(os.Getenv("D04_REOPEN_ROOT"), body)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	client := &http.Client{Transport: exportTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("accepted process replay performed HTTP")
		return nil, storageupload.ErrHeld
	})}
	a, err := j.Submit(context.Background(), "https://backend.example", client, func(context.Context) (string, error) {
		t.Fatal("accepted process replay resolved credential")
		return "", storageupload.ErrHeld
	})
	if err != nil || a == nil || a.AcceptanceID != "durable-acceptance" {
		t.Fatal("process lost accepted receipt")
	}
}

func TestProductionExportAcceptedReceiptReopenNoSecondIO(t *testing.T) {
	for _, incremental := range []bool{false, true} {
		for _, encrypted := range []bool{false, true} {
			t.Run(fmt.Sprintf("incremental=%t/encrypted=%t", incremental, encrypted), func(t *testing.T) {
				f := readyExportFixture(t, incremental, encrypted, 1048576)
				f.lost = true
				if a, err := f.run(); err == nil || a != nil {
					t.Fatal("lost response became acceptance")
				}
				d := f.disk(t)
				if d.Phase != "submitting" || len(d.Receipt.Objects) != 4 || d.Acceptance != nil {
					t.Fatalf("partial receipt authority: phase=%s export=%t maps=%d calls=%v", d.Phase, d.Export != nil, len(d.Maps), f.calls)
				}
				for _, o := range d.Receipt.Objects {
					if o.CiphertextSHA256 != nativeHash(f.data[o.Key]) || o.CiphertextBytes != int64(len(f.data[o.Key])) {
						t.Fatal("stored identity")
					}
				}
				calls, streams := len(f.calls), f.streams
				a, err := f.run()
				if err != nil || a == nil {
					t.Fatal("reopen acceptance", err)
				}
				if f.streams != streams || !reflect.DeepEqual(f.calls[calls:], []string{"receipt"}) {
					t.Fatal("acceptance replay repeated source/provider/key IO")
				}
				if f.disk(t).Phase != "accepted" {
					t.Fatal("acceptance not durable")
				}
				if !incremental && !encrypted {
					verifyAcceptedInSeparateProcess(t, f)
				}
				calls = len(f.calls)
				b, err := f.run()
				if err != nil || !reflect.DeepEqual(a, b) || len(f.calls) != calls || f.streams != streams {
					t.Fatal("accepted replay repeated IO")
				}
				for _, action := range f.e.dynamic.(interface{ Actions() []k8stest.Action }).Actions() {
					if action.GetVerb() == "delete" || action.GetVerb() == "patch" {
						t.Fatal("finalization or cleanup before package boundary")
					}
				}
			})
		}
	}
}

func TestProductionExportBoundaryAndZeroStreams(t *testing.T) {
	for _, size := range []int{1, 8 << 20, (8 << 20) + 1} {
		for _, encrypted := range []bool{false, true} {
			for _, zero := range []bool{false, true} {
				t.Run(fmt.Sprintf("bytes=%d/encrypted=%t/zero=%t", size, encrypted, zero), func(t *testing.T) {
					f := readyExportFixture(t, true, encrypted, size)
					if zero {
						f.sourceFault = "zero"
					}
					a, err := f.run()
					if err != nil || a == nil {
						t.Fatal("acceptance", err)
					}
					d := f.disk(t)
					for _, o := range d.Receipt.Objects {
						if o.Role == "volume_payload" {
							want := int64(size)
							if zero {
								want = 0
							}
							if o.PlaintextBytes != want {
								t.Fatal("plaintext count")
							}
							if !zero && o.PlaintextSHA256 != nativeHash(bytes.Repeat([]byte{7}, size)) {
								t.Fatal("single-pass source hash")
							}
							if o.CiphertextSHA256 != nativeHash(f.data[o.Key]) {
								t.Fatal("ciphertext hash")
							}
						}
					}
					if zero {
						for _, call := range f.calls {
							if strings.HasSuffix(call, "/data") {
								t.Fatal("zero extent body read")
							}
						}
					}
				})
			}
		}
	}
}

func TestProductionFullExportCombinedHoleZero(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%t", encrypted), func(t *testing.T) {
			f := readyExportFixtureVolumes(t, false, encrypted, 64, 1)
			f.sourceFault = "hole-zero"
			accepted, err := f.run()
			if err != nil || accepted == nil {
				t.Fatalf("full sparse acceptance: %v", err)
			}
			d := f.disk(t)
			if len(d.Maps) != 1 || d.Maps[0].VirtualSize != 64 || len(d.Maps[0].Ranges) != 2 || d.Maps[0].Ranges[1].Offset != 48 {
				t.Fatalf("sparse full map: %#v", d.Maps)
			}
			for _, o := range d.Receipt.Objects {
				if o.Role == "volume_payload" && (o.PlaintextBytes != 32 || o.PlaintextSHA256 != nativeHash(bytes.Repeat([]byte{7}, 32))) {
					t.Fatalf("sparse payload receipt: bytes=%d sha=%s", o.PlaintextBytes, o.PlaintextSHA256)
				}
			}
		})
	}
}

func TestProductionExportExactOneAndThreeVolumeMembership(t *testing.T) {
	for _, count := range []int{1, 3} {
		for _, incremental := range []bool{false, true} {
			t.Run(fmt.Sprintf("volumes=%d/incremental=%t", count, incremental), func(t *testing.T) {
				f := readyExportFixtureVolumes(t, incremental, true, 1048576, count)
				a, err := f.run()
				if err != nil || a == nil {
					t.Fatal(err)
				}
				d := f.disk(t)
				if len(d.Receipt.Objects) != 2*count || len(d.Maps) != count || len(d.Export.Volumes) != count || f.streams != 2*count {
					t.Fatal("partial or extra membership")
				}
			})
		}
	}
}

func mutateExportObject(t *testing.T, f *exportFixture, resource schema.GroupVersionResource, name string, change func(*unstructured.Unstructured)) {
	t.Helper()
	ctx := context.Background()
	o, err := f.e.dynamic.Resource(resource).Namespace("ns").Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	change(o)
	tracker := f.e.dynamic.(interface{ Tracker() k8stest.ObjectTracker }).Tracker()
	if err = tracker.Update(resource, o, "ns"); err != nil {
		t.Fatal(err)
	}
}
func bindExportFixture(t *testing.T, f *exportFixture) {
	t.Helper()
	j, err := f.e.PrepareStorageTransaction(context.Background(), f.body)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	s, err := j.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	x, err := f.e.inspectExport(context.Background(), &s)
	if err != nil {
		t.Fatal(err)
	}
	if j.BindExport(*x) != nil {
		t.Fatal("bind")
	}
}
func TestProductionExportOriginalAttributionRefusals(t *testing.T) {
	for _, kind := range []string{"export", "service", "pod", "slice", "vm", "vmi", "pvc", "vmb", "tracker"} {
		for _, mode := range []string{"replacement", "owner"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				f := readyExportFixture(t, true, false, 1048576)
				bindExportFixture(t, f)
				resource, name := kvtypes.ExportResource, "export-original"
				switch kind {
				case "service":
					resource, name = exportServiceResource, "service-original"
				case "pod":
					resource, name = exportPodResource, "pod-original"
				case "slice":
					resource, name = exportSliceResource, "slice-original"
				case "vm":
					resource, name = kvtypes.VMResource, f.state.Request.Plan.VMName
				case "vmi":
					resource, name = kvtypes.VMIResource, f.state.Request.Plan.VMName
				case "pvc":
					resource, name = pvcResource, "data-two"
				case "vmb":
					resource, name = kvtypes.BackupResource, f.state.Native.Objects[1].Name
				case "tracker":
					resource, name = kvtypes.BackupTrackerResource, f.state.Native.Objects[0].Name
				}
				// VM/PVC authority is direct UID binding, not a controller owner claim.
				mutateExportObject(t, f, resource, name, func(o *unstructured.Unstructured) {
					if mode == "replacement" || kind == "vm" || kind == "pvc" || kind == "tracker" {
						o.SetUID("foreign-replacement")
					} else {
						o.SetOwnerReferences(nil)
					}
				})
				if a, err := f.run(); err == nil || a != nil {
					t.Fatal("foreign authority accepted")
				}
				if len(f.calls) != 0 || f.streams != 0 {
					t.Fatal("effect before refusal")
				}
			})
		}
	}
	for _, mode := range []string{"missing-volume", "duplicate-volume", "extra-volume", "wrong-target", "changed-map", "bad-ca", "credential-url", "endpoint-target", "endpoint-owner", "ambiguous-pod", "changed-checkpoint", "token-replacement", "selector-drift", "pod-not-ready", "address-family", "duplicate-condition", "malformed-condition"} {
		t.Run(mode, func(t *testing.T) {
			f := readyExportFixture(t, false, false, 1048576)
			bindExportFixture(t, f)
			switch mode {
			case "duplicate-condition", "malformed-condition":
				mutateExportObject(t, f, kvtypes.BackupResource, f.state.Native.Objects[1].Name, func(o *unstructured.Unstructured) {
					conditions, _, _ := unstructured.NestedSlice(o.Object, "status", "conditions")
					if mode == "duplicate-condition" {
						conditions = append(conditions, conditions[0])
					} else {
						conditions = append(conditions, "malformed")
					}
					_ = unstructured.SetNestedSlice(o.Object, conditions, "status", "conditions")
				})
			case "selector-drift":
				mutateExportObject(t, f, exportServiceResource, "service-original", func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedStringMap(o.Object, map[string]string{"routing": "foreign"}, "spec", "selector")
				})
			case "pod-not-ready":
				mutateExportObject(t, f, exportPodResource, "pod-original", func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedSlice(o.Object, []interface{}{map[string]interface{}{"type": "Ready", "status": "False"}}, "status", "conditions")
				})
			case "address-family":
				mutateExportObject(t, f, exportSliceResource, "slice-original", func(o *unstructured.Unstructured) { o.Object["addressType"] = "IPv6" })
			case "endpoint-target", "endpoint-owner":
				mutateExportObject(t, f, exportSliceResource, "slice-original", func(o *unstructured.Unstructured) {
					if mode == "endpoint-owner" {
						o.SetOwnerReferences(nil)
					} else {
						items, _, _ := unstructured.NestedSlice(o.Object, "endpoints")
						items[0].(map[string]interface{})["targetRef"].(map[string]interface{})["uid"] = "foreign"
						o.Object["endpoints"] = items
					}
				})
			case "ambiguous-pod":
				o, _ := f.e.dynamic.Resource(exportPodResource).Namespace("ns").Get(context.Background(), "pod-original", metav1.GetOptions{})
				o.SetName("extra-pod")
				o.SetUID("extra-pod-uid")
				if f.e.dynamic.(interface{ Tracker() k8stest.ObjectTracker }).Tracker().Add(o) != nil {
					t.Fatal("fixture")
				}
			case "token-replacement":
				mutateExportObject(t, f, coreV1Secret, f.state.Native.Objects[2].Name, func(o *unstructured.Unstructured) { o.SetUID("replacement") })
			default:
				mutateExportObject(t, f, kvtypes.BackupResource, f.state.Native.Objects[1].Name, func(o *unstructured.Unstructured) {
					items, _, _ := unstructured.NestedSlice(o.Object, "status", "includedVolumes")
					switch mode {
					case "missing-volume":
						items = items[:1]
					case "duplicate-volume":
						items[1] = items[0]
					case "extra-volume":
						items = append(items, items[0])
					case "wrong-target":
						items[0].(map[string]interface{})["diskTarget"] = "other"
					case "changed-map":
						items[0].(map[string]interface{})["mapEndpoint"] = "https://other.example/map"
					case "bad-ca":
						_ = unstructured.SetNestedField(o.Object, "invalid", "status", "endpointCert")
					case "credential-url":
						items[0].(map[string]interface{})["dataEndpoint"] = "https://user:secret@example/data"
					case "changed-checkpoint":
						_ = unstructured.SetNestedField(o.Object, "incidental", "status", "checkpointName")
					}
					_ = unstructured.SetNestedSlice(o.Object, items, "status", "includedVolumes")
				})
			}
			if a, err := f.run(); err == nil || a != nil {
				t.Fatal("invalid attribution admitted")
			}
			if len(f.calls) != 0 || f.streams != 0 {
				t.Fatal("effects before refusal")
			}
		})
	}
}

func TestProductionIncrementalRefusesFullAllocationMap(t *testing.T) {
	f := readyExportFixture(t, true, false, 64)
	f.sourceFault = "allocation-data"
	if accepted, err := f.run(); err == nil || accepted != nil {
		t.Fatal("full allocation response supplied incremental cleanliness")
	}
	if f.receipt != nil || len(f.data) != 0 || len(f.disk(t).Maps) != 0 {
		t.Fatal("invalid incremental map reached payload or receipt custody")
	}
	for _, call := range f.calls {
		if call == "create" || call == "upload" || call == "receipt" {
			t.Fatal("invalid map caused provider mutation or receipt submission", call)
		}
	}
}

func TestProductionExportStreamAndUncertainRefusals(t *testing.T) {
	for _, fault := range []string{"missing", "oversized", "redirect", "truncated", "extra"} {
		t.Run(fault, func(t *testing.T) {
			f := readyExportFixture(t, false, false, 1048576)
			f.sourceFault = fault
			if a, err := f.run(); err == nil || a != nil {
				t.Fatal("invalid stream accepted")
			}
			if f.receipt != nil {
				t.Fatal("incomplete receipt submitted")
			}
			for _, call := range f.calls {
				if (fault == "missing" || fault == "oversized" || fault == "redirect") && call == "create" {
					t.Fatal("provider mutation before valid maps")
				}
			}
		})
	}
	for _, operation := range []string{"create", "part", "complete", "head"} {
		t.Run("lost-"+operation, func(t *testing.T) {
			f := readyExportFixture(t, false, false, 1048576)
			f.failControl = operation
			if a, err := f.run(); err == nil || a != nil {
				t.Fatal("uncertainty accepted")
			}
			d := f.disk(t)
			if d.Phase != "held" || f.receipt != nil {
				t.Fatal("uncertainty custody")
			}
			calls, streams := len(f.calls), f.streams
			f.failControl = ""
			if a, err := f.run(); err == nil || a != nil || len(f.calls) != calls || f.streams != streams {
				t.Fatal("uncertain attempt blindly retried")
			}
		})
	}
	for _, boundary := range []string{"source", "head", "token-after-head"} {
		t.Run("drift-at-"+boundary, func(t *testing.T) {
			f := readyExportFixture(t, true, false, 1048576)
			changed := false
			f.before = func(op string) {
				if (op == boundary || (boundary == "token-after-head" && op == "head")) && !changed {
					changed = true
					resource, name := pvcResource, "data-two"
					if boundary == "token-after-head" {
						resource, name = coreV1Secret, f.state.Native.Objects[2].Name
					}
					mutateExportObject(t, f, resource, name, func(o *unstructured.Unstructured) { o.SetUID("replacement") })
				}
			}
			if a, err := f.run(); err == nil || a != nil {
				t.Fatal("drift accepted")
			}
			if f.receipt != nil {
				t.Fatal("drift published receipt")
			}
		})
	}
	t.Run("conflicting-acceptance", func(t *testing.T) {
		f := readyExportFixture(t, false, false, 1048576)
		f.corruptAck = true
		if a, err := f.run(); err == nil || a != nil {
			t.Fatal("conflict accepted")
		}
		calls, streams := len(f.calls), f.streams
		if f.disk(t).Phase != "submitting" {
			t.Fatal("lost receipt custody")
		}
		f.corruptAck = false
		if a, err := f.run(); err != nil || a == nil || f.streams != streams || !reflect.DeepEqual(f.calls[calls:], []string{"receipt"}) {
			t.Fatal("conflict retry reread")
		}
	})
}
