//go:build kubevirt

package kubevirt

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"vnbui/agent/internal/storageupload"
)

func fragmentedMapReader(t *testing.T, count int, description func(int) string) (*transactionExport, *int) {
	t.Helper()
	calls := 0
	client := &http.Client{Transport: exportTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		start, end := offset/4096, min(offset/4096+512, count)
		page := mapPage{Extents: []mapExtent{}}
		for i := start; i < end; i++ {
			page.Extents = append(page.Extents, mapExtent{Offset: uint64(i * 4096), Length: 4096, Description: description(i)})
		}
		if end < count {
			n := uint64(end * 4096)
			page.NextOffset = &n
		}
		data, _ := json.Marshal(page)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: http.Header{}}, nil
	})}
	return &transactionExport{ctx: context.Background(), client: client, validate: func() error { return nil }}, &calls
}

func TestMapFragmentationCountsStoredRangesAndCoalescesAcrossPages(t *testing.T) {
	x, calls := fragmentedMapReader(t, 18000, func(i int) string {
		if i%2 == 0 {
			return "dirty"
		}
		return "clean"
	})
	v := storageupload.ExportVolume{VolumeID: "disk", MapURL: "https://export.example/map"}
	m, count, err := x.extents(v, 18000*4096, "incremental", 10000)
	if err != nil || count != 9000 || len(m.Ranges) != 9000 || *calls != 36 {
		t.Fatalf("clean ranges consumed durable budget: %d/%d calls=%d err=%v", count, len(m.Ranges), *calls, err)
	}
	x, calls = fragmentedMapReader(t, 18000, func(int) string { return "dirty" })
	m, count, err = x.extents(v, 18000*4096, "incremental", 1)
	if err != nil || count != 1 || m.Ranges[0].Length != 18000*4096 || *calls != 36 {
		t.Fatalf("adjacent pages did not coalesce: %+v %d %v", m, count, err)
	}
}

func TestMapUnrepresentableRangesRefuseWithValidatedCursor(t *testing.T) {
	x, calls := fragmentedMapReader(t, 24000, func(i int) string {
		if i%2 == 0 {
			return "dirty"
		}
		return "clean"
	})
	_, _, err := x.extents(storageupload.ExportVolume{VolumeID: "disk", MapURL: "https://export.example/map"}, 24000*4096, "incremental", 10000)
	f := faultOf(err)
	if err == nil || f.Reason != "map_stored_range_limit" || f.Disposition != "refused" || f.Offset == 0 || f.RawRanges <= 10000 || *calls >= 47 {
		t.Fatalf("unbounded or undiagnosed refusal: %+v calls=%d", f, *calls)
	}
}

func TestMapDirtyZeroAndCleanGapsRemainDistinct(t *testing.T) {
	x, _ := fragmentedMapReader(t, 6, func(i int) string { return []string{"dirty", "dirty,zero", "dirty,zero", "clean", "dirty", "dirty"}[i] })
	m, _, err := x.extents(storageupload.ExportVolume{VolumeID: "disk", MapURL: "https://export.example/map"}, 6*4096, "incremental", 3)
	if err != nil || len(m.Ranges) != 3 || m.Ranges[0].ZeroFill || !m.Ranges[1].ZeroFill || m.Ranges[1].Length != 8192 || m.Ranges[2].Offset != 4*4096 {
		t.Fatalf("TRIM/gap semantics changed: %+v %v", m, err)
	}
}

func TestMapDiagnosticNeverIncludesResponseOrURL(t *testing.T) {
	x := &transactionExport{ctx: context.Background(), validate: func() error { return nil }, client: &http.Client{Transport: exportTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("private-credential-and-body")), Header: http.Header{}}, nil
	})}}
	_, _, err := x.extents(storageupload.ExportVolume{MapURL: "https://export.example/private-path"}, 4096, "full", 10000)
	f := faultOf(err)
	b, _ := json.Marshal(f)
	if f.HTTPStatus != 403 || f.Disposition != "refused" || strings.Contains(string(b), "private") || strings.Contains(string(b), "https") {
		t.Fatalf("unsafe or incomplete fault: %s", b)
	}
}
