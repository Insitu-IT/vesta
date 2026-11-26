//go:build kubevirt

package kubevirt

import (
	"strings"
	"testing"
)

// These tests use the production classifier directly and can also run with
// `go test extent_map.go extent_map_test.go`, without the Kubernetes toolchain.
func TestIncrementalNeverTreatsFullAllocationAsClean(t *testing.T) {
	for _, description := range []string{"data", "hole", "zero", "hole,zero"} {
		t.Run(description, func(t *testing.T) {
			got, err := storedExtents([]mapExtent{{Length: 4096, Description: description}}, "incremental")
			if err == nil || got != nil || !strings.Contains(err.Error(), "unknown incremental") {
				t.Fatalf("full allocation map must not supply incremental cleanliness: %+v, %v", got, err)
			}
		})
	}
}

func TestExtentClassifierRetainsSupportedMapSemantics(t *testing.T) {
	full, err := storedExtents([]mapExtent{{Length: 4, Description: "data"}, {Offset: 4, Length: 4, Description: "hole,zero"}}, "full")
	if err != nil || len(full) != 1 || full[0].PayloadOffset == nil || *full[0].PayloadOffset != 0 || full[0].Length != 4 {
		t.Fatal("full data/allocation semantics changed", full, err)
	}
	inc, err := storedExtents([]mapExtent{{Length: 4, Description: "clean"}, {Offset: 4, Length: 4, Description: "dirty,zero"}, {Offset: 8, Length: 4, Description: "dirty"}}, "incremental")
	if err != nil || len(inc) != 2 || !inc[0].ZeroFill || inc[0].PayloadOffset != nil || inc[1].PayloadOffset == nil || *inc[1].PayloadOffset != 0 {
		t.Fatal("incremental clean/dirty/zero semantics changed", inc, err)
	}
}
