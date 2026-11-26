package libvirt

import (
	"errors"
	"fmt"
	"math"
	"testing"
)

func TestDiskCapacityUnknownAndLookupBudget(t *testing.T) {
	disks := []map[string]interface{}{{"target": "valid"}, {"target": "error"}, {"target": "zero"}, {"target": "overflow"}, {"target": ""}}
	for i := 0; i < maxDiskCapacityLookups; i++ {
		disks = append(disks, map[string]interface{}{"target": fmt.Sprint(i)})
	}
	calls := 0
	attachDiskCapacities(disks, func(target string) (uint64, error) {
		calls++
		switch target {
		case "error":
			return 0, errors.New("unavailable")
		case "zero":
			return 0, nil
		case "overflow":
			return math.MaxUint64, nil
		default:
			return 1024, nil
		}
	})
	if calls != maxDiskCapacityLookups {
		t.Fatalf("lookup budget: %d", calls)
	}
	if disks[0]["capacity_bytes"] != int64(1024) || disks[0]["capacity_source"] != "libvirt.domain.blockInfo.capacity" {
		t.Fatalf("capacity: %+v", disks[0])
	}
	for _, i := range []int{1, 2, 3, 4, len(disks) - 1} {
		if disks[i]["capacity_bytes"] != nil {
			t.Fatalf("unknown capacity: %+v", disks[i])
		}
	}
}
