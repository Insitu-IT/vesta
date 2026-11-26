package libvirt

import "math"

// Limit inventory work without traversing image contents or querying guests.
const maxDiskCapacityLookups = 64

func attachDiskCapacities(disks []map[string]interface{}, read func(string) (uint64, error)) {
	lookups := 0
	for _, disk := range disks {
		disk["capacity_bytes"] = nil
		target, _ := disk["target"].(string)
		if target == "" || lookups >= maxDiskCapacityLookups {
			continue
		}
		lookups++
		capacity, err := read(target)
		if err != nil || capacity == 0 || capacity > math.MaxInt64 {
			continue
		}
		disk["capacity_bytes"] = int64(capacity)
		disk["capacity_source"] = "libvirt.domain.blockInfo.capacity"
	}
}
