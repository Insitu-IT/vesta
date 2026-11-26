//go:build kubevirt

package kubevirt

import (
	"math"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/operationbudget"
)

// Native COW scratch covers every controller participant, including disks
// excluded from upload. Transfer estimates continue to use selectedBytes.
func nativeBytes(r *models.StorageTransactionRequest) (int64, error) {
	var total int64
	for _, v := range r.Plan.Source.NativeDisks() {
		if v.CapacityBytes <= 0 || total > math.MaxInt64-v.CapacityBytes {
			return 0, operationbudget.ErrEstimate
		}
		total += v.CapacityBytes
	}
	if total == 0 {
		return 0, operationbudget.ErrEstimate
	}
	return total, nil
}
