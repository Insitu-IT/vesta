package kubevirt

import (
	"math"
	"math/big"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"
)

// parseMemoryToKB converts bytes to KiB, rounding positive fractions up.
// Zero represents unavailable memory internally; inventory exposes it as null.
func parseMemoryToKB(s string) int64 {
	q, err := resource.ParseQuantity(strings.TrimSpace(s))
	if err != nil || q.Sign() <= 0 {
		return 0
	}
	bytes, ok := new(big.Rat).SetString(q.AsDec().String())
	if !ok || bytes.Cmp(new(big.Rat).SetInt64(math.MaxInt64)) >= 0 {
		// Kubernetes can saturate oversized binary quantities at MaxInt64.
		return 0
	}
	kib := new(big.Rat).Quo(bytes, big.NewRat(1024, 1))
	value, remainder := new(big.Int), new(big.Int)
	value.QuoRem(kib.Num(), kib.Denom(), remainder)
	if remainder.Sign() > 0 {
		value.Add(value, big.NewInt(1))
	}
	if !value.IsInt64() {
		return 0
	}
	return value.Int64()
}

// mapPhaseToState converts KubeVirt VMI phase to vnbui VM state.
func mapPhaseToState(phase string) string {
	switch strings.ToLower(phase) {
	case "running":
		return "running"
	case "scheduling", "scheduled", "pending":
		return "pending"
	case "succeeded", "failed":
		return "shutoff"
	case "paused":
		return "paused"
	default:
		return "unknown"
	}
}

// phaseToEventType maps KubeVirt VMI phase to provider event type string.
// Returns empty string for phases that should not generate events.
func phaseToEventType(phase string) string {
	switch strings.ToLower(phase) {
	case "running":
		return "vm_started"
	case "succeeded", "failed":
		return "vm_stopped"
	case "paused":
		return "vm_paused"
	default:
		return ""
	}
}
