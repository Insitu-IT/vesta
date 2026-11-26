package operationbudget

import (
	"encoding/json"
	"math"
	"time"
)

// BundleBytes reads costs from an already validated, receipt-bound bundle.
// Callers must validate chain/receipt/authority before using this estimate.
func BundleBytes(data []byte) (transfer, materialized int64, err error) {
	var bundle struct {
		Members []struct {
			Receipt struct {
				Objects []struct {
					PlaintextBytes  int64 `json:"plaintext_bytes"`
					CiphertextBytes int64 `json:"ciphertext_bytes"`
				} `json:"objects"`
			} `json:"receipt"`
		} `json:"members"`
	}
	if len(data) > 32<<20 || json.Unmarshal(data, &bundle) != nil || len(bundle.Members) == 0 || len(bundle.Members) > 256 {
		return 0, 0, ErrEstimate
	}
	for _, member := range bundle.Members {
		if len(member.Receipt.Objects) == 0 || len(member.Receipt.Objects) > 10000 {
			return 0, 0, ErrEstimate
		}
		for _, object := range member.Receipt.Objects {
			if object.PlaintextBytes < 0 || object.CiphertextBytes < 0 || transfer > math.MaxInt64-object.CiphertextBytes || materialized > math.MaxInt64-object.PlaintextBytes {
				return 0, 0, ErrEstimate
			}
			transfer += object.CiphertextBytes
			materialized += object.PlaintextBytes
		}
	}
	return transfer, materialized, nil
}

func SumBytes(values ...int64) (int64, error) {
	var total int64
	for _, v := range values {
		if v < 0 || total > math.MaxInt64-v {
			return 0, ErrEstimate
		}
		total += v
	}
	return total, nil
}

func (p Policy) Begin(bytes, partBytes int64, ceiling time.Duration, now time.Time) (*Progress, error) {
	b, err := p.Estimate(bytes, partBytes, 0, ceiling)
	if err != nil {
		return nil, err
	}
	return &Progress{StartedAt: now.UTC(), LastProgressAt: now.UTC(), Stage: "queued", Budget: b}, nil
}

// Opaque workers report durable milestones but cannot yet attest intermediate
// byte progress. Do not pretend a repeated Running observation is progress or
// apply a short per-part silence budget to an entire disk reconstruction.
func (p *Progress) WorkerDeadline(now time.Time) (time.Time, string) {
	if p == nil || !p.Valid() {
		return time.Time{}, "operation_budget_missing_or_invalid"
	}
	if now.Before(p.StartedAt) || !now.Before(p.Deadline()) {
		return p.Deadline(), "operation_budget_exhausted"
	}
	if p.Stage == "queued" || p.Stage == "preparing" {
		return p.Deadline(), p.Exhausted(now)
	}
	return p.Deadline(), ""
}
