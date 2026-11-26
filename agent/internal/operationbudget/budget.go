// Package operationbudget bounds work from recorded estimates. It grants no
// authority to repeat effects, delete resources or release retained custody.
package operationbudget

import (
	"errors"
	"math"
	"math/big"
	"strconv"
	"time"
)

var (
	ErrEstimate = errors.New("operation estimate or policy is invalid")
	ErrWindow   = errors.New("estimated operation and closure budgets exceed the available window")
)

const maxSeconds = int64(math.MaxInt64 / int64(time.Second))

type Policy struct {
	ObservationCoefficient  float64 `json:"observation_coefficient,omitempty"`
	TimeCoefficient         float64 `json:"time_coefficient"`
	NoProgressCoefficient   float64 `json:"no_progress_coefficient"`
	BootstrapBytesPerSecond int64   `json:"bootstrap_bytes_per_second"`
	PreparationSeconds      int64   `json:"preparation_estimate_seconds"`
	ControlSeconds          int64   `json:"control_estimate_seconds"`
	ScratchCoefficient      float64 `json:"scratch_coefficient"`
}

func DefaultPolicy() Policy {
	return Policy{ObservationCoefficient: 3, TimeCoefficient: 3, NoProgressCoefficient: 3,
		BootstrapBytesPerSecond: 8 << 20, PreparationSeconds: 180,
		ControlSeconds: 60, ScratchCoefficient: 1.2}
}

func coefficient(value, upper float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 1 && value <= upper
}

func (p Policy) Valid() bool {
	return (p.ObservationCoefficient == 0 || coefficient(p.ObservationCoefficient, 100)) && coefficient(p.TimeCoefficient, 100) && coefficient(p.NoProgressCoefficient, 100) &&
		coefficient(p.ScratchCoefficient, 4) && p.BootstrapBytesPerSecond > 0 && p.BootstrapBytesPerSecond <= 1<<40 &&
		p.PreparationSeconds > 0 && p.PreparationSeconds <= 86400 && p.ControlSeconds > 0 && p.ControlSeconds <= 3600
}

type Budget struct {
	ExpectedBytes      int64  `json:"expected_bytes"`
	BytesPerSecond     int64  `json:"bytes_per_second"`
	RateSource         string `json:"rate_source"`
	ExpectedSeconds    int64  `json:"expected_seconds"`
	RunSeconds         int64  `json:"run_seconds"`
	PreparationSeconds int64  `json:"preparation_seconds"`
	SilenceSeconds     int64  `json:"silence_seconds"`
	ClosureSeconds     int64  `json:"closure_seconds"`
}

func scaled(seconds int64, factor float64) (int64, error) {
	value, err := multiplyCeil(seconds, factor)
	if err != nil || value < 1 || value > maxSeconds {
		return 0, ErrEstimate
	}
	return value, nil
}

// Use the configured decimal coefficient without float rounding of byte counts.
// A large capacity rounded down by even one byte is not a valid reservation.
func multiplyCeil(value int64, factor float64) (int64, error) {
	if value < 0 || !coefficient(factor, 100) {
		return 0, ErrEstimate
	}
	f, ok := new(big.Rat).SetString(strconv.FormatFloat(factor, 'f', -1, 64))
	if !ok {
		return 0, ErrEstimate
	}
	f.Mul(f, new(big.Rat).SetInt64(value))
	q, rem := new(big.Int), new(big.Int)
	q.QuoRem(f.Num(), f.Denom(), rem)
	if rem.Sign() != 0 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsInt64() {
		return 0, ErrEstimate
	}
	return q.Int64(), nil
}

func quotient(bytes, rate int64) int64 {
	result := bytes / rate
	if bytes%rate != 0 {
		result++
	}
	return result
}

// Estimate includes preparation, transfer and finalization, and leaves a
// separate native-closure reserve. A hard provider ceiling is not a target:
// work that cannot fit is refused rather than silently truncated to it.
// measuredRate must come from qualified successful work in the same scope;
// zero explicitly selects the recorded conservative bootstrap rate.
func (p Policy) Estimate(bytes, partBytes, measuredRate int64, ceiling time.Duration) (Budget, error) {
	if !p.Valid() || bytes < 0 || partBytes <= 0 || measuredRate < 0 || measuredRate > 1<<40 || ceiling <= 0 {
		return Budget{}, ErrEstimate
	}
	rate, source := measuredRate, "successful_same_scope"
	if rate == 0 {
		rate, source = p.BootstrapBytesPerSecond, "configured_bootstrap"
	}
	transfer := quotient(bytes, rate)
	if transfer > maxSeconds-p.PreparationSeconds-p.ControlSeconds {
		return Budget{}, ErrEstimate
	}
	b := Budget{ExpectedBytes: bytes, BytesPerSecond: rate, RateSource: source,
		ExpectedSeconds: transfer + p.PreparationSeconds + p.ControlSeconds}
	var err error
	if b.RunSeconds, err = scaled(b.ExpectedSeconds, p.TimeCoefficient); err != nil {
		return Budget{}, err
	}
	b.PreparationSeconds, err = scaled(p.PreparationSeconds, p.TimeCoefficient)
	if err != nil {
		return Budget{}, err
	}
	b.SilenceSeconds, err = scaled(max(p.ControlSeconds, quotient(partBytes, rate)), p.NoProgressCoefficient)
	if err != nil {
		return Budget{}, err
	}
	b.ClosureSeconds, err = scaled(p.ControlSeconds, p.TimeCoefficient)
	if err != nil {
		return Budget{}, err
	}
	if b.RunSeconds > int64(ceiling/time.Second)-b.ClosureSeconds {
		return Budget{}, ErrWindow
	}
	return b, nil
}

// ScratchBytes reserves a worst-case unique copy of all selected disk bytes,
// including format margin. It is separate from transfer size or journal space.
func (p Policy) ScratchBytes(selectedBytes int64) (int64, error) {
	if !p.Valid() || selectedBytes <= 0 {
		return 0, ErrEstimate
	}
	return multiplyCeil(selectedBytes, p.ScratchCoefficient)
}

// GrowthReserve derives the minimum free-space headroom from measured growth
// and the time needed to detect and close a native operation. It supplements,
// rather than replaces, the initial worst-case reservation.
func GrowthReserve(bytesPerSecond, detectionSeconds, closureSeconds int64, factor float64) (int64, error) {
	if bytesPerSecond < 0 || detectionSeconds <= 0 || closureSeconds <= 0 ||
		detectionSeconds > maxSeconds-closureSeconds || !coefficient(factor, 100) {
		return 0, ErrEstimate
	}
	seconds := detectionSeconds + closureSeconds
	if bytesPerSecond > math.MaxInt64/seconds {
		return 0, ErrEstimate
	}
	return multiplyCeil(bytesPerSecond*seconds, factor)
}

// ObservationSeconds bounds unavailable read-only health evidence. Zero remains
// disabled for journals created before observation recovery was introduced.
func (p Policy) ObservationSeconds() (int64, error) {
	if !p.Valid() || p.ObservationCoefficient == 0 {
		return 0, ErrEstimate
	}
	return scaled(p.ControlSeconds, p.ObservationCoefficient)
}
