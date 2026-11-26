package config

import (
	"math"
	"os"
	"strconv"

	"vnbui/agent/internal/operationbudget"
)

func envCoefficient(name string, fallback float64) float64 {
	s, found := os.LookupEnv(name)
	if !found {
		return fallback
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return math.NaN()
	}
	return v
}

func loadOperationBudget() operationbudget.Policy {
	p := operationbudget.DefaultPolicy()
	p.ObservationCoefficient = envCoefficient("OPERATION_OBSERVATION_COEFFICIENT", p.ObservationCoefficient)
	p.TimeCoefficient = envCoefficient("OPERATION_TIME_COEFFICIENT", p.TimeCoefficient)
	p.NoProgressCoefficient = envCoefficient("OPERATION_NO_PROGRESS_COEFFICIENT", p.NoProgressCoefficient)
	p.ScratchCoefficient = envCoefficient("OPERATION_SCRATCH_COEFFICIENT", p.ScratchCoefficient)
	p.BootstrapBytesPerSecond = int64(envStrictInt("OPERATION_BOOTSTRAP_BYTES_PER_SECOND", int(p.BootstrapBytesPerSecond)))
	p.PreparationSeconds = int64(envStrictInt("OPERATION_PREPARATION_ESTIMATE_SECONDS", int(p.PreparationSeconds)))
	p.ControlSeconds = int64(envStrictInt("OPERATION_CONTROL_ESTIMATE_SECONDS", int(p.ControlSeconds)))
	return p
}

// Zero is used by embedded callers constructing a Config without environment
// loading. Partially configured or invalid policies never fall back silently.
func (c *Config) SafetyPolicy() operationbudget.Policy {
	if c.OperationBudget == (operationbudget.Policy{}) {
		return operationbudget.DefaultPolicy()
	}
	return c.OperationBudget
}
