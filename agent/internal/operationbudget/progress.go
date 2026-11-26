package operationbudget

import "time"

// Progress is persisted with the operation's original request identity.
// Callers must durably save changes before using them to admit more work.
type Progress struct {
	StartedAt      time.Time `json:"started_at"`
	LastProgressAt time.Time `json:"last_progress_at"`
	Stage          string    `json:"stage"`
	Cursor         int64     `json:"cursor"`
	Budget         Budget    `json:"budget"`
}

var stages = map[string]int{"queued": 0, "preparing": 1, "mapping": 2, "transferring": 3, "finalizing": 4, "publishing": 5, "complete": 6}

func (p Progress) Valid() bool {
	_, known := stages[p.Stage]
	b := p.Budget
	return known && !p.StartedAt.IsZero() && !p.LastProgressAt.Before(p.StartedAt) && p.Cursor >= 0 &&
		b.ExpectedBytes >= 0 && b.BytesPerSecond > 0 && b.BytesPerSecond <= 1<<40 &&
		(b.RateSource == "configured_bootstrap" || b.RateSource == "successful_same_scope") &&
		b.ExpectedSeconds > 0 && b.RunSeconds >= b.ExpectedSeconds && b.RunSeconds <= maxSeconds &&
		b.PreparationSeconds > 0 && b.PreparationSeconds <= b.RunSeconds &&
		b.SilenceSeconds > 0 && b.SilenceSeconds <= maxSeconds && b.ClosureSeconds > 0 && b.ClosureSeconds <= maxSeconds
}

// Advance ignores repeated observations and backward stage/cursor movement.
// A heartbeat, retry or repeated map page cannot extend the silence budget.
func (p *Progress) Advance(now time.Time, stage string, cursor int64) (bool, error) {
	order, known := stages[stage]
	if !p.Valid() || !known || now.Before(p.LastProgressAt) || cursor < 0 {
		return false, ErrEstimate
	}
	previous := stages[p.Stage]
	if order < previous || (order == previous && cursor <= p.Cursor) {
		return false, nil
	}
	p.Stage, p.Cursor, p.LastProgressAt = stage, cursor, now.UTC()
	return true, nil
}

func (p Progress) Deadline() time.Time {
	return p.StartedAt.Add(time.Duration(p.Budget.RunSeconds) * time.Second)
}

// Exhausted separates queue/preparation from useful-progress silence. Its
// absolute deadline is anchored at first acceptance, including across restart.
func (p Progress) Exhausted(now time.Time) string {
	if !p.Valid() || now.Before(p.StartedAt) || now.Before(p.LastProgressAt) {
		return "invalid_budget_or_clock"
	}
	if p.Stage == "complete" {
		return ""
	}
	if !now.Before(p.Deadline()) {
		return "operation_budget_exhausted"
	}
	seconds := p.Budget.SilenceSeconds
	if stages[p.Stage] <= stages["preparing"] {
		seconds = p.Budget.PreparationSeconds
	}
	if now.Sub(p.LastProgressAt) >= time.Duration(seconds)*time.Second {
		if p.Stage == "queued" {
			return "admission_wait_exhausted"
		}
		return "no_progress_budget_exhausted"
	}
	return ""
}
