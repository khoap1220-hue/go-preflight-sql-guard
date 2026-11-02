// Package preflightguard provides read-only startup self-checks, graceful database
// degradation circuit breakers, and concurrent query cost attribution for Go backends
// and blockchain indexers.
package preflightguard

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// CheckStatus represents the outcome of an individual startup preflight probe.
type CheckStatus string

const (
	StatusPass CheckStatus = "PASS"
	StatusWarn CheckStatus = "WARN"
	StatusFail CheckStatus = "FAIL"
)

// ProbeResult captures a single preflight check's diagnostic report.
type ProbeResult struct {
	Name       string        `json:"name"`
	Status     CheckStatus   `json:"status"`
	Duration   time.Duration `json:"duration"`
	Detail     string        `json:"detail"`
	ReadOnly   bool          `json:"read_only"`
}

// ProbeFunc is a read-only-by-default preflight check function.
type ProbeFunc func(ctx context.Context) (string, error)

type registeredProbe struct {
	name     string
	critical bool
	fn       ProbeFunc
}

// PreflightRunner executes a deterministic sequence of startup readiness probes.
type PreflightRunner struct {
	probes []registeredProbe
}

// NewPreflightRunner constructs an empty PreflightRunner.
func NewPreflightRunner() *PreflightRunner {
	return &PreflightRunner{}
}

// Register adds a read-only startup probe. If critical is true, failure causes RunAll to return an error.
func (r *PreflightRunner) Register(name string, critical bool, fn ProbeFunc) {
	r.probes = append(r.probes, registeredProbe{
		name:     name,
		critical: critical,
		fn:       fn,
	})
}

// RunAll executes all registered probes and returns the structured report and an aggregate error if any critical probe fails.
func (r *PreflightRunner) RunAll(ctx context.Context) ([]ProbeResult, error) {
	results := make([]ProbeResult, 0, len(r.probes))
	var criticalFailures []string

	for _, p := range r.probes {
		t0 := time.Now()
		detail, err := p.fn(ctx)
		elapsed := time.Since(t0)

		res := ProbeResult{
			Name:     p.name,
			Duration: elapsed,
			Detail:   detail,
			ReadOnly: true,
		}
		if err != nil {
			res.Detail = err.Error()
			if p.critical {
				res.Status = StatusFail
				criticalFailures = append(criticalFailures, fmt.Sprintf("%s: %v", p.name, err))
			} else {
				res.Status = StatusWarn
			}
		} else {
			res.Status = StatusPass
		}
		results = append(results, res)
	}

	if len(criticalFailures) > 0 {
		return results, fmt.Errorf("startup preflight failed (%d critical): %v", len(criticalFailures), criticalFailures)
	}
	return results, nil
}

// DegradationState represents the live health mode of a backing store.
type DegradationState string

const (
	StateHealthy  DegradationState = "HEALTHY"
	StateDegraded DegradationState = "DEGRADED_READ_ONLY"
)

// ErrStoreUnavailable is returned when the primary store fails and no fallback is configured.
var ErrStoreUnavailable = errors.New("primary database store unavailable")

// DegradationGuard tracks consecutive storage errors and shifts seamlessly to a fallback reader.
type DegradationGuard struct {
	mu                sync.RWMutex
	threshold         int
	consecutiveErrors int
	state             DegradationState
}

// NewDegradationGuard initializes a circuit breaker that enters StateDegraded after threshold consecutive errors.
func NewDegradationGuard(threshold int) *DegradationGuard {
	if threshold < 1 {
		threshold = 3
	}
	return &DegradationGuard{
		threshold: threshold,
		state:     StateHealthy,
	}
}

// State returns the current degradation state safely across goroutines.
func (g *DegradationGuard) State() DegradationState {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.state
}

// Execute runs primaryFn and falls back to fallbackFn when an error occurs or the guard is degraded.
func (g *DegradationGuard) Execute(
	primaryFn func() (any, error),
	fallbackFn func() (any, error),
) (any, DegradationState, error) {
	val, err := primaryFn()
	if err == nil {
		g.mu.Lock()
		g.consecutiveErrors = 0
		g.state = StateHealthy
		st := g.state
		g.mu.Unlock()
		return val, st, nil
	}

	g.mu.Lock()
	g.consecutiveErrors++
	if g.consecutiveErrors >= g.threshold {
		g.state = StateDegraded
	}
	st := g.state
	g.mu.Unlock()

	if fallbackFn != nil {
		fbVal, fbErr := fallbackFn()
		return fbVal, st, fbErr
	}
	return nil, st, ErrStoreUnavailable
}

// QueryCostSummary aggregates execution duration and scanned rows per query tag.
type QueryCostSummary struct {
	QueryTag      string        `json:"query_tag"`
	Calls         int64         `json:"calls"`
	TotalDuration time.Duration `json:"total_duration"`
	TotalRows     int64         `json:"total_rows"`
}

// QueryCostTracker attributes database load to specific query tags in a thread-safe ledger.
type QueryCostTracker struct {
	mu    sync.RWMutex
	stats map[string]*QueryCostSummary
}

// NewQueryCostTracker creates a thread-safe query cost attribution ledger.
func NewQueryCostTracker() *QueryCostTracker {
	return &QueryCostTracker{
		stats: make(map[string]*QueryCostSummary),
	}
}

// Record logs a completed query's duration and row count under its logical tag.
func (t *QueryCostTracker) Record(queryTag string, duration time.Duration, rowsAffected int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.stats[queryTag]
	if !ok {
		entry = &QueryCostSummary{QueryTag: queryTag}
		t.stats[queryTag] = entry
	}
	entry.Calls++
	entry.TotalDuration += duration
	entry.TotalRows += rowsAffected
}

// Snapshot returns a copy of the current cost attribution metrics.
func (t *QueryCostTracker) Snapshot() map[string]QueryCostSummary {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[string]QueryCostSummary, len(t.stats))
	for k, v := range t.stats {
		out[k] = *v
	}
	return out
}
