package preflightguard

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestPreflightRunner_AllPassAndCriticalFailure(t *testing.T) {
	runner := NewPreflightRunner()
	runner.Register("config-coherence", true, func(ctx context.Context) (string, error) {
		return "retention=30d, network=pubnet", nil
	})
	runner.Register("db-migrations", true, func(ctx context.Context) (string, error) {
		return "schema version 14 up-to-date", nil
	})

	results, err := runner.RunAll(context.Background())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(results) != 2 || results[0].Status != StatusPass {
		t.Fatalf("unexpected preflight results: %+v", results)
	}

	runner.Register("rpc-archive", true, func(ctx context.Context) (string, error) {
		return "", errors.New("connection refused")
	})
	_, err = runner.RunAll(context.Background())
	if err == nil {
		t.Fatal("expected critical failure error, got nil")
	}
}

func TestDegradationGuard_TransitionsAndRecovers(t *testing.T) {
	guard := NewDegradationGuard(2)
	failPrimary := func() (any, error) { return nil, errors.New("db timeout") }
	okPrimary := func() (any, error) { return "live-db-rows", nil }
	cachedFallback := func() (any, error) { return "cached-snapshot", nil }

	val, st, err := guard.Execute(failPrimary, cachedFallback)
	if err != nil || val != "cached-snapshot" || st != StateHealthy {
		t.Fatalf("first failure should stay HEALTHY below threshold=2: val=%v st=%v err=%v", val, st, err)
	}

	val, st, err = guard.Execute(failPrimary, cachedFallback)
	if err != nil || val != "cached-snapshot" || st != StateDegraded {
		t.Fatalf("second failure should transition to DEGRADED_READ_ONLY: val=%v st=%v err=%v", val, st, err)
	}

	val, st, err = guard.Execute(okPrimary, cachedFallback)
	if err != nil || val != "live-db-rows" || st != StateHealthy {
		t.Fatalf("successful primary call should recover to HEALTHY: val=%v st=%v err=%v", val, st, err)
	}
}

func TestQueryCostTracker_ConcurrentRaceSafety(t *testing.T) {
	tracker := NewQueryCostTracker()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tracker.Record("alert_rollup_query", 5*time.Millisecond, 10)
		}()
	}
	wg.Wait()

	snap := tracker.Snapshot()
	summary, ok := snap["alert_rollup_query"]
	if !ok || summary.Calls != 20 || summary.TotalRows != 200 {
		t.Fatalf("unexpected concurrent cost attribution summary: %+v", summary)
	}
}
