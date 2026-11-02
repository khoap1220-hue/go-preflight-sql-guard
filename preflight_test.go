package preflightguard

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func createSyntheticSQLiteFile(t *testing.T, walMode bool) string {
	t.Helper()
	var hdr [100]byte
	copy(hdr[0:16], []byte("SQLite format 3\x00"))
	binary.BigEndian.PutUint16(hdr[16:18], 4096) // 4KB page size
	if walMode {
		hdr[18] = 2
		hdr[19] = 2
	} else {
		hdr[18] = 1
		hdr[19] = 1
	}
	binary.BigEndian.PutUint32(hdr[24:28], 7)  // change counter
	binary.BigEndian.PutUint32(hdr[28:32], 12) // 12 pages
	binary.BigEndian.PutUint32(hdr[40:44], 4)  // schema cookie
	binary.BigEndian.PutUint32(hdr[44:48], 4)  // schema format 4
	binary.BigEndian.PutUint32(hdr[56:60], 1)  // UTF-8

	tmpPath := filepath.Join(t.TempDir(), "test_ledger.db")
	if err := os.WriteFile(tmpPath, hdr[:], 0600); err != nil {
		t.Fatalf("failed to write synthetic sqlite header: %v", err)
	}
	return tmpPath
}

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

func TestIsReadOnlySQLQuery_BlocksMutationsAndStackedQueries(t *testing.T) {
	validQueries := []string{
		"SELECT 1",
		"SELECT\n  count(*)\nFROM ledgers;",
		"WITH recent AS (SELECT 1) SELECT * FROM recent",
		"SELECT schema_version FROM migrations ORDER BY id DESC LIMIT 1;",
		"PRAGMA journal_mode",
		"SHOW transaction_read_only",
		"EXPLAIN SELECT * FROM ledgers WHERE seq = 100",
	}
	for _, q := range validQueries {
		if err := IsReadOnlySQLQuery(q); err != nil {
			t.Fatalf("expected valid read-only query %q, got error: %v", q, err)
		}
	}

	forbiddenQueries := []string{
		"",
		"   ;  ",
		"DELETE FROM users WHERE id = 1",
		"SELECT 1; DROP TABLE users",
		"UPDATE balances SET amount = 0",
		"SELECT * INTO hacked_table FROM users",
		"PRAGMA journal_mode = DELETE",
		"PRAGMA writable_schema(1)",
		"SELECT pg_terminate_backend(123)",
		"SELECT set_config('log_statement', 'none', false)",
		"SELECT * FROM users -- comment injection",
	}
	for _, q := range forbiddenQueries {
		if err := IsReadOnlySQLQuery(q); err == nil {
			t.Fatalf("expected query %q to be rejected as unsafe, but it passed", q)
		}
	}
}

func TestValidatePostgresOrSQLiteDSN_EnforcesRemoteTLSAndRedactsPassword(t *testing.T) {
	_, err := ValidatePostgresOrSQLiteDSN("postgres://admin:supersecret@db.internal.example.com:5432/indexer?sslmode=disable", true)
	if err == nil {
		t.Fatal("expected remote postgres DSN with sslmode=disable to fail when requireTLSForRemote=true")
	}

	rep, err := ValidatePostgresOrSQLiteDSN("postgres://admin:supersecret@db.internal.example.com:5432/indexer?sslmode=verify-full", true)
	if err != nil {
		t.Fatalf("expected verify-full DSN to pass, got %v", err)
	}
	if rep.SSLMode != "verify-full" || rep.Host != "db.internal.example.com" {
		t.Fatalf("unexpected DSN report: %+v", rep)
	}
	if rep.RedactedDSN == "" || rep.RedactedDSN != "postgres://admin:REDACTED@db.internal.example.com:5432/indexer?sslmode=verify-full" {
		t.Fatalf("password was not properly redacted: %s", rep.RedactedDSN)
	}
}

func TestInspectSQLiteFileHeader_ReadsBinaryMetadataAndWAL(t *testing.T) {
	walDB := createSyntheticSQLiteFile(t, true)
	info, err := InspectSQLiteFileHeader(walDB)
	if err != nil {
		t.Fatalf("expected valid SQLite header inspection, got %v", err)
	}
	if !info.WALMode || info.PageSize != 4096 || info.PageCount != 12 || info.TextEncoding != "UTF-8" {
		t.Fatalf("unexpected SQLite header metadata: %+v", info)
	}

	rollbackDB := createSyntheticSQLiteFile(t, false)
	probe := NewSQLiteFileProbe(rollbackDB, true)
	if _, err := probe(context.Background()); err == nil {
		t.Fatal("expected requireWAL=true probe to fail on rollback-mode SQLite file")
	}

	// Corrupt page size to non-power-of-two (999) and verify rejection
	rawBytes, err := os.ReadFile(walDB)
	if err != nil {
		t.Fatalf("read synthetic db: %v", err)
	}
	binary.BigEndian.PutUint16(rawBytes[16:18], 999)
	badPageDB := filepath.Join(t.TempDir(), "bad_pagesize.db")
	if err := os.WriteFile(badPageDB, rawBytes, 0600); err != nil {
		t.Fatalf("write bad_pagesize.db: %v", err)
	}
	if _, err := InspectSQLiteFileHeader(badPageDB); err == nil {
		t.Fatal("expected non-power-of-two SQLite page size (999) to be rejected")
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

func TestQueryCostTracker_ConcurrentRaceSafetyAndTrackQuery(t *testing.T) {
	tracker := NewQueryCostTracker()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = tracker.TrackQuery(context.Background(), "alert_rollup_query", func(ctx context.Context) (int64, error) {
				time.Sleep(1 * time.Millisecond)
				return 10, nil
			})
		}()
	}
	wg.Wait()

	snap := tracker.Snapshot()
	summary, ok := snap["alert_rollup_query"]
	if !ok || summary.Calls != 20 || summary.TotalRows != 200 || summary.Errors != 0 {
		t.Fatalf("unexpected concurrent cost attribution summary: %+v", summary)
	}
}

func TestInspectSQLiteWAL_BigAndLittleEndianAndFrameEstimate(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Synthetic Big-Endian WAL with 2 frames
	beWalPath := filepath.Join(tmpDir, "ledger.db-wal")
	pageSize := uint32(4096)
	frameSize := 24 + pageSize
	beData := make([]byte, 32+2*frameSize)
	binary.BigEndian.PutUint32(beData[0:4], 0x377f0683)
	binary.BigEndian.PutUint32(beData[4:8], 3007000)
	binary.BigEndian.PutUint32(beData[8:12], pageSize)
	binary.BigEndian.PutUint32(beData[12:16], 42) // checkpoint sequence

	if err := os.WriteFile(beWalPath, beData, 0600); err != nil {
		t.Fatalf("failed to write big-endian wal: %v", err)
	}

	beInfo, err := InspectSQLiteWAL(beWalPath)
	if err != nil {
		t.Fatalf("InspectSQLiteWAL failed on big-endian wal: %v", err)
	}
	if beInfo.Magic != 0x377f0683 || beInfo.PageSize != 4096 || beInfo.CheckpointSeq != 42 || beInfo.FrameCountEstimate != 2 {
		t.Fatalf("unexpected beInfo: %+v", beInfo)
	}

	// 2. Synthetic Little-Endian WAL with 1 frame
	leWalPath := filepath.Join(tmpDir, "ledger_le.db-wal")
	leData := make([]byte, 32+1*frameSize)
	binary.LittleEndian.PutUint32(leData[0:4], 0x377f0682)
	binary.LittleEndian.PutUint32(leData[4:8], 3007000)
	binary.LittleEndian.PutUint32(leData[8:12], pageSize)
	binary.LittleEndian.PutUint32(leData[12:16], 99)

	if err := os.WriteFile(leWalPath, leData, 0600); err != nil {
		t.Fatalf("failed to write little-endian wal: %v", err)
	}

	leInfo, err := InspectSQLiteWAL(leWalPath)
	if err != nil {
		t.Fatalf("InspectSQLiteWAL failed on little-endian wal: %v", err)
	}
	if leInfo.Magic != 0x377f0682 || leInfo.PageSize != 4096 || leInfo.CheckpointSeq != 99 || leInfo.FrameCountEstimate != 1 {
		t.Fatalf("unexpected leInfo: %+v", leInfo)
	}

	// 3. Truncated WAL file (< 32 bytes)
	truncWalPath := filepath.Join(tmpDir, "trunc.db-wal")
	if err := os.WriteFile(truncWalPath, beData[:20], 0600); err != nil {
		t.Fatalf("failed to write truncated wal: %v", err)
	}
	_, err = InspectSQLiteWAL(truncWalPath)
	if err == nil {
		t.Fatal("expected error on truncated WAL file, got nil")
	}

	// 4. Invalid Magic
	badMagicWalPath := filepath.Join(tmpDir, "bad_magic.db-wal")
	badData := make([]byte, 32)
	binary.BigEndian.PutUint32(badData[0:4], 0xdeadbeef)
	if err := os.WriteFile(badMagicWalPath, badData, 0600); err != nil {
		t.Fatalf("failed to write bad magic wal: %v", err)
	}
	_, err = InspectSQLiteWAL(badMagicWalPath)
	if err == nil {
		t.Fatal("expected error on invalid magic bytes, got nil")
	}
}
