// Package preflightguard provides read-only startup self-checks, database/sql
// pool & read-only query probes, DSN TLS/WAL security validation, zero-CGo SQLite3
// binary header inspection, graceful database degradation circuit breakers, and
// concurrent query cost attribution for Go backends and blockchain indexers.
package preflightguard

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
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
	DurationMs float64       `json:"duration_ms"`
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
			Name:       p.name,
			Duration:   elapsed,
			DurationMs: float64(elapsed.Microseconds()) / 1000.0,
			Detail:     detail,
			ReadOnly:   true,
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

var writeKeywordRegex = regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|REPLACE|GRANT|REVOKE|VACUUM|ATTACH|DETACH|REINDEX|COPY|INTO|CALL|EXEC|EXECUTE|MERGE|LOCK|SET|DO|DISCARD|CHECKPOINT|CLUSTER)\b`)
var pragmaWriteRegex = regexp.MustCompile(`(?i)\bPRAGMA\s+[a-zA-Z0-9_.]+\s*(=|\()`)
var dangerousPGFuncRegex = regexp.MustCompile(`(?i)\b(pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_rotate_logfile|pg_promote|set_config|nextval|setval|lo_import|lo_export|lo_unlink)\s*\(`)
var readOnlyStartRegex = regexp.MustCompile(`(?is)^(SELECT|PRAGMA|SHOW|EXPLAIN|WITH)\b`)

// IsReadOnlySQLQuery enforces that a SQL probe string is a single-statement read-only query.
func IsReadOnlySQLQuery(query string) error {
	trimmed := strings.TrimSpace(query)
	if trimmed == "" {
		return errors.New("SQL query cannot be empty")
	}
	// Strip single trailing semicolon if present, then reject any internal semicolons (stacked queries)
	withoutTrailing := strings.TrimSpace(strings.TrimSuffix(trimmed, ";"))
	if withoutTrailing == "" {
		return errors.New("SQL query cannot be empty")
	}
	if strings.Contains(withoutTrailing, ";") {
		return errors.New("multi-statement stacked SQL queries are forbidden in read-only preflight probes")
	}
	if strings.Contains(withoutTrailing, "--") || strings.Contains(withoutTrailing, "/*") {
		return errors.New("SQL comments are forbidden in read-only preflight probes")
	}
	if writeKeywordRegex.MatchString(withoutTrailing) {
		return errors.New("DDL/DML write keywords are forbidden in read-only preflight probes")
	}
	if pragmaWriteRegex.MatchString(withoutTrailing) {
		return errors.New("mutating PRAGMA assignments or calls are forbidden in read-only preflight probes")
	}
	if dangerousPGFuncRegex.MatchString(withoutTrailing) {
		return errors.New("mutating or administrative database functions are forbidden in read-only preflight probes")
	}
	if !readOnlyStartRegex.MatchString(withoutTrailing) {
		return errors.New("preflight SQL query must begin with SELECT, PRAGMA, SHOW, EXPLAIN, or WITH")
	}
	return nil
}

// NewSQLPingAndPoolProbe constructs a ProbeFunc that pings a live *sql.DB handle and inspects connection pool saturation.
func NewSQLPingAndPoolProbe(db *sql.DB, maxAllowedWaitCount int64) ProbeFunc {
	return func(ctx context.Context) (string, error) {
		if db == nil {
			return "", errors.New("sql.DB handle is nil")
		}
		if err := db.PingContext(ctx); err != nil {
			return "", fmt.Errorf("db.PingContext failed: %w", err)
		}
		stats := db.Stats()
		if maxAllowedWaitCount > 0 && stats.WaitCount > maxAllowedWaitCount {
			return "", fmt.Errorf("connection pool wait count (%d) exceeds threshold (%d)", stats.WaitCount, maxAllowedWaitCount)
		}
		return fmt.Sprintf("open=%d in_use=%d idle=%d wait_count=%d", stats.OpenConnections, stats.InUse, stats.Idle, stats.WaitCount), nil
	}
}

// NewSQLReadOnlyQueryProbe validates that query is strictly read-only and executes it via db.QueryRowContext.
func NewSQLReadOnlyQueryProbe(db *sql.DB, query string) ProbeFunc {
	return func(ctx context.Context) (string, error) {
		if err := IsReadOnlySQLQuery(query); err != nil {
			return "", err
		}
		if db == nil {
			return "", errors.New("sql.DB handle is nil")
		}
		var result any
		if err := db.QueryRowContext(ctx, query).Scan(&result); err != nil {
			return "", fmt.Errorf("read-only probe query failed: %w", err)
		}
		return fmt.Sprintf("result=%v", result), nil
	}
}

// Queryer provides an interface for executing single-row SQL queries, matching *sql.DB and *sql.Tx.
type Queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// WatermarkProbeConfig defines configuration for verifying a table's checkpoint sequence.
type WatermarkProbeConfig struct {
	Table       string `json:"table"`
	CursorCol   string `json:"cursor_col"`
	MinSequence uint32 `json:"min_sequence"`
}

var sqlIdentifierRegex = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// VerifyTableAndWatermark performs a read-only query to fetch the maximum sequence in the given table and cursor column,
// verifying that table and cursor column names are safe alphanumeric/underscore identifiers and that the sequence >= minSequence.
func VerifyTableAndWatermark(ctx context.Context, q Queryer, table string, cursorCol string, minSequence uint32) (uint32, error) {
	if q == nil {
		return 0, errors.New("nil queryer provided")
	}
	if !sqlIdentifierRegex.MatchString(table) {
		return 0, fmt.Errorf("invalid table identifier %q: must contain only alphanumeric characters and underscores", table)
	}
	if !sqlIdentifierRegex.MatchString(cursorCol) {
		return 0, fmt.Errorf("invalid cursor column identifier %q: must contain only alphanumeric characters and underscores", cursorCol)
	}

	query := fmt.Sprintf("SELECT COALESCE(MAX(%s), 0) FROM %s", cursorCol, table)
	var watermark int64
	if err := q.QueryRowContext(ctx, query).Scan(&watermark); err != nil {
		return 0, fmt.Errorf("watermark probe query failed on %s.%s: %w", table, cursorCol, err)
	}
	if watermark < 0 {
		return 0, fmt.Errorf("watermark sequence is negative: %d", watermark)
	}
	seq := uint32(watermark)
	if seq < minSequence {
		return seq, fmt.Errorf("stored watermark sequence %d is below minimum required sequence %d (cursor regression)", seq, minSequence)
	}
	return seq, nil
}

// NewWatermarkProbe constructs a ProbeFunc that verifies table watermark invariants.
func NewWatermarkProbe(q Queryer, cfg WatermarkProbeConfig) ProbeFunc {
	return func(ctx context.Context) (string, error) {
		seq, err := VerifyTableAndWatermark(ctx, q, cfg.Table, cfg.CursorCol, cfg.MinSequence)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("table=%s cursor=%s sequence=%d min=%d", cfg.Table, cfg.CursorCol, seq, cfg.MinSequence), nil
	}
}

// DSNValidationReport summarizes security and durability properties of a database connection string.
type DSNValidationReport struct {
	Driver      string `json:"driver"`
	Host        string `json:"host"`
	SSLMode     string `json:"ssl_mode"`
	WALEnabled  bool   `json:"wal_enabled"`
	ReadOnly    bool   `json:"read_only"`
	RedactedDSN string `json:"redacted_dsn"`
}

// ValidatePostgresOrSQLiteDSN inspects a Postgres or SQLite DSN for TLS enforcement, credential masking, and WAL settings.
func ValidatePostgresOrSQLiteDSN(rawDSN string, requireTLSForRemote bool) (DSNValidationReport, error) {
	trimmed := strings.TrimSpace(rawDSN)
	if trimmed == "" {
		return DSNValidationReport{}, errors.New("database DSN cannot be empty")
	}

	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://") {
		u, err := url.Parse(trimmed)
		if err != nil {
			return DSNValidationReport{}, fmt.Errorf("invalid postgres DSN URL: %w", err)
		}
		host := u.Hostname()
		if host == "" {
			host = "localhost"
		}
		q := u.Query()
		sslMode := q.Get("sslmode")
		if sslMode == "" {
			sslMode = "prefer"
		}
		isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1"
		if requireTLSForRemote && !isLocal && (sslMode == "disable" || sslMode == "allow") {
			return DSNValidationReport{}, fmt.Errorf("remote PostgreSQL host %q forbids insecure sslmode=%q", host, sslMode)
		}

		redactedURL := *u
		if redactedURL.User != nil {
			username := redactedURL.User.Username()
			if _, hasPwd := redactedURL.User.Password(); hasPwd {
				redactedURL.User = url.UserPassword(username, "REDACTED")
			}
		}
		ro := q.Get("default_transaction_read_only") == "on" || q.Get("target_session_attrs") == "read-only"
		return DSNValidationReport{
			Driver:      "postgres",
			Host:        host,
			SSLMode:     sslMode,
			WALEnabled:  true,
			ReadOnly:    ro,
			RedactedDSN: redactedURL.String(),
		}, nil
	}

	// SQLite file or URI DSN
	wal := strings.Contains(lower, "_journal_mode=wal") || strings.Contains(lower, "journal_mode=wal")
	ro := strings.Contains(lower, "mode=ro") || strings.Contains(lower, "_query_only=1") || strings.Contains(lower, "_query_only=true")
	return DSNValidationReport{
		Driver:      "sqlite3",
		Host:        "local-file",
		SSLMode:     "n/a",
		WALEnabled:  wal,
		ReadOnly:    ro,
		RedactedDSN: trimmed,
	}, nil
}

var sqlite3MagicHeader = []byte("SQLite format 3\x00")

// SQLiteHeaderInfo contains binary metadata parsed directly from the first 100 bytes of a SQLite3 database file.
type SQLiteHeaderInfo struct {
	FilePath         string `json:"file_path"`
	PageSize         int    `json:"page_size"`
	WriteVersion     byte   `json:"write_version"`
	ReadVersion      byte   `json:"read_version"`
	WALMode          bool   `json:"wal_mode"`
	PageCount        uint32 `json:"page_count"`
	TotalSizeBytes   int64  `json:"total_size_bytes"`
	ChangeCounter    uint32 `json:"change_counter"`
	SchemaCookie     uint32 `json:"schema_cookie"`
	SchemaFormat     uint32 `json:"schema_format"`
	TextEncoding     string `json:"text_encoding"`
	UserVersion      uint32 `json:"user_version"`
}

// InspectSQLiteFileHeader reads the 100-byte binary header of a SQLite3 file without requiring CGo drivers.
func InspectSQLiteFileHeader(filePath string) (SQLiteHeaderInfo, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return SQLiteHeaderInfo{}, fmt.Errorf("open sqlite file: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return SQLiteHeaderInfo{}, fmt.Errorf("stat sqlite file: %w", err)
	}
	if stat.Size() < 100 {
		return SQLiteHeaderInfo{}, fmt.Errorf("file %q is too small (%d bytes) to be a valid SQLite3 database (minimum 100 bytes)", filePath, stat.Size())
	}

	var hdr [100]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return SQLiteHeaderInfo{}, fmt.Errorf("read 100-byte sqlite header: %w", err)
	}
	if !bytes.Equal(hdr[0:16], sqlite3MagicHeader) {
		return SQLiteHeaderInfo{}, fmt.Errorf("invalid SQLite3 magic header in %q", filePath)
	}

	rawPageSize := binary.BigEndian.Uint16(hdr[16:18])
	pageSize := int(rawPageSize)
	if rawPageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize > 65536 || (pageSize&(pageSize-1)) != 0 {
		return SQLiteHeaderInfo{}, fmt.Errorf("invalid SQLite3 page size %d in %q (must be power of two between 512 and 65536)", pageSize, filePath)
	}
	writeVer := hdr[18]
	readVer := hdr[19]
	changeCounter := binary.BigEndian.Uint32(hdr[24:28])
	pageCount := binary.BigEndian.Uint32(hdr[28:32])
	schemaCookie := binary.BigEndian.Uint32(hdr[40:44])
	schemaFormat := binary.BigEndian.Uint32(hdr[44:48])
	encodingCode := binary.BigEndian.Uint32(hdr[56:60])
	userVersion := binary.BigEndian.Uint32(hdr[60:64])

	encodingStr := "UNKNOWN"
	switch encodingCode {
	case 1:
		encodingStr = "UTF-8"
	case 2:
		encodingStr = "UTF-16le"
	case 3:
		encodingStr = "UTF-16be"
	}

	return SQLiteHeaderInfo{
		FilePath:       filePath,
		PageSize:       pageSize,
		WriteVersion:   writeVer,
		ReadVersion:    readVer,
		WALMode:        writeVer == 2 && readVer == 2,
		PageCount:      pageCount,
		TotalSizeBytes: stat.Size(),
		ChangeCounter:  changeCounter,
		SchemaCookie:   schemaCookie,
		SchemaFormat:   schemaFormat,
		TextEncoding:   encodingStr,
		UserVersion:    userVersion,
	}, nil
}

// NewSQLiteFileProbe constructs a ProbeFunc that verifies a SQLite3 file's binary header and optionally requires WAL mode.
func NewSQLiteFileProbe(filePath string, requireWAL bool) ProbeFunc {
	return func(ctx context.Context) (string, error) {
		info, err := InspectSQLiteFileHeader(filePath)
		if err != nil {
			return "", err
		}
		if requireWAL && !info.WALMode {
			return "", fmt.Errorf("sqlite file %q is not in WAL mode (write_version=%d, read_version=%d)", filePath, info.WriteVersion, info.ReadVersion)
		}
		return fmt.Sprintf(
			"page_size=%d pages=%d size_bytes=%d wal=%v schema_cookie=%d encoding=%s",
			info.PageSize, info.PageCount, info.TotalSizeBytes, info.WALMode, info.SchemaCookie, info.TextEncoding,
		), nil
	}
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
	var val any
	var err error
	if primaryFn == nil {
		err = errors.New("primaryFn is nil")
	} else {
		val, err = primaryFn()
	}
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

// QueryCostSummary aggregates execution duration, error counts, and scanned rows per query tag.
type QueryCostSummary struct {
	QueryTag      string        `json:"query_tag"`
	Calls         int64         `json:"calls"`
	Errors        int64         `json:"errors"`
	TotalDuration time.Duration `json:"total_duration"`
	MaxDuration   time.Duration `json:"max_duration"`
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
	t.RecordWithError(queryTag, duration, rowsAffected, nil)
}

// RecordWithError logs a completed query's duration, row count, and optional error.
func (t *QueryCostTracker) RecordWithError(queryTag string, duration time.Duration, rowsAffected int64, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.stats[queryTag]
	if !ok {
		entry = &QueryCostSummary{QueryTag: queryTag}
		t.stats[queryTag] = entry
	}
	entry.Calls++
	if err != nil {
		entry.Errors++
	}
	entry.TotalDuration += duration
	if duration > entry.MaxDuration {
		entry.MaxDuration = duration
	}
	entry.TotalRows += rowsAffected
}

// TrackQuery executes fn, measures wall-clock latency, and records cost attribution automatically.
func (t *QueryCostTracker) TrackQuery(ctx context.Context, queryTag string, fn func(ctx context.Context) (int64, error)) error {
	t0 := time.Now()
	rows, err := fn(ctx)
	t.RecordWithError(queryTag, time.Since(t0), rows, err)
	return err
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
