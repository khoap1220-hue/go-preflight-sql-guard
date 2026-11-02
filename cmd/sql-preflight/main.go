package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	preflight "github.com/khoap1220-hue/go-preflight-sql-guard"
)

type cliReport struct {
	OverallPass bool                                 `json:"overall_pass"`
	Probes      []preflight.ProbeResult              `json:"probes"`
	SQLiteFiles []preflight.SQLiteHeaderInfo         `json:"sqlite_files,omitempty"`
	DSNChecks   []preflight.DSNValidationReport      `json:"dsn_checks,omitempty"`
	QueryCosts  map[string]preflight.QueryCostSummary `json:"query_costs,omitempty"`
	Error       string                               `json:"error,omitempty"`
}

func main() {
	sqlitePathsFlag := flag.String("sqlite", "", "Comma-separated list of SQLite .db file paths to inspect")
	requireWALFlag := flag.Bool("require-wal", false, "Require SQLite files to have WAL mode enabled in header")
	dsnFlag := flag.String("dsn", "", "Database DSN string to validate for TLS and read-only safety")
	requireTLSFlag := flag.Bool("require-tls", true, "Require TLS for remote PostgreSQL DSNs")
	sqlQueryFlag := flag.String("check-sql", "SELECT 1", "Verify that a SQL query is strictly single-statement read-only")
	flag.Parse()

	runner := preflight.NewPreflightRunner()
	tracker := preflight.NewQueryCostTracker()
	var sqliteInfos []preflight.SQLiteHeaderInfo
	var dsnReports []preflight.DSNValidationReport

	if *sqlQueryFlag != "" {
		q := *sqlQueryFlag
		runner.Register("readonly-sql-syntax", true, func(ctx context.Context) (string, error) {
			if err := preflight.IsReadOnlySQLQuery(q); err != nil {
				return "", err
			}
			return fmt.Sprintf("verified read-only SQL: %q", q), nil
		})
	}

	if *dsnFlag != "" {
		rawDSN := *dsnFlag
		reqTLS := *requireTLSFlag
		runner.Register("dsn-security-check", true, func(ctx context.Context) (string, error) {
			rep, err := preflight.ValidatePostgresOrSQLiteDSN(rawDSN, reqTLS)
			if err != nil {
				return "", err
			}
			dsnReports = append(dsnReports, rep)
			return fmt.Sprintf("driver=%s host=%s sslmode=%s redacted=%s", rep.Driver, rep.Host, rep.SSLMode, rep.RedactedDSN), nil
		})
	}

	if *sqlitePathsFlag != "" {
		paths := strings.Split(*sqlitePathsFlag, ",")
		for _, rawPath := range paths {
			p := strings.TrimSpace(rawPath)
			if p == "" {
				continue
			}
			pathCopy := p
			runner.Register("sqlite-header:"+pathCopy, true, func(ctx context.Context) (string, error) {
				var info preflight.SQLiteHeaderInfo
				err := tracker.TrackQuery(ctx, "inspect_sqlite_header", func(ctx context.Context) (int64, error) {
					var iErr error
					info, iErr = preflight.InspectSQLiteFileHeader(pathCopy)
					if iErr != nil {
						return 0, iErr
					}
					return int64(info.PageCount), nil
				})
				if err != nil {
					return "", err
				}
				sqliteInfos = append(sqliteInfos, info)
				if *requireWALFlag && !info.WALMode {
					return "", fmt.Errorf("file %q has write_version=%d (expected WAL=2)", pathCopy, info.WriteVersion)
				}
				return fmt.Sprintf("page_size=%d pages=%d size=%dB wal=%v encoding=%s", info.PageSize, info.PageCount, info.TotalSizeBytes, info.WALMode, info.TextEncoding), nil
			})
		}
	}

	results, runErr := runner.RunAll(context.Background())
	out := cliReport{
		OverallPass: runErr == nil,
		Probes:      results,
		SQLiteFiles: sqliteInfos,
		DSNChecks:   dsnReports,
		QueryCosts:  tracker.Snapshot(),
	}
	if runErr != nil {
		out.Error = runErr.Error()
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	if runErr != nil {
		os.Exit(1)
	}
}
