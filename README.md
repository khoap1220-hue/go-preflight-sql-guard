# 🐹 go-preflight-sql-guard (v0.3.0)

[![Tests](https://img.shields.io/badge/Tests-6%2F6_Passing-2ea44f?logo=go)](preflight_test.go)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](go.mod)
[![GPG Verified](https://img.shields.io/badge/Commits-GPG_Verified-2ea44f?logo=github)](https://github.com/khoap1220-hue/go-preflight-sql-guard/commits/main)

**`go-preflight-sql-guard`** is a zero-dependency Go library and CLI tool for building resilient blockchain indexers and high-availability SQL services. It provides **`database/sql` Connection Pool & Read-Only Query Probes**, **Zero-CGo SQLite3 Binary Header & WAL Inspection**, **PostgreSQL/SQLite DSN TLS Validation**, **Graceful Database Degradation Circuit Breakers**, and **Thread-Safe Query Cost Attribution**.

---

## ✨ Key Capabilities

1. **Read-Only SQL Sanitizer & `database/sql` Probes (`IsReadOnlySQLQuery`, `NewSQLPingAndPoolProbe`, `NewSQLReadOnlyQueryProbe`):** Blocks stacked queries (`;`), SQL comment injections, and DDL/DML write keywords before executing startup readiness checks against `*sql.DB`.
2. **Zero-CGo SQLite3 Binary Header Inspector (`InspectSQLiteFileHeader`, `NewSQLiteFileProbe`):** Reads the 100-byte `"SQLite format 3\x00"` header directly from disk to verify `PageSize`, `WALMode` (`write_version == 2`), `PageCount`, `SchemaCookie`, and `UTF-8` encoding without requiring CGo.
3. **DSN Security & TLS Validator (`ValidatePostgresOrSQLiteDSN`):** Rejects insecure `sslmode=disable` on remote PostgreSQL hosts and masks embedded credentials in diagnostic logs.
4. **`DegradationGuard` & `QueryCostTracker`:** Automatically transitions to `DEGRADED_READ_ONLY` snapshot serving during primary DB outages and tracks per-query latency/row/error attribution safely across goroutines.

---

## 🚀 CLI & Library Usage

### Run the Preflight CLI on Real SQLite Databases & DSNs

```bash
go run ./cmd/sql-preflight \
  --sqlite ./data/shop.db \
  --require-wal \
  --dsn "postgres://indexer:secret@db.example.com:5432/stellar?sslmode=verify-full" \
  --check-sql "SELECT schema_version FROM migrations LIMIT 1"
```

### Library Example

```go
package main

import (
	"context"
	"fmt"
	preflight "github.com/khoap1220-hue/go-preflight-sql-guard"
)

func main() {
	runner := preflight.NewPreflightRunner()
	runner.Register("sqlite-wal-check", true, preflight.NewSQLiteFileProbe("./data/shop.db", true))
	results, err := runner.RunAll(context.Background())
	fmt.Println(results, err)
}
```

## 🧪 Running Tests

```bash
go vet ./...
go test -v ./...
```

## 📄 License

Released under the [MIT License](LICENSE).

---

## 👤 Author & Verification Standard

Architected and maintained by **Khoa Phan (`@khoap1220-hue`)**.
> *"I architect and ship production-grade primitives across Rust, Go, TypeScript, and Python — powered by my proprietary multi-agent verification & triage pipeline, with every single line human-audited, race-tested (`go test -race`), and 100% GPG-signed."*
