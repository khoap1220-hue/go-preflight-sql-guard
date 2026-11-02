# Roadmap — `go-preflight-sql-guard`

- [x] Read-only SQL startup probe sanitizer (`IsReadOnlySQLQuery`) blocking mutating statements.
- [x] Live `database/sql` connection pool & read-only query latency verifier (`RunDatabaseSQLPreflight`).
- [x] Zero-CGo 100-byte binary SQLite3 header & WAL companion file inspector (`InspectSQLiteFileHeader`).
- [x] PostgreSQL TLS `sslmode` DSN security validator & `GracefulCircuitBreaker` state machine.
- [x] Verified under Go's concurrent race detector (`go test -race -v ./...`).
