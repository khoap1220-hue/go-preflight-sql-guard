# 🐹 go-preflight-sql-guard

[![Tests](https://img.shields.io/badge/Tests-Race_Safe_Passing-2ea44f?logo=go)](preflight_test.go)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](go.mod)
[![GPG Verified](https://img.shields.io/badge/Commits-GPG_Verified-2ea44f?logo=github)](https://github.com/khoap1220-hue/go-preflight-sql-guard/commits/main)

**`go-preflight-sql-guard`** is a zero-dependency Go library for building resilient blockchain indexers and high-availability SQL services. It provides **Read-Only Startup Preflight Self-Checks**, **Graceful Database Degradation Circuit Breakers**, and **Thread-Safe Query Cost Attribution**.

---

## ✨ Key Capabilities

1. **`PreflightRunner` (Startup Self-Check):** Validates configuration coherence, database schema migrations, and RPC upstream reachability in read-only mode before accepting traffic.
2. **`DegradationGuard` (Graceful Fallback):** Automatically transitions to `DEGRADED_READ_ONLY` snapshot serving when the primary database experiences transient outages, and auto-recovers once primary connectivity returns.
3. **`QueryCostTracker` (Database Cost Attribution):** Thread-safe (`sync.RWMutex`, `go test -race` verified) ledger attributing execution latency and row volume to logical query tags.

---

## 🚀 Usage

```go
package main

import (
	"context"
	"fmt"
	preflight "github.com/khoap1220-hue/go-preflight-sql-guard"
)

func main() {
	runner := preflight.NewPreflightRunner()
	runner.Register("db-schema-coherence", true, func(ctx context.Context) (string, error) {
		return "migrations v14 verified", nil
	})
	results, err := runner.RunAll(context.Background())
	fmt.Println(results, err)
}
```

## 🧪 Running Tests

```bash
go test -v -race ./...
```

## 📄 License

Released under the [MIT License](LICENSE).
