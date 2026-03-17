# Contributing to VulnCore 🛡️

Thanks for taking the time to contribute. Every bug report, feature idea, and pull request makes VulnCore better.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Branch Naming](#branch-naming)
- [Commit Convention](#commit-convention)
- [Pull Request Process](#pull-request-process)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Environment Variables Reference](#environment-variables-reference)

---

## Code of Conduct

Be respectful. No harassment, discrimination, or toxic behavior. This is a learning-friendly project — no question is too basic.

---

## How Can I Contribute?

### 🐛 Report a Bug

Open an issue using the **Bug Report** template. Include:
- Your Linux distro and version (`uname -a`)
- Steps to reproduce
- Expected vs actual behavior
- Logs (`journalctl -u vulncore -n 50` or terminal output)
- Rust and Go versions

### 💡 Suggest a Feature

Open an issue using the **Feature Request** template. Describe the problem you're solving, not just the solution.

### 🔧 Submit a Fix or Feature

1. Check existing issues and PRs to avoid duplicates
2. Fork the repo and create your branch from `develop`
3. Write code and tests
4. Open a Pull Request targeting `develop`

### 📖 Improve Documentation

Fix typos, clarify instructions, add examples — docs PRs are always welcome.

---

## Development Setup

### Prerequisites

| Tool   | Version | Install                                       |
|--------|---------|-----------------------------------------------|
| Rust   | 1.75+   | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` |
| Go     | 1.22+   | https://go.dev/dl/                            |
| Git    | any     | `apt install git`                             |
| Docker | 24+     | Optional, for container testing               |

### Local Setup

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/vulncore.git
cd vulncore

# Install Go dependencies + update Rust toolchain
make deps

# Build everything (Rust scanner + Go API)
make build

# Run tests
make test

# Start the server with auth enabled
VULNCORE_PASSWORD=dev123 VULNCORE_SECRET=dev-secret make run
# → http://localhost:8080/login
```

### Docker Setup

```bash
# Edit VULNCORE_PASSWORD in docker-compose.yml first
docker-compose up --build

# Or in detached mode
docker-compose up --build -d
docker-compose logs -f
```

---

## Branch Naming

```
feat/short-description      → new feature
fix/short-description       → bug fix
docs/short-description      → documentation only
refactor/short-description  → code change without behavior change
test/short-description      → adding or fixing tests
chore/short-description     → build, CI, tooling, deps
```

Examples:
```
feat/webhook-discord-embed
fix/sqlite-wal-memory-db
docs/docker-setup
chore/update-rust-deps
```

---

## Commit Convention

We follow **Conventional Commits**:

```
<type>(<scope>): <short description>

[optional body — explain WHY, not WHAT]

[optional footer — e.g. Closes #42]
```

### Types

| Type       | When to use                              |
|------------|------------------------------------------|
| `feat`     | New feature visible to users             |
| `fix`      | Bug fix                                  |
| `docs`     | Documentation only                       |
| `test`     | Adding or updating tests                 |
| `refactor` | Code change without feature/fix          |
| `perf`     | Performance improvement                  |
| `chore`    | Build, CI, dependencies, tooling         |
| `style`    | Formatting, whitespace (no logic change) |

### Scopes

| Scope       | What it covers                        |
|-------------|---------------------------------------|
| `scanner`   | Rust scanner engine                   |
| `api`       | Go REST API                           |
| `dashboard` | Web frontend                          |
| `auth`      | Authentication middleware             |
| `export`    | Report export                         |
| `webhook`   | Webhook alerts                        |
| `docker`    | Dockerfile, docker-compose            |
| `ci`        | GitHub Actions workflows              |
| `db`        | SQLite schema, migrations, GORM       |

### Examples

```
feat(webhook): add Discord embed format with severity colors
fix(db): skip WAL pragma for in-memory test databases
perf(scanner): batch EPSS API calls in groups of 50
docs(auth): add bearer token examples to API reference
chore(ci): bump actions/checkout to v4
```

---

## Pull Request Process

1. **Target branch**: always `develop`, never `main` directly
2. **Title**: follow commit convention (e.g. `feat(auth): add token refresh endpoint`)
3. **Description**: fill out the PR template — what, why, how to test
4. **Tests**: include tests for new behavior; update existing tests if behavior changed
5. **CI must pass**: all GitHub Actions checks must be green before merge
6. **One concern per PR**: don't mix unrelated features or fixes

### PR Checklist

```
[ ] make build passes locally
[ ] make test passes locally
[ ] cargo clippy -- -D warnings clean (Rust)
[ ] go vet ./... clean (Go)
[ ] New environment variables documented in PR description
[ ] README updated if new features were added
[ ] CHANGELOG.md updated under [Unreleased]
[ ] Branch is up to date with develop
```

---

## Project Structure

```
vulncore/
│
├── scanner/                    # Rust — core scanner engine
│   └── src/
│       ├── main.rs             # CLI entry point (clap)
│       ├── lib.rs              # Crate root — re-exports modules
│       ├── models.rs           # Shared types: PortResult, Vulnerability, ScanOutput
│       ├── port_scanner.rs     # Async TCP scanner (Tokio + Semaphore)
│       ├── service_detector.rs # Banner grabbing and service fingerprinting
│       ├── cve_matcher.rs      # OSV.dev + CISA KEV + EPSS queries
│       ├── pkg_reader.rs       # dpkg / rpm / pacman / apk readers
│       └── tests.rs            # Unit tests
│
├── api/                        # Go — REST API and orchestrator
│   ├── main.go                 # Router setup, middleware wiring, server start
│   ├── go.mod / go.sum
│   ├── middleware/
│   │   └── auth.go             # RequireAuth() gin middleware, TokenFromCredentials()
│   ├── handlers/
│   │   ├── auth.go             # Login, Me
│   │   ├── scan.go             # RunFullScan, GetScanStatus, ScanPorts, ScanPackages
│   │   ├── reports.go          # GetVulnerabilities, GetLastReport, GetAllReports
│   │   ├── dashboard.go        # GetStats, GetTimeline, GetHistory
│   │   ├── export.go           # ExportLastReport (JSON / CSV)
│   │   └── handlers_test.go    # HTTP handler tests using httptest
│   ├── bridge/
│   │   └── rust_ffi.go         # Subprocess bridge: runs vulncore-scanner, parses JSON
│   ├── db/
│   │   └── sqlite.go           # GORM models, Init(), WAL config, indexes
│   ├── scheduler/
│   │   └── cron.go             # Daily full scan + hourly port scan
│   └── webhooks/
│       └── sender.go           # Slack / Discord webhook notifications
│
├── web/                        # Frontend — no build step required
│   ├── index.html              # Main dashboard SPA
│   ├── login.html              # Authentication page
│   └── assets/
│       ├── css/hacker.css      # Full design system (Space Grotesk + JetBrains Mono)
│       └── js/hacker.js        # Dashboard logic, auth guard, fetch interceptor
│
├── configs/
│   ├── vulncore.toml           # Application configuration
│   └── vulncore.service        # systemd service unit
│
├── .github/
│   ├── workflows/ci.yml        # Rust + Go build/test/lint pipeline
│   ├── ISSUE_TEMPLATE/         # Bug report, feature request, security
│   └── PULL_REQUEST_TEMPLATE/
│
├── Dockerfile                  # Multi-stage: rust-builder → go-builder → final
├── docker-compose.yml          # Single-command deployment
├── .dockerignore
├── Makefile                    # build, run, test, check, clean, zip
├── install.sh                  # Automated multi-distro installer
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md             # This file
└── SECURITY.md
```

---

## Testing

### Running Tests

```bash
# All tests
make test

# Rust only
cd scanner && cargo test --verbose

# Go only
cd api && go test ./... -v

# Go with coverage report
cd api && go test ./... -coverprofile=coverage.out && go tool cover -html=coverage.out
```

### Writing Tests

**Rust (`scanner/src/tests.rs`)** — add `#[test]` functions at module level. The `tests.rs` file is declared as `mod tests` in `lib.rs`; do not add a wrapper `mod tests {}` inside the file.

```rust
#[test]
fn test_your_feature() {
    // arrange
    let input = ...;
    // act
    let result = your_function(input);
    // assert
    assert_eq!(result, expected);
}
```

**Go (`api/handlers/handlers_test.go`)** — use `httptest` with a fresh in-memory database per test.

```go
func TestYourEndpoint(t *testing.T) {
    r, _ := setupRouter(t)
    w := httptest.NewRecorder()
    req, _ := http.NewRequest("GET", "/api/your-endpoint", nil)
    r.ServeHTTP(w, req)
    if w.Code != http.StatusOK {
        t.Errorf("Expected 200, got %d", w.Code)
    }
}
```

**Important Go test notes:**
- `db.Init(":memory:")` skips WAL pragmas (WAL is incompatible with SQLite in-memory databases)
- `GetScanStatus` always returns 200 — `status` field equals `"error"` for unknown IDs
- `GetLastReport` returns 200 with `{scan: null, ...}` when no completed scans exist

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VULNCORE_PORT` | No | `8080` | API server port |
| `VULNCORE_ENV` | No | `development` | Set `production` for Gin release mode |
| `VULNCORE_SCANNER_PATH` | No | `./vulncore-scanner` | Path to Rust binary |
| `VULNCORE_DEFAULT_TARGET` | No | `127.0.0.1` | Default scan target for scheduler |
| `VULNCORE_DB_PATH` | No | auto | Override SQLite path |
| `VULNCORE_USERNAME` | No | `admin` | Login username |
| `VULNCORE_PASSWORD` | **Yes** | — | Login password (required for auth) |
| `VULNCORE_SECRET` | No | built-in | HMAC secret for token signing |
| `VULNCORE_WEBHOOK_URL` | No | — | Slack or Discord webhook URL |
| `VULNCORE_WEBHOOK_MIN_SEVERITY` | No | `CRITICAL` | Alert threshold (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`) |

---

## Questions?

Open a [Discussion](https://github.com/KikeGonRam/vulncore/discussions) — we're happy to help.