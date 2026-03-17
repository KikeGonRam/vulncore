# Changelog

All notable changes to VulnCore are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [Unreleased]

### Planned
- Differential reports — show only new CVEs since last scan
- UDP port scanning support
- `.deb` / `.rpm` / AUR package distribution
- Dark/light theme toggle on dashboard
- Scan scheduling via UI (not just cron)
- Rate limiting on API endpoints

---

## [0.5.0] — 2026-03-17

### Added
- **Docker multi-stage build** — Rust + Go compiled in separate build stages, minimal final image based on `debian:bookworm-slim`
- **docker-compose.yml** — Single command deployment with persistent volume for SQLite
- **`.dockerignore`** — Excludes build artifacts, database files, and secrets from Docker context
- **Health check endpoint** — `GET /api/health` returns `{"status":"ok"}`, used by Docker healthcheck

### Changed
- `api/main.go` — Added `/api/health` route; root `/` now redirects to dashboard
- `configs/vulncore.service` — Updated `ReadWritePaths` to match Docker volume path

---

## [0.4.0] — 2026-03-17

### Added
- **Authentication** (`api/middleware/auth.go`, `api/handlers/auth.go`) — Bearer token auth protecting all `/api/*` routes
  - `POST /api/auth/login` — validates credentials, returns HMAC-signed token
  - `GET /api/auth/me` — verifies current token
  - Token derived from `VULNCORE_USERNAME` + `VULNCORE_SECRET` via HMAC-SHA256
- **Login page** (`web/login.html`) — standalone auth page with the same dark cybersecurity aesthetic
  - Stores token in `localStorage`, redirects to `/login` on `401`
  - Auto-validates existing token on load
- **JSON/CSV export** (`api/handlers/export.go`) — `GET /api/reports/last/export?format=json|csv`
  - JSON: full structured report with summary, vulnerabilities, ports, packages
  - CSV: flat vulnerability list, ready for spreadsheet import
  - Both trigger browser download with timestamped filename
- **Webhook alerts** (`api/webhooks/sender.go`) — fires after every completed scan
  - Supports Slack (Block Kit format) and Discord (plain content)
  - Configurable minimum severity via `VULNCORE_WEBHOOK_MIN_SEVERITY`
  - Sends in a goroutine — never blocks scan execution
- **Scan type selector** — `POST /api/scan/full` now accepts `scan_type` field (`full`/`ports`/`packages`)
  - Dashboard modal shows 3 visual cards with speed indicators
  - Packages-only scan disables the port range input automatically

### Changed
- `api/main.go` — All `/api/*` routes except health and login now require auth middleware
- `api/handlers/scan.go` — `executeScan` dispatches to correct Rust command based on `scan_type`; triggers webhook on completion
- `web/assets/js/hacker.js` — Fetch interceptor injects `Authorization` header automatically; logout function clears localStorage
- `web/index.html` — Topbar shows logged-in username, JSON/CSV export buttons, and logout button

### Environment Variables Added
| Variable | Default | Description |
|----------|---------|-------------|
| `VULNCORE_USERNAME` | `admin` | Login username |
| `VULNCORE_PASSWORD` | *(required)* | Login password |
| `VULNCORE_SECRET` | *(required)* | HMAC signing secret |
| `VULNCORE_WEBHOOK_URL` | *(empty)* | Slack or Discord webhook URL |
| `VULNCORE_WEBHOOK_MIN_SEVERITY` | `CRITICAL` | Alert threshold |

---

## [0.3.0] — 2026-03-17

### Added
- **Dashboard redesign** — New cybersecurity aesthetic using Space Grotesk + JetBrains Mono
  - CRT scanline overlay effect
  - Stat cards with colored bottom accent bar and count-up animation
  - Window frames with macOS-style traffic light dots
  - Real-time system clock in topbar
  - Sidebar active indicator with cyan glow
- **Scan console** — Live log output during scan execution with progress bar
- **History table** — Session ID, target, type, status, start time, duration, vuln count, port count

### Changed
- `web/assets/css/hacker.css` — Complete rewrite; CSS variables for all colors, responsive sidebar collapses to icons at <900px
- `web/assets/js/hacker.js` — `loadDashboard` destroys charts before re-fetching to prevent stale state; charts navigate to dashboard page before re-rendering so canvas is visible
- `web/index.html` — History thead corrected to 8 columns matching JS output; default port range changed to `1-9999` to include port 8080; scan type modal added

### Fixed
- Charts failing to re-render after scan completion — canvas must be visible (in active page) before Chart.js initializes
- History row `(s.ID ?? s.id ?? "").substring is not a function` — GORM returns `uint` IDs; converted with `str()` helper before `.substring()`
- Port state filter — GORM serializes `"open"` in lowercase from SQLite; `loadPorts` now normalizes with `.toLowerCase()`
- `UNKNOWN` severity chip — `chip()` now strips non-alpha characters and falls back gracefully

---

## [0.2.0] — 2026-03-16

### Added
- **SQLite performance tuning** (`api/db/sqlite.go`)
  - WAL journal mode + memory-mapped I/O via DSN parameters
  - GORM indexes on all frequently-queried columns (`status`, `severity`, `scan_id`, composite port index)
  - `SkipDefaultTransaction`, `PrepareStmt`, Silent logger
  - WAL parameters skipped for `:memory:` databases (used in tests)
- **WSL2 SQLite fix** (`api/main.go`) — Detects `/mnt/c` prefix and redirects DB to `~/.vulncore/vulncore.db` on the Linux filesystem
- **Scanner timeout** (`api/bridge/rust_ffi.go`) — `context.WithTimeout` on all subprocess calls (10 min full, 2 min ports); ANSI escape stripping; JSON extraction skips leading log lines
- **CISA KEV integration** (`scanner/src/cve_matcher.rs`) — Fetches live Known Exploited Vulnerabilities catalog, marks `is_exploited = true` on matches
- **EPSS integration** (`scanner/src/cve_matcher.rs`) — Fetches Exploit Prediction Scoring System scores in batches of 50

### Changed
- `api/handlers/scan.go` — `GetScanStatus` always returns 200 (status field = `"error"` for unknown IDs); `RunFullScan` returns 500 if DB create fails
- `api/handlers/dashboard.go` — `GetStats` uses `Find()` + `Limit(1)` instead of `First()` to avoid GORM "record not found" log spam; `GetTimeline` returns `[]TimelinePoint{}` instead of `null` when empty
- `api/handlers/reports.go` — `GetLastReport` returns 200 with `{scan:null, ports:[], packages:[], vulnerabilities:[]}` when no completed scans exist
- `web/assets/js/hacker.js` — Poll stops on `status === 'error'`; max 300 poll attempts (15 min); full dashboard refresh + navigation after scan completes

### Fixed
- `go.sum` missing from CI — removed from `.gitignore`; `go mod tidy` added before `go vet` in CI
- Rust `cargo fmt` import order in `cve_matcher.rs`
- Infinite polling when scanner binary not found
- SQLite disk I/O errors on WSL2 NTFS mounts

---

## [0.1.0] — 2026-03-16

### Added
- **Port Scanner (Rust)** — Async TCP scanner using Tokio with configurable concurrency and timeout; service fingerprinting for 25+ well-known ports
- **Service Detector (Rust)** — Banner grabbing via raw TCP probes for SSH, HTTP, FTP, SMTP, MySQL, Redis, MongoDB, Elasticsearch
- **Package Reader (Rust)** — Reads installed packages from `dpkg`, `rpm`, `pacman`, `apk`
- **CVE Matcher (Rust)** — Queries OSV.dev API per package; 200ms rate limit between requests to avoid throttling
- **REST API (Go)** — Gin framework with CORS, structured logging, graceful shutdown
  - `POST /api/scan/full` — async full scan
  - `GET /api/scan/:id/status` — poll scan status
  - `GET /api/vulnerabilities` — CVE list with severity/package filters
  - `GET /api/dashboard/stats` — aggregated statistics
  - `GET /api/dashboard/timeline` — 30-day vulnerability timeline
  - `GET /api/history` — scan history
- **SQLite persistence** — GORM models for `Scan`, `Vulnerability`, `Port`, `Package` with `AutoMigrate`
- **Scheduled scans** — daily full scan at 02:00, hourly port scan via `robfig/cron`
- **Web Dashboard** — vanilla JS + Chart.js; severity stat cards, donut chart, timeline chart, top vulnerable packages, CVE table, port table, package inventory
- **GitHub Actions CI** — Rust (fmt, clippy, test, build release) + Go (vet, test, build) jobs; release artifact packaging on `main`
- **systemd service unit** — `ProtectSystem`, `NoNewPrivileges`, `PrivateTmp` hardening
- **install.sh** — automated multi-distro installer (apt/dnf/pacman/apk)
- **Makefile** — `build`, `run`, `test`, `check`, `install`, `clean`, `zip` targets

### Security
- Rust memory safety on all network-facing scanner code
- Async Tokio runtime — no blocking I/O in the port scanner
- Go API intended to run as unprivileged user via systemd service

---

[Unreleased]: https://github.com/KikeGonRam/vulncore/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/KikeGonRam/vulncore/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/KikeGonRam/vulncore/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/KikeGonRam/vulncore/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/KikeGonRam/vulncore/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/KikeGonRam/vulncore/releases/tag/v0.1.0