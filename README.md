# VulnCore 🛡️

**High-performance vulnerability scanner for Linux servers.**  
Built with Rust (scanner engine) + Go (REST API) + Web dashboard.

[![CI](https://github.com/KikeGonRam/vulncore/actions/workflows/ci.yml/badge.svg)](https://github.com/KikeGonRam/vulncore/actions)
![License](https://img.shields.io/badge/license-MIT-blue)
![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)
![Go](https://img.shields.io/badge/go-1.22%2B-blue)
![Linux](https://img.shields.io/badge/platform-linux-green)
![Docker](https://img.shields.io/badge/docker-ready-2496ED)

---

## Features

- **Port Scanner** — Fast async TCP scanner with service fingerprinting and banner grabbing
- **Package CVE Matching** — Reads `dpkg` / `rpm` / `pacman` / `apk` and queries OSV.dev + CISA KEV + EPSS APIs
- **Web Dashboard** — Real-time threat intelligence with severity charts, scan history and timeline
- **Authentication** — Bearer token login protecting all API routes
- **Export Reports** — Download scan results as JSON or CSV with one click
- **Webhook Alerts** — Notify Slack or Discord when CRITICAL/HIGH vulnerabilities are found
- **Scheduled Scans** — Daily full scan at 02:00 + hourly port scan via built-in cron
- **REST API** — Full JSON API for integration with external tools
- **Docker Ready** — Multi-stage Docker image and `docker-compose.yml` included
- **Multi-distro** — Ubuntu, Debian, Fedora, RHEL, Arch, Alpine Linux

---

## Architecture

```
scanner/   → Rust  — async port scanning, service detection, CVE/KEV/EPSS matching
api/       → Go    — REST API, auth middleware, scheduler, SQLite persistence, webhooks
web/       → HTML  — dashboard (no build step required), login page
configs/   → TOML  — configuration file, systemd service unit
```

---

## Requirements

| Tool    | Version        | Notes                          |
|---------|----------------|--------------------------------|
| Rust    | 1.75+          | For building the scanner       |
| Go      | 1.22+          | For building the API           |
| Linux   | Any modern     | WSL2 supported                 |
| Docker  | 24+            | Optional — for containerized deploy |

---

## Quick Start

### Option A — Docker (recommended for production)

```bash
# 1. Clone
git clone https://github.com/KikeGonRam/vulncore
cd vulncore

# 2. Set your password in docker-compose.yml (VULNCORE_PASSWORD)
# 3. Build and start
docker-compose up --build -d

# Dashboard → http://localhost:8080
# Default credentials: admin / changeme123 (change before deploying!)
```

### Option B — Build from source (development)

```bash
# 1. Clone
git clone https://github.com/KikeGonRam/vulncore
cd vulncore

# 2. Install dependencies
make deps

# 3. Build (Rust scanner + Go API)
make build

# 4. Run with authentication
VULNCORE_PASSWORD=yourpassword make run
# → Dashboard: http://localhost:8080
# → Login:     http://localhost:8080/login
```

---

## Authentication

All `/api/*` routes (except `/api/health` and `/api/auth/login`) require a Bearer token.

```bash
# 1. Login
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpassword"}'
# Returns: {"token": "abc123...", "username": "admin"}

# 2. Use the token
curl http://localhost:8080/api/dashboard/stats \
  -H "Authorization: Bearer abc123..."
```

The web dashboard handles authentication automatically — it redirects to `/login` when no token is present, stores the token in `localStorage`, and attaches it to every API request.

---

## Usage

### Web Dashboard

Open `http://localhost:8080` in your browser. Log in with your credentials.

From the dashboard you can:
- Run scans (Full / Ports only / Packages only)
- View real-time vulnerability data and severity charts
- Browse CVEs, open ports, and installed packages
- Export reports as JSON or CSV
- See full scan history

### CLI — Port Scan

```bash
./dist/vulncore-scanner ports --target 192.168.1.1 --range 1-65535
```

### CLI — Package CVE Scan

```bash
./dist/vulncore-scanner packages
```

### CLI — Full Scan

```bash
./dist/vulncore-scanner full --target 127.0.0.1 --range 1-9999
```

### API — Trigger a scan

```bash
TOKEN="your-token-here"

# Full scan
curl -X POST http://localhost:8080/api/scan/full \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","port_range":"1-9999","scan_type":"full"}'

# Ports only (faster)
curl -X POST http://localhost:8080/api/scan/full \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","port_range":"1-1024","scan_type":"ports"}'

# Packages only
curl -X POST http://localhost:8080/api/scan/full \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","scan_type":"packages"}'
```

### API — Export a report

```bash
# JSON report
curl "http://localhost:8080/api/reports/last/export?format=json" \
  -H "Authorization: Bearer $TOKEN" -o report.json

# CSV report
curl "http://localhost:8080/api/reports/last/export?format=csv" \
  -H "Authorization: Bearer $TOKEN" -o report.csv
```

---

## API Reference

All routes except `/api/health` and `/api/auth/login` require `Authorization: Bearer <token>`.

| Method | Endpoint                      | Description                            |
|--------|-------------------------------|----------------------------------------|
| GET    | `/api/health`                 | Health check (public)                  |
| POST   | `/api/auth/login`             | Authenticate and get token (public)    |
| GET    | `/api/auth/me`                | Verify current token                   |
| POST   | `/api/scan/full`              | Start async scan (full/ports/packages) |
| GET    | `/api/scan/ports`             | Synchronous port-only scan             |
| GET    | `/api/scan/packages`          | Synchronous package CVE scan           |
| GET    | `/api/scan/:id/status`        | Poll scan status + live summary        |
| GET    | `/api/vulnerabilities`        | List CVEs with filters                 |
| GET    | `/api/vulnerabilities/:id`    | Single CVE detail                      |
| GET    | `/api/reports/last`           | Last completed scan report             |
| GET    | `/api/reports/last/export`    | Export report as JSON or CSV           |
| GET    | `/api/reports`                | All scan reports                       |
| GET    | `/api/dashboard/stats`        | Aggregated statistics                  |
| GET    | `/api/dashboard/timeline`     | 30-day vulnerability timeline          |
| GET    | `/api/history`                | Scan history with counts               |

### Scan type parameter

The `POST /api/scan/full` endpoint accepts a `scan_type` field:

| Value      | What it runs                          | Speed  |
|------------|---------------------------------------|--------|
| `full`     | Port scan + package CVE matching      | Slow   |
| `ports`    | TCP port scan only                    | Fast   |
| `packages` | Package CVE matching only (no target) | Medium |

### Vulnerability filters

`GET /api/vulnerabilities` accepts query parameters:

| Parameter  | Example           | Description               |
|------------|-------------------|---------------------------|
| `severity` | `CRITICAL`        | Filter by severity level  |
| `package`  | `openssl`         | Filter by package name    |
| `scan_id`  | `uuid-here`       | Filter by scan            |
| `exploited`| `true`            | Show only KEV entries     |
| `limit`    | `300`             | Max results (default 100) |

---

## Configuration

### Environment Variables

| Variable                         | Default          | Description                              |
|----------------------------------|------------------|------------------------------------------|
| `VULNCORE_PORT`                  | `8080`           | API server port                          |
| `VULNCORE_ENV`                   | `development`    | Set `production` for release mode        |
| `VULNCORE_SCANNER_PATH`          | `./vulncore-scanner` | Path to Rust binary                 |
| `VULNCORE_DEFAULT_TARGET`        | `127.0.0.1`      | Default target for scheduled scans       |
| `VULNCORE_DB_PATH`               | auto-detected    | SQLite file path (Linux FS recommended)  |
| `VULNCORE_USERNAME`              | `admin`          | Dashboard login username                 |
| `VULNCORE_PASSWORD`              | *(required)*     | Dashboard login password                 |
| `VULNCORE_SECRET`                | *(required)*     | HMAC secret for token signing            |
| `VULNCORE_WEBHOOK_URL`           | *(empty)*        | Slack or Discord webhook URL             |
| `VULNCORE_WEBHOOK_MIN_SEVERITY`  | `CRITICAL`       | Minimum severity to trigger alert        |

### TOML config file

Copy and edit `configs/vulncore.toml` for fine-grained control over scan defaults, scheduler timing, and API keys.

---

## Webhook Alerts

VulnCore can send alerts to Slack or Discord when a scan completes and finds vulnerabilities above the configured severity threshold.

**Slack:**
```bash
VULNCORE_WEBHOOK_URL=https://hooks.slack.com/services/T00/B00/xxxx
VULNCORE_WEBHOOK_MIN_SEVERITY=HIGH
```

**Discord:**
```bash
VULNCORE_WEBHOOK_URL=https://discord.com/api/webhooks/xxxx/yyyy
VULNCORE_WEBHOOK_MIN_SEVERITY=CRITICAL
```

The webhook payload includes the scan target, scan type, session ID, and a breakdown by severity level.

---

## CVE Data Sources

| Source     | Type     | Notes                                      |
|------------|----------|--------------------------------------------|
| OSV.dev    | REST API | Free, no key required                      |
| CISA KEV   | JSON feed| Known Exploited Vulnerabilities catalog    |
| EPSS       | REST API | Exploit Prediction Scoring System (FIRST)  |

---

## Severity Scoring

| Level      | CVSS Score | Action                    |
|------------|------------|---------------------------|
| 🔴 CRITICAL | ≥ 9.0      | Immediate patch required  |
| 🟠 HIGH     | 7.0–8.9    | Urgent review             |
| 🟡 MEDIUM   | 4.0–6.9    | Monitor and plan patch    |
| 🟢 LOW      | < 4.0      | Informational             |

---

## Docker

### Build and run

```bash
docker-compose up --build -d
```

### Persistent data

Scan results are stored in a Docker volume (`vulncore-data`). The database persists across container restarts.

```bash
# View logs
docker-compose logs -f

# Stop
docker-compose down

# Stop and remove data
docker-compose down -v
```

### Production checklist

- [ ] Change `VULNCORE_PASSWORD` from the default `changeme123`
- [ ] Set a strong random `VULNCORE_SECRET` (e.g. `openssl rand -hex 32`)
- [ ] Put a reverse proxy (nginx / Caddy) in front for TLS
- [ ] Set `VULNCORE_ENV=production`

---

## WSL2 Notes

If you're running from a Windows-mounted path (`/mnt/c/...`), VulnCore automatically redirects the SQLite database to `~/.vulncore/vulncore.db` on the Linux filesystem. This avoids POSIX file-locking errors caused by NTFS.

You can override this with `VULNCORE_DB_PATH=/your/linux/path/vulncore.db`.

---

## Roadmap

- [x] v0.1 — Port scanner + API core
- [x] v0.2 — Package reader + OSV/CISA KEV/EPSS integration
- [x] v0.3 — Web dashboard with real-time charts
- [x] v0.4 — Authentication + JSON/CSV export + webhook alerts
- [x] v0.5 — Docker multi-stage image + docker-compose
- [ ] v0.6 — Differential reports (new CVEs since last scan)
- [ ] v0.7 — UDP scanning support
- [ ] v1.0 — `.deb` / `.rpm` / AUR packages

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

```bash
# Quick start for contributors
git checkout -b feat/my-feature
make build && make test
git commit -m "feat(scope): description"
git push origin feat/my-feature
# Open a Pull Request targeting develop
```

---

## License

MIT © 2026 Luis Enrique Gonzalez Ramirez — see [LICENSE](LICENSE)