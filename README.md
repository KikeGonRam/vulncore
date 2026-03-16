# VulnCore 🛡️

**High-performance vulnerability scanner for Linux servers.**  
Built with Rust (scanner engine) + Go (API & orchestrator) + Web dashboard.

![License](https://img.shields.io/badge/license-MIT-blue)
![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)
![Go](https://img.shields.io/badge/go-1.22%2B-blue)
![Linux](https://img.shields.io/badge/platform-linux-green)

---

## Features

- **Port Scanner** — Fast async TCP scanner with service fingerprinting & banner grabbing
- **Package CVE Matching** — Reads dpkg / rpm / pacman / apk and queries OSV.dev + NVD APIs
- **Web Dashboard** — Real-time vulnerability overview, severity charts, scan history
- **Scheduled Scans** — Daily full scan + hourly port scan via built-in cron scheduler
- **REST API** — Full JSON API for integration with other tools
- **Multi-distro** — Ubuntu, Debian, Fedora, RHEL, Arch, Alpine Linux

---

## Architecture

```
scanner/   → Rust  — port scanning, service detection, CVE matching
api/       → Go    — REST API, scheduler, SQLite persistence
web/       → HTML  — dashboard (no build step required)
configs/   → TOML  — configuration
```

---

## Requirements

| Tool | Version |
|------|---------|
| Rust | 1.75+   |
| Go   | 1.22+   |
| Linux | Any modern distro |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/yourusername/vulncore
cd vulncore

# 2. Install dependencies
make deps

# 3. Build everything
make build

# 4. Run
make run
# → Dashboard: http://localhost:8080
# → API:       http://localhost:8080/api
```

---

## Usage

### Web Dashboard
Open `http://localhost:8080` in your browser.

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
./dist/vulncore-scanner full --target 127.0.0.1 --range 1-1024
```

### API — Trigger a scan
```bash
curl -X POST http://localhost:8080/api/scan/full \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","port_range":"1-1024"}'
```

### API — Get vulnerabilities
```bash
curl "http://localhost:8080/api/vulnerabilities?severity=CRITICAL"
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan/full` | Start full scan |
| GET  | `/api/scan/ports` | Port-only scan |
| GET  | `/api/scan/packages` | Package CVE scan |
| GET  | `/api/scan/:id/status` | Scan status + summary |
| GET  | `/api/vulnerabilities` | List CVEs (filterable) |
| GET  | `/api/vulnerabilities/:id` | CVE detail |
| GET  | `/api/reports/last` | Last scan report |
| GET  | `/api/reports` | All reports |
| GET  | `/api/dashboard/stats` | Dashboard statistics |
| GET  | `/api/dashboard/timeline` | 30-day vulnerability timeline |
| GET  | `/api/history` | Scan history |

---

## Configuration

Copy and edit `configs/vulncore.toml`:

```toml
[server]
port = 8080

[targets]
default = "127.0.0.1"

[scan_defaults]
port_range  = "1-1024"
timeout_ms  = 500
concurrency = 256

[apis]
nvd_api_key = ""  # Optional — increases NVD rate limit
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VULNCORE_PORT` | `8080` | API server port |
| `VULNCORE_ENV` | `development` | Set `production` for release mode |
| `VULNCORE_SCANNER_PATH` | `./vulncore-scanner` | Path to Rust binary |
| `VULNCORE_DEFAULT_TARGET` | `127.0.0.1` | Default scan target |

---

## CVE Data Sources

| Source | Type | Notes |
|--------|------|-------|
| [OSV.dev](https://osv.dev) | REST API | Free, no key required |
| [NVD (NIST)](https://nvd.nist.gov) | REST API | Free, API key recommended |
| Debian Security | JSON feed | Debian/Ubuntu specific |

---

## Severity Scoring

| Level | CVSS Score | Action |
|-------|-----------|--------|
| 🔴 CRITICAL | ≥ 9.0 | Immediate patch required |
| 🟠 HIGH | 7.0–8.9 | Urgent review |
| 🟡 MEDIUM | 4.0–6.9 | Monitor and plan patch |
| 🟢 LOW | < 4.0 | Informational |

---

## Roadmap

- [ ] v0.1 — Port scanner + API core
- [ ] v0.2 — Package reader + NVD/OSV integration
- [ ] v0.3 — Web dashboard
- [ ] v0.4 — Alerting via webhook (Slack/Discord)
- [ ] v0.5 — Differential reports (new CVEs since last scan)
- [ ] v1.0 — .deb / .rpm / AUR packages + systemd service

---

## Contributing

1. Fork the repo
2. Create a branch: `git checkout -b feat/my-feature`
3. Commit: `git commit -m "feat: add X"`
4. Push: `git push origin feat/my-feature`
5. Open a Pull Request

---

## License

MIT © 2026 VulnCore Contributors
