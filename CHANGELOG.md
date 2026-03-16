# Changelog

All notable changes to VulnCore will be documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- Webhook alerts for critical CVEs (Slack / Discord / Teams)
- Differential reports — show only new CVEs since last scan
- Docker image + docker-compose setup
- `.deb` / `.rpm` / AUR package distribution
- systemd service auto-installer
- Dark/light theme toggle on dashboard

---

## [0.1.0] — 2026-03-16

### Added
- **Port Scanner (Rust)** — async TCP scanner with configurable concurrency and timeout
- **Service Detector (Rust)** — banner grabbing and service fingerprinting on open ports
- **Package Reader (Rust)** — reads installed packages from `dpkg`, `rpm`, `pacman`, `apk`
- **CVE Matcher (Rust)** — queries OSV.dev API and matches packages against known vulnerabilities
- **REST API (Go)** — full JSON API with Gin framework
  - `POST /api/scan/full` — trigger asynchronous full scan
  - `GET  /api/scan/ports` — port-only scan
  - `GET  /api/scan/packages` — package CVE scan
  - `GET  /api/scan/:id/status` — poll scan status
  - `GET  /api/vulnerabilities` — list CVEs with severity/package filters
  - `GET  /api/dashboard/stats` — aggregated statistics
  - `GET  /api/dashboard/timeline` — 30-day vulnerability timeline
  - `GET  /api/history` — scan history
- **SQLite persistence (Go/GORM)** — stores scans, ports, packages, vulnerabilities
- **Scheduled scans** — daily full scan at 02:00 + hourly port scan via cron
- **Web Dashboard** — real-time overview with Chart.js
  - Severity stat cards (Critical / High / Medium / Open Ports)
  - 30-day vulnerability timeline chart
  - Severity distribution donut chart
  - Top vulnerable packages table
  - CVE list with expandable details
  - Port scan results table
  - Package list with search
  - Scan history
  - New scan modal
- **Multi-distro support** — Ubuntu, Debian, Fedora, RHEL, Arch, Alpine
- **Makefile** — unified `build`, `run`, `test`, `install`, `clean` targets
- **GitHub Actions CI** — build + test pipeline for Rust and Go
- **systemd service unit** — production deployment ready
- **install.sh** — automated multi-distro installer

### Security
- Port scanner uses async Tokio runtime — no blocking I/O
- Rust memory safety guarantees on all network-facing code
- Go API runs as unprivileged user in systemd service
- `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem` hardening in service unit

---

[Unreleased]: https://github.com/YOUR_USERNAME/vulncore/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/YOUR_USERNAME/vulncore/releases/tag/v0.1.0
