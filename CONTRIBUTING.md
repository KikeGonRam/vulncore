# Contributing to VulnCore 🛡️

First off — thanks for taking the time to contribute! Every bug report, idea, and pull request makes VulnCore better for everyone.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Branch Naming](#branch-naming)
- [Commit Convention](#commit-convention)
- [Pull Request Process](#pull-request-process)
- [Project Structure](#project-structure)

---

## Code of Conduct

Be respectful. We don't tolerate harassment, discrimination, or toxic behavior of any kind. This is a learning-friendly project — no question is too basic.

---

## How Can I Contribute?

### 🐛 Report a Bug
Open an issue using the **Bug Report** template. Include:
- Your Linux distro and version
- Steps to reproduce
- Expected vs actual behavior
- Logs if available (`journalctl -u vulncore -f`)

### 💡 Suggest a Feature
Open an issue using the **Feature Request** template. Describe the problem you're trying to solve, not just the solution.

### 🔧 Submit a Fix or Feature
1. Check existing issues/PRs to avoid duplicates
2. Fork the repo and create your branch
3. Write code + tests
4. Open a Pull Request

### 📖 Improve Documentation
Fix typos, clarify instructions, add examples — docs PRs are always welcome.

---

## Development Setup

### Prerequisites
| Tool    | Version |
|---------|---------|
| Rust    | 1.75+   |
| Go      | 1.22+   |
| Git     | any     |
| Linux   | any modern distro (WSL2 works) |

### Local Setup

```bash
# Fork & clone
git clone https://github.com/YOUR_USERNAME/vulncore.git
cd vulncore

# Install dependencies
make deps

# Build everything
make build

# Run tests
make test

# Start dev server
make run
# → http://localhost:8080
```

---

## Branch Naming

```
feat/short-description      → new feature
fix/short-description       → bug fix
docs/short-description      → documentation only
refactor/short-description  → code refactor, no behavior change
test/short-description      → adding or fixing tests
chore/short-description     → build, CI, tooling changes
```

Examples:
```
feat/webhook-alerts
fix/port-scanner-timeout
docs/api-reference
```

---

## Commit Convention

We follow **Conventional Commits**:

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

### Types
| Type       | When to use |
|------------|-------------|
| `feat`     | New feature |
| `fix`      | Bug fix |
| `docs`     | Documentation changes |
| `test`     | Adding or updating tests |
| `refactor` | Code change with no feature/fix |
| `perf`     | Performance improvement |
| `chore`    | Build process, CI, dependencies |
| `style`    | Formatting, whitespace |

### Examples
```
feat(scanner): add UDP port scanning support
fix(cve-matcher): handle OSV API rate limit correctly
docs(readme): add Docker deployment section
test(api): add scan handler integration tests
chore(ci): add release artifact upload step
```

---

## Pull Request Process

1. **Target branch**: always `develop`, never `main` directly
2. **Title**: follow commit convention (e.g. `feat(dashboard): add dark/light theme toggle`)
3. **Description**: fill out the PR template — what, why, how
4. **Tests**: include tests for new behavior
5. **CI must pass**: all GitHub Actions checks green
6. **One concern per PR**: don't mix features and unrelated fixes

### PR Checklist
```
[ ] Code builds without errors (make build)
[ ] Tests pass (make test)
[ ] No clippy warnings (Rust)
[ ] No go vet warnings (Go)
[ ] Added/updated tests if needed
[ ] Updated README or docs if needed
[ ] Branch is up to date with develop
```

---

## Project Structure

```
vulncore/
├── scanner/          # Rust — core engine
│   └── src/
│       ├── port_scanner.rs     # TCP port scanning
│       ├── service_detector.rs # Banner grabbing
│       ├── cve_matcher.rs      # OSV/NVD CVE lookup
│       ├── pkg_reader.rs       # dpkg/rpm/pacman/apk
│       └── models.rs           # shared data types
│
├── api/              # Go — REST API + orchestrator
│   ├── main.go
│   ├── handlers/     # HTTP endpoint handlers
│   ├── bridge/       # Rust↔Go subprocess bridge
│   ├── db/           # SQLite models + migrations
│   └── scheduler/    # Cron-based auto scans
│
├── web/              # Frontend dashboard (vanilla JS)
│   └── index.html
│
└── configs/          # TOML config, systemd service
```

---

## Questions?

Open a [Discussion](https://github.com/YOUR_USERNAME/vulncore/discussions) — we're happy to help.
