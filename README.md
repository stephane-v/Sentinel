# Sentinel — Supply Chain Security Scanner

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Docker](https://img.shields.io/badge/Docker-required-blue.svg)
![Shell](https://img.shields.io/badge/Written%20in-Bash-orange.svg)

Standalone Docker scanner that detects known vulnerabilities (CVE), compromised packages (supply chain attacks), and security misconfigurations in your projects.

## Features

- **IOC detection** : malicious files, suspicious patterns, invisible Unicode characters (GlassWorm), known payload hashes
- **Python scan** : compromised PyPI packages, unpinned dependencies, CVEs via pip-audit, osv-scanner and Grype
- **Node.js scan** : compromised npm packages, suspicious install scripts, CVEs via npm audit, osv-scanner and Grype
- **Docker analysis** : secrets in Dockerfile (ARG/ENV), sensitive files copied, missing non-root USER, single-stage builds, build.args secrets detection
- **4-level verdict system** : CLEAN / INFO / ATTENTION / CRITICAL with smart false positive filtering
- **Markdown report** generated automatically with summary table and exit code

## Security by design

- `.env` files are **excluded from all scans** — their content (secrets, tokens, API keys) is never read, logged, or sent to external tools
- Project volume is mounted **read-only** (`:ro`)
- Container runs as a **non-root user** (`sentinel`)
- **Multi-stage Docker image** (3 stages) to reduce attack surface
- Container runs with `read_only: true`, `no-new-privileges` and `cap_drop: ALL`
- Tmpfs for `/tmp` and `/var/tmp`

## Embedded tools

| Tool | Role |
|------|------|
| [pip-audit](https://github.com/pypa/pip-audit) | Python vulnerabilities (PyPI/OSV database) |
| [osv-scanner](https://github.com/google/osv-scanner) | Multi-ecosystem (Google OSV database) |
| [grype](https://github.com/anchore/grype) | Vulnerability scanner (Anchore database) |
| npm audit | Built-in Node.js vulnerability scanner |

## Installation

```bash
git clone <repo-url> sentinel
cd sentinel
cp .env.example .env
# Edit .env with your paths and preferences
docker compose build
```

## Configuration

Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

```ini
# Directory containing projects to scan (absolute path)
PROJECTS_DIR=/home/user/projects

# Directories to exclude (comma-separated)
EXCLUDE_DIRS=sentinel

# Minimum severity threshold: low, medium, high, critical
SEVERITY_MIN=medium

# Report language: en or fr
REPORT_LANG=en

# UID/GID for report file permissions
UID=1000
GID=1000
```

The `.env` file is git-ignored (contains local paths).

## Usage

### Scan all projects

```bash
docker compose run --rm sentinel
```

### Scan a specific subdirectory

```bash
docker compose run --rm sentinel scan /projects/my-project
```

### Scan with critical severity only

```bash
SEVERITY_MIN=critical docker compose run --rm sentinel
```

### Exclude directories from scan

```bash
EXCLUDE_DIRS=sentinel,old-project,archive docker compose run --rm sentinel
```

### Update CVE databases

```bash
docker compose run --rm sentinel update
```

### Generate report in French

```bash
REPORT_LANG=fr docker compose run --rm sentinel
```

Command-line variables override `.env` values.

## Example output

```
Verdict: ✅ CLEAN — No issues detected.

| Category                         | Result                              |
|----------------------------------|-------------------------------------|
| Confirmed IOCs (files/hashes)    | ✅ 0 found                          |
| Known compromised packages       | ✅ 0 found                          |
| Malicious hashes                 | ✅ 0 found                          |
| pip-audit vulnerabilities        | ✅ 0 critical                       |
| npm audit vulnerabilities        | ✅ 0 critical                       |
| Grype vulnerabilities            | ✅ 0 found                          |
| Suspicious Unicode (source code) | ✅ 0 found                          |
| Suspicious patterns in code      | ✅ 0 found                          |
| Secrets in build.args            | ✅ 0 found                          |
| Unpinned dependencies            | 💡 ~45 across 8 projects            |
| Dockerfiles without USER         | 💡 3 file(s)                        |
| Single-stage builds              | 💡 2 file(s)                        |
| Filtered false positives         | ⚪ 4 file(s) (binary/i18n/IDE)      |
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROJECTS_DIR` | `/home/user/projects` | Directory containing projects to scan |
| `EXCLUDE_DIRS` | `sentinel` | Directories to exclude (comma-separated) |
| `SCAN_DEPTH` | `4` | Maximum search depth in directory tree |
| `SEVERITY_MIN` | `medium` | Minimum severity threshold: `low`, `medium`, `high`, `critical` |
| `REPORT_FORMAT` | `md` | Report format: `md` or `json` |
| `REPORT_LANG` | `en` | Report language: `en` or `fr` |
| `IOC_AUTO_UPDATE` | `true` | Auto-update IOCs from public feeds (OSV.dev, GitHub Advisories) |
| `UID` | `1000` | Container user UID |
| `GID` | `1000` | Container user GID |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | CLEAN or INFO — no critical issue or IOC detected |
| `1` | ATTENTION — suspicious elements require manual verification |
| `2` | CRITICAL — confirmed IOCs or compromised packages detected |

## Reports

Reports are generated in `./reports/` with the format `sentinel-YYYY-MM-DD_HHMMSS.md`.

## Architecture

```
sentinel/
├── .env.example                # Default configuration (copy to .env)
├── .gitignore
├── docker-compose.yml          # Runs the scanner
├── Dockerfile                  # Multi-stage image (3 stages)
├── LICENSE                     # MIT License
├── scanner/
│   ├── sentinel.sh             # Main script (orchestrator)
│   ├── scan_python.sh          # Python scan (pip-audit + IOCs)
│   ├── scan_node.sh            # Node.js scan (npm audit + IOCs)
│   ├── scan_docker.sh          # Dockerfile + docker-compose analysis
│   ├── scan_iocs.sh            # IOC search (supply chain indicators)
│   ├── update_iocs.sh          # Auto-update IOCs from public feeds
│   ├── i18n/
│   │   ├── en.sh               # English translations (default)
│   │   └── fr.sh               # French translations
│   ├── iocs/
│   │   ├── compromised_npm.txt     # Known compromised npm packages
│   │   ├── compromised_pypi.txt    # Known compromised PyPI packages
│   │   ├── malicious_files.txt     # Known malicious filenames
│   │   ├── malicious_patterns.txt  # Grep patterns for malicious code
│   │   └── malicious_hashes.txt    # SHA-256 hashes of known payloads
│   └── templates/
│       └── report.md.tpl       # Report template
├── reports/                    # Generated reports (persisted via volume)
├── data/                       # CVE databases (persisted via volume)
└── README.md
```

## IOC auto-update

When running `docker compose run --rm sentinel update`, Sentinel automatically fetches the latest malware indicators from public threat intelligence feeds:

- **[OSV.dev](https://osv.dev)** — Google's open vulnerability database. Fetches `MAL-*` advisories (confirmed malware) for npm and PyPI from the last 90 days.
- **[GitHub Advisory Database](https://github.com/advisories)** — GitHub's security advisories. Fetches advisories classified as `MALWARE` for npm and PyPI.

New entries are merged with existing IOC lists without duplicates. Manual entries are never removed. A backup is created before each update.

Set `IOC_AUTO_UPDATE=false` in `.env` to disable (air-gapped environments).

IOC lists are persisted in the `./data/iocs/` volume so updates survive container rebuilds.

## Included IOC databases

The IOC lists cover known supply chain attacks:
- **Shai-Hulud** v1/v2 (npm, Sept 2025)
- **LiteLLM TeamPCP** (PyPI, March 2026)
- **Cline CLI** compromised (npm, Feb 2026)
- PyPI typosquatting (termncolor, colorinal, etc.)
- Exfiltration patterns (webhook.site, C2 domains)
- Invisible Unicode characters (GlassWorm technique)

## Alternatives and positioning

Sentinel does not replace existing security tools — it complements them.

Most supply chain security tools fall into two categories: **CVE scanners** (osv-scanner, Snyk, npm audit) that detect known vulnerabilities after they are published, and **install-time protectors** (Socket.dev, SafeDep PMG, Aikido Safe Chain) that block malicious packages before they enter your project. Sentinel occupies a different niche: **post-incident forensics and Docker security audit**. It answers the question _"have my existing projects been compromised?"_ rather than _"will this new package compromise me?"_.

Sentinel scans your project directories for traces of known supply chain attacks — IOC files, malicious patterns, compromised package versions, invisible Unicode characters — and also audits your Dockerfiles for secret exposure, missing USER directives, and single-stage builds. Everything runs locally in a hardened Docker container. No data leaves your machine.

It is designed for independent developers and small teams who deploy on their own infrastructure, without GitHub Actions, cloud SaaS, or CI/CD pipelines.

For comprehensive protection, consider combining:
1. **Sentinel** — forensic scan of existing projects + Dockerfile audit + IOC detection
2. **osv-scanner** or **npm audit / pip-audit** — known CVE detection (Sentinel already embeds these)
3. **Socket.dev**, **SafeDep PMG**, or **Aikido Safe Chain** — proactive install-time protection

### Detection capabilities

| Capability | Sentinel | Socket.dev | OSV-Scanner | Snyk | npm/pip audit | Safe Chain | PMG | shai-hulud-scanner |
|---|---|---|---|---|---|---|---|---|
| Known CVE detection | ✅ via npm/pip audit, osv-scanner, Grype | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ |
| Zero-day malware detection | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| Campaign IOC detection | ✅ Shai-Hulud, LiteLLM, Cline, GlassWorm | ⚠️ partial | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Shai-Hulud only |
| Behavioral analysis | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| Dockerfile/secrets audit | ✅ | ❌ | ❌ | ⚠️ containers | ❌ | ❌ | ❌ | ❌ |
| Install-time protection | ❌ | ✅ sfw | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| Unicode steganography | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| SHA-256 hash matching | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| SBOM | ❌ | ✅ | ✅ | ✅ | ⚠️ npm sbom | ❌ | ✅ | ❌ |

### Operational characteristics

| Characteristic | Sentinel | Socket.dev | OSV-Scanner | Snyk | npm/pip audit | Safe Chain | PMG | shai-hulud-scanner |
|---|---|---|---|---|---|---|---|---|
| License | MIT | Proprietary | Apache 2.0 | Proprietary | MIT / built-in | Open source | Open source | MIT |
| Runtime dependencies | Docker | Node.js | Go binary | Node.js | Built-in | Node.js | Go binary | Python |
| Ecosystems | npm + pip | 10+ | 11+ | 20+ | 1 each | npm + pip | npm + pip | npm only |
| Works offline | ⚠️ IOCs yes, CVE needs db update | ❌ | ✅ | ❌ | ⚠️ | ❌ | ❌ | ✅ |
| Zero cloud dependency | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ✅ |
| Self-hosted / no SaaS | ✅ | ❌ | ✅ | ❌ | ✅ | ⚠️ | ⚠️ | ✅ |
| Suited for solo dev / small team | ✅ | ⚠️ | ✅ | ⚠️ | ✅ | ✅ | ✅ | ✅ |
| File timestamps in reports | ✅ mtime + birth | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

### Roadmap

Features not yet implemented:
- **ctime anti-timestomping** — Sentinel already displays file birth time and mtime for each detection, but does not yet use kernel ctime (`stat -c '%z'`) which is resistant to timestomping. Future versions will show ctime alongside mtime to help identify backdated files.
- **SBOM generation** — export dependency lists in SPDX/CycloneDX format
- **JSON report format** — `REPORT_FORMAT=json` is accepted but not yet implemented

### Links

| Tool | URL |
|---|---|
| Socket.dev | https://socket.dev |
| OSV-Scanner | https://github.com/google/osv-scanner |
| Snyk | https://snyk.io |
| pip-audit | https://github.com/pypa/pip-audit |
| Aikido Safe Chain | https://github.com/AikidoSec/safe-chain |
| SafeDep PMG | https://github.com/safedep/pmg |
| shai-hulud-scanner | https://github.com/Drasrax/npm-shai-hulud-scanner |

## Contributing

Issues and pull requests welcome.

The easiest way to contribute is to update the IOC lists in `scanner/iocs/`:
- `compromised_npm.txt` — known compromised npm packages
- `compromised_pypi.txt` — known compromised PyPI packages
- `malicious_files.txt` — filenames dropped by known malware
- `malicious_patterns.txt` — grep patterns for malicious code
- `malicious_hashes.txt` — SHA-256 hashes of known payloads

When a new supply chain attack is disclosed, adding its indicators here
helps the entire community detect it.

## License

MIT License — see [LICENSE](LICENSE).
