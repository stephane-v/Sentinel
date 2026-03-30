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
- **Sentinel scans itself** — no blanket self-exclusion; only `scanner/iocs/` and `scanner/i18n/` (which contain IOC patterns by definition) are filtered
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

# Directories to exclude (comma-separated, empty by default)
# Sentinel's own IOC data files are automatically filtered
EXCLUDE_DIRS=

# Minimum severity threshold: low, medium, high, critical
SEVERITY_MIN=medium

# Report language: en or fr
REPORT_LANG=en

# Auto-update IOCs from public feeds during 'update' command
IOC_AUTO_UPDATE=true

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
EXCLUDE_DIRS=old-project,archive docker compose run --rm sentinel
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
| `EXCLUDE_DIRS` | *(empty)* | Directories to exclude from scan (comma-separated) |
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

## Included IOC databases

The IOC lists cover known supply chain attacks:
- **Shai-Hulud** v1/v2 (npm, Sept 2025)
- **LiteLLM TeamPCP** (PyPI, March 2026)
- **Cline CLI** compromised (npm, Feb 2026)
- PyPI typosquatting (termncolor, colorinal, etc.)
- Exfiltration patterns (webhook.site, C2 domains)
- Invisible Unicode characters (GlassWorm technique)

## Maintaining IOC databases

### Automatic updates

Running `sentinel update` refreshes three databases:

1. **Grype** vulnerability database (Anchore)
2. **OSV-Scanner** offline database (Google)
3. **IOC lists** from public threat intelligence feeds:
   - [OSV.dev](https://osv.dev) API — advisories prefixed `MAL-` (confirmed malware) for npm and PyPI
   - [GitHub Advisory Database](https://github.com/advisories) — advisories classified as `MALWARE` for npm and pip

```bash
docker compose run --rm sentinel update
```

Updated IOCs are written directly to `scanner/iocs/` (bind-mounted read-write). You can review and commit:

```bash
git diff scanner/iocs/
git add scanner/iocs/
git commit -m "chore: update IOC feeds $(date +%Y-%m-%d)"
git push
```

Set `IOC_AUTO_UPDATE=false` in `.env` to disable feeds (air-gapped environments).

### Manual contributions

Each IOC file has a specific format:

| File | Format | Example |
|------|--------|---------|
| `compromised_npm.txt` | `package@version` | `@ctrl/tinycolor@4.1.1` |
| `compromised_pypi.txt` | `package@version` | `litellm@1.82.7` |
| `malicious_files.txt` | filename (one per line) | `setup_bun.js` |
| `malicious_patterns.txt` | grep pattern (one per line) | `Shai-Hulud` |
| `malicious_hashes.txt` | SHA-256 hash (one per line) | `de0e25a3e6c1...` |

Lines starting with `#` are comments. To contribute: fork the repo, add entries to the relevant file, keep it sorted, and submit a pull request with a reference to the advisory.

### When a new attack is disclosed

1. **Find the IOCs** — check the advisory for: compromised package names and versions, malicious filenames, SHA-256 hashes, grep patterns, exfiltration domains
2. **Add to the right file** — each IOC type goes in its specific file
3. **Test** — run Sentinel against a known-clean project to verify no false positives
4. **Submit** — open a PR or push directly

Example — adding Shai-Hulud v2 IOCs:

```
# compromised_npm.txt
posthog-js@1.96.1

# malicious_files.txt
setup_bun.js
bun_environment.js

# malicious_patterns.txt
Sha1-Hulud: The Second Coming

# malicious_hashes.txt
de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6
```

### Update schedule

- **Before each build session**: `sentinel update` then `sentinel scan`
- **Weekly** at minimum if not actively building
- **Immediately** after a major supply chain attack is disclosed

### Verifying database freshness

The report header shows the Grype DB date (`Grype DB: 2026-03-28`). For IOC files, check git history:

```bash
git log --oneline scanner/iocs/
```

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
