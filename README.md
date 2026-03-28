# Sentinel — Supply Chain Security Scanner

Scanner Docker autonome qui detecte les vulnerabilites connues (CVE), les paquets compromis (supply chain attacks), et les mauvaises pratiques de securite dans vos projets.

## Fonctionnalites

- **Detection IOCs** : fichiers malveillants, patterns suspects, caracteres Unicode invisibles (GlassWorm), hashes de payloads connus
- **Scan Python** : paquets PyPI compromis, dependances non pinnees, CVE via pip-audit et osv-scanner
- **Scan Node.js** : paquets npm compromis, install scripts suspects, CVE via npm audit et osv-scanner
- **Analyse Docker** : secrets dans Dockerfile (ARG/ENV), fichiers sensibles copies, absence de USER non-root, single-stage builds
- **Rapport Markdown** genere automatiquement avec code retour (0=clean, 1=alertes, 2=critique)

## Securite by design

- Les fichiers `.env` sont **exclus de tous les scans** — leur contenu (secrets, tokens, cles API) n'est jamais lu, journalise, ni envoye a des outils externes
- Le volume des projets est monte en **lecture seule** (`:ro`)
- Le conteneur tourne avec un **utilisateur non-root** (`sentinel`)
- Image Docker **multi-stage** (3 stages) pour reduire la surface d'attaque
- Conteneur en `read_only: true` avec `no-new-privileges` et `cap_drop: ALL`
- Tmpfs pour `/tmp` et `/var/tmp`

## Outils embarques

| Outil | Role |
|-------|------|
| [pip-audit](https://github.com/pypa/pip-audit) | Vulnerabilites Python (base PyPI/OSV) |
| [osv-scanner](https://github.com/google/osv-scanner) | Multi-ecosysteme (base Google OSV) |
| [grype](https://github.com/anchore/grype) | Scanner de vulnerabilites (base Anchore) |
| npm audit | Vulnerabilites Node.js integrees |

## Installation

```bash
git clone <repo-url> sentinel
cd sentinel
cp .env.example .env
# Editer .env avec vos chemins et preferences
docker compose build
```

## Configuration

Copier `.env.example` en `.env` et adapter :

```bash
cp .env.example .env
```

```ini
# Repertoire des projets a scanner (chemin absolu)
PROJECTS_DIR=/home/user/projects

# Repertoires a exclure (separes par des virgules)
EXCLUDE_DIRS=sentinel

# Seuil minimum : low, medium, high, critical
SEVERITY_MIN=medium

# UID/GID pour les permissions des rapports
UID=1000
GID=1000
```

Le fichier `.env` est ignore par git (contient des chemins locaux).

## Utilisation

### Scanner tous les projets

```bash
docker compose run --rm sentinel
```

### Scanner un sous-repertoire specifique

```bash
docker compose run --rm sentinel scan /projects/mon-projet
```

### Scanner avec seuil critique uniquement

```bash
SEVERITY_MIN=critical docker compose run --rm sentinel
```

### Exclure des repertoires du scan

```bash
EXCLUDE_DIRS=sentinel,old-project,archive docker compose run --rm sentinel
```

### Mettre a jour les bases CVE

```bash
docker compose run --rm sentinel update
```

Les variables passees en ligne de commande surchargent celles du `.env`.

## Variables d'environnement

| Variable | Defaut | Description |
|----------|--------|-------------|
| `PROJECTS_DIR` | `/home/user/projects` | Repertoire des projets a scanner |
| `EXCLUDE_DIRS` | `sentinel` | Repertoires a exclure (separes par des virgules) |
| `SCAN_DEPTH` | `4` | Profondeur max de recherche de fichiers |
| `SEVERITY_MIN` | `medium` | Seuil minimum : `low`, `medium`, `high`, `critical` |
| `REPORT_FORMAT` | `md` | Format du rapport : `md` ou `json` |
| `UID` | `1000` | UID de l'utilisateur dans le conteneur |
| `GID` | `1000` | GID de l'utilisateur dans le conteneur |

## Codes de retour

| Code | Signification |
|------|--------------|
| `0` | Aucune vulnerabilite critique ni IOC detecte |
| `1` | Des vulnerabilites ou mauvaises pratiques detectees |
| `2` | IOCs ou paquets compromis detectes — action immediate requise |

## Rapports

Les rapports sont generes dans `./reports/` avec le format `sentinel-YYYY-MM-DD_HHMMSS.md`.

## Architecture

```
sentinel/
├── .env.example                # Configuration par defaut (a copier en .env)
├── .gitignore
├── docker-compose.yml          # Lance le scanner
├── Dockerfile                  # Image multi-stage (3 stages)
├── scanner/
│   ├── sentinel.sh             # Script principal (orchestrateur)
│   ├── scan_python.sh          # Scan pip/PyPI (pip-audit + IOCs)
│   ├── scan_node.sh            # Scan npm (npm audit + IOCs)
│   ├── scan_docker.sh          # Analyse Dockerfiles + docker-compose
│   ├── scan_iocs.sh            # Recherche IOCs supply chain connus
│   ├── iocs/
│   │   ├── compromised_npm.txt     # Paquets npm compromis
│   │   ├── compromised_pypi.txt    # Paquets PyPI compromis
│   │   ├── malicious_files.txt     # Noms de fichiers malveillants
│   │   ├── malicious_patterns.txt  # Patterns grep suspects
│   │   └── malicious_hashes.txt    # SHA-256 de payloads connus
│   └── templates/
│       └── report.md.tpl       # Template du rapport
├── reports/                    # Rapports generes (persiste via volume)
├── data/                       # Bases CVE mises a jour (persiste via volume)
└── README.md
```

## Bases IOC incluses

Les listes IOC couvrent les attaques supply chain connues :
- **Shai-Hulud** v1/v2 (npm, sept 2025)
- **LiteLLM TeamPCP** (PyPI, mars 2026)
- **Cline CLI** compromis (npm, fev 2026)
- Typosquatting PyPI (termncolor, colorinal, etc.)
- Patterns d'exfiltration (webhook.site, domaines C2)
- Caracteres Unicode invisibles (technique GlassWorm)

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
| Known CVE detection | ✅ via npm/pip audit, osv-scanner | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ |
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
| License | Open source | Proprietary | Apache 2.0 | Proprietary | MIT / built-in | Open source | Open source | MIT |
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
- **Grype project scanning** — Grype DB is updated via `sentinel update` but not yet used to scan project dependencies. Future versions will run `grype dir:` or `grype sbom:` against each project.
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

## Licence

Usage interne — outil de securite defensive.
