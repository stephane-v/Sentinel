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
docker compose build
```

## Utilisation

### Scanner tous les projets d'un repertoire

```bash
PROJECTS_DIR=/home/user/projects docker compose run --rm sentinel
```

### Scanner un sous-repertoire specifique

```bash
docker compose run --rm sentinel scan /projects/mon-projet
```

### Scanner avec seuil critique uniquement

```bash
PROJECTS_DIR=/home/user/projects SEVERITY_MIN=critical docker compose run --rm sentinel
```

### Mettre a jour les bases CVE

```bash
docker compose run --rm sentinel update
```

## Permissions

Le conteneur utilise un utilisateur non-root. Pour que les rapports soient ecrits correctement, passez votre UID/GID :

```bash
UID=$(id -u) GID=$(id -g) PROJECTS_DIR=/home/user/projects docker compose run --rm sentinel
```

Ou creez le repertoire `reports/` avec les bonnes permissions avant le premier lancement :

```bash
mkdir -p reports data
```

## Variables d'environnement

| Variable | Defaut | Description |
|----------|--------|-------------|
| `PROJECTS_DIR` | `/home/user/projects` | Repertoire des projets a scanner |
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

## Licence

Usage interne — outil de securite defensive.
