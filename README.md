# Sentinel — Supply Chain Security Scanner

Scanner Docker autonome qui détecte les vulnérabilités connues (CVE), les paquets compromis (supply chain attacks), et les mauvaises pratiques de sécurité dans vos projets.

## Fonctionnalités

- **Détection IOCs** : fichiers malveillants, patterns suspects, caractères Unicode invisibles (GlassWorm), hashes de payloads connus
- **Scan Python** : paquets PyPI compromis, dépendances non pinnées, CVE via pip-audit et osv-scanner
- **Scan Node.js** : paquets npm compromis, install scripts suspects, CVE via npm audit et osv-scanner
- **Analyse Docker** : secrets dans Dockerfile (ARG/ENV), fichiers sensibles copiés, absence de USER non-root, single-stage builds
- **Rapport Markdown** généré automatiquement avec code retour (0=clean, 1=alertes, 2=critique)

## Outils embarqués

| Outil | Rôle |
|-------|------|
| [pip-audit](https://github.com/pypa/pip-audit) | Vulnérabilités Python (base PyPI/OSV) |
| [osv-scanner](https://github.com/google/osv-scanner) | Multi-écosystème (base Google OSV) |
| [grype](https://github.com/anchore/grype) | Scanner de vulnérabilités (base Anchore) |
| npm audit | Vulnérabilités Node.js intégrées |

## Installation

```bash
git clone <repo-url> sentinel
cd sentinel
docker compose build
```

## Utilisation

### Scanner tous les projets d'un répertoire

```bash
PROJECTS_DIR=/home/user/projects docker compose run --rm sentinel
```

### Scanner un sous-répertoire spécifique

```bash
docker compose run --rm sentinel scan /projects/mon-projet
```

### Scanner avec seuil critique uniquement

```bash
PROJECTS_DIR=/home/user/projects SEVERITY_MIN=critical docker compose run --rm sentinel
```

### Mettre à jour les bases CVE

```bash
docker compose run --rm sentinel update
```

## Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `PROJECTS_DIR` | `/home/user/projects` | Répertoire des projets à scanner |
| `SCAN_DEPTH` | `4` | Profondeur max de recherche de fichiers |
| `SEVERITY_MIN` | `medium` | Seuil minimum : `low`, `medium`, `high`, `critical` |
| `REPORT_FORMAT` | `md` | Format du rapport : `md` ou `json` |

## Codes de retour

| Code | Signification |
|------|--------------|
| `0` | Aucune vulnérabilité critique ni IOC détecté |
| `1` | Des vulnérabilités ou mauvaises pratiques détectées |
| `2` | IOCs ou paquets compromis détectés — action immédiate requise |

## Rapports

Les rapports sont générés dans `./reports/` avec le format `sentinel-YYYY-MM-DD_HHMMSS.md`.

## Sécurité du conteneur

Le conteneur scanner respecte les bonnes pratiques :
- Volume des projets monté en **lecture seule** (`:ro`)
- Conteneur en `read_only: true`
- `no-new-privileges` activé
- Toutes les capabilities supprimées (`cap_drop: ALL`)
- Tmpfs pour `/tmp` et `/var/tmp`

## Architecture

```
sentinel/
├── docker-compose.yml          # Lance le scanner
├── Dockerfile                  # Image du scanner
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
├── reports/                    # Rapports générés (persisté via volume)
├── data/                       # Bases CVE mises à jour (persisté via volume)
└── README.md
```

## Bases IOC incluses

Les listes IOC couvrent les attaques supply chain connues :
- **Shai-Hulud** v1/v2 (npm, sept 2025)
- **LiteLLM TeamPCP** (PyPI, mars 2026)
- **Cline CLI** compromis (npm, fév 2026)
- Typosquatting PyPI (termncolor, colorinal, etc.)
- Patterns d'exfiltration (webhook.site, domaines C2)
- Caractères Unicode invisibles (technique GlassWorm)

## Licence

Usage interne — outil de sécurité défensive.
