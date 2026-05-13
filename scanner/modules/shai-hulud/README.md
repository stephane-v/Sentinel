# Sentinel — Shai-Hulud Module

Detects the **Mini Shai-Hulud** supply chain attack family (CVE-2026-45321).

| Wave | Date | Packages | Method |
|------|------|----------|--------|
| Wave 1 | Sept 2025 | `@ctrl/*`, ~30 packages | Typosquatting + build hijack |
| Wave 2 | Nov 2025 | CrowdStrike ecosystem, ~470 packages | Actions `pull_request_target` Pwn Request |
| Wave 3 | Apr–May 2026 | `@uipath/*`, `@mistralai/mistralai`, `guardrails-ai`, `opensearch-js`, `mbt`, `@cap-js/sqlite`, `intercom-client` | Chained OIDC exfil |
| Wave 4 | 11 May 2026 | 42 `@tanstack/*` packages | Pwn Request + cache poisoning + OIDC exfil from `/proc/<pid>/mem` |

**Attribution**: TeamPCP (StepSecurity, Wiz)

## IoC last updated: 2026-05-13

## What the module detects

1. **Compromised packages in lockfiles** — `package-lock.json` (v1/v2/v3), `pnpm-lock.yaml`, `yarn.lock` (v1 classic + v2+ Berry)
2. **Runtime artifacts** — `router_runtime.js`, `tanstack_runner.js`, signed `bundle.js`
3. **Malicious GitHub Actions workflows** — `shai-hulud.yaml`, `shai-hulud.yml`
4. **Persistence daemons** — `gh-token-monitor` LaunchAgent (macOS) / systemd unit (Linux)
5. **Unblocked C2 domains** — `git-tanstack.com`, `getsession.org`, `filev2.getsession.org`, `api.masscan.cloud`

## CVE and advisory references

| Ref | URL |
|-----|-----|
| CVE-2026-45321 / GHSA-g7cv-rxg3-hmpx | https://github.com/advisories/GHSA-g7cv-rxg3-hmpx |
| Socket blog (Wave 4) | https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack |
| Snyk blog (Wave 4) | https://snyk.io/blog/tanstack-npm-packages-compromised/ |
| StepSecurity (Wave 3/4) | https://www.stepsecurity.io (search "Mini Shai-Hulud is back") |
| Wiz blog (Wave 4) | https://wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised |
| TanStack postmortem | https://github.com/TanStack/router/issues/7383 |

## Wave timestamps (for GitHub Actions audit)

| Wave | Start (UTC) | End (UTC) |
|------|-------------|-----------|
| Wave 1 | 2025-09-01T00:00Z | 2025-09-15T00:00Z |
| Wave 2 | 2025-11-01T00:00Z | 2025-11-20T00:00Z |
| Wave 3 | 2026-04-01T00:00Z | 2026-05-10T00:00Z |
| Wave 4 | 2026-05-11T00:00Z | 2026-05-13T00:00Z |

Audit all CI runs within these windows for credential exfiltration to C2 domains.

## Manual IoC enrichment

To add newly discovered packages:

1. Open `iocs/npm-packages.txt`
2. Find the correct wave comment section
3. Add `package@exact-version` on its own line
4. Update the `# Last updated:` header at the top of the file
5. Commit with message: `chore(iocs): add <package> to shai-hulud Wave N`

**Format rules:**
- One entry per line: `package@version`
- Scoped packages: `@scope/package@version`
- Comments start with `#`
- Wave sections start with `# Wave N — <date> (<campaign>)`

## Future: automated IoC updates

A future `update-iocs.sh` script could pull from the GitHub Advisory Database via the GraphQL API:

```graphql
query {
  securityAdvisories(identifier: {type: GHSA, value: "GHSA-g7cv-rxg3-hmpx"}) {
    nodes {
      vulnerabilities(first: 100) {
        nodes {
          package { name ecosystem }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
  }
}
```

This would allow CI-driven IoC refreshes without manual intervention.

## Running the module standalone

```bash
# Scan current directory
bash scanner/modules/shai-hulud/scan.sh .

# Scan a project with custom depth
bash scanner/modules/shai-hulud/scan.sh /path/to/project --max-depth 8

# Via sentinel.sh
./sentinel.sh --module shai-hulud /path/to/project
```

## Running bats tests

```bash
# Install bats (choose one):
npm install -g bats         # via npm
brew install bats-core      # macOS
apk add bats                # Alpine
apt-get install bats        # Debian/Ubuntu

# Run tests
bats tests/shai-hulud.bats
```
