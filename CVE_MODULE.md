# Hustler CVE Module

Deep, version-aware CVE matching for **client-side JS libraries** and
**server-side technologies**, with offline-first updates and
bug-bounty-safe exploitability triage.

## How it works

```
detection → range matching → enrichment → verdict
```

1. **Detection** (`internal/cve/detect.go`)
   - Client: 60+ banner/global signatures, versions pinned in script URLs
     (`jquery@3.6.0`, `bootstrap-5.1.3.min.js`, `?ver=`), `package.json` /
     dependency blocks from sourcemaps and bundled manifests.
   - Server: deterministic `Server` / `X-Powered-By` / `X-AspNet-Version` /
     `X-Generator` header rules, `<meta name="generator">` and error-page
     body rules, plus wappalyzer CPE versions as extra evidence.
2. **Range matching** (`version.go`, `scan.go`)
   - retire.js semantics: vulnerable iff `version >= atOrAbove` (when set)
     **and** `version < below` (fixed version, else legacy max version).
   - Exact-version records (`atOrAbove == below`, e.g. Apache 2.4.49) match
     that version only. Records with no bounds never auto-match — they are
     advisory data for `cve verify`.
   - Comparison handles `v`-prefixes, 4-part versions, OpenSSL letter
     patch levels (`1.0.1e < 1.0.1f`), and pre-releases (`1.9.0b1 < 1.9.0`).
3. **Enrichment** — CVSS/CWE backfilled from NVD (cached), KEV + EPSS
   loaded from local feeds.
4. **Verdict** (`exploit.go`) — `confirmed` (CISA KEV) → `likely` (known
   PoC or EPSS ≥ 0.5) → `possible` (version match) → `unknown`, each with
   safe verification steps and a nuclei command.

## Update sources (`cve update`)

| Source | What | Default |
|---|---|---|
| `retirejs` | JS library ranges (full snapshot) | ✅ on |
| `osv` | osv.dev `POST /v1/query` ranges for ~60 npm packages | ✅ on |
| `kev` | CISA Known Exploited Vulnerabilities catalog | ✅ on |
| `epss` | FIRST EPSS scores for CVEs already in the DB | ✅ on |
| `nvd` | Per-product NVD CPE cache for server software (apache, nginx, php, …) | opt-in |

```bash
hustler cve update                              # default set
hustler cve update --source retirejs,osv        # subset
hustler cve update --source nvd                 # needs NVD_API_KEY env for speed
hustler cve update --source osv --packages jquery,lodash,axios
hustler cve status                              # per-source freshness + KEV/EPSS age
hustler cve list --library lodash --limit 0
```

Files land in `./data/cve/` (`retirejs_*.json`, `osv_*.json`, `nvd_*.json`,
`seed_server.json`, `kev.json`, `epss.json`, `nvd_cache.json`,
`manifest.json`). Scans only read local files: fast and offline-capable.

## Scanning

```bash
# Self-contained live scan, no MongoDB needed (passive GETs only)
hustler cve scan --target example.com
hustler cve scan --target https://example.com --online --json
hustler cve scan --target example.com --js-limit 30 --min-confidence 0.7

# Deep-dive one ID: affected ranges, verdict, PoC, nuclei, remediation
hustler cve verify CVE-2021-23337
```

In the daemon pipeline, client-side matching runs in the JS phase
(`LibraryCVEAnalyzer` → `RunScan`, offline) and server-side matching runs
as a separate pass over the freshly fetched homepage — findings are never
double-counted. `hustler js hunt <domain>` shows fix versions and
🎯/⚠ exploit badges.

## Exploit policy

Hustler **never fires exploit payloads automatically**. Verification means:

- version-banner re-checks (passive),
- nuclei templates (vendor-safe checks): `nuclei -t http/cves/2021/CVE-2021-41773.yaml -u https://TARGET`,
- curated lab-only PoC steps for client-side issues (prototype pollution,
  jQuery XSS, …) that reproduce against the same version locally,
- header-toggling replays with your own session for auth-bypass class.

Active probing stays behind `cve.enable_active_probes: false` (default)
and even then is limited to safe re-reads — intrusive RCE/traversal
payloads are always manual, in-scope-only actions.

## Configuration (`config.yaml`)

```yaml
cve:
  data_dir: "./data/cve"
  enable_online_lookup: true
  rate_limit_rps: 2.0
  update_interval_days: 7
  min_confidence: 0.5
  nvd_api_key: ""              # or NVD_API_KEY env (50 req/30s vs 5)
  enable_exploit_checks: true  # passive KEV/EPSS/PoC triage
  enable_active_probes: false  # keep false
  # osv_packages: []           # override npm seed list
  # server_tech: []            # override NVD product seed
```

## Code map

| File | Role |
|---|---|
| `internal/cve/module.go` | Module wiring, `Analyze`, wappalyzer bridge, storage |
| `internal/cve/detect.go` | Client/server fingerprinting, OSV/CPE mapping |
| `internal/cve/version.go` | Version parsing, comparison, range matching |
| `internal/cve/scan.go` | `RunScan` pipeline, live HTTP helpers, `cve scan` engine |
| `internal/cve/update.go` | All update sources, manifest, KEV/EPSS, seed data |
| `internal/cve/exploit.go` | KEV/EPSS loaders, verdicts, PoC playbooks, nuclei |
| `internal/analyzers/library_cve_analyzer.go` | Pipeline adapter (offline `RunScan` + Mongo store) |
