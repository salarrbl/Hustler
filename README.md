# Hustler

**Hustler** is a Go-based bug bounty automation tool for **deep JavaScript vulnerability analysis**. It ingests targets from bug bounty platforms or manual entry, then runs targeted analysis modules: secrets detection, DOM XSS source/sink analysis, API endpoint extraction, parameter enumeration, broken link hijacking (BLH), library CVE matching, and sensitive endpoint checking.

## Features

| Module | Description |
|--------|-------------|
| **JS Discovery** | Katana (active crawl) + Wayback CDX (historical) — finds live & historical JS files |
| **Secret Scanner** | 67+ patterns, Shannon entropy, confidence scoring, redacted storage |
| **Sink Analyzer** | 13 DOM XSS sinks + 13 sources, proximity analysis, origin check detection |
| **Endpoint Extractor** | 5 regex groups, API-like filtering, method inference |
| **Parameter Extractor** | 5 regex groups, context deduction (query/body/form/header/path) |
| **BLH Analyzer** | DNS + HTTP checks, unclaimed S3/GitHub Pages/Azure, risk scoring |
| **Library CVE** | Multi-source: retire.js (5000+ JS libs), osv.dev, npm advisories, embedded server tech |
| **Sensitive Endpoints** | Active GET checks (disabled by default), configurable paths/patterns |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           HUSTLER ARCHITECTURE                               │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐     ┌──────────────┐     ┌────────────────────────────────┐
│   CLI        │     │   DAEMON     │     │   MONGODB                      │
│  (Commands)  │────▶│  (Background)│────▶│   (Persistence)                │
└──────────────┘     └──────────────┘     └────────────────────────────────┘
       │                    │                        │
       ▼                    ▼                        ▼
┌──────────────┐     ┌──────────────┐     ┌────────────────────────────────┐
│  target add  │     │  Job Queue   │     │  Collections:                  │
│  js hunt     │     │  (Worker     │     │  - targets                     │
│  daemon      │     │   Pool)      │     │  - programs                    │
│  start/      │     │              │     │  - jobs                        │
│  status/stop │     │  ┌────────┐  │     │  - js_files                    │
└──────────────┘     │  │Worker 1│  │     │  - secrets                     │
                     │  │Worker 2│  │     │  - sinks                       │
       ┌────────────▶│  │Worker 3│  │     │  - endpoints                   │
       │  (jobs     │  └────────┘  │     │  - params                      │
       │   written  └──────────────┘     │  - blh_candidates              │
       │   to DB)            │           │  - library_cves                │
       ▼                     ▼           │  - sensitive_endpoints         │
┌─────────────────────────────────────────────────────────────────────────────┐
│                        DISCOVERY & ANALYSIS PIPELINE                         │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐
│  TARGET     │───▶│ DISCOVERY   │───▶│ FETCH &     │───▶│ ANALYZERS       │
│  DOMAIN     │    │ (Find JS)   │    │ STORE JS    │    │ (Find Issues)   │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────────┘
       │                │                   │                    │
       ▼                ▼                   ▼                    ▼
  - domain           - Katana           - HTTP GET           - SecretScanner
  - scope            (active crawl)      - Hash dedup        - SinkAnalyzer
  - platform         - Wayback CDX      - Content store     - EndpointExtractor
  - program          - Gau (disabled)    - Metadata          - ParamExtractor
  - config                                            - S3/MinIO (optional)
                                                                   - BLHAnalyzer
                                                                   - LibraryCVEAnalyzer (multi-source)
                                                                   - SensitiveEndpointAnalyzer
```

## Core Components

| Package | Purpose |
|---------|---------|
| `internal/cli/` | Cobra CLI commands (target, program, daemon, js, cve, watchdogs, web) |
| `internal/daemon/` | Background job processor with 3s polling |
| `internal/jobqueue/` | Worker pool (alternative concurrent implementation) |
| `internal/discovery/` | Katana + Wayback CDX + Gau discovery |
| `internal/js/` | JS file fetch, hash dedupe, analyzer orchestration |
| `internal/analyzers/` | 7 static analyzers + 1 active checker |
| `internal/cve/` | **NEW** Multi-source CVE module with confidence scoring |
| `internal/models/` | All data structures (Target, Program, Job, findings) |
| `internal/mongo/` | MongoDB connection & collection helpers |
| `internal/config/` | YAML config with env var overrides |
| `internal/watchdogs/` | Bug bounty platform sync (disabled by default) |

## Quick Start

```bash
# Prerequisites
go install github.com/projectdiscovery/katana/cmd/katana@latest  # REQUIRED
go install github.com/lc/gau/v2/cmd/gau@latest                    # optional

# Build
cd hustler
go build -o hustler ./cmd/hustler

# Configure (edit config.yaml with your MongoDB URI)
cp config.yaml.example config.yaml

# Start daemon (background job processor)
./hustler daemon start

# Add targets (enqueues hunt jobs with platform/program categorization)
./hustler target add example.com --platform hackerone --program example
./hustler target import scope.txt --platform bugcrowd --program acme

# Monitor
./hustler daemon status
watch -n 5 ./hustler daemon status

# View findings (read-only)
./hustler js hunt example.com

# CVE database management
./hustler cve update          # download latest (shows NEW CVEs found)
./hustler cve status          # show database stats
./hustler cve list --library lodash --limit 0  # filter, unlimited results

# Web UI
./hustler web                 # http://localhost:8080
#   Login: rebel / crow  (set internal/cli/auth.go to change)
#   Protected SPA dashboard: Overview, target explorer, findings tabs.
#   API: /api/session, /api/dashboard, /api/targets, /api/findings/{id}, /api/jobs

# Program management
./hustler program list
./hustler program add walmart --platform hackerone
```

## Target Hierarchy

```
Platform (hackerone, bugcrowd, intigriti, yeswehack, openbugbounty, freelance)
  └─ Program (e.g., "walmart", "shopify")
       └─ Domains (e.g., walmart.com, shopify.com)
```

- Every target **requires** `--platform` and `--program` flags
- Programs auto-created if they don't exist
- Uncategorized targets (pre-existing) shown separately

## Configuration (`config.yaml`)

```yaml
# MongoDB Connection
mongo:
  uri: "mongodb://localhost:27017"
  database: "hustler"

# Logging
logging:
  level: "info"                    # debug, info, warn, error
  format: "console"                # console, json

# JavaScript Hunting Module
js:
  max_concurrent_fetches: 10       # Parallel HTTP fetches (semaphore)
  fetch_timeout_seconds: 15        # HTTP request timeout
  max_file_size_mb: 10             # Max response body size
  user_agent: "Hustler/1.0"
  use_katana: true                 # Enable Katana discovery
  use_gau: false                   # Enable Gau discovery (slow/blocked)
  katana_depth: 2                  # Katana crawl depth
  katana_timeout: 180              # Katana timeout (seconds)
  entropy_threshold: 3.5           # Secret scanner entropy threshold
  enable_source_maps: true         # Fetch & store source maps
  skip_hashes: []                  # SHA256 prefixes to skip (known libs)

# Sensitive Endpoint Check (Active - DISABLED BY DEFAULT)
sensitive:
  enabled: false                   # MUST explicitly enable
  heuristic_paths:
    - "/api/user"
    - "/api/admin"
    - "/api/config"
  sensitive_patterns:
    - "password"
    - "secret"
    - "token"
    - "api_key"

# CVE Module (NEW)
cve:
  data_dir: "./data/cve"           # Local cache location
  enable_online_lookup: true       # Query osv.dev/npm APIs
  rate_limit_rps: 2.0              # API requests per second
  update_interval_days: 7          # Auto-update frequency
  min_confidence: 0.5              # Minimum confidence to report

# Daemon Settings
hustler:
  max_concurrent_hunts: 3          # Worker pool size
  poll_interval_seconds: 3         # Daemon polling interval

# Watchdogs (Platform Sync - DISABLED BY DEFAULT)
watchdogs:
  enabled: false
  sources:
    - "hackerone"
    - "bugcrowd"
```

## Documentation

| File | Description |
|------|-------------|
| `README.md` | This file |
| `CLI_REFERENCE.md` | Complete command reference with all flags |
| `CVE_MODULE.md` | CVE module technical documentation |
| `CVE_QUICKREF.md` | CVE commands quick reference |
| `wiki/01-Overview.md` | Architecture & components |
| `wiki/02-Analyzer-Methodologies.md` | How each analyzer works |
| `wiki/03-Discovery-JS-Module.md` | Discovery pipeline & JS processing |
| `wiki/04-Daemon-JobQueue-CLI.md` | Daemon, worker pool, CLI commands |
| `wiki/05-Configuration.md` | Config.yaml reference & profiles |
| `wiki/06-Data-Models-MongoDB.md` | MongoDB schemas & Go models |
| `wiki/07-Usage-Workflows.md` | Bug bounty workflows & MongoDB queries |

## Requirements

- Go 1.21+
- MongoDB (local or remote)
- Katana binary in PATH (`go install github.com/projectdiscovery/katana/cmd/katana@latest`)
- Gau binary in PATH (optional, disabled by default)

## License

MIT