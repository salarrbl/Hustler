# Hustler - Bug Bounty JavaScript Hunting Tool

## Overview

Hustler is a Go-based bug bounty automation tool that performs **deep, targeted analysis of JavaScript files** on subdomains. It transitions from manual single-file scanning to an automated discovery pipeline that finds JS files using Katana (active crawling) and Wayback CDX (historical).

## Architecture Philosophy

- **CLI-first** - Web UI is a thin layer on top of the same core
- **Explicit triggering** - Every scan is explicitly triggered per target, per module (no broad/automatic scanning)
- **Architecture before implementation** - Clear module boundaries before writing code
- **Incremental builds** - One module at a time, working end-to-end before adding the next
- **Watchdogs disabled by default** - `watchdogs.enabled: false` in config
- **Worker pool for concurrency** - Goroutines + channels, FIFO queue, configurable limit (default: 3)

## High-Level Data Flow

```
┌──────────────┐     ┌──────────────┐     ┌────────────────────────────────┐
│   CLI        │     │   DAEMON     │     │   MONGODB                      │
│  (Commands)  │────▶│  (Background)│────▶│   (Persistence)                │
└──────────────┘     └──────────────┘     └────────────────────────────────┘
       │                    │                        │
       ▼                    ▼                        ▼
┌──────────────┐     ┌──────────────┐     ┌────────────────────────────────┐
│  target add  │     │  Job Queue   │     │  Collections:                  │
│  program     │     │  (Worker     │     │  - targets                     │
│  js hunt     │     │   Pool)      │     │  - programs                    │
│  daemon      │     │              │     │  - jobs                        │
│  start/      │     │  ┌────────┐  │     │  - js_files                    │
│  status/stop │     │  │Worker 1│  │     │  - secrets                     │
└──────────────┘     │  │Worker 2│  │     │  - sinks                       │
                     │  │Worker 3│  │     │  - endpoints                   │
       ┌────────────▶│  └────────┘  │     │  - params                      │
       │  (jobs     └──────────────┘     │  - blh_candidates              │
       │   written  │         │           │  - library_cves                │
       │   to DB)   ▼         ▼           │  - sensitive_endpoints         │
       ▼          ▼         ▼           └────────────────────────────────┘
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
  - platform         (active crawl)      - Hash dedup        - SinkAnalyzer
  - program          - Wayback CDX      - Content store     - EndpointExtractor
  - config           - Gau (disabled)    - Metadata          - ParamExtractor
                                             - S3/MinIO      - BLHAnalyzer
                                                                 - LibraryCVEAnalyzer
                                                                 - SensitiveEndpointAnalyzer
```

## Target Hierarchy

```
Platform (hackerone, bugcrowd, intigriti, yeswehack, openbugbounty, freelance)
  └─ Program (e.g., "walmart", "shopify")
       └─ Domains (e.g., walmart.com, shopify.com)
```

Every target **requires** `--platform` and `--program` flags. Programs are auto-created if they don't exist.

## Core Components

### 1. CLI Layer (`internal/cli/`)
| File | Commands |
|------|----------|
| `root.go` | Root command, shell completion setup |
| `target.go` | `target add|list|remove|import` |
| `program.go` | `program list|add` |
| `daemon.go` | `daemon start|status|stop` |
| `js.go` | `js hunt` (read-only findings viewer) |
| `cve.go` | `cve update|status|list` |
| `watchdogs.go` | `watchdogs sync` (disabled by default) |
| `web.go` | `web [port]` - Web dashboard |

### 2. Daemon Layer (`internal/daemon/`)
- **daemon.go** - Main daemon loop, job polling every 3s, worker coordination

### 3. Job Queue (`internal/jobqueue/`)
- **worker_pool.go** - Goroutine worker pool with channel-based FIFO queue (alternative implementation)

### 4. Discovery (`internal/discovery/`)
- **discovery.go** - JavaScript file discovery using Katana + Wayback CDX + Gau

### 5. JS Module (`internal/js/`)
- **module.go** - JS file fetching, processing, hash deduplication, analyzer orchestration

### 6. Analyzers (`internal/analyzers/`)
| Analyzer | Purpose |
|----------|---------|
| `secret_scanner.go` | 67+ patterns, entropy, confidence scoring |
| `sink_analyzer.go` | 13 DOM XSS sinks + 13 sources, proximity, origin check |
| `endpoint_extractor.go` | 5 regex groups, API-like filtering, method inference |
| `param_extractor.go` | 5 regex groups, context deduction |
| `blh_analyzer.go` | DNS + HTTP, unclaimed S3/GitHub Pages/Azure |
| `library_cve_analyzer.go` | Legacy fingerprint + CVE matching |
| `sensitive_endpoint_analyzer.go` | Active GET checks (disabled by default) |

### 7. CVE Module (`internal/cve/`) **NEW**
| File | Purpose |
|------|---------|
| `module.go` | Multi-source CVE database & analysis |
| | - retire.js: 5000+ client-side JS library CVEs |
| | - osv.dev: npm, Go, Rust, PyPI, Maven, etc. |
| | - npm advisories |
| | - Embedded: Apache, Nginx, PHP, OpenSSL |
| | - Confidence scoring (0-1) to reduce false positives |
| | - CLI: `hustler cve update|status|list` |
| | - Auto-update: weekly background updates |

### 8. Models (`internal/models/`)
- **models.go** - All data structures (Target, Program, Job, JSFile, Secret, Sink, Endpoint, Param, BLHCandidate, LibraryCVE, DiscoveredURL, SensitiveEndpointCandidate)

### 9. MongoDB (`internal/mongo/`)
- **mongo.go** - Database connection and collection helpers

### 10. Config (`internal/config/`)
- **config.go** - Configuration structures
- **loader.go** - YAML config loading with env var overrides

### 11. Watchdogs (`internal/watchdogs/`)
- **connector.go** - Bug bounty platform sync (read-only, incremental, explicit)

## Configuration (`config.yaml`)

```yaml
mongo:
  uri: "mongodb://localhost:27017"
  database: "hustler"

logging:
  level: "info"
  format: "console"

js:
  max_concurrent_fetches: 10
  fetch_timeout_seconds: 15
  max_file_size_mb: 10
  user_agent: "Hustler/1.0"
  use_katana: true
  use_gau: false
  katana_depth: 2
  katana_timeout: 180
  entropy_threshold: 3.5
  enable_source_maps: true
  skip_hashes: []

cve:
  data_dir: "./data/cve"
  enable_online_lookup: true
  rate_limit_rps: 2.0
  update_interval_days: 7
  min_confidence: 0.5

sensitive:
  enabled: false
  heuristic_paths:
    - "/api/user"
    - "/api/admin"
  sensitive_patterns:
    - "password"
    - "secret"
    - "token"

hustler:
  max_concurrent_hunts: 3
  poll_interval_seconds: 3

watchdogs:
  enabled: false
  sources:
    - "hackerone"
    - "bugcrowd"
```

## Command Reference

| Command | Description |
|---------|-------------|
| `hustler target add <domain> --platform hackerone --program walmart` | Add target & enqueue hunt job |
| `hustler target import file.txt --platform bugcrowd --program acme` | Bulk import (lines or JSON) |
| `hustler target list` | Tree view: platform → program → domains |
| `hustler target remove <domain>` | Remove target |
| `hustler program list` | Show programs by platform (with empty) |
| `hustler program add walmart --platform hackerone` | Create program explicitly |
| `hustler daemon start` | Start background daemon (phase-level logs) |
| `hustler daemon status` | Show running jobs with current phase |
| `hustler daemon stop` | Graceful shutdown |
| `hustler js hunt <domain>` | Read-only findings viewer (colorized) |
| `hustler cve update` | Update CVE database (shows new CVEs) |
| `hustler cve status` | Show CVE database stats |
| `hustler cve list --library lodash --limit 0` | List CVEs with filters |
| `hustler watchdogs sync` | Sync from Watchdogs (requires config) |
| `hustler web [port]` | Web dashboard at localhost:8080 |

## Documentation Index

| File | Description |
|------|-------------|
| `01-Overview.md` | This file |
| `02-Analyzer-Methodologies.md` | How each analyzer works |
| `03-Discovery-JS-Module.md` | Discovery pipeline & JS processing |
| `04-Daemon-JobQueue-CLI.md` | Daemon, worker pool, CLI commands |
| `05-Configuration.md` | Config.yaml reference & profiles |
| `06-Data-Models-MongoDB.md` | MongoDB schemas & Go models |
| `07-Usage-Workflows.md` | Bug bounty workflows & queries |

---

*Next pages detail each analyzer methodology and implementation.*