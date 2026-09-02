# Hustler - Bug Bounty JavaScript Hunting Tool

## Overview

Hustler is a Go-based bug bounty automation tool that performs **deep, targeted analysis of JavaScript files** on subdomains. It transitions from manual single-file scanning to an automated discovery pipeline that finds JS files using tools like `gau`, `katana`, and `CDX` (Wayback Machine).

## Architecture Philosophy

- **CLI-first** - Web UI is a thin layer on top of the same core
- **Explicit triggering** - Every scan is explicitly triggered per target, per module (no broad/automatic scanning)
- **Architecture before implementation** - Clear module boundaries before writing code
- **Incremental builds** - One module at a time, working end-to-end before adding the next
- **Watchdogs disabled by default** - `watchdogs.enabled: false` in config
- **Worker pool for concurrency** - Goroutines + channels, FIFO queue, configurable limit (default: 3)

## High-Level Data Flow

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
│  daemon      │     │   Pool)      │     │  - jobs                        │
│  start/      │     │              │     │  - js_files                    │
│  status/stop │     │  ┌────────┐  │     │  - secrets                     │
└──────────────┘     │  │Worker 1│  │     │  - sinks                       │
                     │  │Worker 2│  │     │  - endpoints                   │
       ┌────────────▶│  │Worker 3│  │     │  - parameters                  │
       │  (jobs     │  │  └────────┘  │     │  - blh_candidates            │
       │   written  │  └──────────────┘     │  - library_cves              │
       │   to DB)  │         │             │  - sensitive_endpoints       │
       ▼           ▼         ▼             └────────────────────────────────┘
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
  - source           - Wayback CDX      - Content store     - EndpointExtractor
  - config           - Gau (disabled)    - Metadata          - ParamExtractor
                                             - S3/MinIO      - BLHAnalyzer
                                                                     - LibraryCVEAnalyzer
                                                                     - SensitiveEndpointAnalyzer
```

## Core Components

### 1. CLI Layer (`internal/cli/`)
- **root.go** - Root command, shell completion setup
- **target.go** - `target add|list|remove` commands
- **js.go** - `js hunt` command (read-only findings viewer)
- **daemon.go** - `daemon start|status|stop` commands
- **watchdogs.go** - Watchdogs sync command (disabled by default)
- **colors.go** - Color helpers for output formatting

### 2. Daemon Layer (`internal/daemon/`)
- **daemon.go** - Main daemon loop, job polling, worker pool coordination

### 3. Job Queue (`internal/jobqueue/`)
- **worker_pool.go** - Goroutine worker pool with channel-based FIFO queue

### 4. Discovery (`internal/discovery/`)
- **discovery.go** - JavaScript file discovery using multiple sources

### 5. JS Module (`internal/js/`)
- **module.go** - JS file fetching, processing, hash deduplication

### 6. Analyzers (`internal/analyzers/`)
- **secret_scanner.go** - Secret/API key detection
- **sink_analyzer.go** - DOM XSS sink detection
- **endpoint_extractor.go** - API endpoint extraction
- **param_extractor.go** - Parameter enumeration
- **blh_analyzer.go** - Broken Link Hijacking detection
- **library_cve_analyzer.go** - Vulnerable library detection
- **sensitive_endpoint_analyzer.go** - Sensitive endpoint detection

### 7. Models (`internal/models/`)
- **models.go** - All data structures (Target, Job, JSFile, Secret, Sink, etc.)

### 8. MongoDB (`internal/mongo/`)
- **mongo.go** - Database connection and collection helpers

### 9. Config (`internal/config/`)
- **config.go** - Configuration structures
- **loader.go** - YAML config loading

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
  fetch_timeout_seconds: 30
  max_file_size_mb: 10
  user_agent: "Hustler/1.0"
  use_katana: true
  use_gau: false
  katana_depth: 2
  katana_timeout: 180

sensitive:
  enabled: false

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
| `hustler target add <domain>` | Add target & enqueue hunt job (non-blocking) |
| `hustler target list` | List all targets with status |
| `hustler target remove <domain>` | Remove target from database |
| `hustler js hunt <domain>` | View findings & job status (read-only) |
| `hustler daemon start` | Start background daemon (processes jobs) |
| `hustler daemon status` | Show daemon status + XSS source reference |
| `hustler daemon stop` | Graceful daemon shutdown |
| `hustler watchdogs sync` | Sync targets from bug bounty platforms (disabled) |
| `hustler completion <shell>` | Generate shell completion script |

---

*Next pages detail each analyzer methodology and implementation.*