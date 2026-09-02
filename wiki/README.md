# Hustler Wiki - Complete Documentation

## Table of Contents

| # | Document | Description |
|---|----------|-------------|
| 01 | [Overview](01-Overview.md) | Architecture, data flow, core components, command reference |
| 02 | [Analyzer Methodologies](02-Analyzer-Methodologies.md) | Deep dive into each analyzer: Secret, Sink, BLH, Endpoint, Param, CVE, Sensitive |
| 03 | [Discovery & JS Module](03-Discovery-JS-Module.md) | Katana, Wayback CDX, Gau, fetch pipeline, analyzers |
| 04 | [Daemon, Job Queue & CLI](04-Daemon-JobQueue-CLI.md) | Background processing, worker pool, CLI commands, job lifecycle |
| 05 | [Configuration](05-Configuration.md) | Complete config.yaml reference, env vars, profiles |
| 06 | [Data Models & MongoDB](06-Data-Models-MongoDB.md) | All collections, schemas, indexes, Go models, queries |
| 07 | [Usage & Workflows](07-Usage-Workflows.md) | Step-by-step workflows for bug bounty hunting |

---

## Quick Navigation

### For New Users
1. Start with **[01-Overview](01-Overview.md)** - understand the architecture
2. Read **[07-Usage-Workflows](07-Usage-Workflows.md)** - quick start guide
3. Check **[05-Configuration](05-Configuration.md)** - configure for your environment

### For Developers/Contributors
1. **[02-Analyzer-Methodologies](02-Analyzer-Methodologies.md)** - how each analyzer works
2. **[03-Discovery-JS-Module](03-Discovery-JS-Module.md)** - discovery & processing pipeline
3. **[04-Daemon-JobQueue-CLI](04-Daemon-JobQueue-CLI.md)** - daemon & job queue internals
4. **[06-Data-Models-MongoDB](06-Data-Models-MongoDB.md)** - data structures & schemas

### For Bug Bounty Hunters
1. **[07-Usage-Workflows](07-Usage-Workflows.md)** - practical hunting workflows
2. **[02-Analyzer-Methodologies](02-Analyzer-Methodologies.md)** - what each analyzer finds
3. **[06-Data-Models-MongoDB](06-Data-Models-MongoDB.md)** - MongoDB queries for analysis

---

## Key Concepts Summary

### What Hustler Does
```
Target Domain → Discovery (Katana/Wayback) → Fetch JS Files → Analyze → Store Findings
                                    ↓
                              MongoDB Collections
                                    ↓
                            View via: ./hustler js hunt <domain>
```

### Core Philosophy
- **Explicit triggering** - No automatic scanning; every target added manually
- **Daemon-based** - Background processor picks up queued jobs
- **Incremental** - Re-runs only process new/changed files
- **MongoDB-centric** - All state persisted, queryable, resumable
- **CLI-first** - Web UI is secondary

### Main Commands
| Command | Purpose |
|---------|---------|
| `hustler target add <domain>` | Add target, enqueue job (non-blocking) |
| `hustler daemon start` | Start background processor (MUST RUN) |
| `hustler daemon status` | Check status + see what's running |
| `hustler js hunt <domain>` | View findings (read-only, colorized) |
| `hustler target list/remove` | Manage targets |

### What Each Analyzer Finds

| Analyzer | Finds | Risk Level |
|----------|-------|------------|
| **Secret Scanner** | API keys, tokens, passwords, DB URLs, SSH keys | Critical-High |
| **Sink Analyzer** | DOM XSS sinks (eval, innerHTML, postMessage, etc.) | High-Medium |
| **BLH Analyzer** | Unclaimed S3, GitHub Pages, expired domains | Critical-High |
| **Endpoint Extractor** | API endpoints for further testing | Medium |
| **Param Extractor** | Parameter names for fuzzing/injection | Medium |
| **Library CVE** | Vulnerable JS libraries (jQuery, Lodash, etc.) | High-Medium |
| **Sensitive Endpoint** | Endpoints leaking sensitive data (opt-in) | Variable |

---

## File Structure

```
Hustler/
├── cmd/hustler/main.go           # Entry point
├── config.yaml                   # Configuration
├── internal/
│   ├── analyzers/                # 7 analysis modules
│   │   ├── secret_scanner.go
│   │   ├── sink_analyzer.go
│   │   ├── blh_analyzer.go
│   │   ├── endpoint_extractor.go
│   │   ├── param_extractor.go
│   │   ├── library_cve_analyzer.go
│   │   └── sensitive_endpoint_analyzer.go
│   ├── cli/                      # CLI commands
│   │   ├── root.go
│   │   ├── target.go
│   │   ├── js.go
│   │   ├── daemon.go
│   │   ├── watchdogs.go
│   │   └── colors.go
│   ├── config/                   # Config loading
│   ├── daemon/                   # Daemon loop
│   ├── discovery/                # JS file discovery
│   ├── jobqueue/                 # Worker pool (alt impl)
│   ├── js/                       # JS processing pipeline
│   ├── models/                   # Data models
│   └── mongo/                    # MongoDB helpers
└── wiki/                         # This documentation
```

---

## External Dependencies

| Tool | Purpose | Required |
|------|---------|----------|
| **MongoDB** | Persistence | ✅ Yes |
| **Katana** | Active JS discovery | ✅ Yes |
| **Gau** | Historical URLs | ❌ Optional (disabled) |
| **Go 1.21+** | Runtime | ✅ Yes |

---

## Contributing

### Adding a New Analyzer
1. Create `internal/analyzers/new_analyzer.go`
2. Implement `Scan/Analyze` method
3. Add model struct in `internal/models/models.go`
4. Register in `internal/js/module.go:runAnalyzers()`
5. Add MongoDB collection indexes
6. Document in `02-Analyzer-Methodologies.md`

### Adding a Discovery Source
1. Add method to `internal/discovery/discovery.go`
2. Add config fields in `internal/config/config.go`
3. Call from `DiscoverJSURLs()`
4. Document in `03-Discovery-JS-Module.md`

---

## License & Credits

- **Katana** - ProjectDiscovery (active crawling)
- **Wayback Machine** - Internet Archive (historical data)
- **Gau** - lc (historical URLs, alternative)
- **Retire.js** - CVE database reference (library_cve_analyzer)
- **domgo.at** - XSS source reference

---

*Generated from Hustler codebase. For questions, check the source files in `internal/` or the corresponding wiki documents.*