# Hustler Wiki

Technical documentation for the Hustler bug bounty automation tool.

## Table of Contents

| # | Document | Description |
|---|----------|-------------|
| 01 | [Overview](01-Overview.md) | Architecture, components, target hierarchy |
| 02 | [Analyzer Methodologies](02-Analyzer-Methodologies.md) | How each analyzer works (secrets, sinks, BLH, endpoints, params, CVE) |
| 03 | [Discovery & JS Module](03-Discovery-JS-Module.md) | Katana, Wayback CDX, Gau discovery + JS processing pipeline |
| 04 | [Daemon, Job Queue & CLI](04-Daemon-JobQueue-CLI.md) | Background daemon, worker pool, all CLI commands |
| 05 | [Configuration](05-Configuration.md) | Complete config.yaml reference with profiles |
| 06 | [Data Models & MongoDB](06-Data-Models-MongoDB.md) | All MongoDB schemas and Go structs |
| 07 | [Usage Workflows](07-Usage-Workflows.md) | Bug bounty workflows, MongoDB queries, integration |

---

## Quick Links

- **Main README**: [../README.md](../README.md)
- **CLI Reference**: [../CLI_REFERENCE.md](../CLI_REFERENCE.md)
- **CVE Module**: [../CVE_MODULE.md](../CVE_MODULE.md) | [Quick Ref](../CVE_QUICKREF.md)

---

## Architecture Overview

```
CLI Commands ──▶ Daemon (3s poll) ──▶ Discovery (Katana + Wayback) ──▶ JS Fetch + 8 Analyzers ──▶ MongoDB
```

### Core Modules
1. **Discovery** - Katana (active) + Wayback CDX (historical)
2. **JS Module** - Fetch, hash dedupe, incremental scanning
3. **Analyzers** - Secrets, Sinks, Endpoints, Params, BLH, CVE (legacy + new), Sensitive
4. **CVE Module** - retire.js, osv.dev, npm, embedded server tech with confidence scoring
5. **Daemon** - Background job processor with phase-level logging
6. **CLI** - Target/Program/Daemon/JS/CVE/Watchdogs/Web commands

### Key Features
- **Explicit triggering** - No automatic scanning
- **Incremental** - Hash-based dedupe, only new/changed files processed
- **Hierarchical targets** - Platform → Program → Domain
- **Confidence scoring** - Reduces false positives
- **Multi-source CVE** - 5000+ JS libs + server tech

---

## Getting Started

See [README.md](../README.md#quick-start) for installation and basic workflow.

---

## Contributing

Documentation is generated from source code. To update:
1. Modify the relevant Go files
2. Regenerate documentation (or update wiki files manually)
3. Keep wiki in sync with implementation

---

*Last updated: 2026-09-04*