# Hustler — Vulnerability Automation Platform

> A standalone vulnerability-discovery automation platform for authorized security testing and bug bounty work.

## Architecture

Hustler has two completely separate data systems:

```
                    HUSTLER
                       │
             ┌─────────┴─────────┐
             │                   │
          READ/WRITE          READ ONLY
             │                   │
             ▼                   ▼
       Hustler MongoDB      WatchDogs MongoDB
          "hustler"             "watchdogs"
```

- **Hustler Database** (`hustler`): Owns and manages its own MongoDB - source of truth for vulnerability-analysis state
- **WatchDogs Database** (`watchdogs`): External recon system - READ ONLY connection for recon data

## Features

### Phase 1 (Current) - Foundation
- ✅ Target Management (CRUD via CLI & API)
- ✅ Hustler MongoDB with proper indexes
- ✅ Job System (queued, running, completed, failed, cancelled)
- ✅ REST API with session auth (rebel:krow)
- ✅ WatchDogs Read-Only Ingestion

### Phase 2 (Next) - WatchDogs Integration
- 🔄 Import live assets from WatchDogs
- 🔄 Normalize assets into Hustler data model
- 🔄 Create base URL records

### Phase 3 - URL Intelligence
- URL normalization & deduplication
- Junk filtering
- Parameter extraction
- Endpoint extraction

### Phase 4 - Hypothesis Engine
- GF pattern matching
- Hypothesis generation & classification
- Extensible vulnerability categories

### Phase 5 - JavaScript Intelligence
- Secret detection
- Source/sink analysis
- postMessage analysis

### Phase 6 - Vulnerability Analysis
- Reflected XSS pipeline
- Broken link hijacking
- SSRF/SQLi candidates

### Phase 7 - Dashboard & Correlation
- Live job status
- Hypotheses & findings
- Evidence tracking

## Quick Start

### Prerequisites
- Go 1.23+
- MongoDB running (local or remote)
- WatchDogs running with data in `watchdogs` database

### Installation

```bash
cd /home/qarqa/rebel/Hustler
make dev-setup
```

This will:
1. Download dependencies
2. Create default config at `~/.hustler/config.json`
3. Build the `hustler` binary

### Configuration

Default config location: `~/.hustler/config.json`

```json
{
  "hustler_db": {
    "uri": "mongodb://localhost:27017",
    "database": "hustler"
  },
  "watchdogs_db": {
    "uri": "mongodb://localhost:27017",
    "database": "watchdogs",
    "read_only": true
  },
  "api": {
    "host": "127.0.0.1",
    "port": 8081,
    "username": "rebel",
    "password": "krow"
  },
  "web_ui": {
    "host": "127.0.0.1",
    "port": 88,
    "api_url": "http://127.0.0.1:8081"
  },
  "auth": {
    "session_secret": "change-me-in-production-32-bytes!!",
    "session_max_age_hours": 24
  },
  "log_level": "info"
}
```

Environment variable overrides:
- `HUSTLER_CONFIG` - Config file path
- `HUSTLER_DB_URI` - Hustler MongoDB URI
- `HUSTLER_DB_NAME` - Hustler database name
- `WATCHDOGS_DB_URI` - WatchDogs MongoDB URI
- `WATCHDOGS_DB_NAME` - WatchDogs database name
- `HUSTLER_API_HOST` / `HUSTLER_API_PORT` - API server
- `HUSTLER_API_USER` / `HUSTLER_API_PASS` - API credentials
- `HUSTLER_WEB_HOST` / `HUSTLER_WEB_PORT` - Web UI
- `HUSTLER_WEB_API_URL` - Web UI API URL
- `HUSTLER_SESSION_SECRET` - Session secret
- `HUSTLER_LOG_LEVEL` - Log level

### Usage

#### Start API Server
```bash
./hustler serve
# Or with custom host/port
./hustler serve --host 0.0.0.0 --port 8081
```

#### Manage Targets
```bash
# Add a target
./hustler target add example.com --name "Example Corp" --description "Main target"

# List targets
./hustler target list

# Import from WatchDogs
./hustler target import example.com

# Delete target
./hustler target delete example.com
```

#### Manage Jobs
```bash
# List all recent jobs
./hustler job list

# List jobs for a target
./hustler job list <target_id>
```

### API Endpoints

#### Auth
- `POST /auth/login` - Login (username: rebel, password: krow)
- `POST /auth/logout` - Logout
- `GET /auth/me` - Current user

#### Targets
- `POST /api/targets` - Create target
- `GET /api/targets` - List targets
- `GET /api/targets/:id` - Get target
- `DELETE /api/targets/:id` - Delete target
- `POST /api/targets/:id/import` - Import from WatchDogs

#### Assets
- `GET /api/assets?target_id=<id>` - List assets

#### URLs
- `GET /api/urls?target_id=<id>` - List URLs

#### Jobs
- `GET /api/jobs?target_id=<id>` - List jobs
- `GET /api/jobs/:id` - Get job
- `POST /api/jobs` - Create job

#### Dashboard
- `GET /api/dashboard/stats` - Dashboard statistics

### Database Collections (Hustler)

```
hustler
├── targets           # Target scope definitions
├── assets            # Live subdomains (from WatchDogs or recon)
├── urls              # Discovered URLs
├── parameters        # Extracted parameters
├── endpoints         # API endpoints
├── javascript        # JavaScript files
├── javascript_secrets # Detected secrets in JS
├── hypotheses        # Generated hypotheses
├── findings          # Confirmed findings
├── jobs              # Job queue & history
├── analysis_results  # Analysis module results
└── settings          # Platform settings
```

### Data Flow

```
WatchDogs (read-only)
       ↓
Import Job
       ↓
Hustler DB: targets → assets → urls
       ↓
Normalization Jobs
       ↓
Parameter/Endpoint Extraction
       ↓
GF Analysis → Hypotheses
       ↓
JS Analysis → Secrets, Sources, Sinks
       ↓
Validation → Findings
       ↓
Dashboard / Reports
```

## Non-Negotiable Rules

1. **Hustler has its own MongoDB database** (`hustler`)
2. **Hustler DB is the source of truth** for Hustler
3. **Adding a target writes ONLY to Hustler DB**
4. **Hustler READS from WatchDogs** (`watchdogs` database)
5. **Hustler NEVER writes to WatchDogs**
6. **JavaScript analysis does NOT discover subdomains**
7. **GF results are hypotheses, NOT confirmed vulnerabilities**
8. **Separate: Observations → Hypotheses → Candidates → Findings**
9. **Keep layers separate**: Sources → Ingestion → Normalization → Analysis → Hypotheses → Validation → Findings → UI

## Development

```bash
# Format code
make fmt

# Vet code
make vet

# Build
make build

# Run tests
make test

# Run with race detector
make race
```

## License

MIT - For authorized security testing only.