# Daemon, Job Queue & CLI Architecture

This document explains the background processing architecture, job queue implementation, and CLI command structure.

## Daemon Architecture (`cmd/hustler/main.go`)

### Overview
The daemon is a **long-running background process** that:
1. Polls MongoDB every 3 seconds for queued jobs
2. Processes each job (spawns goroutine per job)
3. Handles graceful shutdown on SIGINT/SIGTERM
4. Tracks running state via PID file

### Daemon Loop (`runDaemon`)

```go
func runDaemon(cfg *config.FullConfig) {
    // 1. Save PID
    os.WriteFile("/tmp/hustler-daemon.pid", []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
    defer os.Remove("/tmp/hustler-daemon.pid")

    // 2. Signal handling
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-sigCh
        fmt.Println("\n🛡️  Shutting down Hustler daemon...")
        os.Exit(0)
    }()

    fmt.Println("🛡️  Hustler Daemon Initializing...")
    fmt.Println("✅ Connected to MongoDB")
    fmt.Println("\n⚡ Daemon started. Ready to process hunt jobs.")
    fmt.Println("   Commands:")
    fmt.Println("     • Add target:  hustler target add <domain> [--platform hackerone]")
    fmt.Println("     • Status:      hustler daemon status")
    fmt.Println("     • Stop:        hustler daemon stop")

    ctx := context.Background()
    ticker := time.NewTicker(3 * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        processQueuedJobs(ctx, cfg)
    }
}
```

### Job Processing (`processQueuedJobs` → `processJob`)

```
processQueuedJobs() (every 3s)
       │
       ▼
Find jobs with status="queued" (FIFO order)
       │
       ▼
For each job:
       │
       ▼
processJob(job) ──▶ spawns goroutine
       │
       ├── Update job status → "running", set started_at
       │
       ├── Get target from DB
       │
       ├── DiscoveryRunner.DiscoverJSURLs(target)
       │       ├── Katana (active crawl)
       │       ├── Wayback CDX
       │       └── Gau (if enabled)
       │
       ├── If URLs found: JSModule.FetchAndProcessWithCounter(jsURLs)
       │       ├── Fetch all JS files (concurrent, hash-deduped)
       │       ├── Run 8 analyzers
       │       └── Store all findings in MongoDB
       │
       ├── Update job status → "done", set finished_at
       │
       └── Update target status → "completed"
```

### Error Handling
- Any failure → job status = "error", store error message
- Daemon continues to next job
- Target status updated to "error" on job failure

---

## Worker Pool (`internal/jobqueue/worker_pool.go`) — Alternative Implementation

### Overview
Alternative implementation providing **concurrent job processing** with:
- Fixed worker count (configurable, default 3)
- Channel-based job queue (buffered 1000)
- MongoDB job recovery on startup
- Graceful shutdown

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    WORKER POOL                               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐    jobQueue (chan)    ┌─────────────────┐  │
│  │  EnqueueJob │ ───────────────────▶  │  Worker 1       │  │
│  └─────────────┘                       │  processHunt()  │  │
│                                        └─────────────────┘  │
│                                        ┌─────────────────┐  │
│                                        │  Worker 2       │  │
│                                        │  processHunt()  │  │
│                                        └─────────────────┘  │
│                                        ┌─────────────────┐  │
│                                        │  Worker 3       │  │
│                                        │  processHunt()  │  │
│                                        └─────────────────┘  │
│                                                              │
│  running map[jobID]*Job  ◀── tracks currently processing    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Key Methods

| Method | Purpose |
|--------|---------|
| `Start()` | Recovers pending jobs from MongoDB, starts N workers |
| `EnqueueJob(job)` | Adds job to channel (non-blocking if queue has space) |
| `EnqueueJobForTarget(targetID, source)` | Creates job, stores in MongoDB, enqueues |
| `Stop()` | Graceful shutdown - waits for running jobs |
| `GetRunningCount()` | Current active jobs |
| `GetQueuedCount()` | Pending jobs in channel |

### Job Recovery on Startup
```go
func (wp *WorkerPool) recoverPendingJobs() {
    // Find jobs with status "queued" OR "running"
    cursor := coll.Find(ctx, bson.M{"status": bson.M{"$in": ["queued", "running"]}})
    
    for job := range jobs {
        // Reset to queued
        job.Status = JobStatusQueued
        wp.EnqueueJob(&job)
    }
}
```
This ensures **no job is lost** if daemon crashes or is restarted.

### Worker Processing
```go
func (wp *WorkerPool) worker(id int) {
    for job := range wp.jobQueue {
        // Track running
        wp.running[job.ID] = job
        
        // Update MongoDB: status=running, started_at=now
        wp.updateJobStatus(job)
        
        // Process hunt (same logic as daemon.processJob)
        err := wp.processHunt(job)
        
        // Update final status
        if err != nil {
            job.Status = JobStatusError
            job.Error = err.Error()
        } else {
            job.Status = JobStatusDone
        }
        job.FinishedAt = time.Now()
        wp.updateJobStatus(job)
        
        // Remove from running
        delete(wp.running, job.ID)
    }
}
```

### Concurrency Control
- `cfg.MaxConcurrentHunts` (default 3) = number of workers
- All job types (manual + watchdogs) share same pool
- FIFO via channel

---

## CLI Commands (`internal/cli/`)

### Command Structure

```
hustler
├── target
│   ├── add <domain>           # Add target, enqueue job (requires --platform --program)
│   ├── import <file>          # Bulk import (requires --platform --program)
│   ├── list                   # List all targets (platform → program → domains)
│   └── remove <domain-or-id>  # Remove target
├── program
│   ├── list                   # Show programs by platform (with empty)
│   └── add <name> --platform  # Create program explicitly
├── js
│   └── hunt <domain>          # Read-only findings viewer (colorized)
├── daemon
│   ├── start                  # Start background daemon
│   ├── status                 # Show daemon status + active jobs
│   └── stop                   # Graceful stop
├── cve
│   ├── update                 # Update CVE database (shows new CVEs)
│   ├── status                 # Show CVE database stats
│   └── list                   # List CVEs with filters (--library, --severity, --source, --cve, --limit)
├── watchdogs
│   └── sync                   # Sync from platforms (disabled by default)
├── web [port]                 # Web dashboard (default 8080)
└── completion <shell>         # Shell completions
```

### Command Details

#### `hustler target add <domain> --platform <platform> --program <program>`
```go
// internal/cli/target.go
func addTarget(cmd, args) {
    // 1. Validate domain
    // 2. Check if exists
    // 3. Require platform and program flags
    // 4. Get or create program
    // 5. Create Target struct
    target := models.NewTarget(domain, models.SourceManual)
    target.Platform = models.TargetPlatform(platform)
    target.ProgramID = programID
    
    // 6. Insert into targets collection
    coll.InsertOne(ctx, target)
    
    // 7. Create & enqueue job
    job := &models.Job{
        ID:       uuid.New().String(),
        TargetID: target.ID,
        Status:   models.JobStatusQueued,
        QueuedAt: time.Now(),
        Source:   "manual",
    }
    jobColl.InsertOne(ctx, job)
    
    // 8. Return immediately (non-blocking)
    fmt.Printf("Enqueued hunt job: %s\n", job.ID)
    fmt.Printf("Added target: %s (ID: %s) [%s / %s]\n", domain, target.ID, platform, programName)
}
```
**Key**: Returns immediately. Daemon picks up job on next poll (within 3s).

#### `hustler target import <file> --platform <platform> --program <program>`
- Supports **line-separated** domains (one per line, `#` comments ignored)
- Supports **JSON array** (if first char is `[`)
- All targets get same platform/program
- Output: `Added: N, Skipped: M`

#### `hustler target list`
Shows hierarchical tree:
```
◆ hackerone:
────────────────────────────────────────────────────────────
  ◆ walmart (3)
    walmart.com                          manual       pending
    corp.walmart.com                     manual       pending
    sparkshop.com                        manual       pending
  ◆ shopify (1)
    shopify.com                          manual       pending
  ⚠ Uncategorized (2)
    test.com
    legacy.example.com

◇ bugcrowd:
────────────────────────────────────────────────────────────
  ⚠ Uncategorized (1)
    acme.com

◆ freelance:
────────────────────────────────────────────────────────────
  ⚠ Uncategorized (2)
    time.ir
    divar.ir
```
- Shows status (`pending`, `active`, `completed`, `error`) and source (`manual`, `watchdogs`)
- Color-coded platforms

#### `hustler program list`
Same tree but shows **empty programs too**.

#### `hustler js hunt <domain>`
```go
// internal/cli/js.go
func huntTarget(cmd, args) {
    // 1. Find target by domain
    // 2. Get latest job for target
    // 3. Print job status (color-coded)
    // 4. Query & print findings:
    //    - secrets (color by confidence)
    //    - sinks (color by origin_check)
    //    - blh_candidates (color by risk)
    //    - library_cves (color by severity)
    //    - endpoints, params, sensitive_endpoints
}
```
**Read-only** - does NOT trigger scans.

#### `hustler daemon start`
Starts background daemon with phase-level logging:
```
🎯 Hunt started: walmart.com [hackerone]
🔍 [katana] Crawling...
✅ [katana] Found 365 JS URLs
🔍 [wayback] Querying CDX...
✅ [wayback] Found 12 JS URLs
📥 Fetching 41 unique JS files...
🔬 [secrets]   29 findings
🔬 [sinks]     391 findings
🔬 [endpoints] 156 findings
🔬 [params]    87 findings
🔬 [blh]       3 candidates
🔬 [cve]       5 matches
🏁 Hunt complete: walmart.com (8m 12s)
```

#### `hustler daemon status`
Shows:
- Process status (PID check)
- Daemon function description
- Job statistics (queued/running/done/error)
- Currently processing jobs with inferred phase
- Queued jobs list
- Target count

#### `hustler cve update`
```bash
🔍 Initializing CVE module...
📥 Downloading CVE database from online sources...
✅ CVE database updated successfully (38.0s)

🆕 New CVEs added: 27
📚 New libraries: 1
📦 Updated sources: 2
  @angular/core: 27 new CVE(s)
    🟡 CVE-2021-4231 (≤ 10.2.5)
    🟡 CVE-2021-4231 (≤ 11.0.5)
    🟡 CVE-2021-4231 (≤ 11.1.0-next.3)
    ... and 24 more

⚠ Errors:
  • npm: Get "https://registry.npmjs.org/...": net/http: TLS handshake timeout
```

#### `hustler cve list`
```bash
# All CVEs (unlimited)
hustler cve list --limit 0

# Filter by library
hustler cve list --library lodash --limit 0

# Filter by severity
hustler cve list --severity high --limit 10

# Filter by source
hustler cve list --source retire.js

# Search by CVE ID
hustler cve list --cve CVE-2021-44228

# JSON output
hustler cve list --format json --library react
```

---

## Job Lifecycle

```
┌─────────────┐
│   CREATED   │  (target add → job inserted with status="queued")
└──────┬──────┘
       │
       ▼ (daemon polls every 3s)
┌─────────────┐
│   QUEUED    │  (waiting for worker)
└──────┬──────┘
       │
       ▼ (worker picks up)
┌─────────────┐
│  RUNNING    │  (started_at set)
│             │  discovery → fetch → analyze
└──────┬──────┘
       │
       ├── Success ────▶ ┌─────────────┐
       │                 │    DONE     │  (finished_at set)
       │                 └─────────────┘
       │
       └── Failure ─────▶ ┌─────────────┐
                          │    ERROR    │  (error message stored)
                          └─────────────┘
```

---

## MongoDB Collections

| Collection | Purpose | Key Fields |
|------------|---------|------------|
| `targets` | Target domains | `_id`, `domain`, `source`, `platform`, `program_id`, `status`, `added_at` |
| `programs` | Bug bounty programs | `_id`, `name`, `platform`, `added_at` |
| `jobs` | Hunt jobs | `_id`, `target_id`, `status`, `queued_at`, `started_at`, `finished_at`, `error`, `source`, `current_step` |
| `js_files` | Fetched JS files | `_id`, `target_id`, `url`, `js_hash`, `status_code`, `content_length`, `fetched_at` |
| `secrets` | Secret findings | `_id`, `target_id`, `js_file_id`, `pattern`, `matched`, `entropy`, `confidence`, `is_minified` |
| `sinks` | Source/sink hits | `_id`, `target_id`, `js_file_id`, `sink_type`, `source_type`, `confidence`, `has_origin_check`, `is_minified`, `low_confidence` |
| `endpoints` | API endpoints | `_id`, `target_id`, `js_file_id`, `endpoint`, `method`, `full_url`, `context` |
| `params` | Parameters | `_id`, `target_id`, `js_file_id`, `param_name`, `context`, `location` |
| `blh_candidates` | BLH findings | `_id`, `target_id`, `js_file_id`, `referenced_domain`, `resolution_status`, `risk_level`, `cloud_provider`, `evidence`, `found_in`, `is_target_subdomain` |
| `library_cves` | Vulnerable libs | `_id`, `target_id`, `js_file_id`, `library_name`, `version`, `cve_id`, `severity`, `description`, `reference` |
| `discovered_urls` | Incremental tracking | `_id`, `target_id`, `url`, `url_type`, `source`, `first_seen`, `last_seen` |
| `sensitive_endpoint_candidates` | Active check results | `_id`, `target_id`, `endpoint`, `status_code`, `response_size`, `matched_patterns`, `source` |

---

## Configuration

```yaml
hustler:
  max_concurrent_hunts: 3      # Worker pool size (daemon uses sequential, pool uses this)
  poll_interval_seconds: 3     # Daemon polling interval

# Daemon uses internal config, not worker pool config
# Worker pool is alternative implementation
```

---

## Process Management

### Starting Daemon (Production)

```bash
# Option 1: tmux (recommended)
tmux new-session -d -s hustler './hustler daemon start'

# Option 2: systemd (create /etc/systemd/system/hustler.service)
[Unit]
Description=Hustler Bug Bounty Daemon
After=network.target mongod.service

[Service]
Type=simple
User=bugbounty
WorkingDirectory=/opt/hustler
ExecStart=/opt/hustler/hustler daemon start
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target

# Then: systemctl enable hustler && systemctl start hustler
```

### Checking Status
```bash
./hustler daemon status
```

### Stopping
```bash
./hustler daemon stop
# or
tmux kill-session -t hustler
# or
systemctl stop hustler
```

---

## Shell Completion

```bash
# Generate completion
./hustler completion bash > /etc/bash_completion.d/hustler
./hustler completion zsh > /usr/share/zsh/site-functions/_hustler
./hustler completion fish > ~/.config/fish/completions/hustler.fish

# Target domain completion works for:
# - hustler target remove <TAB>
# - hustler js hunt <TAB>
```

---

## Integration Points

### Adding Targets Programmatically
```go
// From another tool/script
job, err := workerPool.EnqueueJobForTarget(ctx, targetID, "api")
```

### Monitoring Job Progress
```bash
# Watch job status
watch -n 5 './hustler daemon status'

# Or query MongoDB directly
mongo hustler --eval 'db.jobs.find({status: "running"}).pretty()'
```

### Getting Results
```bash
# All findings for target
./hustler js hunt example.com

# Just secrets
mongo hustler --eval 'db.secrets.find({target_id: "..."}).pretty()'

# Export to JSON
mongoexport -d hustler -c secrets -q '{"target_id": "..."}' -o secrets.json
```

---

*See `cmd/hustler/main.go`, `internal/jobqueue/worker_pool.go`, and `internal/cli/` for implementation details.*