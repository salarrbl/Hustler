# Usage Guide & Workflows

Complete guide for using Hustler in bug bounty workflows.

## Quick Start

### Prerequisites
```bash
# Install Go 1.21+
# Install MongoDB
# Install Katana (REQUIRED)
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Install Gau (optional)
go install github.com/lc/gau/v2/cmd/gau@latest

# Build Hustler
cd /path/to/Hustler
go build -o hustler ./cmd/hustler
```

### Initialize MongoDB
```bash
# Start MongoDB
mongod --dbpath /data/db

# Or Docker
docker run -d -p 27017:27017 --name mongodb mongo:latest
```

### Configure
```bash
cp config.yaml.example config.yaml
# Edit config.yaml with your MongoDB URI
```

---

## Basic Workflow

### 1. Start Daemon (Terminal 1)
```bash
./hustler daemon start
```
Output:
```
🛡️  Hustler Daemon Initializing...
✅ Connected to MongoDB

⚡ Daemon started. Ready to process hunt jobs.
   Commands:
     • Add target:  hustler target add <domain> [--platform hackerone]
     • Status:      hustler daemon status
     • Stop:        hustler daemon stop
```

**Keep this running** - it processes jobs in background.

---

### 2. Add Targets (Terminal 2)
```bash
# Add single target (requires platform and program)
./hustler target add example.com --platform hackerone --program example

# Add multiple
./hustler target add target1.com --platform bugcrowd --program acme
./hustler target add target2.com --platform intigriti --program acme
./hustler target add target3.com --platform freelance --program my-client
```

Output:
```
Enqueued hunt job: 550e8400-e29b-41d4-a716-446655440000
Added target: example.com (ID: 6ba7b810-9dad-11d1-80b4-00c04fd430c8) [hackerone / example]
```

**Returns immediately** - job is queued, daemon picks it up within 3 seconds.

---

### 3. Monitor Progress
```bash
# Check daemon status
./hustler daemon status

# Watch continuously
watch -n 5 ./hustler daemon status
```

Output:
```
Hustler Daemon Status:
  Process: RUNNING (PID 12345)

Daemon Function:
  • Polls MongoDB every 3 seconds for queued hunt jobs
  • Discovery: Katana (active crawl) + Wayback CDX + Gau (disabled)
  • Analysis: Secret scanning, Sink analysis, Endpoint extraction, Param extraction
  • BLH checks, CVE mapping, Library fingerprinting
  • Stores findings in MongoDB collections

Job Statistics:
  Queued:   0
  Running:  1
  Completed: 2
  Errors:   0

Currently Processing (1 jobs):
  • Job: 550e8400-e29b-41d4-a716-446655440000
    Target: example.com [hackerone]
    Started: 2024-01-15T10:30:05Z
    Phase: Fetching & Analyzing JS files

Targets: 3 total
```

---

### 4. View Results
```bash
# View all findings for a target
./hustler js hunt example.com
```

Output (colorized):
```
=== Target: example.com (ID: 6ba7b810-9dad-11d1-80b4-00c04fd430c8) ===

Last Hunt Job:
  ID:     550e8400-e29b-41d4-a716-446655440000
  Status: done
  Queued: 2024-01-15T10:30:00Z
  Started: 2024-01-15T10:30:05Z
  Finished: 2024-01-15T10:32:30Z
  Source: manual

=== Findings ===

Secrets (12):
  █ high_entropy_string (line 42, confidence: 0.85, entropy: 4.2)
  █ aws_secret_access_key (line 15, confidence: 0.95, entropy: 4.5)
  █ generic_api_key (line 88, confidence: 0.65, entropy: 3.8)

Sinks (45):
  █ innerHTML from url_params (line 23, confidence: 0.75, origin_check: false)
  █ postMessage from postMessage_data (line 67, confidence: 0.75, origin_check: false)
  █ setTimeout from url_hash (line 102, confidence: 0.50, origin_check: false)

BLH Candidates (3):
  █ cdn.unclaimed.com [unclaimed_s3] (critical) - S3 bucket appears unclaimed
  █ old.github.io [github_pages_missing] (high) - GitHub Pages 404 pattern

Library CVEs (5):
  █ jQuery v1.12.4: CVE-2020-11022 (medium) - XSS via htmlPrefilter
  █ Lodash v4.17.15: CVE-2021-23337 (high) - Prototype Pollution

Endpoints (28):
  - /api/v1/users (GET) - fetch
  - /api/v1/auth/login (POST) - axios

Parameters (156):
  - userId (query)
  - api_key (header)
  - csrf_token (body)

Sensitive Endpoints (0):
```

**Color Legend:**
- **Red+Bold**: Critical/High risk (confidence ≥ 0.7, postMessage without origin check, critical BLH)
- **Yellow**: Medium risk (confidence 0.4-0.69, high/medium BLH)
- **Green**: Low risk (confidence < 0.4, low BLH)
- **Gray**: Queued jobs
- **Blue**: Running jobs

---

## Advanced Workflows

### Workflow 1: Large Scope Recon
```bash
# 1. Add all targets from scope file
cat scope.txt | while read domain; do
  ./hustler target add "$domain" --platform hackerone --program main-program
done

# 2. Monitor
watch -n 10 ./hustler daemon status

# 3. When done, export all findings
mongoexport -d hustler -c secrets -o all_secrets.json
mongoexport -d hustler -c sinks -o all_sinks.json
mongoexport -d hustler -c blh_candidates -o all_blh.json
mongoexport -d hustler -c library_cves -o all_cves.json
```

---

### Workflow 2: Bulk Import
```bash
# From text file (one domain per line, # comments ignored)
./hustler target import scope.txt --platform hackerone --program main-program

# From JSON array
echo '["t1.com", "t2.com", "t3.com"]' | ./hustler target import - --platform bugcrowd --program acme

# Output:
# Added: target1.com [Platform: hackerone]
# Added: target2.com [Platform: hackerone]
# Skipped (exists): target3.com
# Done. Added: 2, Skipped: 1
```

---

### Workflow 3: CVE Database Management
```bash
# Initial update (downloads retire.js, osv.dev, npm data)
./hustler cve update

# Check status anytime
./hustler cve status

# List all CVEs for a library
./hustler cve list --library lodash --limit 0

# Filter by severity
./hustler cve list --severity high --limit 20

# Search specific CVE
./hustler cve list --cve CVE-2021-44228

# JSON output for scripting
./hustler cve list --library react --format json
```

**Daemon auto-updates weekly** if enabled in config.

---

### Workflow 4: BLH Hunting
```bash
# 1. Add targets with many external references
./hustler target add shopify.com --platform hackerone --program shopify
./hustler target add github.io --platform freelance --program github-pages
./hustler target add s3.amazonaws.com --platform bugcrowd --program aws

# 2. Wait for BLH analysis (runs after JS processing)

# 3. Filter for critical BLH
mongo hustler --eval 'db.blh_candidates.find({risk_level: "critical"}).pretty()'
```

**What BLH finds:**
- Unclaimed S3 buckets (`NoSuchBucket` response)
- Unclaimed GitHub Pages (404 on github.io)
- Expired domains (NXDOMAIN)
- Azure blob storage, etc.

---

### Workflow 5: Secret Hunting
```bash
# 1. Hunt targets
./hustler target add api.example.com --platform hackerone --program api

# 2. Check high-confidence secrets
mongo hustler --eval 'db.secrets.find({confidence: {$gte: 0.8}}).pretty()'

# 3. Filter by pattern
mongo hustler --eval 'db.secrets.find({pattern: "aws_secret_access_key"}).pretty()'

# 4. Export for reporting
mongoexport -d hustler -c secrets --type=csv -f target_id,pattern,confidence,entropy,line -o secrets.csv
```

**What secrets it finds:**
- AWS keys (Access Key ID, Secret, Session Token)
- GCP keys, Azure credentials
- Slack/Discord tokens
- Database URLs (MongoDB, Postgres, Redis, MySQL)
- JWT tokens, OAuth tokens, Bearer tokens
- SSH keys, Git credentials
- Generic high-entropy strings
- Hardcoded passwords

---

### Workflow 6: DOM XSS Hunting (Sink Analysis)
```bash
# 1. Hunt
./hustler target add app.example.com --platform intigriti --program app

# 2. Check sinks without origin check (highest XSS risk)
mongo hustler --eval 'db.sinks.find({sink_type: "postMessage", has_origin_check: false}).pretty()'

# 3. Check high-confidence sinks
mongo hustler --eval 'db.sinks.find({confidence: {$gte: 0.75}}).pretty()'

# 4. Look for dangerous sinks
mongo hustler --eval 'db.sinks.find({sink_type: {$in: ["eval", "innerHTML", "document.write", "Function"]}}).pretty()'
```

**High-Risk Sinks:**
- `eval` / `Function` - Code execution
- `innerHTML` / `outerHTML` / `document.write` - HTML injection
- `postMessage` without origin check - Cross-origin XSS
- `setTimeout`/`setInterval` with string argument - Code execution

---

### Workflow 7: API Endpoint Enumeration
```bash
# 1. Hunt
./hustler target add api.example.com --platform hackerone --program api

# 2. Get all endpoints
mongo hustler --eval 'db.endpoints.find({target_id: "..."}).pretty()'

# 3. Filter for sensitive endpoints
mongo hustler --eval 'db.endpoints.find({endpoint: {$regex: "(admin|internal|debug|config)"}}).pretty()'

# 4. Get parameters for fuzzing
mongo hustler --eval 'db.params.find({target_id: "..."}, {param_name: 1, context: 1}).pretty()'

# 5. Export for nuclei/ffuf
mongoexport -d hustler -c endpoints -q '{"target_id": "..."}' --type=csv -f endpoint,method -o endpoints.csv
```

---

### Workflow 8: Vulnerable Library Detection
```bash
# 1. Hunt
./hustler target add legacy.example.com --platform hackerone --program legacy

# 2. Check CVEs
mongo hustler --eval 'db.library_cves.find({severity: {$in: ["critical", "high"]}}).pretty()'

# 3. Get library inventory
mongo hustler --eval 'db.library_cves.aggregate([{$group: {_id: "$library_name", versions: {$addToSet: "$version"}, cves: {$sum: 1}}}])'

# 4. Check CVE database directly
./hustler cve list --library jquery --severity high
./hustler cve list --source retire.js
```

---

### Workflow 9: Incremental Scanning
Hustler supports **incremental scanning** - re-running on same target only processes new/changed files.

```bash
# First run
./hustler target add example.com --platform hackerone --program test
# ... wait for completion ...

# Later (new deployment, new JS files)
./hustler target add example.com --platform hackerone --program test
# Only NEW or CHANGED JS files are processed
# Results accumulate in MongoDB
```

**How it works:**
1. Discovery finds all JS URLs
2. `discovered_urls` collection checked for previously seen URLs
3. Only new URLs fetched
4. Content hash (SHA256) checked - if same hash exists for target, skips
5. If content changed (new hash) → re-processed

---

### Workflow 10: Program Management
```bash
# List all programs by platform
./hustler program list

# Create program explicitly
./hustler program add walmart --platform hackerone
./hustler program add acme-corp --platform freelance

# Then add targets to it
./hustler target add walmart.com --platform hackerone --program walmart
```

---

### Workflow 11: Watchdogs (Platform Sync) - Disabled by Default
```yaml
# config.yaml
watchdogs:
  enabled: true
  sources:
    - "hackerone"
    - "bugcrowd"
```

```bash
# Sync targets from platforms
./hustler watchdogs sync
```

**Note:** Requires platform API tokens in config. Disabled by default to prevent accidental scope violations.

---

### Workflow 12: Web Dashboard
```bash
./hustler web
# Open http://localhost:8080
# Browse tree: Platform → Program → Domain
# Click domain → view findings
# Add new targets via "Add Target" button (requires platform + program)
```

---

## MongoDB Queries for Analysis

### Find All High-Risk Findings
```javascript
// Critical secrets
db.secrets.find({confidence: {$gte: 0.85}})

// postMessage without origin check (DOM XSS)
db.sinks.find({sink_type: "postMessage", has_origin_check: false})

// Critical BLH (unclaimed S3, NXDOMAIN)
db.blh_candidates.find({risk_level: "critical"})

// High/Critical CVEs
db.library_cves.find({severity: {$in: ["critical", "high"]}})
```

### Target Summary Report
```javascript
db.targets.aggregate([
  { $lookup: { from: "secrets", localField: "_id", foreignField: "target_id", as: "secrets" }},
  { $lookup: { from: "sinks", localField: "_id", foreignField: "target_id", as: "sinks" }},
  { $lookup: { from: "blh_candidates", localField: "_id", foreignField: "target_id", as: "blh" }},
  { $lookup: { from: "library_cves", localField: "_id", foreignField: "target_id", as: "cves" }},
  { $project: {
      domain: 1,
      platform: 1,
      source: 1,
      status: 1,
      secrets: { $size: "$secrets" },
      high_conf_secrets: { $size: { $filter: { input: "$secrets", cond: { $gte: ["$$this.confidence", 0.8] } } } },
      sinks: { $size: "$sinks" },
      dangerous_sinks: { $size: { $filter: { input: "$sinks", cond: { $in: ["$$this.sink_type", ["eval", "innerHTML", "postMessage"]] } } } },
      blh_critical: { $size: { $filter: { input: "$blh", cond: { $eq: ["$$this.risk_level", "critical"] } } } },
      cve_high: { $size: { $filter: { input: "$cves", cond: { $in: ["$$this.severity", ["critical", "high"]] } } } }
  }},
  { $sort: { "blh_critical": -1, "cve_high": -1, "high_conf_secrets": -1 } }
])
```

### Export for Reporting
```bash
# Export findings as CSV
mongoexport -d hustler -c secrets --type=csv -f target_id,pattern,confidence,entropy,line -o secrets.csv
mongoexport -d hustler -c sinks --type=csv -f target_id,sink_type,source_type,confidence,has_origin_check -o sinks.csv
mongoexport -d hustler -c blh_candidates --type=csv -f target_id,referenced_domain,risk_level,resolution_status -o blh.csv
mongoexport -d hustler -c library_cves --type=csv -f target_id,library_name,version,cve_id,severity -o cves.csv
```

---

## Integration with Other Tools

### With Nuclei (for endpoint testing)
```bash
# Export endpoints
mongoexport -d hustler -c endpoints -q '{"target_id": "..."}' --type=csv -f endpoint,method -o endpoints.csv

# Feed to nuclei
cat endpoints.csv | cut -d, -f1 | nuclei -t cves/ -t exposures/
```

### With ffuf (for parameter fuzzing)
```bash
# Get parameters
mongo hustler --eval 'db.params.find({target_id: "..."}, {param_name: 1}).forEach(printjson)'
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Daemon not processing jobs | Check `./hustler daemon status` - daemon must be RUNNING |
| "katana not found" | Install katana: `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| No JS files found | Check Katana depth, try increasing to 3; verify domain accessible |
| High false positives | Increase `entropy_threshold` to 4.0+ in config |
| MongoDB connection error | Verify `mongo.uri` in config.yaml, check MongoDB running |
| Daemon stops unexpectedly | Check logs, run in tmux/systemd for persistence |
| Jobs stuck in "running" | Restart daemon - it recovers pending jobs from MongoDB |
| CVE update timeout | Check network/proxy, increase timeout |
| No new CVEs on update | Already up to date - check `./data/cve/.last_update` |

---

## Production Deployment

### Systemd Service
```ini
# /etc/systemd/system/hustler.service
[Unit]
Description=Hustler Bug Bounty Daemon
After=network.target mongod.service
Requires=mongod.service

[Service]
Type=simple
User=bugbounty
WorkingDirectory=/opt/hustler
ExecStart=/opt/hustler/hustler daemon start
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable hustler
sudo systemctl start hustler
sudo journalctl -u hustler -f  # View logs
```

### Tmux (Simple)
```bash
tmux new-session -d -s hustler './hustler daemon start'
tmux attach -t hustler  # Attach to view logs
# Ctrl+B, D to detach
```

---

*See `wiki/` for detailed documentation on each component.*