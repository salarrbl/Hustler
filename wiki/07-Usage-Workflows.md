# Usage Guide & Workflows

Complete guide for using Hustler in bug bounty workflows.

## Quick Start

### Prerequisites
```bash
# Install Go 1.21+
# Install MongoDB
# Install Katana
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
2024-01-15T10:30:00 INF Starting Hustler daemon...
Daemon started. Add targets with: hustler target add <domain>
Status: hustler daemon status
Stop: hustler daemon stop
```

**Keep this running** - it processes jobs in background.

---

### 2. Add Targets (Terminal 2)
```bash
# Add single target
./hustler target add example.com

# Add multiple
./hustler target add target1.com
./hustler target add target2.com
./hustler target add target3.com
```

Output:
```
Enqueued hunt job: 550e8400-e29b-41d4-a716-446655440000
Added target: example.com (ID: 6ba7b810-9dad-11d1-80b4-00c04fd430c8)
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
    Target: example.com (6ba7b810-9dad-11d1-80b4-00c04fd430c8)
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
  ./hustler target add "$domain"
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

### Workflow 2: Focused Analysis (Specific JS File)

```bash
# If you found an interesting JS file manually
./hustler target add target.com

# Wait for processing, then check results
./hustler js hunt target.com

# Or scan a specific URL directly (if you have the URL)
# Note: This was removed in current version - use target add + js hunt
```

---

### Workflow 3: BLH Hunting

```bash
# 1. Add targets with many external references
./hustler target add shopify.com
./hustler target add github.io
./hustler target add s3.amazonaws.com

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

### Workflow 4: Secret Hunting

```bash
# 1. Hunt targets
./hustler target add api.example.com

# 2. Check high-confidence secrets
mongo hustler --eval 'db.secrets.find({confidence: {$gte: 0.8}}).pretty()'

# 3. Filter by pattern
mongo hustler --eval 'db.secrets.find({pattern: "aws_secret_access_key"}).pretty()'
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

### Workflow 5: DOM XSS Hunting (Sink Analysis)

```bash
# 1. Hunt
./hustler target add app.example.com

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

### Workflow 6: API Endpoint Enumeration

```bash
# 1. Hunt
./hustler target add api.example.com

# 2. Get all endpoints
mongo hustler --eval 'db.endpoints.find({target_id: "..."}).pretty()'

# 3. Filter for sensitive endpoints
mongo hustler --eval 'db.endpoints.find({endpoint: {$regex: "(admin|internal|debug|config)"}}).pretty()'

# 4. Get parameters for fuzzing
mongo hustler --eval 'db.params.find({target_id: "..."}, {param_name: 1, context: 1}).pretty()'
```

---

### Workflow 7: Vulnerable Library Detection

```bash
# 1. Hunt
./hustler target add legacy.example.com

# 2. Check CVEs
mongo hustler --eval 'db.library_cves.find({severity: {$in: ["critical", "high"]}}).pretty()'

# 3. Get library inventory
mongo hustler --eval 'db.library_cves.aggregate([{$group: {_id: "$library_name", versions: {$addToSet: "$version"}, cves: {$sum: 1}}}])'
```

---

## Incremental Scanning

Hustler supports **incremental scanning** - re-running on same target only processes new/changed files.

```bash
# First run
./hustler target add example.com
# ... wait for completion ...

# Later (new deployment, new JS files)
./hustler target add example.com
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

## Watchdogs (Platform Sync) - Disabled by Default

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

## Shell Completion

```bash
# Bash
./hustler completion bash > /etc/bash_completion.d/hustler
source /etc/bash_completion.d/hustler

# Zsh
./hustler completion zsh > "${fpath[1]}/_hustler"

# Fish
./hustler completion fish > ~/.config/fish/completions/hustler.fish
```

**Tab completion works for:**
```bash
./hustler target remove <TAB>        # Shows target domains
./hustler js hunt <TAB>              # Shows target domains
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

# Fuzz
ffuf -u "https://target.com/api/endpoint?FUZZ=test" -w params.txt
```

### With Custom Scripts
```python
# Python example: Get high-risk findings
from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017")
db = client["hustler"]

# Critical BLH
for blh in db.blh_candidates.find({"risk_level": "critical"}):
    print(f"CRITICAL: {blh['referenced_domain']} - {blh['evidence']}")

# High-confidence secrets
for secret in db.secrets.find({"confidence": {"$gte": 0.85}}):
    print(f"SECRET: {secret['pattern']} (confidence: {secret['confidence']})")
```

---

## Best Practices

1. **Always run daemon in tmux/systemd** - survives disconnection
2. **Use separate MongoDB database per program** - avoid mixing scope
3. **Review BLH critical findings first** - highest impact (subdomain takeover)
4. **Check postMessage sinks without origin check** - common DOM XSS
5. **Run incrementally** - re-add targets after deployments
6. **Export and archive findings** - MongoDB can grow large
7. **Tune entropy threshold** - 3.5 default, 4.0+ for fewer false positives
8. **Disable sensitive endpoint check** unless explicitly authorized
9. **Monitor disk space** - JS files + source maps can be large
10. **Use skip_hashes** for known library files to reduce noise

---

*See `01-Overview.md` for architecture, `02-Analyzer-Methodologies.md` for analyzer details, `03-Discovery-JS-Module.md` for discovery internals, `04-Daemon-JobQueue-CLI.md` for daemon/CLI, `05-Configuration.md` for config options, `06-Data-Models-MongoDB.md` for data schemas.*