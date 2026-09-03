# Discovery & JS Module Documentation

This document explains how Hustler discovers JavaScript files and processes them.

## Discovery Pipeline (`internal/discovery/discovery.go`)

### Overview
The discovery phase finds JavaScript URLs for a target using **three sources** (configurable):

| Source | Tool | Type | Default |
|--------|------|------|---------|
| **Katana** | `katana` binary | Active crawl | ✅ Enabled |
| **Wayback CDX** | HTTP API | Historical | ✅ Enabled |
| **Gau** | `gau` binary | Historical | ❌ Disabled |

### Configuration
```yaml
js:
  use_katana: true        # Active crawling - finds LIVE JS files
  use_gau: false          # Historical - often slow/blocked
  katana_depth: 2         # Crawl depth
  katana_timeout: 180     # Seconds
```

---

### 1. Katana (Active Crawling) — **Primary**

**Command:**
```bash
katana -u https://example.com -jc -d 2 -nc -silent
```

**Flags:**
- `-u` - Target URL
- `-jc` - Extract JavaScript file endpoints (JS crawler mode)
- `-d 2` - Depth 2 (crawl links from links)
- `-nc` - No color output
- `-silent` - Suppress banners/logs

**How it works:**
1. Starts at `https://target.com`
2. Renders pages (headless browser) and extracts all links
3. Follows links up to depth 2
4. Identifies JavaScript files by `.js` extension
5. Outputs clean URLs (one per line)

**Why Katana?**
- **Active** - renders JavaScript, finds dynamically loaded resources
- **Modern** - handles SPAs, React, Vue, Next.js, etc.
- **Fast** - concurrent, optimized for bug bounty
- **Reliable** - the primary discovery method

**Parsing:**
```go
// Filters output lines:
if strings.HasSuffix(line, ".js") || strings.Contains(line, ".js?")
```

---

### 2. Wayback CDX API (Historical)

**Endpoint:**
```
https://web.archive.org/cdx/search/cdx?
  url=*.example.com/*.js&
  output=json&
  fl=original&
  limit=1000&
  collapse=urlkey
```

**Parameters:**
- `url=*.domain/*.js` - Match all JS files for domain + subdomains
- `output=json` - JSON Lines format
- `fl=original` - Return only original URL field
- `limit=1000` - Cap results
- `collapse=urlkey` - Deduplicate by URL key (same content)

**Response Format (JSON Lines):**
```json
["https://example.com/main.js"]
["https://cdn.example.com/app.js"]
["https://assets.example.com/bundle.js"]
```

**Parsing:**
```go
var arr []string
json.Unmarshal([]byte(line), &arr)
url := arr[0]
```

**Why CDX over waybackurls?**
- **Official API** - more reliable, structured
- **Collapse** - built-in deduplication
- **Filtering** - server-side `.js` filtering
- **No binary dependency** - pure HTTP

---

### 3. Gau (GetAllUrls) — Disabled by Default

**Command:**
```bash
gau --providers wayback https://example.com --subs
```

**Issues:**
- Often blocked by Wayback (rate limits)
- Slow (sequential by default)
- Requires Go binary

**Use Case:**
- Supplementary historical data
- When CDX is insufficient

---

### Discovery Output

```go
type DiscoveryResult struct {
    URLs  []string          // All unique JS URLs
    Stats map[string]int    // Count per source: {"katana": 150, "wayback_cdx": 45}
}
```

**Deduplication:** All sources combined into `map[string]bool` for uniqueness.

---

## JS Module Pipeline (`internal/js/module.go`)

### Overview
The JS Module handles the **complete processing pipeline** for discovered JS files:

```
discoverViaKatana() ──▶
discoverViaWayback() ──▶
discoverViaGau() ──────▶
                        ▼
              ┌───────────────────┐
              │  DEDUPLICATE      │ ──▶ Remove duplicates, normalize URLs
              └───────────────────┘
                        ▼
              ┌───────────────────┐
              │  INCREMENTAL CHECK│ ──▶ Skip already-processed URLs (hash-based)
              └───────────────────┘
                        ▼
              ┌───────────────────┐
              │  FETCH (concurrent)│ ──▶ HTTP GET with semaphore (default 10)
              └───────────────────┘
                        ▼
              ┌───────────────────┐
              │  HASH DEDUPE      │ ──▶ SHA256 content hash, skip if seen for target
              └───────────────────┘
                        ▼
              ┌───────────────────┐
              │  STORE JS FILE    │ ──▶ MongoDB: js_files collection
              └───────────────────┘
                        ▼
              ┌───────────────────┐
              │  RUN ANALYZERS    │ ──▶ 8 analyzers in sequence
              └───────────────────┘
```

---

### Step 1: URL Deduplication & Normalization

```go
func deduplicateURLs(urls []string) []string
```
- Trim whitespace
- Parse URL, remove fragment (`#hash`)
- Normalize (resolve relative paths)
- Deduplicate via map

---

### Step 2: Incremental Check

```go
func getKnownURLs(ctx, targetID, urls) map[string]bool
```
- Queries `discovered_urls` collection for `target_id` + `url`
- Returns map of already-seen URLs
- Only **new URLs** proceed to fetch

---

### Step 3: Concurrent Fetch

```go
semaphore := make(chan struct{}, m.cfg.MaxConcurrentFetch) // default 10
```
- Goroutine per URL, limited by semaphore
- HTTP client with:
  - Connection pooling (max 2x concurrent)
  - 30s idle timeout
  - No redirect following (preserve original URL)
  - Configurable timeout (default 15s)

---

### Step 4: Hash-Based Deduplication (Content-Level)

```go
hash := sha256.Sum256(body)
hashStr := hex.EncodeToString(hash[:])
```
- SHA256 of response body
- Checks `js_files` collection for `target_id` + `js_hash`
- **Skips** if identical content already processed for this target
- **Global skip list** for known libraries (jQuery, React, etc. via config)

---

### Step 5: JS File Storage

```go
type JSFile struct {
    ID             string
    TargetID       string
    URL            string
    JSHash         string      // SHA256 for dedupe
    StatusCode     int
    ContentType    string
    ContentLength  int64
    FetchedAt      time.Time
    SourceMapURL   string      // If //# sourceMappingURL= found
    SourceMapHash  string
}
```
Stored in `js_files` collection.

---

### Step 6: Source Map Detection

```go
func extractSourceMapURL(content, baseURL string) string
```
- Scans **last 50 lines** of JS
- Patterns:
  - `//# sourceMappingURL=...`
  - `/*# sourceMappingURL=... */`
- Resolves relative URLs against base JS URL
- If enabled (`cfg.EnableSourceMaps`), fetches and stores source map hash

---

### Step 7: Analyzer Pipeline

```go
func runAnalyzersWithCounter(ctx, target, jsFiles, contentMap, htmlContent, pc)
```

| Order | Analyzer | Input | Output Collection |
|-------|----------|-------|-------------------|
| 1 | SecretScanner | content | `secrets` |
| 2 | SinkAnalyzer | content | `sinks` |
| 3 | EndpointExtractor | content | `endpoints` |
| 4 | ParamExtractor | content | `params` |
| 5 | BLHAnalyzer | contentMap | `blh_candidates` |
| 6 | LibraryCVEAnalyzer | contentMap | `library_cves` (legacy) |
| 7 | CVE Module | jsFiles + HTTP responses | `library_cves` (NEW) |
| 8 | SensitiveEndpointAnalyzer | endpoints from DB | `sensitive_endpoint_candidates` |

**Key Design:** Each analyzer:
- Runs independently per JS file
- Writes directly to MongoDB
- Logs count per file
- Errors don't stop pipeline (warn and continue)

---

### Discovered URLs Tracking

```go
func storeDiscoveredURLs(ctx, targetID, endpoints, source)
```
- Tracks **how** each URL was found
- Sources: `katana`, `wayback_cdx`, `gau`, `extracted_from_js`, `manual`
- Enables **incremental scanning** on re-runs

---

## Data Flow Summary

```
Target (domain)
       │
       ▼
DiscoveryRunner.DiscoverJSURLs()
       │
       ├── Katana (active) ──▶ 500-2000 URLs typical
       ├── Wayback CDX ──────▶ 100-500 URLs typical
       └── Gau (disabled) ───▶ 0
       │
       ▼
Unique URLs (deduplicated)
       │
       ▼
JSModule.FetchAndProcessWithCounter()
       │
       ├── getKnownURLs() ──▶ Filter already-seen
       │
       ├── Fetch (10 concurrent)
       │    ├── HTTP GET
       │    ├── SHA256 hash
       │    ├── Check js_files for hash
       │    └── Store new JSFile
       │
       └── runAnalyzers() ──▶ 8 analyzers → 8 MongoDB collections
```

---

## Incremental Scanning

On **re-run** of same target:
1. Discovery finds same + new URLs
2. `getKnownURLs()` filters out previously seen URLs
3. For new URLs: fetch → hash check → if new content, process
4. If same URL but **different content** (hash changed) → re-process
5. Results **accumulate** in MongoDB (not replaced)

---

## Configuration Options

```yaml
js:
  max_concurrent_fetches: 10      # Semaphore limit
  fetch_timeout_seconds: 15       # HTTP timeout
  max_file_size_mb: 10            # Body read limit
  user_agent: "Hustler/1.0"
  use_katana: true                # Discovery
  use_gau: false                  # Discovery
  katana_depth: 2
  katana_timeout: 180
  entropy_threshold: 3.5          # Secret scanner
  enable_source_maps: true
  skip_hashes: []                 # Known library hashes to skip
```

---

## Extending Discovery

### Add New Discovery Source
1. Add method to `DiscoveryRunner`:
```go
func (d *DiscoveryRunner) discoverViaNewSource(ctx, domain) ([]string, error)
```
2. Call in `DiscoverJSURLs()` if enabled in config
3. Add config field in `internal/config/config.go`

### Modify Katana Arguments
Edit `discoverViaKatana()` - change flags like `-d`, add `-kf` (known files), etc.

---

*See `internal/discovery/discovery.go` and `internal/js/module.go` for full implementation.*