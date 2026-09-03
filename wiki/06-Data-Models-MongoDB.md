# Data Models & MongoDB Schema

Complete reference for all data structures and database collections.

## MongoDB Collections Overview

| Collection | Description | Key Indexes |
|------------|-------------|-------------|
| `targets` | Target domains to scan | `domain` (unique), `source`, `status`, `platform`, `program_id` |
| `programs` | Bug bounty programs | `name` + `platform` (unique) |
| `jobs` | Hunt job queue | `target_id`, `status`, `queued_at`, `source` |
| `js_files` | Fetched JavaScript files | `target_id`, `js_hash`, `url`, `target_id`+`js_hash` (unique) |
| `secrets` | Secret findings | `target_id`, `js_file_id`, `pattern`, `confidence` |
| `sinks` | Source/sink analysis | `target_id`, `js_file_id`, `sink_type`, `has_origin_check` |
| `endpoints` | API endpoints | `target_id`, `endpoint` |
| `params` | Parameter names | `target_id`, `param_name`, `context` |
| `blh_candidates` | Broken link hijacking | `target_id`, `referenced_domain`, `risk_level`, `resolution_status` |
| `library_cves` | Vulnerable libraries | `target_id`, `library_name`, `cve_id`, `severity` |
| `discovered_urls` | Incremental tracking | `target_id`+`url` (unique), `source`, `last_seen` |
| `sensitive_endpoint_candidates` | Active check results | `target_id`, `endpoint`, `status_code` |

---

## Collection Schemas

### `targets`
```javascript
{
  _id: "uuid-string",                    // Primary key
  domain: "example.com",                  // Target domain (unique)
  source: "manual",                       // "manual" | "watchdogs"
  platform: "hackerone",                  // "hackerone" | "bugcrowd" | "intigriti" | "yeswehack" | "openbugbounty" | "freelance"
  program_id: "uuid-string",              // Reference to programs._id
  status: "pending",                      // "pending" | "active" | "completed" | "error"
  added_at: ISODate("2024-01-15T10:30:00Z"),
  updated_at: ISODate("2024-01-15T10:30:00Z"),
  
  // Watchdogs-specific (when source="watchdogs")
  root_domain: "example.com",
  status_code: 200,
  technologies: ["React", "Next.js", "Cloudflare"],
  title: "Example Application",
  ports: ["80", "443"],
  cdn: "Cloudflare",
  providers: ["AWS", "Vercel"],
  discovered_at: ISODate("2024-01-10T08:00:00Z"),
  
  // Web UI job tracking fields
  job_status: "done",
  job_started_at: ISODate("2024-01-15T10:30:05Z"),
  job_finished_at: ISODate("2024-01-15T10:35:00Z")
}
```

**Indexes:**
```javascript
db.targets.createIndex({ domain: 1 }, { unique: true })
db.targets.createIndex({ source: 1 })
db.targets.createIndex({ status: 1 })
db.targets.createIndex({ platform: 1 })
db.targets.createIndex({ program_id: 1 })
```

---

### `programs`
```javascript
{
  _id: "uuid-string",
  name: "walmart",
  platform: "hackerone",
  added_at: ISODate("2024-01-15T10:30:00Z")
}
```

**Indexes:**
```javascript
db.programs.createIndex({ name: 1, platform: 1 }, { unique: true })
```

---

### `jobs`
```javascript
{
  _id: "uuid-string",                     // Job ID
  target_id: "uuid-string",               // Reference to targets._id
  status: "queued",                       // "queued" | "running" | "done" | "error"
  queued_at: ISODate("2024-01-15T10:30:00Z"),
  started_at: ISODate("2024-01-15T10:30:05Z"),   // Null if not started
  finished_at: ISODate("2024-01-15T10:35:00Z"),  // Null if not finished
  error: "",                              // Error message if status="error"
  source: "manual",                       // "manual" | "watchdogs"
  current_step: "analyzing.js"            // Current phase: "discovery.katana", "discovery.wayback", "analyzing.js", "analyzing.cve", "complete"
}
```

**Indexes:**
```javascript
db.jobs.createIndex({ target_id: 1 })
db.jobs.createIndex({ status: 1 })
db.jobs.createIndex({ queued_at: 1 })
db.jobs.createIndex({ target_id: 1, status: 1 })  // For finding target's latest job
```

---

### `js_files`
```javascript
{
  _id: "uuid-string",
  target_id: "uuid-string",
  url: "https://example.com/main.js",
  js_hash: "a1b2c3d4e5f6...",             // SHA256 of content (deduplication)
  content: "...",                         // Optional: full content (debugging)
  status_code: 200,
  content_type: "application/javascript",
  content_length: 15432,
  fetched_at: ISODate("2024-01-15T10:31:00Z"),
  source_map_url: "https://example.com/main.js.map",
  source_map_hash: "f6e5d4c3b2a1..."
}
```

**Indexes:**
```javascript
db.js_files.createIndex({ target_id: 1 })
db.js_files.createIndex({ js_hash: 1 })
db.js_files.createIndex({ target_id: 1, js_hash: 1 }, { unique: true })  // Dedupe
db.js_files.createIndex({ url: 1 })
```

---

### `secrets`
```javascript
{
  _id: "uuid-string",
  target_id: "uuid-string",
  js_file_id: "uuid-string",
  pattern: "aws_secret_access_key",       // Pattern name that matched
  matched: "AKIA****************DEF",      // Redacted match
  line: 42,
  column: 15,
  entropy: 4.2,
  confidence: 0.85,
  context: "...aws_secret_access_key = \"AKIA...\"...",
  found_at: ISODate("2024-01-15T10:31:05Z"),
  is_minified: false
}
```

**Indexes:**
```javascript
db.secrets.createIndex({ target_id: 1 })
db.secrets.createIndex({ js_file_id: 1 })
db.secrets.createIndex({ pattern: 1 })
db.secrets.createIndex({ confidence: -1 })  // High confidence first
```

---

### `sinks`
```javascript
{
  _id: "uuid-string",
  target_id: "uuid-string",
  js_file_id: "uuid-string",
  sink_type: "innerHTML",                 // eval, innerHTML, postMessage, etc.
  source_type: "url_params",              // Source of user input
  line: 15,
  column: 8,
  snippet: "  element.innerHTML = userInput;\n> element.innerHTML = getData();\n  ...",
  confidence: 0.75,
  has_origin_check: false,                // Only for postMessage
  found_at: ISODate("2024-01-15T10:31:10Z"),
  is_minified: false,
  low_confidence: false
}
```

**Indexes:**
```javascript
db.sinks.createIndex({ target_id: 1 })
db.sinks.createIndex({ js_file_id: 1 })
db.sinks.createIndex({ sink_type: 1 })
db.sinks.createIndex({ has_origin_check: 1 })  // Find postMessage without origin check
db.sinks.createIndex({ confidence: -1 })
```

---

### `endpoints`
```javascript
{
  _id: "uuid-string",
  target_id: "uuid-string",
  js_file_id: "uuid-string",
  endpoint: "/api/v1/users",
  method: "GET",                          // "GET" | "POST" | "PUT" | "DELETE" | ""
  full_url: "https://example.com/api/v1/users",
  context: "fetch",                       // "fetch" | "axios" | "form" | "extracted"
  found_at: ISODate("2024-01-15T10:31:15Z")
}
```

**Indexes:**
```javascript
db.endpoints.createIndex({ target_id: 1 })
db.endpoints.createIndex({ endpoint: 1 })
db.endpoints.createIndex({ method: 1 })
```

---

### `params`
```javascript
{
  _id: "uuid-string",
  target_id: "uuid-string",
  js_file_id: "uuid-string",
  param_name: "userId",
  context: "query",                       // "query" | "body" | "form" | "header" | "path" | "unknown"
  location: "URLSearchParams",            // Where in code: "fetch", "URLSearchParams", etc.
  found_at: ISODate("2024-01-15T10:31:20Z")
}
```

**Indexes:**
```javascript
db.params.createIndex({ target_id: 1 })
db.params.createIndex({ param_name: 1 })
db.params.createIndex({ context: 1 })
```

---

### `blh_candidates`
```javascript
{
  _id: "uuid-string",
  target_id: "uuid-string",
  js_file_id: "uuid-string",
  referenced_url: "https://cdn.example.com/script.js",
  referenced_domain: "cdn.example.com",
  resolution_status: "unclaimed_s3",      // "resolved" | "nxdomain" | "unclaimed_s3" | "github_pages_missing" | "missing" | "http_error" | "unreachable"
  risk_level: "critical",                 // "critical" | "high" | "medium" | "low"
  cloud_provider: "S3",                   // "S3" | "Azure" | "GitHub" | "unknown"
  evidence: "S3 bucket appears unclaimed",
  found_in: "js_file",                    // "js_file" | "html_page"
  is_target_subdomain: false,
  found_at: ISODate("2024-01-15T10:31:25Z")
}
```

**Indexes:**
```javascript
db.blh_candidates.createIndex({ target_id: 1 })
db.blh_candidates.createIndex({ referenced_domain: 1 })
db.blh_candidates.createIndex({ risk_level: 1 })
db.blh_candidates.createIndex({ resolution_status: 1 })
db.blh_candidates.createIndex({ cloud_provider: 1 })
```

---

### `library_cves`
```javascript
{
  _id: "uuid-string",
  target_id: "uuid-string",
  js_file_id: "uuid-string",
  library_name: "jQuery",
  version: "1.12.4",
  cve_id: "CVE-2020-11022",
  severity: "medium",                     // "critical" | "high" | "medium" | "low"
  description: "XSS via htmlPrefilter",
  reference: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11022",
  found_at: ISODate("2024-01-15T10:31:30Z")
}
```

**Indexes:**
```javascript
db.library_cves.createIndex({ target_id: 1 })
db.library_cves.createIndex({ library_name: 1 })
db.library_cves.createIndex({ cve_id: 1 })
db.library_cves.createIndex({ severity: 1 })
```

---

### `discovered_urls`
```javascript
{
  _id: "uuid-string",
  target_id: "uuid-string",
  url: "https://example.com/main.js",
  url_type: "js_file",                    // "js_file" | "endpoint"
  source: "katana",                       // "katana" | "wayback_cdx" | "gau" | "extracted_from_js" | "manual"
  first_seen: ISODate("2024-01-15T10:30:00Z"),
  last_seen: ISODate("2024-01-15T10:31:00Z")
}
```

**Indexes:**
```javascript
db.discovered_urls.createIndex({ target_id: 1, url: 1 }, { unique: true })
db.discovered_urls.createIndex({ target_id: 1 })
db.discovered_urls.createIndex({ source: 1 })
db.discovered_urls.createIndex({ last_seen: -1 })
```

---

### `sensitive_endpoint_candidates`
```javascript
{
  _id: "uuid-string",
  target_id: "uuid-string",
  endpoint: "https://example.com/api/user/profile",
  status_code: 200,
  response_size: 2048,
  matched_patterns: ["email", "password", "token"],
  checked_at: ISODate("2024-01-15T10:32:00Z"),
  source: "common_path"                   // "common_path" | "js_extracted" | "html_extracted"
}
```

**Indexes:**
```javascript
db.sensitive_endpoint_candidates.createIndex({ target_id: 1 })
db.sensitive_endpoint_candidates.createIndex({ endpoint: 1 })
db.sensitive_endpoint_candidates.createIndex({ status_code: 1 })
```

---

## Go Models (`internal/models/models.go`)

### Target
```go
type Target struct {
    ID           string       `bson:"_id" json:"id"`
    Domain       string       `bson:"domain" json:"domain"`
    Source       TargetSource `bson:"source" json:"source"`
    Platform     TargetPlatform `bson:"platform,omitempty" json:"platform,omitempty"`
    ProgramID    string       `bson:"program_id,omitempty" json:"program_id,omitempty"`
    Status       TargetStatus `bson:"status" json:"status"`
    AddedAt      time.Time    `bson:"added_at" json:"added_at"`
    UpdatedAt    time.Time    `bson:"updated_at" json:"updated_at"`
    RootDomain   string       `bson:"root_domain,omitempty" json:"root_domain,omitempty"`
    StatusCode   int          `bson:"status_code,omitempty" json:"status_code,omitempty"`
    Technologies []string     `bson:"technologies,omitempty" json:"technologies,omitempty"`
    Title        string       `bson:"title,omitempty" json:"title,omitempty"`
    Ports        []string     `bson:"ports,omitempty" json:"ports,omitempty"`
    CDN          string       `bson:"cdn,omitempty" json:"cdn,omitempty"`
    Providers    []string     `bson:"providers,omitempty" json:"providers,omitempty"`
    DiscoveredAt *time.Time   `bson:"discovered_at,omitempty" json:"discovered_at,omitempty"`
    JobStatus     string     `bson:"job_status,omitempty" json:"job_status,omitempty"`
    JobStartedAt  *time.Time `bson:"job_started_at,omitempty" json:"job_started_at,omitempty"`
    JobFinishedAt *time.Time `bson:"job_finished_at,omitempty" json:"job_finished_at,omitempty"`
}
```

### Program
```go
type Program struct {
    ID        string    `bson:"_id" json:"id"`
    Name      string    `bson:"name" json:"name"`
    Platform  string    `bson:"platform" json:"platform"`
    AddedAt   time.Time `bson:"added_at" json:"added_at"`
}
```

### Job
```go
type Job struct {
    ID         string      `bson:"_id" json:"id"`
    TargetID   string      `bson:"target_id" json:"target_id"`
    Status     JobStatus   `bson:"status" json:"status"`
    QueuedAt   time.Time   `bson:"queued_at" json:"queued_at"`
    StartedAt  *time.Time  `bson:"started_at,omitempty" json:"started_at,omitempty"`
    FinishedAt *time.Time  `bson:"finished_at,omitempty" json:"finished_at,omitempty"`
    Error      string      `bson:"error,omitempty" json:"error,omitempty"`
    Source     string      `bson:"source" json:"source"`
    CurrentStep string      `bson:"current_step,omitempty" json:"current_step,omitempty"`
}
```

### JSFile
```go
type JSFile struct {
    ID            string    `bson:"_id" json:"id"`
    TargetID      string    `bson:"target_id" json:"target_id"`
    URL           string    `bson:"url" json:"url"`
    JSHash        string    `bson:"js_hash" json:"js_hash"`
    Content       string    `bson:"content,omitempty" json:"content,omitempty"`
    StatusCode    int       `bson:"status_code" json:"status_code"`
    ContentType   string    `bson:"content_type" json:"content_type"`
    ContentLength int64     `bson:"content_length" json:"content_length"`
    FetchedAt     time.Time `bson:"fetched_at" json:"fetched_at"`
    SourceMapURL  string    `bson:"source_map_url,omitempty" json:"source_map_url,omitempty"`
    SourceMapHash string    `bson:"source_map_hash,omitempty" json:"source_map_hash,omitempty"`
}
```

### Secret
```go
type Secret struct {
    ID         string    `bson:"_id" json:"id"`
    TargetID   string    `bson:"target_id" json:"target_id"`
    JSFileID   string    `bson:"js_file_id" json:"js_file_id"`
    Pattern    string    `bson:"pattern" json:"pattern"`
    Matched    string    `bson:"matched" json:"matched"`
    Line       int       `bson:"line" json:"line"`
    Column     int       `bson:"column,omitempty" json:"column,omitempty"`
    Entropy    float64   `bson:"entropy" json:"entropy"`
    Confidence float64   `bson:"confidence" json:"confidence"`
    Context    string    `bson:"context,omitempty" json:"context,omitempty"`
    FoundAt    time.Time `bson:"found_at" json:"found_at"`
    IsMinified bool      `bson:"is_minified,omitempty" json:"is_minified,omitempty"`
}
```

### Sink
```go
type Sink struct {
    ID              string    `bson:"_id" json:"id"`
    TargetID        string    `bson:"target_id" json:"target_id"`
    JSFileID        string    `bson:"js_file_id" json:"js_file_id"`
    SinkType        string    `bson:"sink_type" json:"sink_type"`
    SourceType      string    `bson:"source_type" json:"source_type"`
    Line            int       `bson:"line" json:"line"`
    Column          int       `bson:"column,omitempty" json:"column,omitempty"`
    Snippet         string    `bson:"snippet" json:"snippet"`
    Confidence      float64   `bson:"confidence" json:"confidence"`
    HasOriginCheck  bool      `bson:"has_origin_check" json:"has_origin_check"`
    FoundAt         time.Time `bson:"found_at" json:"found_at"`
    IsMinified      bool      `bson:"is_minified,omitempty" json:"is_minified,omitempty"`
    LowConfidence   bool      `bson:"low_confidence,omitempty" json:"low_confidence,omitempty"`
}
```

### Endpoint
```go
type Endpoint struct {
    ID       string    `bson:"_id" json:"id"`
    TargetID string    `bson:"target_id" json:"target_id"`
    JSFileID string    `bson:"js_file_id" json:"js_file_id"`
    Endpoint string    `bson:"endpoint" json:"endpoint"`
    Method   string    `bson:"method,omitempty" json:"method,omitempty"`
    FullURL  string    `bson:"full_url,omitempty" json:"full_url,omitempty"`
    Context  string    `bson:"context,omitempty" json:"context,omitempty"`
    FoundAt  time.Time `bson:"found_at" json:"found_at"`
}
```

### Param
```go
type Param struct {
    ID        string    `bson:"_id" json:"id"`
    TargetID  string    `bson:"target_id" json:"target_id"`
    JSFileID  string    `bson:"js_file_id" json:"js_file_id"`
    ParamName string    `bson:"param_name" json:"param_name"`
    Context   string    `bson:"context" json:"context"`
    Location  string    `bson:"location,omitempty" json:"location,omitempty"`
    FoundAt   time.Time `bson:"found_at" json:"found_at"`
}
```

### BLHCandidate
```go
type BLHCandidate struct {
    ID                string    `bson:"_id" json:"id"`
    TargetID          string    `bson:"target_id" json:"target_id"`
    JSFileID          string    `bson:"js_file_id,omitempty" json:"js_file_id,omitempty"`
    ReferencedURL     string    `bson:"referenced_url,omitempty" json:"referenced_url,omitempty"`
    ReferencedDomain  string    `bson:"referenced_domain" json:"referenced_domain"`
    ResolutionStatus  string    `bson:"resolution_status" json:"resolution_status"`
    RiskLevel         string    `bson:"risk_level" json:"risk_level"`
    CloudProvider     string    `bson:"cloud_provider,omitempty" json:"cloud_provider,omitempty"`
    Evidence          string    `bson:"evidence,omitempty" json:"evidence,omitempty"`
    FoundIn           string    `bson:"found_in,omitempty" json:"found_in,omitempty"`
    IsTargetSubdomain bool      `bson:"is_target_subdomain,omitempty" json:"is_target_subdomain,omitempty"`
    FoundAt           time.Time `bson:"found_at" json:"found_at"`
}
```

### LibraryCVE
```go
type LibraryCVE struct {
    ID          string    `bson:"_id" json:"id"`
    TargetID    string    `bson:"target_id" json:"target_id"`
    JSFileID    string    `bson:"js_file_id" json:"js_file_id"`
    LibraryName string    `bson:"library_name" json:"library_name"`
    Version     string    `bson:"version" json:"version"`
    CVEID       string    `bson:"cve_id" json:"cve_id"`
    Severity    string    `bson:"severity" json:"severity"`
    Description string    `bson:"description,omitempty" json:"description,omitempty"`
    Reference   string    `bson:"reference,omitempty" json:"reference,omitempty"`
    FoundAt     time.Time `bson:"found_at" json:"found_at"`
}
```

### DiscoveredURL
```go
type DiscoveredURL struct {
    ID        string    `bson:"_id" json:"id"`
    TargetID  string    `bson:"target_id" json:"target_id"`
    URL       string    `bson:"url" json:"url"`
    URLType   string    `bson:"url_type" json:"url_type"`
    Source    string    `bson:"source" json:"source"`
    FirstSeen time.Time `bson:"first_seen" json:"first_seen"`
    LastSeen  time.Time `bson:"last_seen" json:"last_seen"`
}
```

### SensitiveEndpointCandidate
```go
type SensitiveEndpointCandidate struct {
    ID              string    `bson:"_id" json:"id"`
    TargetID        string    `bson:"target_id" json:"target_id"`
    Endpoint        string    `bson:"endpoint" json:"endpoint"`
    StatusCode      int       `bson:"status_code" json:"status_code"`
    ResponseSize    int       `bson:"response_size" json:"response_size"`
    MatchedPatterns []string  `bson:"matched_patterns" json:"matched_patterns"`
    FoundAt         time.Time `bson:"found_at" json:"found_at"`
    Source          string    `bson:"source,omitempty" json:"source,omitempty"`
}
```

---

## Enums

### TargetSource
```go
type TargetSource string
const (
    SourceWatchdogs TargetSource = "watchdogs"
    SourceManual    TargetSource = "manual"
)
```

### TargetPlatform
```go
type TargetPlatform string
const (
    PlatformHackerOne      TargetPlatform = "hackerone"
    PlatformBugcrowd       TargetPlatform = "bugcrowd"
    PlatformIntigriti      TargetPlatform = "intigriti"
    PlatformYesWeHack      TargetPlatform = "yeswehack"
    PlatformOpenBugBounty  TargetPlatform = "openbugbounty"
    PlatformFreelance      TargetPlatform = "freelance"
)
```

### TargetStatus
```go
type TargetStatus string
const (
    StatusPending   TargetStatus = "pending"
    StatusActive    TargetStatus = "active"
    StatusCompleted TargetStatus = "completed"
    StatusError     TargetStatus = "error"
)
```

### JobStatus
```go
type JobStatus string
const (
    JobStatusQueued   JobStatus = "queued"
    JobStatusRunning  JobStatus = "running"
    JobStatusDone     JobStatus = "done"
    JobStatusError    JobStatus = "error"
)
```

---

## PhaseCounter
```go
type PhaseCounter struct {
    Secrets     atomic.Int64
    Sinks       atomic.Int64
    Endpoints   atomic.Int64
    Params      atomic.Int64
    BLH         atomic.Int64
    Cves        atomic.Int64
    Fetched     atomic.Int64
    Skipped     atomic.Int64
}
```

---

## CVE Module Types (`internal/cve/module.go`)

### LocalCVEEntry
```go
type LocalCVEEntry struct {
    Library      string  `json:"library"`
    MaxVersion   string  `json:"max_version"`
    CVEID        string  `json:"cve_id"`
    Severity     string  `json:"severity"`
    CVSS         float64 `json:"cvss"`
    HasPoC       bool    `json:"has_poc"`
    Summary      string  `json:"summary"`
    FixedVersion string  `json:"fixed_version,omitempty"`
    Source       string  `json:"source"` // "snare", "retire.js", "osv", "github", "npm"
}
```

### CVEFinding
```go
type CVEFinding struct {
    CVEID        string  `json:"cve_id"`
    Library      string  `json:"library"`
    DetectedVer  string  `json:"detected_version"`
    FixedVer     string  `json:"fixed_version,omitempty"`
    Severity     string  `json:"severity"`
    CVSS         float64 `json:"cvss"`
    HasPoC       bool    `json:"has_poc"`
    Summary      string  `json:"summary"`
    Source       string  `json:"source"`        // "local", "osv.dev", "github", "npm", "retire.js"
    Confidence   float64 `json:"confidence"`    // 0-1
    MatchType    string  `json:"match_type"`    // "exact", "range", "fuzzy"
    Context      string  `json:"context,omitempty"` // where detected: "header", "js_file", "package_json", "source_map"
}
```

### CVEConfig
```go
type CVEConfig struct {
    DataDir            string  `mapstructure:"data_dir"`
    EnableOnlineLookup bool    `mapstructure:"enable_online_lookup"`
    RateLimitRPS       float64 `mapstructure:"rate_limit_rps"`
    UpdateIntervalDays int     `mapstructure:"update_interval_days"`
    MinConfidence      float64 `mapstructure:"min_confidence"` // minimum confidence to report
}
```

### UpdateResult
```go
type UpdateResult struct {
    NewCVEs        []LocalCVEEntry
    NewLibraries   int
    UpdatedSources int
    Errors         []string
}
```

---

*See `internal/models/models.go` and `internal/cve/module.go` for implementation.*