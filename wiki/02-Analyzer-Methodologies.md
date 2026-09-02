# Analyzer Methodologies

This document explains the methodology behind each analyzer in Hustler.

## 1. Secret Scanner (`internal/analyzers/secret_scanner.go`)

### Purpose
Detect secrets, API keys, tokens, passwords, and other sensitive data embedded in JavaScript files.

### Methodology

#### Pattern-Based Detection
The scanner uses **67+ regex patterns** covering:
- **Cloud Providers**: AWS (Access Key ID, Secret Access Key, Session Token), GCP, Azure, Heroku
- **Communication Platforms**: Slack (tokens, webhooks), Discord
- **Database Connections**: MongoDB, PostgreSQL, MySQL, Redis, JDBC URLs
- **Authentication**: OAuth tokens, Bearer tokens, JWT tokens, refresh/access tokens
- **Configuration Files**: .env patterns, .htaccess auth, SSH keys
- **Generic**: High-entropy strings, Base64 strings, generic API keys/secrets

#### Entropy Analysis (Shannon Entropy)
```go
func calculateEntropy(str string) float64
```
- Calculates **Shannon entropy** of matched strings
- High entropy (> 3.5 default threshold) indicates randomness typical of secrets
- Formula: `H = -Σ(p(x) * log2(p(x)))` where p(x) is frequency of each character

#### Confidence Scoring
```go
func calculateConfidence(pattern, entropy, matched)
```
- **Base confidence**: 0.5 (generic), 0.85 (high-confidence patterns like AWS keys)
- **Entropy boost**: +0.15 if entropy > threshold
- **Entropy penalty**: -0.2 if entropy < 2.5 (likely false positive)
- **Known prefix boost**: +0.1 for prefixes like `sk_`, `pk_`, `AKIA`, `xoxb-`, `ya29.`, `eyJ` (JWT)
- **Capped at 1.0**, floored at 0.0

#### Redaction for Storage
Matched secrets are **redacted** before storage: `AKIA1234567890ABCDEF` → `AKIA********ABCDEF`

### Output
Stored in MongoDB `secrets` collection with: pattern name, redacted match, line/column, entropy, confidence, context snippet.

---

## 2. Sink Analyzer (`internal/analyzers/sink_analyzer.go`)

### Purpose
Perform **source/sink analysis** to identify DOM-based XSS vulnerabilities by finding dangerous sinks and tracing back to user-controlled sources.

### Methodology

#### Sink Patterns (13 sinks)
| Sink Type | Pattern | Risk |
|-----------|---------|------|
| `eval` | `\beval\s*\(` | **Critical** - arbitrary code execution |
| `innerHTML` | `\.innerHTML\s*=` | **High** - HTML injection |
| `outerHTML` | `\.outerHTML\s*=` | **High** - HTML injection |
| `document.write` | `document\.write\s*\(` | **High** - DOM injection |
| `document.writeln` | `document\.writeln\s*\(` | **High** |
| `insertAdjacentHTML` | `insertAdjacentHTML\s*\(` | **High** |
| `execScript` | `execScript\s*\(` | **Critical** (IE only) |
| `setTimeout` | `setTimeout\s*\(` | **Medium** - if first arg is string |
| `setInterval` | `setInterval\s*\(` | **Medium** |
| `Function` | `new\s+Function\s*\(` | **Critical** - code execution |
| `postMessage` | `postMessage\s*\(` | **High** - cross-origin messaging |
| `location.href` | `location\.href\s*=` | **Medium** - navigation |
| `location.assign/replace` | `location\.(assign|replace)\s*\(` | **Medium** |
| `window.open` | `window\.open\s*\(` | **Low** - popup |

#### Source Patterns (13 sources)
| Source Type | Pattern | Description |
|-------------|---------|-------------|
| `url_params` | `URLSearchParams`, `location.search` | Query string parameters |
| `url_hash` | `location.hash` | URL fragment |
| `url_pathname` | `location.pathname` | URL path |
| `postMessage_data` | `event.data`, `message.data` | Cross-origin messages |
| `document_referrer` | `document.referrer` | Referrer header |
| `localStorage` | `localStorage.getItem` | Persistent storage |
| `sessionStorage` | `sessionStorage.getItem` | Session storage |
| `cookie` | `document.cookie` | Cookies |
| `input_value` | `.value`, `.textContent`, `.innerText` | Form inputs |
| `fetch_response` | `fetch(...).then(` | Fetch API responses |
| `xhr_response` | `XMLHttpRequest`, `responseText` | XHR responses |
| `axios_response` | `axios.(get\|post\|...)` | Axios responses |
| `jquery_html/append` | `$.(...).html()`, `$.(...).append()` | jQuery DOM manipulation |

#### Proximity Analysis
For each sink found, searches **±10 lines** for nearby sources. If a source is nearby, confidence increases from 0.5 → 0.75.

#### Origin Check for postMessage
```go
var originCheckPattern = regexp.MustCompile(`(?i)(?:event\.origin|message\.origin)\s*(?:===|==)\s*['\"]`)
```
Checks if `postMessage` calls validate `event.origin` - critical for preventing cross-origin XSS.

### Output
Stored in MongoDB `sinks` collection with: sink type, source type, line/column, snippet, confidence, has_origin_check.

---

## 3. BLH Analyzer (`internal/analyzers/blh_analyzer.go`)

### Purpose
Detect **Broken Link Hijacking (BLH)** candidates - external domains referenced in JS that may be unclaimed and controllable by an attacker.

### Methodology

#### Domain Extraction
```go
func extractDomains(content, baseURL string) []string
```
Two regex patterns:
1. `src/href` attributes: `(?:src|href)=["']([^"']*://[^"']+)["']`
2. Full URLs: `https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s"']*)?`

**Filters out**: Same domain as base URL, internal references.

#### Domain Checking
```go
func checkDomain(ctx, domain) *BLHCandidate
```

1. **DNS Lookup** (`net.LookupIP`):
   - NXDOMAIN → `resolution_status: "nxdomain"`, `risk: "critical"` (can register)
   - No IPs → `resolution_status: "unreachable"`, `risk: "medium"`

2. **Cloud Provider Identification**:
   - S3: `s3[\w-]*amazonaws\.com`
   - Azure: `blob\.core\.windows\.net`, `azurewebsites\.net`
   - GitHub: `raw\.githubusercontent\.com`, `github\.io`

3. **HTTP Check** (GET `/`):
   - `NoSuchBucket` in response → `unclaimed_s3`, `risk: "critical"`
   - 404 on GitHub Pages → `github_pages_missing`, `risk: "high"`
   - Other 404 → `missing`, `risk: "medium"`
   - Success → `resolved`, `risk: "low"`

#### Deduplication
Tracks seen domains per target to avoid re-checking.

### Output
Stored in MongoDB `blh_candidates` collection with: domain, resolution_status, risk_level, cloud_provider, evidence.

### Risk Levels
| Risk | Condition |
|------|-----------|
| **Critical** | NXDOMAIN (registerable), Unclaimed S3 bucket |
| **High** | GitHub Pages 404 (unclaimed repo) |
| **Medium** | HTTP 404, unreachable DNS |
| **Low** | Resolves normally |

---

## 4. Endpoint Extractor (`internal/analyzers/endpoint_extractor.go`)

### Purpose
Extract **API endpoints** from JavaScript files for further testing (auth bypass, IDOR, injection, etc.)

### Methodology

#### Patterns (5 regex groups)
1. **Direct URLs**: `["'](https?://[^"']+)["']`
2. **Relative paths**: `["'](/[a-zA-Z0-9_\-./?=&#%]+)["']`
3. **Function calls**: `fetch/axios/request/$.get/$.post/$.ajax/XMLHttpRequest/open` with URLs
4. **Template literals**: `` `/path` ``
5. **String concatenation**: `["']([^"']*\/[a-zA-Z0-9_\-./]+)["']`

#### API-Like Filtering (`looksLikeAPI`)
Only keeps paths containing:
- `/api/`, `/graphql`, `/v1/`, `/v2/`
- `/admin`, `/internal`, `/query`, `/mutation`
- `/login`, `/auth`, `/user`, `/users`
- `/data`, `/endpoint`

#### Method Inference
Inferred from calling function:
- `fetch`, `axios.get`, `$.get` → `GET`
- `axios.post`, `$.post` → `POST`
- Others → empty (unknown)

### Output
Stored in MongoDB `endpoints` collection with: endpoint URL, method, context, source JS file.

---

## 5. Parameter Extractor (`internal/analyzers/param_extractor.go`)

### Purpose
Extract **parameter names** from JavaScript for use in fuzzing, injection testing, etc.

### Methodology

#### Patterns (5 regex groups)
1. **Query params**: `URLSearchParams`, `location.search` `.get('param')`
2. **Form-style**: `['"]([a-zA-Z0-9_]+)=['"]`
3. **Form fields**: `(?:name|id)\s*[:=]\s*['"]([a-zA-Z0-9_]+)['"]`
4. **Body params**: `fetch/axios/post` with object properties
5. **Object access**: `(req|request|data|body|params|query)\.([a-zA-Z0-9_]+)`

#### Filtering
- Skip params < 2 chars
- Skip common JS keywords: `var`, `let`, `const`, `function`, `return`, `if`, `else`, `for`, `while`, `class`, `new`, `this`, `null`, `true`, `false`

#### Context Deduction
Analyzes surrounding code to classify parameter location:
- `query` - URLSearchParams, search
- `form` - form, submit
- `header` - header, headers
- `body` - body, json
- `unknown` - default

### Output
Stored in MongoDB `params` collection with: param_name, context, location.

---

## 6. Library CVE Analyzer (`internal/analyzers/library_cve_analyzer.go`)

### Purpose
Fingerprint JavaScript libraries and check against known CVE database.

### Methodology

#### Library Fingerprinting (10 signatures)
| Library | Pattern |
|---------|---------|
| jQuery | `jquery\s*[:=]\s*['"]([12]\.\d+\.\d+)['"]` |
| jQuery (banner) | `jQuery JavaScript Library v?([12]\.\d+\.\d+)` |
| Bootstrap | `Bootstrap v?([345]\.\d+\.\d+)` |
| Vue.js | `Vue.{0,30}version\s*[:=]\s*['"]([\d.]+)['"]` |
| React | `react\s*[:=]\s*['"]([\d.]+)['"]` |
| Angular | `angular[^a-z]?([\d.]+)` |
| Lodash | `lodash[@/ ]([\d.]+)` |
| moment.js | `moment\.version\s*=\s*['"]([\d.]+)['"]` |
| axios | `axios[@/ ]([\d.]+)` |

#### CVE Database
Built-in map of library → CVE list (extendable via JSON file):
```go
cveMap := map[string][]LibraryCVE{
    "jQuery": {CVE-2020-11022, CVE-2020-11023},
    "Bootstrap": {CVE-2024-6484},
    "moment.js": {CVE-2022-24785, CVE-2022-31129},
    "Lodash": {CVE-2021-23337},
}
```

#### Loading External CVE Database
```go
func LoadCVEDatabase(path string) error
```
Loads JSON array format:
```json
[
  {"library": "jQuery", "version": "1.12.4", "cve_id": "CVE-2020-11022", "severity": "medium", "description": "...", "reference": "..."}
]
```

#### Matching Logic
For each detected library+version, adds **ALL CVEs** for that library (regardless of version - conservative approach). Version-specific matching could be added.

### Output
Stored in MongoDB `library_cves` collection with: library_name, version, cve_id, severity, description, reference.

---

## 7. Sensitive Endpoint Analyzer (`internal/analyzers/sensitive_endpoint_analyzer.go`)

### Purpose
**Active check** (disabled by default) - makes GET requests to extracted endpoints to detect sensitive data exposure.

### Methodology

#### Configuration-Driven
- `enabled: false` by default (opt-in)
- `heuristic_paths`: paths to check (e.g., `/api/user`, `/api/admin`, `/config`)
- `sensitive_patterns`: patterns to detect in response (e.g., `password`, `token`, `email`, `ssn`)

#### Safe Checking
- **Only GET requests** - never mutates state
- 50KB response size limit
- Concurrent with worker pool

#### Matching
If response matches sensitive patterns AND status 2xx/3xx → flag as candidate.

### Output
Stored in MongoDB `sensitive_endpoint_candidates` collection with: endpoint, status_code, response_size, matched_patterns.

---

## Summary: Analysis Pipeline Order

```go
// In internal/js/module.go:runAnalyzers()
1. Secret Scanner        // Static analysis - secrets in code
2. Sink Analyzer         // Static analysis - DOM XSS sources/sinks
3. Endpoint Extractor    // Static analysis - API endpoints
4. Param Extractor       // Static analysis - parameter names
5. BLH Analyzer          // External check - domain availability
6. Library CVE Analyzer  // Static + DB lookup - vulnerable libs
7. Sensitive Endpoint    // Active check - only if enabled
```

All analyzers write directly to MongoDB collections for the `js hunt` command to display.

---

## Extending Analyzers

### Adding Secret Patterns
Edit `internal/analyzers/secret_scanner.go` → add to `patterns` slice in `NewSecretScanner()`.

### Adding Sink/Source Patterns
Edit `internal/analyzers/sink_analyzer.go` → add to `sinkPatterns` or `sourcePatterns` maps.

### Adding CVE Data
1. Create JSON file with CVE data
2. Call `cveAnalyzer.LoadCVEDatabase("path/to/cves.json")` in `runAnalyzers()`

### Adding Sensitive Patterns
Edit `config.yaml`:
```yaml
sensitive:
  enabled: true
  heuristic_paths:
    - "/api/user"
    - "/api/admin"
  sensitive_patterns:
    - "password"
    - "secret"
    - "token"
    - "email"
    - "ssn"
```

---

*For implementation details of each analyzer, see the source files in `internal/analyzers/`.*