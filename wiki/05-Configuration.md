# Configuration Reference

Complete configuration guide for `config.yaml`.

## Full Config Structure

```yaml
# MongoDB Connection
mongo:
  uri: "mongodb://localhost:27017"     # MongoDB connection string
  database: "hustler"                   # Database name

# Logging
logging:
  level: "info"                         # debug, info, warn, error
  format: "console"                     # console, json

# JavaScript Hunting Module
js:
  max_concurrent_fetches: 10            # Parallel HTTP fetches (semaphore)
  fetch_timeout_seconds: 15             # HTTP request timeout
  max_file_size_mb: 10                  # Max response body size
  user_agent: "Hustler/1.0"             # HTTP User-Agent header
  use_katana: true                      # Enable Katana discovery
  use_gau: false                        # Enable Gau discovery (slow/blocked)
  katana_depth: 2                       # Katana crawl depth
  katana_timeout: 180                   # Katana timeout (seconds)
  entropy_threshold: 3.5                # Secret scanner entropy threshold
  enable_source_maps: true              # Fetch & store source maps
  skip_hashes: []                       # SHA256 prefixes to skip (known libs)

# Discovery Configuration
discovery:
  enabled: true                         # Enable discovery phase
  use_katana: true                      # Katana active crawl
  use_gau: false                        # Gau historical
  # katana_timeout inherited from js.katana_timeout

# Sensitive Endpoint Check (Active - DISABLED BY DEFAULT)
sensitive:
  enabled: false                        # MUST explicitly enable
  heuristic_paths:                      # Paths to check (regex-matched)
    - "/api/user"
    - "/api/admin"
    - "/api/config"
    - "/api/internal"
    - "/debug"
    - "/health"
    - "/actuator"
    - "/metrics"
    - "/.env"
    - "/config"
  sensitive_patterns:                   # Patterns to detect in response
    - "password"
    - "secret"
    - "token"
    - "api_key"
    - "apikey"
    - "access_token"
    - "refresh_token"
    - "private_key"
    - "ssh-rsa"
    - "-----BEGIN"
    - "email"
    - "ssn"
    - "credit_card"
    - "card_number"
    - "cvv"

# Hustler Core Settings
hustler:
  max_concurrent_hunts: 3               # Worker pool size (for worker pool impl)
  poll_interval_seconds: 3              # Daemon polling interval

# Watchdogs (Bug Bounty Platform Sync - DISABLED BY DEFAULT)
watchdogs:
  enabled: false                        # MUST explicitly enable
  sources:
    - "hackerone"
    - "bugcrowd"
  # Platform-specific config would go here
```

---

## Environment Variables

All config values can be overridden via environment variables (prefix `HUSTLER_`):

| Config Path | Env Var | Example |
|-------------|---------|---------|
| `mongo.uri` | `HUSTLER_MONGO_URI` | `mongodb://user:pass@host:27017` |
| `mongo.database` | `HUSTLER_MONGO_DB` | `hustler_prod` |
| `logging.level` | `HUSTLER_LOG_LEVEL` | `debug` |
| `js.max_concurrent_fetches` | `HUSTLER_JS_MAX_FETCHES` | `20` |
| `js.use_katana` | `HUSTLER_JS_USE_KATANA` | `true` |
| `js.entropy_threshold` | `HUSTLER_JS_ENTROPY` | `4.0` |
| `sensitive.enabled` | `HUSTLER_SENSITIVE_ENABLED` | `true` |
| `hustler.max_concurrent_hunts` | `HUSTLER_MAX_HUNTS` | `5` |
| `watchdogs.enabled` | `HUSTLER_WATCHDOGS_ENABLED` | `true` |

---

## Configuration Profiles

### Development / Testing
```yaml
mongo:
  uri: "mongodb://localhost:27017"
  database: "hustler_dev"

logging:
  level: "debug"
  format: "console"

js:
  max_concurrent_fetches: 5
  fetch_timeout_seconds: 10
  use_katana: true
  use_gau: false
  katana_depth: 1
  entropy_threshold: 3.0

sensitive:
  enabled: false

hustler:
  max_concurrent_hunts: 1
  poll_interval_seconds: 5

watchdogs:
  enabled: false
```

### Production (High Throughput)
```yaml
mongo:
  uri: "mongodb://user:pass@mongo-cluster:27017"
  database: "hustler_prod"

logging:
  level: "info"
  format: "json"

js:
  max_concurrent_fetches: 20
  fetch_timeout_seconds: 30
  max_file_size_mb: 50
  use_katana: true
  use_gau: false
  katana_depth: 3
  katana_timeout: 300
  entropy_threshold: 4.0
  enable_source_maps: true
  skip_hashes:
    - "a1b2c3d4"  # jQuery 3.x hash prefix
    - "e5f6g7h8"  # React hash prefix

sensitive:
  enabled: true
  heuristic_paths:
    - "/api/user"
    - "/api/admin"
    - "/api/config"
    - "/api/internal"
    - "/debug"
    - "/health"
    - "/actuator"
    - "/metrics"
    - "/graphql"
    - "/v1/"
    - "/v2/"
  sensitive_patterns:
    - "password"
    - "secret"
    - "token"
    - "api_key"
    - "private_key"
    - "ssh-rsa"
    - "-----BEGIN"
    - "email"
    - "ssn"
    - "credit_card"

hustler:
  max_concurrent_hunts: 5
  poll_interval_seconds: 3

watchdogs:
  enabled: true
  sources:
    - "hackerone"
    - "bugcrowd"
```

### Minimal / CI
```yaml
mongo:
  uri: "mongodb://localhost:27017"
  database: "hustler_ci"

logging:
  level: "warn"
  format: "json"

js:
  max_concurrent_fetches: 3
  fetch_timeout_seconds: 10
  use_katana: true
  use_gau: false
  katana_depth: 1
  entropy_threshold: 3.5

sensitive:
  enabled: false

hustler:
  max_concurrent_hunts: 1
  poll_interval_seconds: 10

watchdogs:
  enabled: false
```

---

## Config Loading (`internal/config/loader.go`)

```go
func Load(path string) (*FullConfig, error) {
    // 1. Read YAML file
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    
    // 2. Parse with viper (supports env var override)
    v := viper.New()
    v.SetConfigType("yaml")
    v.ReadConfig(bytes.NewReader(data))
    v.AutomaticEnv()
    v.SetEnvPrefix("HUSTLER")
    v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
    
    // 3. Unmarshal to struct
    var cfg FullConfig
    if err := v.Unmarshal(&cfg); err != nil {
        return nil, err
    }
    
    // 4. Set defaults for missing values
    cfg.setDefaults()
    
    return &cfg, nil
}
```

### Default Values (if not in config)
```go
func (c *FullConfig) setDefaults() {
    if c.Mongo.URI == "" { c.Mongo.URI = "mongodb://localhost:27017" }
    if c.Mongo.Database == "" { c.Mongo.Database = "hustler" }
    if c.Logging.Level == "" { c.Logging.Level = "info" }
    if c.Logging.Format == "" { c.Logging.Format = "console" }
    if c.JS.MaxConcurrentFetch == 0 { c.JS.MaxConcurrentFetch = 10 }
    if c.JS.FetchTimeoutSec == 0 { c.JS.FetchTimeoutSec = 15 }
    if c.JS.MaxFileSizeMB == 0 { c.JS.MaxFileSizeMB = 10 }
    if c.JS.UserAgent == "" { c.JS.UserAgent = "Hustler/1.0" }
    if c.JS.KatanaDepth == 0 { c.JS.KatanaDepth = 2 }
    if c.JS.KatanaTimeout == 0 { c.JS.KatanaTimeout = 180 }
    if c.JS.EntropyThreshold == 0 { c.JS.EntropyThreshold = 3.5 }
    if c.Discovery.KatanaDepth == 0 { c.Discovery.KatanaDepth = c.JS.KatanaDepth }
    if c.Hustler.MaxConcurrentHunts == 0 { c.Hustler.MaxConcurrentHunts = 3 }
    if c.Hustler.PollIntervalSeconds == 0 { c.Hustler.PollIntervalSeconds = 3 }
}
```

---

## Config Structs (`internal/config/config.go`)

```go
// FullConfig is the root configuration
type FullConfig struct {
    Mongo       MongoConfig                   `mapstructure:"mongo"`
    Logging     LoggingConfig                 `mapstructure:"logging"`
    JS          JSConfig                      `mapstructure:"js"`
    Discovery   DiscoveryConfig               `mapstructure:"discovery"`
    Sensitive   SensitiveEndpointCheckConfig  `mapstructure:"sensitive"`
    Hustler     HustlerConfig                 `mapstructure:"hustler"`
    Watchdogs   WatchdogsConfig               `mapstructure:"watchdogs"`
}

// MongoConfig - Database connection
type MongoConfig struct {
    URI      string `mapstructure:"uri"`
    Database string `mapstructure:"database"`
}

// LoggingConfig
type LoggingConfig struct {
    Level  string `mapstructure:"level"`   // debug, info, warn, error
    Format string `mapstructure:"format"`  // console, json
}

// JSConfig - JavaScript hunting settings
type JSConfig struct {
    MaxConcurrentFetch int      `mapstructure:"max_concurrent_fetches"`
    FetchTimeoutSec    int      `mapstructure:"fetch_timeout_seconds"`
    MaxFileSizeMB      int      `mapstructure:"max_file_size_mb"`
    UserAgent          string   `mapstructure:"user_agent"`
    UseKatana          bool     `mapstructure:"use_katana"`
    UseGau             bool     `mapstructure:"use_gau"`
    KatanaDepth        int      `mapstructure:"katana_depth"`
    KatanaTimeout      int      `mapstructure:"katana_timeout"`
    EntropyThreshold   float64  `mapstructure:"entropy_threshold"`
    EnableSourceMaps   bool     `mapstructure:"enable_source_maps"`
    SkipHashes         []string `mapstructure:"skip_hashes"`
}

// DiscoveryConfig - Discovery phase settings
type DiscoveryConfig struct {
    Enabled     bool `mapstructure:"enabled"`
    UseKatana   bool `mapstructure:"use_katana"`
    UseGau      bool `mapstructure:"use_gau"`
    KatanaDepth int  `mapstructure:"katana_depth"`
}

// SensitiveEndpointCheckConfig - Active endpoint checking
type SensitiveEndpointCheckConfig struct {
    Enabled           bool     `mapstructure:"enabled"`
    HeuristicPaths    []string `mapstructure:"heuristic_paths"`
    SensitivePatterns []string `mapstructure:"sensitive_patterns"`
}

// HustlerConfig - Core daemon/worker settings
type HustlerConfig struct {
    MaxConcurrentHunts   int `mapstructure:"max_concurrent_hunts"`
    PollIntervalSeconds  int `mapstructure:"poll_interval_seconds"`
}

// WatchdogsConfig - Platform sync (disabled by default)
type WatchdogsConfig struct {
    Enabled  bool     `mapstructure:"enabled"`
    Sources  []string `mapstructure:"sources"`
}
```

---

## Validation Rules

| Field | Validation |
|-------|------------|
| `mongo.uri` | Must be valid MongoDB URI |
| `js.max_concurrent_fetches` | 1-100 |
| `js.fetch_timeout_seconds` | 1-300 |
| `js.katana_depth` | 1-10 |
| `js.entropy_threshold` | 0.0-8.0 |
| `hustler.max_concurrent_hunts` | 1-20 |
| `hustler.poll_interval_seconds` | 1-300 |
| `sensitive.enabled` | If true, `heuristic_paths` must not be empty |

---

## Common Issues & Fixes

| Issue | Cause | Fix |
|-------|-------|-----|
| "katana not found" | Katana binary not in PATH | Install katana: `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| "gau failed" | Gau blocked by Wayback | Disable gau: `use_gau: false` |
| High memory usage | Too many concurrent fetches | Reduce `max_concurrent_fetches` |
| Slow discovery | Katana depth too high | Reduce `katana_depth` to 1-2 |
| False positive secrets | Entropy threshold too low | Increase `entropy_threshold` to 4.0+ |
| Daemon not picking up jobs | Poll interval too high | Reduce `poll_interval_seconds` |
| MongoDB connection refused | Wrong URI/database | Check `mongo.uri` and `mongo.database` |

---

## Extending Configuration

### Add New Config Section
1. Add struct in `internal/config/config.go`
2. Add field to `FullConfig`
3. Add default in `loader.go:setDefaults()`
4. Use in relevant module

### Example: Add Rate Limiting Config
```go
// In config.go
type RateLimitConfig struct {
    RequestsPerSecond int `mapstructure:"requests_per_second"`
    Burst             int `mapstructure:"burst"`
}

// In FullConfig
RateLimit RateLimitConfig `mapstructure:"rate_limit"`

// In loader.go:setDefaults()
if c.RateLimit.RequestsPerSecond == 0 { c.RateLimit.RequestsPerSecond = 10 }
if c.RateLimit.Burst == 0 { c.RateLimit.Burst = 20 }

// In config.yaml
rate_limit:
  requests_per_second: 10
  burst: 20
```

---

*See `internal/config/config.go` and `internal/config/loader.go` for implementation.*