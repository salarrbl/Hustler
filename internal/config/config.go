package config

import (
	"time"
)

// FullConfig is the root config with all nested configs
type FullConfig struct {
	Mongo        MongoConfig                  `mapstructure:"mongo"`
	Watchdogs    WatchdogsConfig              `mapstructure:"watchdogs"`
	HTTP         HTTPConfig                   `mapstructure:"http"`
	JS           JSConfig                     `mapstructure:"js"`
	Sensitive    SensitiveEndpointCheckConfig `mapstructure:"sensitive_endpoint_check"`
	Logging      LoggingConfig                `mapstructure:"logging"`
	Hustler      HustlerConfig                `mapstructure:"hustler"`
	Discovery    DiscoveryConfig              `mapstructure:"discovery"`
}

// HustlerConfig holds Hustler-specific settings
type HustlerConfig struct {
	MaxConcurrentHunts int `mapstructure:"max_concurrent_hunts"`
}

// DiscoveryConfig controls which discovery tools to run
type DiscoveryConfig struct {
	Enabled   bool `mapstructure:"enabled"`   // master switch for discovery
	UseKatana bool `mapstructure:"use_katana"` // use katana for crawling (default: true)
	UseGau    bool `mapstructure:"use_gau"`    // use gau (Wayback) for URL discovery (default: false)
	// Additional tools can be added later (ffuf, etc.)
}

// MongoConfig holds MongoDB connection settings
type MongoConfig struct {
	URI        string `mapstructure:"uri"`
	Database   string `mapstructure:"database"`
	MaxPool    uint64 `mapstructure:"max_pool"`
	MinPool    uint64 `mapstructure:"min_pool"`
	TimeoutSec int    `mapstructure:"timeout_sec"`
}

// WatchdogsConfig holds Watchdogs sync settings
// DISABLED BY DEFAULT - must be explicitly enabled
type WatchdogsConfig struct {
	Enabled      bool             `mapstructure:"enabled"`
	MongoURI     string           `mapstructure:"mongo_uri"`
	Database     string           `mapstructure:"database"`
	SyncInterval time.Duration    `mapstructure:"sync_interval"`
	FieldMapping WatchdogsMapping `mapstructure:"field_mapping"`
}

// WatchdogsMapping defines how Watchdogs' collections/fields map to Hustler's Target model
// TODO: confirm Watchdogs schema - these field names need verification against actual Watchdogs MongoDB
type WatchdogsMapping struct {
	Collection        string `mapstructure:"collection"`         // e.g., "http" or "subdomains"
	DomainField       string `mapstructure:"domain_field"`       // field containing the subdomain (e.g., "subdomain")
	RootDomainField   string `mapstructure:"root_domain_field"`  // field containing root domain (e.g., "root_domain")
	StatusField       string `mapstructure:"status_field"`       // field for status code (e.g., "status_code")
	TechField         string `mapstructure:"tech_field"`         // field for technologies (e.g., "technologies")
	TitleField        string `mapstructure:"title_field"`        // field for page title (e.g., "title")
	PortsField        string `mapstructure:"ports_field"`        // field for open ports (e.g., "ports")
	CDNField          string `mapstructure:"cdn_field"`          // field for CDN (e.g., "cdn")
	ProviderField     string `mapstructure:"provider_field"`     // field for discovery provider (e.g., "providers")
	DiscoveredAtField string `mapstructure:"discovered_at_field"` // field for discovery timestamp
}

// HTTPConfig holds HTTP client settings
type HTTPConfig struct {
	TimeoutSec      int  `mapstructure:"timeout_sec"`
	FollowRedirects bool `mapstructure:"follow_redirects"`
	MaxIdleConns    int  `mapstructure:"max_idle_conns"`
	MaxConnsPerHost int  `mapstructure:"max_conns_per_host"`
	UserAgent       string `mapstructure:"user_agent"`
}

// JSConfig holds JavaScript hunting module settings
type JSConfig struct {
	FetchTimeoutSec    int      `mapstructure:"fetch_timeout_sec"`
	MaxConcurrentFetch int      `mapstructure:"max_concurrent_fetch"`
	SkipHashes         []string `mapstructure:"skip_hashes"`          // hashes to skip (known libs)
	EntropyThreshold   float64  `mapstructure:"entropy_threshold"`    // for secret entropy check
	EnableSourceMaps   bool     `mapstructure:"enable_source_maps"`   // fetch .map files
	CDNBlocklistPath   string   `mapstructure:"cdn_blocklist_path"`   // path to CDN blocklist file
	CVEDatasetPath     string   `mapstructure:"cve_dataset_path"`     // path to CVE dataset (retire.js/NVD)
}

// SensitiveEndpointCheckConfig holds settings for the sensitive endpoint checker
type SensitiveEndpointCheckConfig struct {
	Enabled           bool     `mapstructure:"enabled"`                    // defaults to false - must be explicitly enabled
	RateLimitPerSec   int      `mapstructure:"rate_limit_per_sec"`         // conservative rate limit
	HeuristicPaths    []string `mapstructure:"heuristic_paths"`            // paths to check (e.g., /api/, /admin/)
	SensitivePatterns []string `mapstructure:"sensitive_patterns"`         // patterns to look for in responses
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level  string `mapstructure:"level"`   // debug, info, warn, error
	Format string `mapstructure:"format"`  // json, console
}