package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/rs/zerolog/log"
	"hustler/internal/models"
)

// LoadLocalDB loads the local CVE database from JSON files
func (m *CVEModule) LoadLocalDB() error {
	return m.loadLocalDB()
}

// GetLocalDB returns a copy of the local database (read-only)
func (m *CVEModule) GetLocalDB() map[string][]LocalCVEEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string][]LocalCVEEntry)
	for k, v := range m.localDB {
		result[k] = append([]LocalCVEEntry{}, v...)
	}
	return result
}

// LocalCVEEntry represents a CVE entry in the local database.
// Version gating follows retire.js semantics: vulnerable iff
// version >= AtOrAbove (when set) AND version < below, where below is
// FixedVersion when known, else legacy MaxVersion. Entries with neither
// bound are advisory records: they surface in `cve verify` but never
// auto-match (see versionInRange).
type LocalCVEEntry struct {
	Library      string   `json:"library"`
	AtOrAbove    string   `json:"at_or_above,omitempty"`
	MaxVersion   string   `json:"max_version"`
	CVEID        string   `json:"cve_id"`
	Severity     string   `json:"severity"`
	CVSS         float64  `json:"cvss"`
	HasPoC       bool     `json:"has_poc"`
	Summary      string   `json:"summary"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	Source       string   `json:"source"` // "seed", "retire.js", "osv.dev", "nvd", "github", "npm"
	CWE          []string `json:"cwe,omitempty"`
	Aliases      []string `json:"aliases,omitempty"`   // GHSA-..., OSV-... etc.
	References   []string `json:"references,omitempty"` // advisory URLs (max ~3)
	Published    string   `json:"published,omitempty"`
	Modified     string   `json:"modified,omitempty"`
	RangeApprox  bool     `json:"range_approx,omitempty"` // NVD range is best-effort
}

// CVEFinding represents a CVE match with confidence scoring
type CVEFinding struct {
	CVEID        string   `json:"cve_id"`
	Library      string   `json:"library"`
	DetectedVer  string   `json:"detected_version"`
	FixedVer     string   `json:"fixed_version,omitempty"`
	Severity     string   `json:"severity"`
	CVSS         float64  `json:"cvss"`
	HasPoC       bool     `json:"has_poc"`
	Summary      string   `json:"summary"`
	Source       string   `json:"source"`        // "local (...)", "osv.dev", "nvd", ...
	Confidence   float64  `json:"confidence"`    // 0-1
	MatchType    string   `json:"match_type"`    // "exact", "range", "fuzzy"
	Context      string   `json:"context,omitempty"` // where detected: evidence snippet / URL
	EPSS         float64  `json:"epss,omitempty"`
	KEV          bool     `json:"kev,omitempty"`
	Exploitable  string   `json:"exploitable,omitempty"` // confirmed/likely/possible/unknown
	Verify       []string `json:"verify,omitempty"`      // safe verification steps
	Nuclei       string   `json:"nuclei,omitempty"`      // ready-to-run nuclei command
	References   []string `json:"references,omitempty"`
}

// CVEConfig holds configuration for the CVE module
type CVEConfig struct {
	DataDir             string   `mapstructure:"data_dir"`
	EnableOnlineLookup  bool     `mapstructure:"enable_online_lookup"`
	RateLimitRPS        float64  `mapstructure:"rate_limit_rps"`
	UpdateIntervalDays  int      `mapstructure:"update_interval_days"`
	MinConfidence       float64  `mapstructure:"min_confidence"` // minimum confidence to report
	NVDAPIKey           string   `mapstructure:"nvd_api_key"`
	EnableExploitChecks bool     `mapstructure:"enable_exploit_checks"` // KEV/EPSS/PoC triage (passive)
	EnableActiveProbes  bool     `mapstructure:"enable_active_probes"`  // safe re-check probes (default off)
	OSVPackages         []string `mapstructure:"osv_packages"`          // overrides default seed
	ServerTechList      []string `mapstructure:"server_tech"`           // overrides NVD product seed
}

// DefaultCVEConfig returns sensible defaults
func DefaultCVEConfig() CVEConfig {
	return CVEConfig{
		DataDir:             "./data/cve",
		EnableOnlineLookup:  true,
		RateLimitRPS:        2.0, // be respectful to APIs
		UpdateIntervalDays:  7,   // weekly updates
		MinConfidence:       0.5,
		EnableExploitChecks: true,  // passive triage only
		EnableActiveProbes:  false, // never probe without opt-in
	}
}

// UpdateResult holds the result of a database update
type UpdateResult struct {
	NewCVEs        []LocalCVEEntry
	NewLibraries   int
	UpdatedSources int
	Errors         []string
}

// CVEModule is the main CVE analysis module
type CVEModule struct {
	config         CVEConfig
	wappalyzer     *wappalyzer.Wappalyze
	localDB        map[string][]LocalCVEEntry // library -> []entries
	onlineClients  *OnlineClients
	mu             sync.RWMutex
	lastUpdate     time.Time
	updateInProg   bool
}

// OnlineClients holds HTTP clients for various CVE APIs
type OnlineClients struct {
	httpClient *http.Client
	rateLimit  chan struct{}
	osvBase    string
	githubBase string
	nvdBase    string
	npmBase    string
}

// HTTPResponse represents an HTTP response for server-side fingerprinting
type HTTPResponse struct {
	URL        string
	StatusCode int
	Headers    http.Header
	Body       string
}

// NewCVEModule creates a new CVE analysis module
func NewCVEModule(cfg CVEConfig) (*CVEModule, error) {
	// Ensure data directory exists
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data dir: %w", err)
	}

	// Initialize wappalyzer for server-side fingerprinting
	wapp, err := wappalyzer.New()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to initialize wappalyzer, server-side detection disabled")
	}

	m := &CVEModule{
		config: cfg,
		wappalyzer: wapp,
		localDB:  make(map[string][]LocalCVEEntry),
		onlineClients: &OnlineClients{
			httpClient: &http.Client{Timeout: 30 * time.Second},
			rateLimit:  make(chan struct{}, int(cfg.RateLimitRPS)),
			osvBase:    "https://api.osv.dev/v1",
			githubBase: "https://api.github.com",
			nvdBase:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
			npmBase:    "https://registry.npmjs.org",
		},
	}

	// Load local database
	if err := m.loadLocalDB(); err != nil {
		log.Warn().Err(err).Msg("Failed to load local CVE database, using embedded")
		m.loadEmbeddedDB()
	}

	// Ensure the offline server seed exists so versioned server tech
	// matches even before the first online update.
	if seed, err := m.writeSeedServerEntries(); err == nil && len(seed) > 0 {
		_ = m.loadLocalDB()
	}

	// Start rate limiter
	go m.rateLimiter()

	// Check for updates on startup (non-blocking)
	go m.maybeAutoUpdate()

	return m, nil
}

// rateLimiter provides simple token bucket rate limiting
func (m *CVEModule) rateLimiter() {
	ticker := time.NewTicker(time.Second / time.Duration(m.config.RateLimitRPS))
	defer ticker.Stop()
	for range ticker.C {
		select {
		case m.onlineClients.rateLimit <- struct{}{}:
		default:
		}
	}
}

// waitForRateLimit blocks until a rate limit token is available
func (m *CVEModule) waitForRateLimit(ctx context.Context) error {
	select {
	case <-m.onlineClients.rateLimit:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// loadLocalDB loads the local CVE database from JSON files
func (m *CVEModule) loadLocalDB() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entries, err := os.ReadDir(m.config.DataDir)
	if err != nil {
		return err
	}

	m.localDB = make(map[string][]LocalCVEEntry)
	for _, entry := range entries {
		if skipDataFile(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(m.config.DataDir, entry.Name()))
		if err != nil {
			continue
		}
		var libEntries []LocalCVEEntry
		if json.Unmarshal(data, &libEntries) == nil {
			for _, e := range libEntries {
				m.localDB[strings.ToLower(e.Library)] = append(m.localDB[strings.ToLower(e.Library)], e)
			}
		}
	}
	log.Info().Int("libraries", len(m.localDB)).Int("entries", m.countTotalEntries()).Msg("Loaded local CVE database")
	return nil
}

func (m *CVEModule) countTotalEntries() int {
	count := 0
	for _, v := range m.localDB {
		count += len(v)
	}
	return count
}

// loadEmbeddedDB loads hardcoded CVE data (last-resort fallback when the
// data directory is unreadable; `below` bounds are exclusive).
func (m *CVEModule) loadEmbeddedDB() {
	m.localDB = map[string][]LocalCVEEntry{
		"apache": {
			{Library: "apache", AtOrAbove: "2.4.49", MaxVersion: "2.4.49", FixedVersion: "2.4.49", CVEID: "CVE-2021-41773", Severity: "HIGH", CVSS: 7.5, Summary: "Path traversal in Apache HTTP Server", Source: "seed"},
			{Library: "apache", AtOrAbove: "2.4.50", MaxVersion: "2.4.50", FixedVersion: "2.4.50", CVEID: "CVE-2021-42013", Severity: "CRITICAL", CVSS: 9.8, Summary: "Path traversal and RCE in Apache HTTP Server", Source: "seed"},
		},
		"nginx": {
			{Library: "nginx", MaxVersion: "1.20.1", FixedVersion: "1.20.1", CVEID: "CVE-2021-23017", Severity: "HIGH", CVSS: 7.5, Summary: "Resolver cache poisoning", Source: "seed"},
		},
		"php": {
			{Library: "php", MaxVersion: "8.1.0", CVEID: "CVE-2021-21708", Severity: "HIGH", CVSS: 7.5, Summary: "GD library heap buffer overflow", Source: "seed"},
		},
		"openssl": {
			{Library: "openssl", MaxVersion: "1.1.1l", FixedVersion: "1.1.1l", CVEID: "CVE-2021-3450", Severity: "HIGH", CVSS: 7.5, Summary: "TLS certificate verification bypass", Source: "seed"},
		},
	}
	log.Info().Msg("Loaded embedded CVE database")
}

// maybeAutoUpdate checks if the local database needs updating and updates it
func (m *CVEModule) maybeAutoUpdate() {
	ctx := context.Background()
	updateFile := filepath.Join(m.config.DataDir, ".last_update")

	var lastUpdate time.Time
	if data, err := os.ReadFile(updateFile); err == nil {
		lastUpdate, _ = time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	}

	if time.Since(lastUpdate) > time.Duration(m.config.UpdateIntervalDays)*24*time.Hour {
		log.Info().Msg("CVE database outdated, starting background update")
		m.UpdateDatabase(ctx)
	}
}

// UpdateDatabase downloads and updates the local CVE database from the
// default sources (retire.js, osv.dev, kev, epss).
// Returns UpdateResult with details about new CVEs found.
func (m *CVEModule) UpdateDatabase(ctx context.Context) (*UpdateResult, error) {
	return m.UpdateWithSources(ctx, nil, nil)
}

// ForceUpdate forces a database update (called from CLI)
func (m *CVEModule) ForceUpdate(ctx context.Context) (*UpdateResult, error) {
	return m.UpdateDatabase(ctx)
}

// entryKey identifies one ranged CVE record for diffing.
func entryKey(e LocalCVEEntry) string {
	below := e.FixedVersion
	if below == "" {
		below = e.MaxVersion
	}
	return e.CVEID + "|" + e.AtOrAbove + "|" + below
}

// saveLibraryEntries saves CVE entries to a JSON file per library
// Returns list of newly added CVEs
func (m *CVEModule) saveLibraryEntries(prefix string, entries []LocalCVEEntry) ([]LocalCVEEntry, error) {
	byLib := make(map[string][]LocalCVEEntry)
	for _, e := range entries {
		byLib[strings.ToLower(e.Library)] = append(byLib[strings.ToLower(e.Library)], e)
	}

	var newCVEs []LocalCVEEntry

	for lib, libEntries := range byLib {
		filename := filepath.Join(m.config.DataDir, fmt.Sprintf("%s_%s.json", prefix, lib))

		existingEntries := make(map[string]LocalCVEEntry)
		if data, err := os.ReadFile(filename); err == nil {
			var existing []LocalCVEEntry
			if json.Unmarshal(data, &existing) == nil {
				for _, e := range existing {
					key := entryKey(e)
					existingEntries[key] = e
				}
			}
		}

		var toWrite []LocalCVEEntry
		for _, e := range libEntries {
			key := entryKey(e)
			if _, exists := existingEntries[key]; !exists {
				newCVEs = append(newCVEs, e)
				toWrite = append(toWrite, e)
			} else {
				toWrite = append(toWrite, e)
			}
		}

		data, err := json.MarshalIndent(toWrite, "", "  ")
		if err != nil {
			continue
		}
		if err := os.WriteFile(filename, data, 0644); err != nil {
			log.Warn().Err(err).Str("file", filename).Msg("Failed to write CVE data file")
		}
	}

	log.Info().Int("libraries", len(byLib)).Int("entries", len(entries)).Int("new_cves", len(newCVEs)).Str("prefix", prefix).Msg("Saved CVE data")
	return newCVEs, nil
}

// NOTE: the update sources now live in update.go:
//   - updateRetireJSV2  (retire.js snapshot with atOrAbove/below ranges)
//   - updateOSVV2       (osv.dev POST /v1/query, per-package ranges)
//   - updateNVDServerTech (NVD CPE cache for server products)
//   - updateKEV / updateEPSS (exploitability feeds)
// UpdateDatabase/UpdateWithSources orchestrate them.

// calcSeverityFromCVSS converts CVSS score to severity string
func calcSeverityFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// Analyze runs CVE analysis on a target using all available data.
// It funnels detection (client banners/URLs/manifests, server headers/body,
// wappalyzer) through the unified RunScan pipeline: local range matching,
// optional live OSV lookup, KEV/EPSS enrichment and exploitability verdicts.
func (m *CVEModule) Analyze(ctx context.Context, target *models.Target, jsFiles []*models.JSFile, httpResponses []HTTPResponse) ([]models.LibraryCVE, error) {
	var sources []JSSource
	for _, j := range jsFiles {
		if j == nil || j.Content == "" {
			continue
		}
		sources = append(sources, JSSource{URL: j.URL, Content: j.Content})
	}

	opts := ScanOptions{
		DataDir:             m.config.DataDir,
		EnableOnlineLookup:  m.config.EnableOnlineLookup,
		EnableExploitChecks: m.config.EnableExploitChecks,
		MinConfidence:       m.config.MinConfidence,
		MaxOnlineLookups:    10,
		HTTPTimeoutSec:      15,
	}

	in := ScanInput{
		TargetURL:     target.Domain,
		JSFiles:       sources,
		HTTPResponses: httpResponses,
		ExtraTech:     m.wappTech(httpResponses),
	}

	findings := RunScan(ctx, m.GetLocalDB(), m.QueryOSV, opts, in)

	results := make([]models.LibraryCVE, 0, len(findings))
	for _, f := range findings {
		rec := ToLibraryCVE(target.ID, f.Context, f)
		rec.ID = f.CVEID + "-" + target.ID + "-" + f.Library
		rec.FoundAt = time.Now()
		results = append(results, rec)
	}
	return results, nil
}

// wappTech converts wappalyzer fingerprints into DetectedTech evidence.
// Version comes from the CPE string (cpe:2.3:a:vendor:product:version:...);
// technologies without a version are skipped (no version-gated match).
func (m *CVEModule) wappTech(responses []HTTPResponse) []DetectedTech {
	var out []DetectedTech
	if m.wappalyzer == nil {
		return out
	}
	for _, resp := range responses {
		fingerprints := m.wappalyzer.FingerprintWithInfo(resp.Headers, []byte(resp.Body))
		for techName, info := range fingerprints {
			version := ""
			if info.CPE != "" {
				parts := strings.Split(info.CPE, ":")
				if len(parts) >= 6 && parts[5] != "*" && parts[5] != "-" {
					version = parts[5]
				}
			}
			if version == "" {
				continue
			}
			out = append(out, DetectedTech{
				Tech:     NormalizeTechName(techName),
				Version:  version,
				Evidence: "wappalyzer:" + techName + "@" + version,
				Origin:   "wappalyzer",
			})
		}
	}
	return out
}

// NOTE: server/client detection now lives in detect.go (DetectServerTechnologies,
// DetectClientLibraries) and is orchestrated by RunScan in scan.go. The wappalyzer
// contribution is preserved via wappTech above.

// versionMatches reports whether detected is below maxVuln.
// Kept for compatibility; new code uses versionInRange/entryMatchesVersion.
func (m *CVEModule) versionMatches(detected, maxVuln string) bool {
	return versionInRange(detected, "", maxVuln)
}

// deduplicateAndFilter removes duplicates and filters by confidence
func (m *CVEModule) deduplicateAndFilter(findings []CVEFinding) []CVEFinding {
	seen := make(map[string]bool)
	var result []CVEFinding

	for _, f := range findings {
		key := fmt.Sprintf("%s|%s|%s", f.CVEID, f.Library, f.DetectedVer)
		if seen[key] {
			continue
		}
		if f.Confidence < m.config.MinConfidence {
			continue
		}
		seen[key] = true
		result = append(result, f)
	}

	return result
}