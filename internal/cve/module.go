package cve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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

// LocalCVEEntry represents a CVE entry in the local database
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

// CVEFinding represents a CVE match with confidence scoring
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

// CVEConfig holds configuration for the CVE module
type CVEConfig struct {
	DataDir            string  `mapstructure:"data_dir"`
	EnableOnlineLookup bool    `mapstructure:"enable_online_lookup"`
	RateLimitRPS       float64 `mapstructure:"rate_limit_rps"`
	UpdateIntervalDays int     `mapstructure:"update_interval_days"`
	MinConfidence      float64 `mapstructure:"min_confidence"` // minimum confidence to report
}

// DefaultCVEConfig returns sensible defaults
func DefaultCVEConfig() CVEConfig {
	return CVEConfig{
		DataDir:            "./data/cve",
		EnableOnlineLookup: true,
		RateLimitRPS:       2.0, // be respectful to APIs
		UpdateIntervalDays: 7,   // weekly updates
		MinConfidence:      0.5,
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
		if !strings.HasSuffix(entry.Name(), ".json") {
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

// loadEmbeddedDB loads hardcoded CVE data (fallback)
func (m *CVEModule) loadEmbeddedDB() {
	m.localDB = map[string][]LocalCVEEntry{
		"apache": {
			{Library: "apache", MaxVersion: "2.4.49", CVEID: "CVE-2021-41773", Severity: "HIGH", CVSS: 7.5, Summary: "Path traversal in Apache HTTP Server", Source: "snare"},
			{Library: "apache", MaxVersion: "2.4.50", CVEID: "CVE-2021-42013", Severity: "CRITICAL", CVSS: 9.8, Summary: "Path traversal and RCE in Apache HTTP Server", Source: "snare"},
		},
		"nginx": {
			{Library: "nginx", MaxVersion: "1.20.0", CVEID: "CVE-2021-23017", Severity: "HIGH", CVSS: 7.5, Summary: "Resolver cache poisoning", Source: "snare"},
		},
		"php": {
			{Library: "php", MaxVersion: "8.1.0", CVEID: "CVE-2021-21708", Severity: "HIGH", CVSS: 7.5, Summary: "GD library heap buffer overflow", Source: "snare"},
		},
		"openssl": {
			{Library: "openssl", MaxVersion: "1.1.1k", CVEID: "CVE-2021-3450", Severity: "HIGH", CVSS: 7.5, Summary: "TLS certificate verification bypass", Source: "snare"},
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

// UpdateDatabase downloads and updates the local CVE database from multiple sources
// Returns UpdateResult with details about new CVEs found
func (m *CVEModule) UpdateDatabase(ctx context.Context) (*UpdateResult, error) {
	m.mu.Lock()
	if m.updateInProg {
		m.mu.Unlock()
		return nil, fmt.Errorf("update already in progress")
	}
	m.updateInProg = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.updateInProg = false
		m.mu.Unlock()
	}()

	result := &UpdateResult{
		NewCVEs:      []LocalCVEEntry{},
		Errors:       []string{},
	}

	log.Info().Msg("Starting CVE database update")

	// 1. Update from retire.js (JS libraries - client-side)
	newCVEs, err := m.updateFromRetireJS(ctx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("retire.js: %v", err))
		log.Warn().Err(err).Msg("Failed to update from retire.js")
	} else {
		result.NewCVEs = append(result.NewCVEs, newCVEs...)
		result.UpdatedSources++
	}

	// 2. Update from osv.dev (npm, Go, Rust, PyPI - client & server)
	newCVEs, err = m.updateFromOSVAPI(ctx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("osv.dev: %v", err))
		log.Warn().Err(err).Msg("Failed to update from osv.dev API")
	} else {
		result.NewCVEs = append(result.NewCVEs, newCVEs...)
		result.UpdatedSources++
	}

	// 3. Update from npm advisories
	newCVEs, err = m.updateFromNPM(ctx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("npm: %v", err))
		log.Warn().Err(err).Msg("Failed to update from npm")
	} else {
		result.NewCVEs = append(result.NewCVEs, newCVEs...)
		result.UpdatedSources++
	}

	// Track new libraries
	libSet := make(map[string]bool)
	for _, cve := range result.NewCVEs {
		libSet[strings.ToLower(cve.Library)] = true
	}
	result.NewLibraries = len(libSet)

	if result.UpdatedSources > 0 || len(result.NewCVEs) > 0 {
		updateFile := filepath.Join(m.config.DataDir, ".last_update")
		os.WriteFile(updateFile, []byte(time.Now().Format(time.RFC3339)), 0644)
		m.loadLocalDB()
		log.Info().Int("new_cves", len(result.NewCVEs)).Int("new_libs", result.NewLibraries).Msg("CVE database updated successfully")
	} else {
		log.Warn().Msg("CVE database update completed with no successful sources")
	}

	return result, nil
}

// ForceUpdate forces a database update (called from CLI)
func (m *CVEModule) ForceUpdate(ctx context.Context) (*UpdateResult, error) {
	return m.UpdateDatabase(ctx)
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
					key := fmt.Sprintf("%s|%s", e.CVEID, e.MaxVersion)
					existingEntries[key] = e
				}
			}
		}

		var toWrite []LocalCVEEntry
		for _, e := range libEntries {
			key := fmt.Sprintf("%s|%s", e.CVEID, e.MaxVersion)
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

// updateFromRetireJS downloads the retire.js database (client-side JS libraries)
func (m *CVEModule) updateFromRetireJS(ctx context.Context) ([]LocalCVEEntry, error) {
	if err := m.waitForRateLimit(ctx); err != nil {
		return nil, err
	}

	url := "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := m.onlineClients.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("retire.js returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, err
	}

	var entries []LocalCVEEntry
	for libName, libData := range root {
		var libInfo struct {
			Vulnerabilities []struct {
				Below     string   `json:"below"`
				Severity  string   `json:"severity"`
				CWE       []string `json:"cwe"`
				Identifiers struct {
					Summary string   `json:"summary"`
					CVE     []string `json:"CVE"`
					Bug     string   `json:"bug"`
				} `json:"identifiers"`
			} `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(libData, &libInfo); err != nil {
			continue
		}

		for _, vuln := range libInfo.Vulnerabilities {
			for _, cveID := range vuln.Identifiers.CVE {
				entries = append(entries, LocalCVEEntry{
					Library:    libName,
					MaxVersion: vuln.Below,
					CVEID:      cveID,
					Severity:   strings.ToUpper(vuln.Severity),
					CVSS:       0, // retire.js doesn't include CVSS
					HasPoC:     false,
					Summary:    vuln.Identifiers.Summary,
					Source:     "retire.js",
				})
			}
		}
	}

	return m.saveLibraryEntries("retirejs", entries)
}

// updateFromOSVAPI queries osv.dev for known packages
func (m *CVEModule) updateFromOSVAPI(ctx context.Context) ([]LocalCVEEntry, error) {
	packages := []string{
		"lodash", "jquery", "moment", "react", "vue", "angular",
		"express", "axios", "webpack", "typescript", "babel",
		"eslint", "prettier", "jest", "mocha", "chai",
		"puppeteer", "playwright", "ember", "backbone", "underscore",
		"axios", "node-fetch", "request", "superagent", "got",
		"mongoose", "sequelize", "typeorm", "prisma",
		"next", "nuxt", "gatsby", "vite", "svelte",
		"tailwindcss", "bootstrap", "material-ui", "antd", "chakra-ui",
	}

	var allEntries []LocalCVEEntry

	for _, pkg := range packages {
		if err := m.waitForRateLimit(ctx); err != nil {
			continue
		}

		queryURL := fmt.Sprintf("%s/vulns?package=%s", m.onlineClients.osvBase, url.QueryEscape("npm:"+pkg))
		req, _ := http.NewRequestWithContext(ctx, "GET", queryURL, nil)
		resp, err := m.onlineClients.httpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		var resultData struct {
			Vulns []struct {
				ID       string `json:"id"`
				Summary  string `json:"summary"`
				Severity []struct {
					Type  string  `json:"type"`
					Score float64 `json:"score"`
				} `json:"severity"`
				Affected []struct {
					Package string `json:"package"`
					Ranges  []struct {
						Events []struct {
							Introduced string `json:"introduced"`
							Fixed      string `json:"fixed"`
						} `json:"events"`
					} `json:"ranges"`
				} `json:"affected"`
			} `json:"vulns"`
		}

		if err := json.Unmarshal(body, &resultData); err != nil {
			continue
		}

		for _, v := range resultData.Vulns {
			severity := "UNKNOWN"
			cvss := 0.0
			fixedVer := ""
			for _, s := range v.Severity {
				if s.Type == "CVSS_V3" {
					cvss = s.Score
					severity = calcSeverityFromCVSS(s.Score)
				}
			}
			for _, a := range v.Affected {
				for _, r := range a.Ranges {
					for _, evt := range r.Events {
						if evt.Fixed != "" {
							fixedVer = evt.Fixed
						}
					}
				}
			}

			allEntries = append(allEntries, LocalCVEEntry{
				Library:      pkg,
				MaxVersion:   "999.999.999",
				CVEID:        v.ID,
				Severity:     severity,
				CVSS:         cvss,
				HasPoC:       false,
				Summary:      v.Summary,
				FixedVersion: fixedVer,
				Source:       "osv.dev",
			})
		}
	}

	if len(allEntries) > 0 {
		return m.saveLibraryEntries("osv", allEntries)
	}

	return nil, nil
}

// updateFromNPM downloads npm audit data
func (m *CVEModule) updateFromNPM(ctx context.Context) ([]LocalCVEEntry, error) {
	if err := m.waitForRateLimit(ctx); err != nil {
		return nil, err
	}

	url := "https://registry.npmjs.org/-/npm/v1/security/advisories"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := m.onlineClients.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		// npm endpoint may not exist, fallback gracefully
		return nil, nil
	}

	var data map[string]struct {
		ID                  string   `json:"id"`
		Title               string   `json:"title"`
		ModuleName          string   `json:"module_name"`
		Cves                []string `json:"cves"`
		VulnerableVersions  string   `json:"vulnerable_versions"`
		PatchedVersions     string   `json:"patched_versions"`
		Severity            string   `json:"severity"`
		CVSS                float64  `json:"cvss"`
		Overview            string   `json:"overview"`
	}

	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	var entries []LocalCVEEntry
	for _, adv := range data {
		for _, cveID := range adv.Cves {
			entries = append(entries, LocalCVEEntry{
				Library:      adv.ModuleName,
				MaxVersion:   adv.VulnerableVersions,
				CVEID:        cveID,
				Severity:     strings.ToUpper(adv.Severity),
				CVSS:         adv.CVSS,
				HasPoC:       false,
				Summary:      adv.Overview,
				FixedVersion: adv.PatchedVersions,
				Source:       "npm",
			})
		}
	}

	if len(entries) > 0 {
		return m.saveLibraryEntries("npm", entries)
	}

	return nil, nil
}

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

// Analyze runs CVE analysis on a target using all available data
func (m *CVEModule) Analyze(ctx context.Context, target *models.Target, jsFiles []*models.JSFile, httpResponses []HTTPResponse) ([]models.LibraryCVE, error) {
	var allFindings []CVEFinding

	// 1. Server-side tech detection from HTTP responses
	serverFindings := m.analyzeServerTech(ctx, httpResponses)
	allFindings = append(allFindings, serverFindings...)

	// 2. Client-side JS library detection from JS files
	clientFindings := m.analyzeClientLibs(ctx, jsFiles)
	allFindings = append(allFindings, clientFindings...)

	// 3. Package.json / source map analysis
	pkgFindings := m.analyzePackageFiles(ctx, jsFiles)
	allFindings = append(allFindings, pkgFindings...)

	// 4. Deduplicate and filter by confidence
	findings := m.deduplicateAndFilter(allFindings)

	// Convert to models.LibraryCVE for storage
	var results []models.LibraryCVE
	for _, f := range findings {
		results = append(results, models.LibraryCVE{
			ID:          f.CVEID + "-" + target.ID + "-" + f.Library,
			TargetID:    target.ID,
			JSFileID:    f.Context,
			LibraryName: f.Library,
			Version:     f.DetectedVer,
			CVEID:       f.CVEID,
			Severity:    strings.ToLower(f.Severity),
			Description: f.Summary,
			Reference:   fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", f.CVEID),
			FoundAt:     time.Now(),
		})
	}

	return results, nil
}

// analyzeServerTech detects server technologies from HTTP responses
func (m *CVEModule) analyzeServerTech(ctx context.Context, responses []HTTPResponse) []CVEFinding {
	var findings []CVEFinding
	if m.wappalyzer == nil {
		return findings
	}

	for _, resp := range responses {
		// Use FingerprintWithInfo to get version info
		fingerprints := m.wappalyzer.FingerprintWithInfo(resp.Headers, []byte(resp.Body))
		for techName, info := range fingerprints {
			tech := strings.ToLower(techName)
			version := ""
			// Extract version from CPE if available
			if info.CPE != "" {
				// CPE format: cpe:2.3:a:vendor:product:version:...
				parts := strings.Split(info.CPE, ":")
				if len(parts) >= 6 {
					version = parts[5]
				}
			}
			if version == "" {
				continue
			}

			// 1. Look up in local DB
			if entries, ok := m.localDB[tech]; ok {
				for _, entry := range entries {
					if m.versionMatches(version, entry.MaxVersion) {
						findings = append(findings, CVEFinding{
							CVEID:       entry.CVEID,
							Library:     entry.Library,
							DetectedVer: version,
							FixedVer:    entry.FixedVersion,
							Severity:    entry.Severity,
							CVSS:        entry.CVSS,
							HasPoC:      entry.HasPoC,
							Summary:     entry.Summary,
							Source:      "local (" + entry.Source + ")",
							Confidence:  0.6,
							MatchType:   "range",
							Context:     "header",
						})
					}
				}
			}

			// 2. Online lookup if enabled
			if m.config.EnableOnlineLookup {
				onlineFindings := m.lookupServerTechOnline(ctx, tech, version)
				findings = append(findings, onlineFindings...)
			}
		}
	}
	return findings
}

// lookupServerTechOnline queries OSV.dev and other APIs for server tech vulnerabilities
func (m *CVEModule) lookupServerTechOnline(ctx context.Context, tech, version string) []CVEFinding {
	var findings []CVEFinding

	// Map common server tech names to OSV package names
	osvPackageMap := map[string]string{
		"nginx":      "nginx",
		"apache":     "apache-http-server",
		"apache http server": "apache-http-server",
		"openresty":  "openresty",
		"php":        "php",
		"openssl":    "openssl",
		"node.js":    "nodejs",
		"nodejs":     "nodejs",
		"iis":        "microsoft-iis",
		"lighttpd":   "lighttpd",
		"caddy":      "caddy",
		"haproxy":    "haproxy",
		"varnish":    "varnish",
		"tomcat":     "apache-tomcat",
		"jetty":      "eclipse-jetty",
		"wildfly":    "wildfly",
		"glassfish":  "glassfish",
		"weblogic":   "oracle-weblogic",
		"websphere":  "ibm-websphere",
	}

	osvPkg, ok := osvPackageMap[tech]
	if !ok {
		return findings // No mapping for this tech
	}

	// Query OSV.dev for this package/version
	url := fmt.Sprintf("%s/v1/query", m.onlineClients.osvBase)
	payload := map[string]interface{}{
		"package": map[string]string{
			"name": osvPkg,
			"ecosystem": "Linux", // or appropriate ecosystem
		},
		"version": version,
	}

	jsonPayload, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return findings
	}
	req.Header.Set("Content-Type", "application/json")

	// Rate limit
	if err := m.waitForRateLimit(ctx); err != nil {
		return findings
	}

	resp, err := m.onlineClients.httpClient.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return findings
	}

	var osvResult struct {
		Vulns []struct {
			ID        string `json:"id"`
			Summary   string `json:"summary"`
			Details   string `json:"details"`
			Severity  []struct {
				Type  string  `json:"type"`
				Score float64 `json:"score"`
			} `json:"severity"`
			Affected []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
				Ranges []struct {
					Events []struct {
						Introduced string `json:"introduced"`
						Fixed      string `json:"fixed"`
					} `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
		} `json:"vulns"`
	}

	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &osvResult); err != nil {
		return findings
	}

	for _, v := range osvResult.Vulns {
		severity := "UNKNOWN"
		cvss := 0.0
		fixedVer := ""
		for _, s := range v.Severity {
			if s.Type == "CVSS_V3" {
				cvss = s.Score
				severity = calcSeverityFromCVSS(s.Score)
			}
		}
		for _, a := range v.Affected {
			for _, r := range a.Ranges {
				for _, evt := range r.Events {
					if evt.Fixed != "" {
						fixedVer = evt.Fixed
					}
				}
			}
		}

		findings = append(findings, CVEFinding{
			CVEID:       v.ID,
			Library:     tech,
			DetectedVer: version,
			FixedVer:    fixedVer,
			Severity:    severity,
			CVSS:        cvss,
			HasPoC:      false,
			Summary:     v.Summary,
			Source:      "osv.dev",
			Confidence:  0.75,
			MatchType:   "exact",
			Context:     "header",
		})
	}

	return findings
}

// analyzeClientLibs detects client-side JS libraries from JS file content
func (m *CVEModule) analyzeClientLibs(ctx context.Context, jsFiles []*models.JSFile) []CVEFinding {
	var findings []CVEFinding

	// Common JS library patterns
	patterns := map[string][]string{
		"jquery":       {`jQuery v(\d+\.\d+\.\d+)`, `jquery[.-](\d+\.\d+\.\d+)`},
		"lodash":       {`lodash[.-](\d+\.\d+\.\d+)`, `_.VERSION\s*=\s*["'](\d+\.\d+\.\d+)`},
		"react":        {`react[.-](\d+\.\d+\.\d+)`, `React\.version\s*=\s*["'](\d+\.\d+\.\d+)`},
		"vue":          {`vue[.-](\d+\.\d+\.\d+)`, `Vue\.version\s*=\s*["'](\d+\.\d+\.\d+)`},
		"angular":      {`angular[.-](\d+\.\d+\.\d+)`, `angular\.version\s*=\s*["'](\d+\.\d+\.\d+)`},
		"moment":       {`moment[.-](\d+\.\d+\.\d+)`, `moment\.version\s*=\s*["'](\d+\.\d+\.\d+)`},
		"bootstrap":    {`bootstrap[.-](\d+\.\d+\.\d+)`, `Bootstrap\.version\s*=\s*["'](\d+\.\d+\.\d+)`},
		"axios":        {`axios[.-](\d+\.\d+\.\d+)`, `axios\.version\s*=\s*["'](\d+\.\d+\.\d+)`},
		"webpack":      {`webpack[.-](\d+\.\d+\.\d+)`, `webpack\.version\s*=\s*["'](\d+\.\d+\.\d+)`},
		"typescript":   {`typescript[.-](\d+\.\d+\.\d+)`, `TypeScript\s+(\d+\.\d+\.\d+)`},
		"ember":        {`ember[.-](\d+\.\d+\.\d+)`, `Ember\.VERSION\s*=\s*["'](\d+\.\d+\.\d+)`},
		"backbone":     {`backbone[.-](\d+\.\d+\.\d+)`, `Backbone\.VERSION\s*=\s*["'](\d+\.\d+\.\d+)`},
		"underscore":   {`underscore[.-](\d+\.\d+\.\d+)`, `Underscore\.VERSION\s*=\s*["'](\d+\.\d+\.\d+)`},
		"handlebars":   {`handlebars[.-](\d+\.\d+\.\d+)`, `Handlebars\.VERSION\s*=\s*["'](\d+\.\d+\.\d+)`},
		"d3":           {`d3[.-](\d+\.\d+\.\d+)`, `d3\.version\s*=\s*["'](\d+\.\d+\.\d+)`},
		"chart.js":     {`chart[.-](\d+\.\d+\.\d+)`, `Chart\.version\s*=\s*["'](\d+\.\d+\.\d+)`},
		"three.js":     {`three[.-](\d+\.\d+\.\d+)`, `THREE\.REVISION\s*=\s*["'](\d+)`},
		"socket.io":    {`socket\.io[.-](\d+\.\d+\.\d+)`, `io\.version\s*=\s*["'](\d+\.\d+\.\d+)`},
	}

	for _, jsFile := range jsFiles {
		if jsFile.Content == "" {
			continue
		}
		content := jsFile.Content

		for lib, libPatterns := range patterns {
			for _, pattern := range libPatterns {
				re := regexp.MustCompile(pattern)
				matches := re.FindStringSubmatch(content)
				if len(matches) >= 2 {
					version := matches[1]
					if entries, ok := m.localDB[strings.ToLower(lib)]; ok {
						for _, entry := range entries {
							if m.versionMatches(version, entry.MaxVersion) {
								findings = append(findings, CVEFinding{
									CVEID:       entry.CVEID,
									Library:     entry.Library,
									DetectedVer: version,
									FixedVer:    entry.FixedVersion,
									Severity:    entry.Severity,
									CVSS:        entry.CVSS,
									HasPoC:      entry.HasPoC,
									Summary:     entry.Summary,
									Source:      "local (" + entry.Source + ")",
									Confidence:  0.55,
									MatchType:   "range",
									Context:     "js_file:" + jsFile.URL,
								})
							}
						}
					}
				}
			}
		}
	}

	return findings
}

// analyzePackageFiles extracts versions from package.json and source maps
func (m *CVEModule) analyzePackageFiles(ctx context.Context, jsFiles []*models.JSFile) []CVEFinding {
	var findings []CVEFinding

	for _, jsFile := range jsFiles {
		if jsFile.Content == "" {
			continue
		}

		// Look for package.json in source maps or comments
		if strings.Contains(jsFile.Content, "package.json") || strings.Contains(jsFile.Content, "\"version\"") {
			// Try to extract package info from source map comments
			// This is a placeholder for future enhancement
		}
	}

	return findings
}

// versionMatches checks if detected version is affected by CVE (at or below max vulnerable version)
func (m *CVEModule) versionMatches(detected, maxVuln string) bool {
	if maxVuln == "999.999.999" || maxVuln == "" {
		return true // All versions affected
	}

	dv := parseVersion(detected)
	mv := parseVersion(maxVuln)
	if dv == nil || mv == nil {
		return false
	}

	// Compare major.minor.patch
	for i := 0; i < 3; i++ {
		if dv[i] < mv[i] {
			return true
		}
		if dv[i] > mv[i] {
			return false
		}
	}
	return true // Equal versions - affected
}

func parseVersion(s string) []int {
	parts := strings.Split(s, ".")
	var result []int
	for _, p := range parts {
		var n int
		fmt.Sscanf(p, "%d", &n)
		result = append(result, n)
	}
	for len(result) < 3 {
		result = append(result, 0)
	}
	return result[:3]
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