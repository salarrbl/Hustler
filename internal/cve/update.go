package cve

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Update pipeline: refresh the local CVE database from online sources.
//
// Sources:
//   - retire.js : client-side JS libraries (full snapshot, has atOrAbove+below)
//   - osv.dev   : npm / PyPI / Packagist / Go packages (POST /v1/query)
//   - nvd       : server products via CPE match (cached per product, opt-in)
//   - kev       : CISA Known Exploited Vulnerabilities catalog
//   - epss      : FIRST EPSS scores for CVEs already in the DB
//   - seed      : small curated fallback so server matching works offline
//
// Scan-time code only reads local files, so scans stay fast and offline.

// UpdateManifest records what the last update did.
type UpdateManifest struct {
	UpdatedAt string                `json:"updated_at"`
	Sources   map[string]SourceStat `json:"sources"`
	Libraries int                   `json:"libraries"`
	Entries   int                   `json:"entries"`
}

// SourceStat is per-source update accounting.
type SourceStat struct {
	Libraries int    `json:"libraries"`
	Entries   int    `json:"entries"`
	UpdatedAt string `json:"updated_at"`
	Error     string `json:"error,omitempty"`
}

// ReadManifest loads data/cve/manifest.json (nil, nil when absent).
func ReadManifest(dataDir string) (*UpdateManifest, error) {
	data, err := os.ReadFile(filepath.Join(dataDir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m UpdateManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func writeManifest(dataDir string, m *UpdateManifest) {
	_ = atomicWriteJSON(filepath.Join(dataDir, "manifest.json"), m)
}

// atomicWriteJSON writes JSON via temp file + rename.
func atomicWriteJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// skipDataFile reports non-entry files inside the CVE data dir.
func skipDataFile(name string) bool {
	if !strings.HasSuffix(name, ".json") {
		return true
	}
	switch name {
	case "manifest.json", "kev.json", "epss.json", "nvd_cache.json":
		return true
	default:
		return strings.HasPrefix(name, ".")
	}
}

// LoadEntriesFromDir loads every *-entries JSON file in dir into
// library -> entries. Corrupt files are skipped with a warning.
func LoadEntriesFromDir(dir string) (map[string][]LocalCVEEntry, error) {
	out := make(map[string][]LocalCVEEntry)
	listing, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, fi := range listing {
		if skipDataFile(fi.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, fi.Name()))
		if err != nil {
			continue
		}
		var entries []LocalCVEEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			log.Warn().Str("file", fi.Name()).Msg("Skipping unreadable CVE data file")
			continue
		}
		for _, e := range entries {
			out[strings.ToLower(e.Library)] = append(out[strings.ToLower(e.Library)], e)
		}
	}
	return out, nil
}

// dedupeEntries removes exact duplicates, keeping the richest record.
func dedupeEntries(entries []LocalCVEEntry) []LocalCVEEntry {
	type key struct {
		lib, cve, intro, below string
	}
	seen := make(map[key]LocalCVEEntry)
	for _, e := range entries {
		below := e.FixedVersion
		if below == "" {
			below = e.MaxVersion
		}
		k := key{strings.ToLower(e.Library), strings.ToUpper(e.CVEID), e.AtOrAbove, below}
		prev, ok := seen[k]
		if !ok || richness(e) > richness(prev) {
			seen[k] = e
		}
	}
	out := make([]LocalCVEEntry, 0, len(seen))
	for _, e := range seen {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Library != out[j].Library {
			return out[i].Library < out[j].Library
		}
		return out[i].CVEID < out[j].CVEID
	})
	return out
}

func richness(e LocalCVEEntry) int {
	n := 0
	if e.CVSS > 0 {
		n += 2
	}
	n += len(e.CWE) + len(e.Aliases) + len(e.References)
	if e.Summary != "" {
		n++
	}
	if e.FixedVersion != "" {
		n++
	}
	return n
}

// UpdateWithSources refreshes the given sources (empty = defaults).
// packages overrides the OSV package seed when non-empty.
func (m *CVEModule) UpdateWithSources(ctx context.Context, sources []string, packages []string) (*UpdateResult, error) {
	if len(sources) == 0 {
		sources = []string{"retirejs", "osv", "kev", "epss"}
	}
	seen := make(map[string]bool)
	var queue []string
	for _, s := range sources {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.ReplaceAll(s, ".js", "js")
		if s == "npm" {
			s = "osv" // legacy name: npm advisories are covered via osv.dev
		}
		if !seen[s] {
			seen[s] = true
			queue = append(queue, s)
		}
	}

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

	result := &UpdateResult{NewCVEs: []LocalCVEEntry{}, Errors: []string{}}
	manifest, _ := ReadManifest(m.config.DataDir)
	if manifest == nil || manifest.Sources == nil {
		manifest = &UpdateManifest{Sources: make(map[string]SourceStat)}
	}

	run := func(name string, fn func(context.Context) ([]LocalCVEEntry, error)) {
		log.Info().Str("source", name).Msg("Updating CVE source")
		entries, err := fn(ctx)
		st := SourceStat{UpdatedAt: time.Now().Format(time.RFC3339)}
		if err != nil {
			st.Error = err.Error()
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", name, err))
			log.Warn().Err(err).Str("source", name).Msg("CVE source update failed")
		} else {
			result.NewCVEs = append(result.NewCVEs, entries...)
			result.UpdatedSources++
			libs := make(map[string]bool)
			for _, e := range entries {
				libs[strings.ToLower(e.Library)] = true
			}
			st.Libraries = len(libs)
			st.Entries = len(entries)
		}
		manifest.Sources[name] = st
	}

	for _, s := range queue {
		switch s {
		case "retirejs":
			run("retirejs", m.updateRetireJSV2)
		case "osv":
			pkgs := packages
			if len(pkgs) == 0 {
				pkgs = m.config.OSVPackages
			}
			if len(pkgs) == 0 {
				pkgs = defaultOSVPackages
			}
			run("osv", func(ctx context.Context) ([]LocalCVEEntry, error) {
				return m.updateOSVV2(ctx, pkgs)
			})
		case "nvd":
			run("nvd", m.updateNVDServerTech)
		case "kev":
			run("kev", m.updateKEV)
		case "epss":
			run("epss", m.updateEPSS)
		default:
			result.Errors = append(result.Errors, fmt.Sprintf("unknown source %q (want retirejs, osv, nvd, kev, epss)", s))
		}
	}

	// Always ensure the offline seed exists.
	if _, err := m.writeSeedServerEntries(); err != nil {
		log.Warn().Err(err).Msg("Failed to write seed CVE entries")
	}

	libs := make(map[string]bool)
	for _, c := range result.NewCVEs {
		libs[strings.ToLower(c.Library)] = true
	}
	result.NewLibraries = len(libs)

	if db, err := LoadEntriesFromDir(m.config.DataDir); err == nil {
		total := 0
		for _, v := range db {
			total += len(v)
		}
		manifest.Libraries = len(db)
		manifest.Entries = total
	}
	manifest.UpdatedAt = time.Now().Format(time.RFC3339)
	writeManifest(m.config.DataDir, manifest)
	os.WriteFile(filepath.Join(m.config.DataDir, ".last_update"), []byte(time.Now().Format(time.RFC3339)), 0644)
	_ = m.loadLocalDB()

	log.Info().Int("new_cves", len(result.NewCVEs)).Msg("CVE database update finished")
	return result, nil
}

// ---------------------------------------------------------------------------
// retire.js
// ---------------------------------------------------------------------------

func (m *CVEModule) updateRetireJSV2(ctx context.Context) ([]LocalCVEEntry, error) {
	if err := m.waitForRateLimit(ctx); err != nil {
		return nil, err
	}
	const retireURL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"
	req, _ := http.NewRequestWithContext(ctx, "GET", retireURL, nil)
	resp, err := m.onlineClients.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("retire.js returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
	if err != nil {
		return nil, err
	}
	var root map[string]struct {
		Vulnerabilities []struct {
			Below      string   `json:"below"`
			AtOrAbove  string   `json:"atOrAbove"`
			Severity   string   `json:"severity"`
			CWE        []string `json:"cwe"`
			Info       []string `json:"info"`
			Identifiers struct {
				Summary  string   `json:"summary"`
				CVE      []string `json:"CVE"`
				GithubID string   `json:"githubID"`
				Issue    string   `json:"issue"`
				Bug      string   `json:"bug"`
			} `json:"identifiers"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, err
	}
	var entries []LocalCVEEntry
	for libName, libInfo := range root {
		for _, vuln := range libInfo.Vulnerabilities {
			var refs []string
			for _, u := range append(append([]string{}, vuln.Info...), vuln.Identifiers.Issue, vuln.Identifiers.Bug) {
				if strings.HasPrefix(u, "http") {
					refs = append(refs, u)
				}
			}
			var aliases []string
			if vuln.Identifiers.GithubID != "" {
				aliases = append(aliases, vuln.Identifiers.GithubID)
			}
			for _, cveID := range vuln.Identifiers.CVE {
				entries = append(entries, LocalCVEEntry{
					Library:     NormalizeLibName(libName),
					AtOrAbove:   vuln.AtOrAbove,
					MaxVersion:  vuln.Below,
					CVEID:       cveID,
					Severity:    strings.ToUpper(vuln.Severity),
					Summary:     vuln.Identifiers.Summary,
					CWE:         vuln.CWE,
					Aliases:     aliases,
					References:  refs,
					Source:      "retire.js",
				})
			}
		}
	}
	entries = dedupeEntries(entries)
	return m.saveLibraryEntries("retirejs", entries)
}

// ---------------------------------------------------------------------------
// osv.dev (correct POST /v1/query API)
// ---------------------------------------------------------------------------

var defaultOSVPackages = []string{
	"jquery", "jquery-ui", "lodash", "underscore", "moment", "moment-timezone",
	"axios", "react", "react-dom", "next", "vue", "angular", "svelte",
	"ember-source", "backbone", "knockout", "dayjs", "bootstrap",
	"core-js", "d3", "chart.js", "highcharts", "echarts", "three", "gsap",
	"swiper", "handlebars", "mustache", "marked", "markdown-it", "dompurify",
	"tinymce", "ckeditor4", "quill", "pdfjs-dist", "mathjax", "socket.io",
	"webpack", "vite", "typescript", "express", "minimist", "shell-quote",
	"yargs", "commander", "debug", "ms", "semver", "tar", "request",
	"node-fetch", "got", "qs", "body-parser", "cookie", "jsonwebtoken",
	"passport", "sequelize", "mongoose", "validator", "xss", "sanitize-html",
	"select2", "datatables.net", "dropzone", "htmx.org", "alpinejs",
	"jszip", "cheerio", "pug", "ejs",
}

type osvQueryResp struct {
	Vulns []struct {
		ID       string   `json:"id"`
		Summary  string   `json:"summary"`
		Details  string   `json:"details"`
		Aliases  []string `json:"aliases"`
		Severity []struct {
			Type  string          `json:"type"`
			Score json.RawMessage `json:"score"`
		} `json:"severity"`
		Affected []struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Ranges []struct {
				Type   string `json:"type"`
				Events []struct {
					Introduced   string `json:"introduced"`
					Fixed        string `json:"fixed"`
					LastAffected string `json:"last_affected"`
				} `json:"events"`
			} `json:"ranges"`
			DatabaseSpecific struct {
				CweIDs []string `json:"cwe_ids"`
			} `json:"database_specific"`
		} `json:"affected"`
		References []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"references"`
		DatabaseSpecific struct {
			CweIDs []string `json:"cwe_ids"`
		} `json:"database_specific"`
	} `json:"vulns"`
}

// osvNumericScore tolerates both numeric scores and CVSS vector strings
// (vectors need full CVSS computation; those are enriched via NVD later).
func osvNumericScore(raw json.RawMessage) float64 {
	if len(raw) == 0 {
		return 0
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return f
	}
	return 0
}

func (m *CVEModule) osvQuery(ctx context.Context, ecosystem, pkg string) (*osvQueryResp, error) {
	if err := m.waitForRateLimit(ctx); err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"package": map[string]string{"name": pkg, "ecosystem": ecosystem},
	})
	endpoint := strings.TrimSuffix(m.onlineClients.osvBase, "/v1") + "/v1/query"
	if strings.HasSuffix(m.onlineClients.osvBase, "/v1/query") {
		endpoint = m.onlineClients.osvBase
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.onlineClients.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("osv.dev %s:%s -> HTTP %d", ecosystem, pkg, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, err
	}
	var out osvQueryResp
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (m *CVEModule) updateOSVV2(ctx context.Context, packages []string) ([]LocalCVEEntry, error) {
	var all []LocalCVEEntry
	for _, pkg := range packages {
		pkg = strings.TrimSpace(pkg)
		if pkg == "" {
			continue
		}
		res, err := m.osvQuery(ctx, "npm", pkg)
		if err != nil {
			log.Warn().Err(err).Str("package", pkg).Msg("OSV query failed")
			continue
		}
		var entries []LocalCVEEntry
		for _, v := range res.Vulns {
			cvss := 0.0
			for _, s := range v.Severity {
				if (s.Type == "CVSS_V4" || s.Type == "CVSS_V3") && osvNumericScore(s.Score) > cvss {
					cvss = osvNumericScore(s.Score)
				}
			}
			severity := "UNKNOWN"
			if cvss > 0 {
				severity = calcSeverityFromCVSS(cvss)
			}
			var refs []string
			for _, r := range v.References {
				if r.URL != "" && len(refs) < 3 {
					refs = append(refs, r.URL)
				}
			}
			summary := v.Summary
			if summary == "" {
				summary = v.Details
			}
			if len(summary) > 500 {
				summary = summary[:500]
			}
			cwes := append([]string{}, v.DatabaseSpecific.CweIDs...)
			made := false
			for _, a := range v.Affected {
				cwes = append(cwes, a.DatabaseSpecific.CweIDs...)
				for _, r := range a.Ranges {
					introduced, fixed := "", ""
					for _, ev := range r.Events {
						if ev.Introduced != "" && introduced == "" {
							introduced = ev.Introduced
						}
						if ev.Fixed != "" {
							fixed = ev.Fixed
						}
					}
					entries = append(entries, LocalCVEEntry{
						Library:      NormalizeLibName(pkg),
						AtOrAbove:    introduced,
						MaxVersion:   fixed,
						FixedVersion: fixed,
						CVEID:        v.ID,
						Severity:     severity,
						CVSS:         cvss,
						Summary:      summary,
						CWE:          dedupeStrings(cwes),
						Aliases:      v.Aliases,
						References:   refs,
						Source:       "osv.dev",
					})
					made = true
				}
			}
			if !made {
				// No machine-readable range: keep the advisory without a
				// version gate but mark severity unknown-heavy handling to
				// the matcher (unbounded entries are NOT auto-matched; they
				// surface in `cve verify`).
				entries = append(entries, LocalCVEEntry{
					Library:    NormalizeLibName(pkg),
					MaxVersion: "",
					CVEID:      v.ID,
					Severity:   severity,
					CVSS:       cvss,
					Summary:    summary,
					CWE:        dedupeStrings(cwes),
					Aliases:    v.Aliases,
					References: refs,
					Source:     "osv.dev",
				})
			}
		}
		if len(entries) > 0 {
			if _, err := m.saveLibraryEntries("osv", dedupeEntries(entries)); err != nil {
				log.Warn().Err(err).Str("package", pkg).Msg("Failed to save OSV entries")
			}
			all = append(all, entries...)
		}
	}
	// Fill CVSS gaps from NVD (cached, capped, with progress).
	if n, err := m.enrichMissingCVSS(ctx, 25); err != nil {
		log.Warn().Err(err).Msg("NVD CVSS enrichment failed")
	} else if n > 0 {
		log.Info().Int("enriched", n).Msg("NVD CVSS enrichment added scores")
	}
	return dedupeEntries(all), nil
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// ---------------------------------------------------------------------------
// NVD: server-product CPE cache + CVSS enrichment
// ---------------------------------------------------------------------------

var defaultServerTech = []struct {
	Tech string
	CPE  string
}{
	{"apache", "cpe:2.3:a:apache:http_server"},
	{"nginx", "cpe:2.3:a:f5:nginx"},
	{"php", "cpe:2.3:a:php:php"},
	{"openssl", "cpe:2.3:a:openssl:openssl"},
	{"iis", "cpe:2.3:a:microsoft:internet_information_services"},
	{"tomcat", "cpe:2.3:a:apache:tomcat"},
	{"wordpress", "cpe:2.3:a:wordpress:wordpress"},
	{"drupal", "cpe:2.3:a:drupal:drupal"},
	{"nodejs", "cpe:2.3:a:nodejs:node.js"},
	{"django", "cpe:2.3:a:djangoproject:django"},
	{"lighttpd", "cpe:2.3:a:lighttpd:lighttpd"},
}

type nvdCVSS struct {
	BaseScore    float64 `json:"base_score"`
	BaseSeverity string  `json:"base_severity"`
}

type nvdMetric struct {
	CvssData nvdCVSS `json:"cvssData"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdWeakness struct {
	Description []nvdDescription `json:"description"`
}

type nvdReference struct {
	URL string `json:"url"`
}

type nvdCpeMatch struct {
	Criteria              string `json:"criteria"`
	Vulnerable            bool   `json:"vulnerable"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type nvdNode struct {
	CpeMatch []nvdCpeMatch `json:"cpeMatch"`
}

type nvdConfiguration struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdMetricsSet struct {
	CvssMetricV40 []nvdMetric `json:"cvssMetricV40"`
	CvssMetricV31 []nvdMetric `json:"cvssMetricV31"`
	CvssMetricV30 []nvdMetric `json:"cvssMetricV30"`
	CvssMetricV2  []nvdMetric `json:"cvssMetricV2"`
}

type nvdCVE struct {
	ID             string             `json:"id"`
	Published      string             `json:"published"`
	LastModified   string             `json:"lastModified"`
	Descriptions   []nvdDescription   `json:"descriptions"`
	Metrics        *nvdMetricsSet     `json:"metrics"`
	Weaknesses     []nvdWeakness      `json:"weaknesses"`
	References     []nvdReference     `json:"references"`
	Configurations []nvdConfiguration `json:"configurations"`
}

type nvdResp struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		Cve nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

func nvdSleep(key string) time.Duration {
	if key != "" {
		return 700 * time.Millisecond // 50 req / 30s with API key
	}
	return 6500 * time.Millisecond // 5 req / 30s without key
}

func (m *CVEModule) nvdGet(ctx context.Context, params url.Values) (*nvdResp, error) {
	endpoint := strings.TrimSuffix(m.onlineClients.nvdBase, "/") + "?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	if m.config.NVDAPIKey != "" {
		req.Header.Set("apiKey", m.config.NVDAPIKey)
	}
	resp, err := m.onlineClients.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("nvd returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return nil, err
	}
	var out nvdResp
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func nvdSummary(c nvdCVE) string {
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(c.Descriptions) > 0 {
		return c.Descriptions[0].Value
	}
	return ""
}

func nvdScore(metrics *nvdMetricsSet) (float64, string) {
	if metrics == nil {
		return 0, "UNKNOWN"
	}
	for _, sets := range [][]nvdMetric{metrics.CvssMetricV40, metrics.CvssMetricV31, metrics.CvssMetricV30, metrics.CvssMetricV2} {
		if len(sets) > 0 {
			sev := strings.ToUpper(sets[0].CvssData.BaseSeverity)
			if sev == "" {
				sev = calcSeverityFromCVSS(sets[0].CvssData.BaseScore)
			}
			return sets[0].CvssData.BaseScore, sev
		}
	}
	return 0, "UNKNOWN"
}

func nvdCWEs(weak []nvdWeakness) []string {
	var out []string
	for _, w := range weak {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				out = append(out, d.Value)
			}
		}
	}
	return dedupeStrings(out)
}

// cpeCriteriaVersion extracts an exact version from a CPE 2.3 string.
func cpeCriteriaVersion(criteria string) string {
	parts := strings.Split(criteria, ":")
	if len(parts) >= 6 && parts[5] != "*" && parts[5] != "-" {
		return parts[5]
	}
	return ""
}

// updateNVDServerTech builds per-product offline caches for server software.
func (m *CVEModule) updateNVDServerTech(ctx context.Context) ([]LocalCVEEntry, error) {
	techs := m.config.ServerTechList
	var queue []struct{ Tech, CPE string }
	if len(techs) > 0 {
		for _, t := range techs {
			if cpe, ok := CPEForTech(t); ok {
				queue = append(queue, struct{ Tech, CPE string }{NormalizeTechName(t), cpe})
			}
		}
	} else {
		for _, t := range defaultServerTech {
			queue = append(queue, struct{ Tech, CPE string }{t.Tech, t.CPE})
		}
	}

	var all []LocalCVEEntry
	for i, q := range queue {
		if i > 0 {
			select {
			case <-ctx.Done():
				return all, ctx.Err()
			case <-time.After(nvdSleep(m.config.NVDAPIKey)):
			}
		}
		params := url.Values{}
		params.Set("cpeName", q.CPE)
		params.Set("resultsPerPage", "2000")
		res, err := m.nvdGet(ctx, params)
		if err != nil {
			log.Warn().Err(err).Str("tech", q.Tech).Msg("NVD CPE query failed")
			continue
		}
		product := q.CPE[strings.LastIndex(q.CPE, ":")+1:]
		var entries []LocalCVEEntry
		for _, v := range res.Vulnerabilities {
			cvss, sev := nvdScore(v.Cve.Metrics)
			var refs []string
			for _, r := range v.Cve.References {
				if r.URL != "" && len(refs) < 3 {
					refs = append(refs, r.URL)
				}
			}
			summary := nvdSummary(v.Cve)
			cwes := nvdCWEs(v.Cve.Weaknesses)
			matched := false
			for _, cfg := range v.Cve.Configurations {
				for _, node := range cfg.Nodes {
					for _, cm := range node.CpeMatch {
						if !cm.Vulnerable || !strings.Contains(cm.Criteria, ":"+product+":") {
							continue
						}
						atOrAbove := cm.VersionStartIncluding
						if atOrAbove == "" {
							atOrAbove = cm.VersionStartExcluding
						}
						below := cm.VersionEndExcluding
						if below == "" {
							below = cm.VersionEndIncluding
						}
						approx := cm.VersionStartExcluding != "" || cm.VersionEndIncluding != ""
						if exact := cpeCriteriaVersion(cm.Criteria); exact != "" && atOrAbove == "" && below == "" {
							atOrAbove, below, approx = exact, exact, false // exact-version entry
						}
						if atOrAbove == "" && below == "" {
							continue // unbounded: too broad to match safely
						}
						entries = append(entries, LocalCVEEntry{
							Library:      q.Tech,
							AtOrAbove:    atOrAbove,
							MaxVersion:   below,
							FixedVersion: below,
							CVEID:        v.Cve.ID,
							Severity:     sev,
							CVSS:         cvss,
							Summary:      summary,
							CWE:          cwes,
							References:   refs,
							Source:       "nvd",
							RangeApprox:  approx,
							Published:    v.Cve.Published,
							Modified:     v.Cve.LastModified,
						})
						matched = true
					}
				}
			}
			if !matched {
				// No parseable range for this product: keep the record
				// unbounded so `cve verify` still surfaces it.
				entries = append(entries, LocalCVEEntry{
					Library:     q.Tech,
					CVEID:       v.Cve.ID,
					Severity:    sev,
					CVSS:        cvss,
					Summary:     summary,
					CWE:         cwes,
					References:  refs,
					Source:      "nvd",
					RangeApprox: true,
					Published:   v.Cve.Published,
					Modified:    v.Cve.LastModified,
				})
			}
		}
		entries = dedupeEntries(entries)
		if _, err := m.saveLibraryEntries("nvd", entries); err != nil {
			log.Warn().Err(err).Str("tech", q.Tech).Msg("Failed to save NVD entries")
		}
		all = append(all, entries...)
		log.Info().Str("tech", q.Tech).Int("entries", len(entries)).Msg("NVD product cache updated")
	}
	return dedupeEntries(all), nil
}

// nvdCacheEntry is one cached NVD enrichment record.
type nvdCacheEntry struct {
	CVSS     float64  `json:"cvss"`
	Severity string   `json:"severity"`
	CWE      []string `json:"cwe,omitempty"`
	Summary  string   `json:"summary,omitempty"`
}

func loadNVDCache(dir string) map[string]nvdCacheEntry {
	out := make(map[string]nvdCacheEntry)
	data, err := os.ReadFile(filepath.Join(dir, "nvd_cache.json"))
	if err != nil {
		return out
	}
	var cached struct {
		CVEs map[string]nvdCacheEntry `json:"cves"`
	}
	if err := json.Unmarshal(data, &cached); err != nil {
		return out
	}
	for k, v := range cached.CVEs {
		out[strings.ToUpper(strings.TrimSpace(k))] = v
	}
	return out
}

func saveNVDCache(dir string, cache map[string]nvdCacheEntry) {
	payload := map[string]interface{}{
		"updated": time.Now().Format(time.RFC3339),
		"cves":    cache,
	}
	_ = atomicWriteJSON(filepath.Join(dir, "nvd_cache.json"), payload)
}

// enrichMissingCVSS fills CVSS gaps for CVE-ID entries using NVD (cached).
func (m *CVEModule) enrichMissingCVSS(ctx context.Context, cap int) (int, error) {
	db, err := LoadEntriesFromDir(m.config.DataDir)
	if err != nil {
		return 0, err
	}
	cache := loadNVDCache(m.config.DataDir)
	// Collect targets: CVE IDs with no CVSS, not yet cached.
	var ids []string
	seenIDs := make(map[string]bool)
	for _, entries := range db {
		for _, e := range entries {
			id := strings.ToUpper(e.CVEID)
			if !strings.HasPrefix(id, "CVE-") || e.CVSS > 0 || seenIDs[id] {
				continue
			}
			seenIDs[id] = true
			if _, ok := cache[id]; !ok {
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	if len(ids) > cap {
		ids = ids[:cap]
	}
	enriched := 0
	for i, id := range ids {
		if i > 0 {
			select {
			case <-ctx.Done():
				return enriched, ctx.Err()
			case <-time.After(nvdSleep(m.config.NVDAPIKey)):
			}
		}
		if len(ids) > 5 && i%5 == 0 {
			log.Info().Int("done", i).Int("total", len(ids)).Msg("NVD CVSS enrichment in progress")
		}
		params := url.Values{}
		params.Set("cveId", id)
		res, err := m.nvdGet(ctx, params)
		if err != nil || len(res.Vulnerabilities) == 0 {
			continue
		}
		v := res.Vulnerabilities[0].Cve
		cvss, sev := nvdScore(v.Metrics)
		cache[id] = nvdCacheEntry{CVSS: cvss, Severity: sev, CWE: nvdCWEs(v.Weaknesses), Summary: nvdSummary(v)}
		if cvss > 0 {
			enriched++
		}
	}
	if enriched > 0 {
		saveNVDCache(m.config.DataDir, cache)
		// Apply cached scores back into entry files.
		_ = m.applyNVDCache(cache)
	}
	return enriched, nil
}

// applyNVDCache writes cached CVSS/CWE data into matching entry files.
func (m *CVEModule) applyNVDCache(cache map[string]nvdCacheEntry) error {
	listing, err := os.ReadDir(m.config.DataDir)
	if err != nil {
		return err
	}
	for _, fi := range listing {
		if skipDataFile(fi.Name()) {
			continue
		}
		path := filepath.Join(m.config.DataDir, fi.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var entries []LocalCVEEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			continue
		}
		changed := false
		for i, e := range entries {
			c, ok := cache[strings.ToUpper(e.CVEID)]
			if !ok || e.CVSS > 0 {
				continue
			}
			entries[i].CVSS = c.CVSS
			if c.Severity != "" && (e.Severity == "" || e.Severity == "UNKNOWN") {
				entries[i].Severity = c.Severity
			}
			if len(entries[i].CWE) == 0 {
				entries[i].CWE = c.CWE
			}
			changed = true
		}
		if changed {
			_ = atomicWriteJSON(path, entries)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// KEV + EPSS
// ---------------------------------------------------------------------------

func (m *CVEModule) updateKEV(ctx context.Context) ([]LocalCVEEntry, error) {
	if err := m.waitForRateLimit(ctx); err != nil {
		return nil, err
	}
	const kevURL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
	req, _ := http.NewRequestWithContext(ctx, "GET", kevURL, nil)
	resp, err := m.onlineClients.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("kev catalog returned status %d", resp.StatusCode)
	}
	r := csv.NewReader(io.LimitReader(resp.Body, 8*1024*1024))
	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	idx := make(map[string]int)
	for i, h := range header {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	get := func(row []string, names ...string) string {
		for _, n := range names {
			if i, ok := idx[n]; ok && i < len(row) {
				return strings.TrimSpace(row[i])
			}
		}
		return ""
	}
	cves := make(map[string]KEVEntry)
	for {
		row, err := r.Read()
		if err != nil {
			break
		}
		id := strings.ToUpper(get(row, "cveid", "cve id", "cveID"))
		if !strings.HasPrefix(id, "CVE-") {
			continue
		}
		ransom := strings.Contains(strings.ToLower(get(row, "knownransomwarecampaignuse", "known ransomware campaign use")), "known")
		cves[id] = KEVEntry{
			Vendor:     get(row, "vendorproject", "vendor"),
			Product:    get(row, "product"),
			Summary:    get(row, "vulnerabilityname", "vulnerability name"),
			Ransomware: ransom,
		}
	}
	if len(cves) == 0 {
		return nil, fmt.Errorf("kev catalog parsed 0 entries")
	}
	payload := map[string]interface{}{
		"updated": time.Now().Format(time.RFC3339),
		"count":   len(cves),
		"cves":    cves,
	}
	if err := atomicWriteJSON(filepath.Join(m.config.DataDir, "kev.json"), payload); err != nil {
		return nil, err
	}
	log.Info().Int("entries", len(cves)).Msg("KEV catalog updated")
	return nil, nil
}

func (m *CVEModule) updateEPSS(ctx context.Context) ([]LocalCVEEntry, error) {
	db, err := LoadEntriesFromDir(m.config.DataDir)
	if err != nil {
		return nil, err
	}
	ids := make(map[string]bool)
	for _, entries := range db {
		for _, e := range entries {
			if strings.HasPrefix(strings.ToUpper(e.CVEID), "CVE-") {
				ids[strings.ToUpper(e.CVEID)] = true
			}
		}
	}
	var list []string
	for id := range ids {
		list = append(list, id)
	}
	sort.Strings(list)
	if len(list) > 3000 {
		list = list[:3000]
	}
	scores := make(map[string]float64)
	for i := 0; i < len(list); i += 150 {
		if err := m.waitForRateLimit(ctx); err != nil {
			return nil, err
		}
		end := i + 150
		if end > len(list) {
			end = len(list)
		}
		endpoint := "https://api.first.org/data/v1/epss?cve=" + strings.Join(list[i:end], ",")
		req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		resp, err := m.onlineClients.httpClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		var parsed struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			continue
		}
		for _, d := range parsed.Data {
			var f float64
			fmt.Sscanf(d.EPSS, "%f", &f)
			scores[strings.ToUpper(d.CVE)] = f
		}
	}
	if len(scores) == 0 {
		return nil, fmt.Errorf("epss returned 0 scores")
	}
	payload := map[string]interface{}{
		"updated": time.Now().Format(time.RFC3339),
		"count":   len(scores),
		"scores":  scores,
	}
	if err := atomicWriteJSON(filepath.Join(m.config.DataDir, "epss.json"), payload); err != nil {
		return nil, err
	}
	log.Info().Int("scores", len(scores)).Msg("EPSS scores updated")
	return nil, nil
}

// ---------------------------------------------------------------------------
// Offline seed (so server matching works before the first NVD update)
// ---------------------------------------------------------------------------

func (m *CVEModule) writeSeedServerEntries() ([]LocalCVEEntry, error) {
	path := filepath.Join(m.config.DataDir, "seed_server.json")
	if _, err := os.Stat(path); err == nil {
		return nil, nil // never overwrite
	}
	seed := []LocalCVEEntry{
		{Library: "apache", AtOrAbove: "2.4.49", MaxVersion: "2.4.49", FixedVersion: "2.4.49", CVEID: "CVE-2021-41773", Severity: "HIGH", CVSS: 7.5, Summary: "Path traversal and RCE in Apache HTTP Server 2.4.49 (CGI). Actively exploited.", Source: "seed", References: []string{"https://httpd.apache.org/security/vulnerabilities_24.html"}},
		{Library: "apache", AtOrAbove: "2.4.50", MaxVersion: "2.4.50", FixedVersion: "2.4.50", CVEID: "CVE-2021-42013", Severity: "CRITICAL", CVSS: 9.8, Summary: "Path traversal and RCE in Apache HTTP Server 2.4.50. Actively exploited.", Source: "seed", References: []string{"https://httpd.apache.org/security/vulnerabilities_24.html"}},
		{Library: "nginx", MaxVersion: "1.20.1", FixedVersion: "1.20.1", CVEID: "CVE-2021-23017", Severity: "HIGH", CVSS: 7.5, Summary: "Nginx resolver cache poisoning (1-byte memory overwrite).", Source: "seed", RangeApprox: true, References: []string{"https://nginx.org/en/security_advisories.html"}},
		{Library: "php", AtOrAbove: "7.1.0", MaxVersion: "7.1.33", FixedVersion: "7.1.33", CVEID: "CVE-2019-11043", Severity: "CRITICAL", CVSS: 9.8, Summary: "PHP-FPM remote code execution via path_info poisoning (nginx).", Source: "seed", RangeApprox: true, References: []string{"https://bugs.php.net/bug.php?id=78599"}},
		{Library: "openssl", AtOrAbove: "1.0.1", MaxVersion: "1.0.1g", FixedVersion: "1.0.1g", CVEID: "CVE-2014-0160", Severity: "HIGH", CVSS: 7.5, Summary: "Heartbleed: TLS heartbeat memory disclosure.", Source: "seed", References: []string{"https://heartbleed.com/"}},
		{Library: "tomcat", MaxVersion: "9.0.31", FixedVersion: "9.0.31", CVEID: "CVE-2020-1938", Severity: "HIGH", CVSS: 7.5, Summary: "Ghostcat: AJP file read / potential RCE.", Source: "seed", RangeApprox: true, References: []string{"https://tomcat.apache.org/security-9.html"}},
		{Library: "iis", AtOrAbove: "6.0", MaxVersion: "6.0", FixedVersion: "6.0", CVEID: "CVE-2017-7269", Severity: "HIGH", CVSS: 7.5, Summary: "IIS 6.0 WebDAV buffer overflow (exploited in the wild).", Source: "seed", References: []string{"https://github.com/rapid7/metasploit-framework/pull/8113"}},
		{Library: "wordpress", MaxVersion: "5.7.2", FixedVersion: "5.7.2", CVEID: "CVE-2021-29447", Severity: "HIGH", CVSS: 7.5, Summary: "WordPress XXE in media library (author+).", Source: "seed", RangeApprox: true},
		{Library: "drupal", AtOrAbove: "9.0.0", MaxVersion: "9.1.7", FixedVersion: "9.1.7", CVEID: "CVE-2021-33829", Severity: "MEDIUM", CVSS: 5.4, Summary: "CKEditor XSS filter bypass bundled in Drupal core.", Source: "seed", RangeApprox: true},
		{Library: "nodejs", MaxVersion: "16.4.1", FixedVersion: "16.4.1", CVEID: "CVE-2021-22931", Severity: "HIGH", CVSS: 7.5, Summary: "Node.js HTTP request smuggling via invalid names (llhttp).", Source: "seed", RangeApprox: true},
	}
	if err := atomicWriteJSON(path, seed); err != nil {
		return nil, err
	}
	return seed, nil
}
