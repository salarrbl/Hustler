package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"hustler/internal/models"
)

// Unified scan pipeline: detection -> local matching -> optional live OSV
// lookup -> KEV/EPSS enrichment -> exploitability verdict.

// ScanOptions tunes a scan.
type ScanOptions struct {
	DataDir             string
	EnableOnlineLookup  bool
	EnableExploitChecks bool
	MinConfidence       float64
	MaxOnlineLookups    int
	HTTPTimeoutSec      int
}

// DefaultScanOptions returns offline-first defaults.
func DefaultScanOptions(dataDir string) ScanOptions {
	return ScanOptions{
		DataDir:             dataDir,
		EnableOnlineLookup:  false,
		EnableExploitChecks: true,
		MinConfidence:       0.5,
		MaxOnlineLookups:    10,
		HTTPTimeoutSec:      15,
	}
}

// ScanInput is everything a scan can match against.
type ScanInput struct {
	TargetURL     string
	JSFiles       []JSSource
	HTTPResponses []HTTPResponse
	ExtraTech     []DetectedTech // e.g. wappalyzer-derived, matched like server tech
}

// JSSource is one JavaScript unit with its content available.
type JSSource struct {
	URL     string
	Content string
}

// MatchEntries returns range-aware local DB matches for lib@version,
// strongest evidence first. Unbounded advisory records never match here;
// they surface through FindByCVE / `cve verify`.
func MatchEntries(lib, version string, db map[string][]LocalCVEEntry) []LocalCVEEntry {
	var out []LocalCVEEntry
	for _, e := range db[strings.ToLower(lib)] {
		if entryMatchesVersion(version, e) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CVSS != out[j].CVSS {
			return out[i].CVSS > out[j].CVSS
		}
		return out[i].CVEID < out[j].CVEID
	})
	return out
}

// confidenceFor scores a match by evidence quality.
func confidenceFor(origin, matchType string, approx bool) float64 {
	base := 0.55
	switch origin {
	case "banner", "global":
		base = 0.8
	case "package.json":
		base = 0.85
	case "url":
		base = 0.65
	case "meta", "wappalyzer":
		base = 0.75
	case "body":
		base = 0.6
	case "osv.dev":
		base = 0.9
	default:
		if strings.HasPrefix(origin, "header:") {
			base = 0.75
		}
	}
	if matchType == "exact" {
		base += 0.05
	}
	if approx {
		base -= 0.15
	}
	if base > 0.95 {
		base = 0.95
	}
	if base < 0.1 {
		base = 0.1
	}
	return base
}

// RunScan executes the full pipeline over already-fetched inputs.
// db is the local CVE database (see LoadEntriesFromDir); queryOSV may be
// nil to disable live lookups (used by the offline pipeline analyzer).
func RunScan(ctx context.Context, db map[string][]LocalCVEEntry, queryOSV func(context.Context, string, string, string) []LocalCVEEntry, opts ScanOptions, in ScanInput) []CVEFinding {
	var kev map[string]KEVEntry
	var epss map[string]float64
	if opts.EnableExploitChecks {
		kev = LoadKEVMap(opts.DataDir)
		epss = LoadEPSSMap(opts.DataDir)
	}

	var findings []CVEFinding
	seen := make(map[string]bool)

	emit := func(f CVEFinding) {
		if f.Confidence < opts.MinConfidence {
			return
		}
		key := strings.ToUpper(f.CVEID) + "|" + strings.ToLower(f.Library) + "|" + f.DetectedVer
		if seen[key] {
			return
		}
		seen[key] = true
		if opts.EnableExploitChecks {
			a := AssessExploitability(LocalCVEEntry{
				Library: f.Library, CVEID: f.CVEID, Severity: f.Severity,
				CVSS: f.CVSS, HasPoC: f.HasPoC, Summary: f.Summary,
				FixedVersion: f.FixedVer,
			}, kev, epss)
			f.EPSS = a.EPSS
			f.KEV = a.KEV
			f.Exploitable = a.Exploitable
			f.Verify = a.VerifySteps
			f.Nuclei = a.Nuclei
			if a.PoCRef != "" {
				f.References = append([]string{a.PoCRef}, f.References...)
			}
		}
		findings = append(findings, f)
	}

	// 1. Client-side libraries.
	for _, js := range in.JSFiles {
		if js.Content == "" {
			continue
		}
		for _, d := range DetectClientLibraries(js.Content, js.URL) {
			for _, e := range MatchEntries(d.Library, d.Version, db) {
				emit(CVEFinding{
					CVEID: e.CVEID, Library: e.Library, DetectedVer: d.Version,
					FixedVer: e.FixedVersion, Severity: e.Severity, CVSS: e.CVSS,
					HasPoC: e.HasPoC, Summary: e.Summary, Source: "local (" + e.Source + ")",
					Confidence: confidenceFor(d.Origin, "range", e.RangeApprox),
					MatchType:  "range", Context: js.URL, References: e.References,
				})
			}
		}
	}

	// 2. Server-side technologies (header/body rules + caller extras).
	var techs []DetectedTech
	for _, resp := range in.HTTPResponses {
		techs = append(techs, DetectServerTechnologies(resp)...)
	}
	techs = append(techs, in.ExtraTech...)
	for _, t := range techs {
		if t.Version == "" {
			continue // product known, version unknown: no version-gated match
		}
		for _, e := range MatchEntries(t.Tech, t.Version, db) {
			emit(CVEFinding{
				CVEID: e.CVEID, Library: e.Library, DetectedVer: t.Version,
				FixedVer: e.FixedVersion, Severity: e.Severity, CVSS: e.CVSS,
				HasPoC: e.HasPoC, Summary: e.Summary, Source: "local (" + e.Source + ")",
				Confidence: confidenceFor(t.Origin, "range", e.RangeApprox),
				MatchType:  "range", Context: t.Evidence, References: e.References,
			})
		}
	}

	// 3. Optional live OSV lookup for precise package@version answers.
	if opts.EnableOnlineLookup && queryOSV != nil {
		n := 0
		for _, js := range in.JSFiles {
			if n >= opts.MaxOnlineLookups {
				break
			}
			for _, d := range DetectClientLibraries(js.Content, js.URL) {
				if n >= opts.MaxOnlineLookups {
					break
				}
				eco, pkg, ok := OSVTargetForTech(d.Library)
				if !ok {
					continue
				}
				n++
				for _, e := range queryOSV(ctx, eco, pkg, d.Version) {
					emit(CVEFinding{
						CVEID: e.CVEID, Library: d.Library, DetectedVer: d.Version,
						FixedVer: e.FixedVersion, Severity: e.Severity, CVSS: e.CVSS,
						HasPoC: e.HasPoC, Summary: e.Summary, Source: "osv.dev",
						Confidence: confidenceFor("osv.dev", "exact", false),
						MatchType:  "exact", Context: js.URL, References: e.References,
					})
				}
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		si := severityRank(findings[i].Severity)
		sj := severityRank(findings[j].Severity)
		if si != sj {
			return si > sj
		}
		if findings[i].CVSS != findings[j].CVSS {
			return findings[i].CVSS > findings[j].CVSS
		}
		return findings[i].CVEID < findings[j].CVEID
	})
	return findings
}

func severityRank(s string) int {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "UNKNOWN", "":
		return 1
	default:
		return 0
	}
}

// QueryOSV asks osv.dev whether ecosystem:pkg@version is affected.
// OSV computes range matching server-side, so results are exact.
func (m *CVEModule) QueryOSV(ctx context.Context, ecosystem, pkg, version string) []LocalCVEEntry {
	if err := m.waitForRateLimit(ctx); err != nil {
		return nil
	}
	payload := fmt.Sprintf(`{"package":{"name":%q,"ecosystem":%q},"version":%q}`, pkg, ecosystem, version)
	endpoint := strings.TrimSuffix(m.onlineClients.osvBase, "/v1") + "/v1/query"
	if strings.HasSuffix(m.onlineClients.osvBase, "/v1/query") {
		endpoint = m.onlineClients.osvBase
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(payload))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.onlineClients.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil
	}
	var parsed osvQueryResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	var out []LocalCVEEntry
	for _, v := range parsed.Vulns {
		cvss := 0.0
		for _, s := range v.Severity {
			if (s.Type == "CVSS_V4" || s.Type == "CVSS_V3") && osvNumericScore(s.Score) > cvss {
				cvss = osvNumericScore(s.Score)
			}
		}
		sev := "UNKNOWN"
		if cvss > 0 {
			sev = calcSeverityFromCVSS(cvss)
		}
		fixed := ""
		for _, a := range v.Affected {
			for _, r := range a.Ranges {
				for _, ev := range r.Events {
					if ev.Fixed != "" {
						fixed = ev.Fixed
					}
				}
			}
		}
		summary := v.Summary
		if summary == "" {
			summary = v.Details
		}
		var refs []string
		for _, r := range v.References {
			if r.URL != "" && len(refs) < 3 {
				refs = append(refs, r.URL)
			}
		}
		out = append(out, LocalCVEEntry{
			Library: pkg, MaxVersion: fixed, FixedVersion: fixed,
			CVEID: v.ID, Severity: sev, CVSS: cvss, Summary: summary,
			Aliases: v.Aliases, References: refs, Source: "osv.dev",
		})
	}
	return out
}

// FindByCVE returns every local record for an ID (CVE, GHSA or OSV alias).
func FindByCVE(db map[string][]LocalCVEEntry, id string) []LocalCVEEntry {
	id = strings.ToUpper(strings.TrimSpace(id))
	var out []LocalCVEEntry
	for _, entries := range db {
		for _, e := range entries {
			if strings.ToUpper(e.CVEID) == id {
				out = append(out, e)
				continue
			}
			for _, a := range e.Aliases {
				if strings.ToUpper(a) == id {
					out = append(out, e)
					break
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Library != out[j].Library {
			return out[i].Library < out[j].Library
		}
		return out[i].CVEID < out[j].CVEID
	})
	return out
}

// ToLibraryCVE converts a finding into the storage model.
func ToLibraryCVE(targetID, jsFileID string, f CVEFinding) models.LibraryCVE {
	ref := ""
	if len(f.References) > 0 {
		ref = f.References[0]
	} else if strings.HasPrefix(strings.ToUpper(f.CVEID), "CVE-") {
		ref = fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", f.CVEID)
	}
	return models.LibraryCVE{
		TargetID:     targetID,
		JSFileID:     jsFileID,
		LibraryName:  f.Library,
		Version:      f.DetectedVer,
		CVEID:        f.CVEID,
		Severity:     strings.ToLower(f.Severity),
		Description:  f.Summary,
		Reference:    ref,
		CVSS:         f.CVSS,
		FixedVersion: f.FixedVer,
		Source:       f.Source,
		Context:      f.Context,
		Confidence:   f.Confidence,
		EPSS:         f.EPSS,
		KEVListed:    f.KEV,
		Exploitable:  f.Exploitable,
		ExploitNote:  strings.Join(f.Verify, " | "),
		References:   f.References,
	}
}

// ---------------------------------------------------------------------------
// Live HTTP helpers (used by `cve scan` and the daemon server-side pass)
// ---------------------------------------------------------------------------

// FetchHTTPResponse GETs urlStr and captures status, headers and a capped body.
func FetchHTTPResponse(ctx context.Context, client *http.Client, urlStr string, bodyCap int64) (HTTPResponse, error) {
	var out HTTPResponse
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("User-Agent", "Hustler/1.0 (Bug Bounty Automation)")
	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, bodyCap))
	out = HTTPResponse{URL: urlStr, StatusCode: resp.StatusCode, Headers: resp.Header, Body: string(body)}
	return out, nil
}

// FetchHomepage fetches https://domain then http://domain as fallback.
func FetchHomepage(ctx context.Context, client *http.Client, domain string) (HTTPResponse, error) {
	for _, scheme := range []string{"https://", "http://"} {
		resp, err := FetchHTTPResponse(ctx, client, scheme+domain, 512*1024)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}
	}
	return HTTPResponse{}, fmt.Errorf("homepage unreachable for %s", domain)
}

// ScanTargetLive performs a self-contained live scan: homepage fingerprint,
// script discovery, JS fetch, detection, matching and verdicts.
func ScanTargetLive(ctx context.Context, mod *CVEModule, opts ScanOptions, targetURL string, jsLimit int) ([]CVEFinding, []DetectedLib, []DetectedTech, error) {
	timeout := opts.HTTPTimeoutSec
	if timeout <= 0 {
		timeout = 15
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	if !strings.Contains(targetURL, "://") {
		targetURL = "https://" + targetURL
	}

	home, err := FetchHTTPResponse(ctx, client, targetURL, 512*1024)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to fetch %s: %w", targetURL, err)
	}
	techs := DetectServerTechnologies(home)

	scriptURLs := ExtractScriptURLs(targetURL, home.Body)
	if len(scriptURLs) > jsLimit && jsLimit > 0 {
		scriptURLs = scriptURLs[:jsLimit]
	}

	// Fetch scripts concurrently (bounded).
	sem := make(chan struct{}, 4)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var sources []JSSource
	for _, u := range scriptURLs {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
			defer cancel()
			r, err := FetchHTTPResponse(fctx, client, u, 1024*1024)
			if err != nil || r.StatusCode >= 400 {
				return
			}
			mu.Lock()
			sources = append(sources, JSSource{URL: u, Content: r.Body})
			mu.Unlock()
		}(u)
	}
	wg.Wait()

	var libs []DetectedLib
	for _, s := range sources {
		libs = append(libs, DetectClientLibraries(s.Content, s.URL)...)
	}

	findings := RunScan(ctx, mod.GetLocalDB(), mod.QueryOSV, opts, ScanInput{
		TargetURL:     targetURL,
		JSFiles:       sources,
		HTTPResponses: []HTTPResponse{home},
	})
	log.Info().Str("target", targetURL).Int("scripts", len(sources)).Int("findings", len(findings)).Msg("Live CVE scan complete")
	return findings, libs, techs, nil
}
