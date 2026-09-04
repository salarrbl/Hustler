package js

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"hustler/internal/analyzers"
	"hustler/internal/config"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

// JSModule handles the JavaScript hunting pipeline
type JSModule struct {
	cfg          config.JSConfig
	httpClient   *http.Client
	sensitiveCfg config.SensitiveEndpointCheckConfig
}

// NewJSModule creates a new JS hunting module
func NewJSModule(jsCfg config.JSConfig, sensitiveCfg config.SensitiveEndpointCheckConfig) *JSModule {
	transport := &http.Transport{
		MaxIdleConns:        jsCfg.MaxConcurrentFetch * 2,
		MaxIdleConnsPerHost: jsCfg.MaxConcurrentFetch,
		MaxConnsPerHost:     jsCfg.MaxConcurrentFetch,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  false,
	}

	client := &http.Client{
		Timeout:   time.Duration(jsCfg.FetchTimeoutSec) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &JSModule{
		cfg:          jsCfg,
		sensitiveCfg: sensitiveCfg,
		httpClient:   client,
	}
}

type phaseCounter struct {
	secrets     atomic.Int64
	sinks       atomic.Int64
	endpoints   atomic.Int64
	params      atomic.Int64
	blh         atomic.Int64
	cves        atomic.Int64
	fetched     atomic.Int64
	skipped     atomic.Int64
}

// JSFileResult represents the result of fetching a JS file
type JSFileResult struct {
	JSFile     *models.JSFile
	Content    string
	Error      error
	Skipped    bool
	SkipReason string
}

// FetchAndProcess fetches JS files for a target and runs all analyzers
func (m *JSModule) FetchAndProcess(ctx context.Context, target *models.Target, jsURLs []string, htmlContent map[string]string) ([]JSFileResult, error) {
	if len(jsURLs) == 0 {
		return nil, fmt.Errorf("no JS URLs provided")
	}

	// Filter and deduplicate URLs
	uniqueURLs := m.deduplicateURLs(jsURLs)
	log.Info().Int("total", len(jsURLs)).Int("unique", len(uniqueURLs)).Str("target", target.Domain).Msg("Processing JS files")

	// Check which URLs are already known (incremental)
	knowURLs := m.getKnownURLs(ctx, target.ID, uniqueURLs)
	newURLs := make([]string, 0, len(uniqueURLs))
	for _, u := range uniqueURLs {
		if !knowURLs[u] {
			newURLs = append(newURLs, u)
		}
	}
	log.Info().Int("known", len(uniqueURLs)-len(newURLs)).Int("new", len(newURLs)).Msg("URL deduplication complete")

	// Fetch JS files with concurrency control
	semaphore := make(chan struct{}, m.cfg.MaxConcurrentFetch)
	var wg sync.WaitGroup
	results := make([]JSFileResult, len(uniqueURLs))
	resultsMu := sync.Mutex{}

	for i, jsURL := range uniqueURLs {
		wg.Add(1)
		go func(idx int, u string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := m.fetchAndStore(ctx, target, u)
			resultsMu.Lock()
			results[idx] = result
			resultsMu.Unlock()
		}(i, jsURL)
	}

	wg.Wait()

	// Collect successfully fetched results with content
	var fetchedResults []JSFileResult
	var jsFiles []*models.JSFile
	contentMap := make(map[string]string)
	for _, r := range results {
		if r.Error == nil && r.Content != "" {
			fetchedResults = append(fetchedResults, r)
			jsFiles = append(jsFiles, r.JSFile)
			contentMap[r.JSFile.URL] = r.Content
		}
	}

	return results, nil
}

// FetchAndProcessWithCounter fetches JS files for a target and runs all analyzers with phase counters
func (m *JSModule) FetchAndProcessWithCounter(ctx context.Context, target *models.Target, jsURLs []string, htmlContent map[string]string, pc *models.PhaseCounter) ([]JSFileResult, error) {
	if len(jsURLs) == 0 {
		return nil, fmt.Errorf("no JS URLs provided")
	}

	// Filter and deduplicate URLs
	uniqueURLs := m.deduplicateURLs(jsURLs)
	log.Info().Int("total", len(jsURLs)).Int("unique", len(uniqueURLs)).Str("target", target.Domain).Msg("Processing JS files")

	// Check which URLs are already known (incremental)
	knowURLs := m.getKnownURLs(ctx, target.ID, uniqueURLs)
	newURLs := make([]string, 0, len(uniqueURLs))
	for _, u := range uniqueURLs {
		if !knowURLs[u] {
			newURLs = append(newURLs, u)
		}
	}
	log.Info().Int("known", len(uniqueURLs)-len(newURLs)).Int("new", len(newURLs)).Msg("URL deduplication complete")

	// Fetch JS files with concurrency control
	semaphore := make(chan struct{}, m.cfg.MaxConcurrentFetch)
	var wg sync.WaitGroup
	results := make([]JSFileResult, len(uniqueURLs))
	resultsMu := sync.Mutex{}

	for i, jsURL := range uniqueURLs {
		wg.Add(1)
		go func(idx int, u string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := m.fetchAndStore(ctx, target, u)
			resultsMu.Lock()
			results[idx] = result
			resultsMu.Unlock()
		}(i, jsURL)
	}

	wg.Wait()

	// Collect successfully fetched results with content
	var fetchedResults []JSFileResult
	var jsFiles []*models.JSFile
	contentMap := make(map[string]string)
	for _, r := range results {
		if r.Error == nil && r.Content != "" {
			fetchedResults = append(fetchedResults, r)
			jsFiles = append(jsFiles, r.JSFile)
			contentMap[r.JSFile.URL] = r.Content
		}
	}

	// Run analyzers on fetched content
	if len(jsFiles) > 0 {
		m.runAnalyzersWithCounter(ctx, target, jsFiles, contentMap, htmlContent, pc)
	}

	return results, nil
}

// runAnalyzersWithCounter runs all enabled analyzers on the fetched JS files with phase counters
func (m *JSModule) runAnalyzersWithCounter(ctx context.Context, target *models.Target, jsFiles []*models.JSFile, contentMap map[string]string, htmlContent map[string]string, pc *models.PhaseCounter) {
	log.Info().Int("files", len(jsFiles)).Msg("Running analyzers")

	// 1. Secret scanner
	secretScanner := analyzers.NewSecretScanner(m.cfg)
	totalSecrets := 0
	for _, jsFile := range jsFiles {
		content := contentMap[jsFile.URL]
		if content == "" {
			continue
		}
		secrets, err := secretScanner.Scan(ctx, target, jsFile, content)
		if err != nil {
			log.Warn().Err(err).Str("js_file", jsFile.URL).Msg("Secret scanner failed")
		} else {
			totalSecrets += len(secrets)
		}
	}
	pc.Secrets.Add(int64(totalSecrets))

	// 2. Sink analyzer
	sinkAnalyzer := analyzers.NewSinkAnalyzer()
	totalSinks := 0
	for _, jsFile := range jsFiles {
		content := contentMap[jsFile.URL]
		if content == "" {
			continue
		}
		sinks, err := sinkAnalyzer.Scan(ctx, target, jsFile, content)
		if err != nil {
			log.Warn().Err(err).Str("js_file", jsFile.URL).Msg("Sink analyzer failed")
		} else {
			totalSinks += len(sinks)
		}
	}
	pc.Sinks.Add(int64(totalSinks))

	// 3. Endpoint extractor (scan both JS and HTML)
	endpointExtractor := analyzers.NewEndpointExtractor()
	totalEndpoints := 0
	// Scan JS files
	for _, jsFile := range jsFiles {
		content := contentMap[jsFile.URL]
		if content == "" {
			continue
		}
		endpoints, err := endpointExtractor.ExtractEndpoints(ctx, target, jsFile, content, "js_file")
		if err != nil {
			log.Warn().Err(err).Str("js_file", jsFile.URL).Msg("Endpoint extractor failed")
		} else {
			totalEndpoints += len(endpoints)
			// Store discovered endpoints as URLs
			m.storeDiscoveredURLs(ctx, target.ID, endpoints, "extracted_from_js")
		}
	}
	// Scan HTML content
	for htmlURL, html := range htmlContent {
		if html == "" {
			continue
		}
		// Create a temporary JSFile for HTML tracking
		htmlJSFile := &models.JSFile{
			ID:       uuid.New().String(),
			TargetID: target.ID,
			URL:      htmlURL,
		}
		endpoints, err := endpointExtractor.ExtractEndpoints(ctx, target, htmlJSFile, html, "html_page")
		if err != nil {
			log.Warn().Err(err).Str("html_url", htmlURL).Msg("Endpoint extractor failed on HTML")
		} else {
			totalEndpoints += len(endpoints)
		}
	}
	pc.Endpoints.Add(int64(totalEndpoints))

	// 4. Parameter extractor (scan both JS and HTML)
	paramExtractor := analyzers.NewParamExtractor()
	totalParams := 0
	// Scan JS files
	for _, jsFile := range jsFiles {
		content := contentMap[jsFile.URL]
		if content == "" {
			continue
		}
		params, err := paramExtractor.ExtractParams(ctx, target, jsFile, content, "js_file")
		if err != nil {
			log.Warn().Err(err).Str("js_file", jsFile.URL).Msg("Param extractor failed")
		} else {
			totalParams += len(params)
			// Store discovered parameters as discovered URLs
			if len(params) > 0 {
				m.storeDiscoveredURLs(ctx, target.ID, nil, "param_extraction")
			}
		}
	}
	// Scan HTML content
	for htmlURL, html := range htmlContent {
		if html == "" {
			continue
		}
		// Create a temporary JSFile for HTML tracking
		htmlJSFile := &models.JSFile{
			ID:       uuid.New().String(),
			TargetID: target.ID,
			URL:      htmlURL,
		}
		params, err := paramExtractor.ExtractParams(ctx, target, htmlJSFile, html, "html_page")
		if err != nil {
			log.Warn().Err(err).Str("html_url", htmlURL).Msg("Param extractor failed on HTML")
		} else {
			totalParams += len(params)
		}
	}
	pc.Params.Add(int64(totalParams))

	// 5. BLH analyzer
	blhAnalyzer := analyzers.NewBLHAnalyzer(m.httpClient)
	blhCandidates, err := blhAnalyzer.AnalyzeBLH(ctx, target, jsFiles, contentMap, htmlContent)
	if err != nil {
		log.Warn().Err(err).Msg("BLH analyzer failed")
	} else {
		pc.BLH.Add(int64(len(blhCandidates)))
	}

	// 6. Library CVE analyzer
	cveAnalyzer := analyzers.NewLibraryCVEAnalyzer()
	cveResults, err := cveAnalyzer.AnalyzeLibraries(ctx, target, jsFiles, contentMap)
	if err != nil {
		log.Warn().Err(err).Msg("Library CVE analyzer failed")
	} else {
		pc.Cves.Add(int64(len(cveResults)))
	}

	// 7. Sensitive endpoint check (if enabled)
	if m.sensitiveCfg.Enabled {
		sensitiveAnalyzer := analyzers.NewSensitiveEndpointAnalyzer(m.sensitiveCfg, m.httpClient)
		if sensitiveAnalyzer != nil {
			// Get endpoints from DB for this target
			epColl := mongo.GetCollection("endpoints")
			cursor, err := epColl.Find(ctx, map[string]interface{}{"target_id": target.ID})
			if err != nil {
				log.Warn().Err(err).Msg("Failed to query endpoints for sensitive check")
			} else {
				var endpoints []models.Endpoint
				cursor.All(ctx, &endpoints)
				candidates, err := sensitiveAnalyzer.Check(ctx, target, endpoints)
				if err != nil {
					log.Warn().Err(err).Msg("Sensitive endpoint check failed")
				} else {
					log.Info().Int("count", len(candidates)).Msg("Sensitive endpoint check complete")
				}
			}
		}
	}
}

// storeDiscoveredURLs persists discovered URLs to the discovered_urls collection
func (m *JSModule) storeDiscoveredURLs(ctx context.Context, targetID string, endpoints []models.Endpoint, source string) {
	coll := mongo.GetCollection("discovered_urls")
	now := time.Now()
	for _, ep := range endpoints {
		doc := models.DiscoveredURL{
			ID:        uuid.New().String(),
			TargetID:  targetID,
			URL:       ep.Endpoint,
			URLType:   "endpoint",
			Source:    source,
			FirstSeen: now,
			LastSeen:  now,
		}
		// Use upsert to update last_seen if exists
		filter := map[string]interface{}{"target_id": targetID, "url": ep.Endpoint}
		update := map[string]interface{}{"$set": map[string]interface{}{
			"last_seen": now,
		}}
		_, err := coll.UpdateOne(ctx, filter, update)
		if err != nil {
			// If not found, insert new
			coll.InsertOne(ctx, doc)
		}
	}
}

// getKnownURLs checks which URLs are already in the discovered_urls collection
func (m *JSModule) getKnownURLs(ctx context.Context, targetID string, urls []string) map[string]bool {
	coll := mongo.GetCollection("discovered_urls")
	known := make(map[string]bool)
	for _, u := range urls {
		var doc models.DiscoveredURL
		err := coll.FindOne(ctx, map[string]interface{}{
			"target_id": targetID,
			"url":       u,
		}).Decode(&doc)
		if err == nil {
			known[u] = true
		}
	}
	return known
}

// fetchAndStore fetches a single JS file, checks hash dedupe, stores if new
func (m *JSModule) fetchAndStore(ctx context.Context, target *models.Target, jsURL string) JSFileResult {
	// Fetch the JS file
	req, err := http.NewRequestWithContext(ctx, "GET", jsURL, nil)
	if err != nil {
		return JSFileResult{Error: fmt.Errorf("failed to create request: %w", err)}
	}
	req.Header.Set("User-Agent", "Hustler/1.0 (Bug Bounty Automation)")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return JSFileResult{Error: fmt.Errorf("failed to fetch: %w", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return JSFileResult{Error: fmt.Errorf("HTTP %d", resp.StatusCode)}
	}

	// Read body with size limit (10MB)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return JSFileResult{Error: fmt.Errorf("failed to read body: %w", err)}
	}

	content := string(body)
	if len(content) == 0 {
		return JSFileResult{Error: fmt.Errorf("empty content")}
	}

	// Compute SHA256 hash for dedupe
	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])

	// Check if already processed for this target
	coll := mongo.GetCollection("js_files")
	var existing models.JSFile
	err = coll.FindOne(ctx, map[string]interface{}{
		"target_id": target.ID,
		"js_hash":   hashStr,
	}).Decode(&existing)

	if err == nil {
		// Already processed - skip
		log.Debug().Str("url", jsURL).Str("hash", hashStr[:16]).Msg("JS file already processed, skipping")
		return JSFileResult{
			JSFile:     &existing,
			Skipped:    true,
			SkipReason: "hash already exists for this target",
		}
	}

	// Check against global skip hashes (known libraries)
	for _, skipHash := range m.cfg.SkipHashes {
		if strings.HasPrefix(hashStr, skipHash) {
			return JSFileResult{
				Skipped:    true,
				SkipReason: "hash in global skip list",
			}
		}
	}

	// Extract source map URL if present
	sourceMapURL := m.extractSourceMapURL(content, jsURL)

	// Create JSFile record
	jsFile := &models.JSFile{
		ID:            uuid.New().String(),
		TargetID:      target.ID,
		URL:           jsURL,
		JSHash:        hashStr,
		StatusCode:    resp.StatusCode,
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: int64(len(body)),
		FetchedAt:     time.Now(),
		SourceMapURL:  sourceMapURL,
	}

	// Store in MongoDB
	_, err = coll.InsertOne(ctx, jsFile)
	if err != nil {
		return JSFileResult{Error: fmt.Errorf("failed to store JS file: %w", err)}
	}

	// If source map enabled and found, fetch it
	if m.cfg.EnableSourceMaps && sourceMapURL != "" {
		m.fetchSourceMap(ctx, target.ID, jsFile.ID, sourceMapURL)
	}

	// Store as discovered URL
	m.storeDiscoveredURLs(ctx, target.ID, nil, "manual")
	// Add the JS URL itself as discovered
	jsURLDoc := models.DiscoveredURL{
		ID:        uuid.New().String(),
		TargetID:  target.ID,
		URL:       jsURL,
		URLType:   "js_file",
		Source:    "manual",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
	urlColl := mongo.GetCollection("discovered_urls")
	urlColl.InsertOne(ctx, jsURLDoc)

	log.Info().Str("url", jsURL).Str("hash", hashStr[:16]).Int("size", len(body)).Msg("JS file fetched and stored")
	return JSFileResult{JSFile: jsFile, Content: content}
}

// deduplicateURLs removes duplicate URLs and normalizes them
func (m *JSModule) deduplicateURLs(urls []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		// Normalize URL
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		// Remove fragment
		parsed.Fragment = ""
		normalized := parsed.String()
		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, normalized)
		}
	}
	return result
}

// extractSourceMapURL finds sourceMappingURL in JS content
func (m *JSModule) extractSourceMapURL(content, baseURL string) string {
	// Look for //# sourceMappingURL= or /*# sourceMappingURL= */
	lines := strings.Split(content, "\n")
	for i := len(lines) - 1; i >= 0 && i > len(lines)-50; i-- { // Check last 50 lines
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "//# sourceMappingURL=") {
			mapURL := strings.TrimPrefix(line, "//# sourceMappingURL=")
			return m.resolveURL(mapURL, baseURL)
		}
		if strings.HasPrefix(line, "/*# sourceMappingURL=") {
			mapURL := strings.TrimPrefix(line, "/*# sourceMappingURL=")
			mapURL = strings.TrimSuffix(mapURL, "*/")
			return m.resolveURL(mapURL, baseURL)
		}
	}
	return ""
}

// resolveURL resolves a relative URL against a base URL
func (m *JSModule) resolveURL(ref, base string) string {
	baseParsed, err := url.Parse(base)
	if err != nil {
		return ""
	}
	refParsed, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return baseParsed.ResolveReference(refParsed).String()
}

// fetchSourceMap fetches and stores a source map
func (m *JSModule) fetchSourceMap(ctx context.Context, targetID, jsFileID, mapURL string) {
	req, err := http.NewRequestWithContext(ctx, "GET", mapURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Hustler/1.0 (Bug Bounty Automation)")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024)) // 50MB limit for source maps
	if err != nil {
		return
	}

	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])

	// Update JSFile with source map hash
	coll := mongo.GetCollection("js_files")
	coll.UpdateOne(ctx,
		map[string]interface{}{"_id": jsFileID},
		map[string]interface{}{"$set": map[string]interface{}{
			"source_map_hash": hashStr,
		}},
	)
}