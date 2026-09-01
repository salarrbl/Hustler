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
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"hustler/internal/config"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

// JSModule handles the JavaScript hunting pipeline
type JSModule struct {
	cfg       config.JSConfig
	httpClient *http.Client
}

// NewJSModule creates a new JS hunting module
func NewJSModule(cfg config.JSConfig) *JSModule {
	transport := &http.Transport{
		MaxIdleConns:        cfg.MaxConcurrentFetch * 2,
		MaxIdleConnsPerHost: cfg.MaxConcurrentFetch,
		MaxConnsPerHost:     cfg.MaxConcurrentFetch,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  false,
	}

	client := &http.Client{
		Timeout:   time.Duration(cfg.FetchTimeoutSec) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &JSModule{
		cfg:        cfg,
		httpClient: client,
	}
}

// JSFileResult represents the result of fetching a JS file
type JSFileResult struct {
	JSFile   *models.JSFile
	Content  string
	Error    error
	Skipped  bool
	SkipReason string
}

// FetchAndProcess fetches JS files for a target and runs analyzers
func (m *JSModule) FetchAndProcess(ctx context.Context, target *models.Target, jsURLs []string) ([]JSFileResult, error) {
	if len(jsURLs) == 0 {
		return nil, fmt.Errorf("no JS URLs provided")
	}

	// Filter and deduplicate URLs
	uniqueURLs := m.deduplicateURLs(jsURLs)
	log.Info().Int("total", len(jsURLs)).Int("unique", len(uniqueURLs)).Str("target", target.Domain).Msg("Processing JS files")

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
	return results, nil
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
		ID:            uuid.New().String(), // Use UUID for unique ID
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