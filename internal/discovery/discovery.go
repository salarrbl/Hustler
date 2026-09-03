package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"hustler/internal/config"
	"hustler/internal/models"
)

// DiscoveryRunner discovers JS URLs for a target using external tools
type DiscoveryRunner struct {
	cfg         config.DiscoveryConfig
	httpClient  *http.Client
	katanaPath  string
}

// NewDiscoveryRunner creates a new discovery runner
func NewDiscoveryRunner(cfg config.DiscoveryConfig, httpClient *http.Client) *DiscoveryRunner {
	// Try to find katana in common locations
	katanaPath := "katana"
	if p, err := exec.LookPath("katana"); err == nil {
		katanaPath = p
	} else if _, err := os.Stat("/home/qarqa/go/bin/katana"); err == nil {
		katanaPath = "/home/qarqa/go/bin/katana"
	}

	return &DiscoveryRunner{
		cfg:        cfg,
		httpClient: httpClient,
		katanaPath: katanaPath,
	}
}

// DiscoverResult holds both JS URLs and HTML content from crawled pages
type DiscoverResult struct {
	JSURLs      []string
	HTMLContent map[string]string // URL -> HTML content
}

// DiscoverJSURLs discovers JS URLs for a target using enabled tools
func (d *DiscoveryRunner) DiscoverJSURLs(ctx context.Context, target *models.Target) ([]string, error) {
	result, err := d.Discover(ctx, target)
	if err != nil {
		return nil, err
	}
	return result.JSURLs, nil
}

// Discover discovers JS URLs and fetches HTML content for BLH analysis
func (d *DiscoveryRunner) Discover(ctx context.Context, target *models.Target) (*DiscoverResult, error) {
	if !d.cfg.Enabled {
		log.Info().Str("domain", target.Domain).Msg("Discovery disabled in config")
		return &DiscoverResult{JSURLs: []string{}, HTMLContent: map[string]string{}}, nil
	}

	allURLs := make(map[string]bool)
	htmlContent := make(map[string]string)
	stats := make(map[string]int)

	// Use katana if enabled (active crawling - most reliable for modern sites)
	if d.cfg.UseKatana {
		if result, err := d.discoverViaKatana(ctx, target.Domain); err != nil {
			log.Warn().Err(err).Str("domain", target.Domain).Msg("Katana discovery failed")
		} else {
			for _, u := range result.JSURLs {
				allURLs[u] = true
			}
			for k, v := range result.HTMLContent {
				htmlContent[k] = v
			}
			stats["katana"] = len(result.JSURLs)
			stats["katana_html"] = len(result.HTMLContent)
		}
	}

	// Use Wayback CDX API (historical data)
	if urls, err := d.DiscoverViaWaybackCDX(ctx, target.Domain); err != nil {
		log.Warn().Err(err).Str("domain", target.Domain).Msg("Wayback CDX discovery failed")
	} else {
		for _, u := range urls {
			allURLs[u] = true
		}
		stats["wayback_cdx"] = len(urls)
	}

	// Use gau if enabled
	if d.cfg.UseGau {
		if urls, err := d.discoverViaGau(ctx, target.Domain); err != nil {
			log.Warn().Err(err).Str("domain", target.Domain).Msg("Gau discovery failed")
		} else {
			for _, u := range urls {
				allURLs[u] = true
			}
			stats["gau"] = len(urls)
		}
	}

	// Convert to slice
	var result []string
	for u := range allURLs {
		result = append(result, u)
	}

	log.Info().
		Str("domain", target.Domain).
		Int("total_discovered", len(result)).
		Int("html_pages", len(htmlContent)).
		Interface("by_source", stats).
		Msg("Discovery complete")

	return &DiscoverResult{
		JSURLs:      result,
		HTMLContent: htmlContent,
	}, nil
}

// discoverViaKatana runs katana to crawl for JS files and fetches HTML content
func (d *DiscoveryRunner) discoverViaKatana(ctx context.Context, domain string) (*DiscoverResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	// Check if katana is available
	if _, err := exec.LookPath(d.katanaPath); err != nil {
		return &DiscoverResult{JSURLs: []string{}, HTMLContent: map[string]string{}}, fmt.Errorf("katana not found: %w", err)
	}

	cmd := exec.CommandContext(ctx, d.katanaPath,
		"-u", "https://"+domain,
		"-jc",      // extract JS file endpoints
		"-d", "2",  // depth 2
		"-nc",      // no color
		"-silent",  // silent mode
		"-c", "10", // concurrency
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return &DiscoverResult{JSURLs: []string{}, HTMLContent: map[string]string{}}, fmt.Errorf("katana failed: %w", err)
	}

	// Parse output - look for lines containing .js
	lines := strings.Split(string(output), "\n")
	var urls []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip non-URL lines (logs start with [INF] etc.)
		if strings.HasPrefix(line, "[") {
			continue
		}
		if line != "" && (strings.HasSuffix(line, ".js") || strings.Contains(line, ".js?")) {
			urls = append(urls, line)
		}
	}

	// Also fetch HTML content from the main page and a few key pages
	htmlContent := make(map[string]string)
	mainURL := "https://" + domain
	if html, err := d.fetchHTML(ctx, mainURL); err == nil {
		htmlContent[mainURL] = html
	}

	return &DiscoverResult{
		JSURLs:      urls,
		HTMLContent: htmlContent,
	}, nil
}

// fetchHTML fetches HTML content from a URL
func (d *DiscoveryRunner) fetchHTML(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Hustler/1.0 (Bug Bounty Automation)")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// discoverViaWaybackCDX queries the Wayback Machine CDX API for JS URLs
func (d *DiscoveryRunner) DiscoverViaWaybackCDX(ctx context.Context, domain string) ([]string, error) {
	// Wayback CDX API endpoint - query for JS files
	cdxURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*.js&output=json&fl=original&limit=1000&collapse=urlkey", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", cdxURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "Hustler/1.0 (Bug Bounty Automation)")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wayback cdx request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("wayback cdx returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse JSON array format: each line is a JSON array ["original"]
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var urls []string
	lineNum := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lineNum++

		// Skip header line
		if lineNum == 1 {
			if strings.Contains(line, "original") || strings.Contains(line, "urlkey") {
				continue
			}
		}

		// Parse JSON array: ["url"]
		var arr []string
		if err := json.Unmarshal([]byte(line), &arr); err != nil {
			continue
		}
		if len(arr) > 0 && arr[0] != "" {
			url := strings.TrimSpace(arr[0])
			if url != "" && strings.HasSuffix(url, ".js") {
				urls = append(urls, url)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return urls, fmt.Errorf("scanner error: %w", err)
	}

	return urls, nil
}

// discoverViaGau runs the gau binary to fetch URLs from Wayback Machine
func (d *DiscoveryRunner) discoverViaGau(ctx context.Context, domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "gau", "--providers", "wayback", "https://"+domain, "--subs")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return []string{}, fmt.Errorf("gau failed: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	var urls []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && strings.HasSuffix(line, ".js") {
			urls = append(urls, line)
		}
	}
	return urls, nil
}