package analyzers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

// SensitivePathAnalyzer checks for exposed sensitive files (backups, configs, env files, etc.)
type SensitivePathAnalyzer struct {
	client *http.Client
}

// NewSensitivePathAnalyzer creates a new sensitive path analyzer
func NewSensitivePathAnalyzer(httpClient *http.Client) *SensitivePathAnalyzer {
	return &SensitivePathAnalyzer{
		client: httpClient,
	}
}

// sensitivePaths are common paths that should not be exposed
var sensitivePaths = []string{
	// Backup files
	"/.env", "/.env.backup", "/.env.local", "/.env.production",
	"/config.php.bak", "/config.json.bak", "/.git/config",
	"/wp-config.php.bak", "/wp-config.php.txt",
	"/backup.zip", "/backup.tar.gz", "/backup.sql",
	"/database.sql", "/dump.sql", "/db.sql",
	"/wwwroot.zip", "/public_html.zip",
	"/wp-content/uploads/.htaccess", "/wp-config.php.old",

	// Config files
	"/config.php", "/configuration.php", "/config.inc.php",
	"/appsettings.json", "/web.config", "/.htaccess",
	"/composer.json", "/package.json", "/Gemfile",
	"/docker-compose.yml", "/Dockerfile",
	"/.gitignore", "/.env.example", "/.env.template",

	// Debug endpoints
	"/debug", "/debug/vars", "/debug/pprof",
	"/trace", "/trace.html",
	"/health", "/healthz", "/healthcheck",
	"/status", "/status.json",
	"/metrics", "/prometheus",
	"/admin", "/administrator", "/admin.php",
	"/phpmyadmin", "/pma",
	"/server-status", "/server-info",
	"/actuator", "/actuator/health",
	"/swagger-ui.html", "/api-docs", "/swagger.json",
	"/graphql", "/graphiql",

	// Source control
	"/.git", "/.svn", "/.hg",
	"/.git/HEAD", "/.git/config",
	"/.svn/entries",

	// Logs
	"/logs", "/log",
	"/error.log", "/access.log",
	"/debug.log", "/development.log",

	// PHP info
	"/phpinfo.php", "/info.php", "/test.php",
	"/i.php", "/php.php",

	// Common vulnerabilities
	"/xmlrpc.php",
	"/wp-login.php",
	"/wp-admin",
	"/administrator/",
	"/.well-known/security.txt",
	"/robots.txt", // Can leak internal paths
	"/sitemap.xml", // Can leak internal paths

	// Source maps (if not already found in JS analysis)
	"/*.map",
}

// pathPatterns for extracting from JS/HTML
var pathPatterns = []*regexp.Regexp{
	// Direct file references
	regexp.MustCompile(`['"` + "`" + `](/[a-zA-Z0-9_\-./?=&%#]+)(?:\.env|\.bak|\.backup|\.old|\.sql|\.zip|\.tar\.gz|\.php|\.json|\.xml|\.yml|\.yaml|\.map|\.log)`),
	// Config paths
	regexp.MustCompile(`['"` + "`" + `](/[^'"` + "`" + `\s]+config[^'"` + "`" + `\s]*)`),
	// Debug paths
	regexp.MustCompile(`['"` + "`" + `](/[^'"` + "`" + `\s]*(?:debug|trace|admin|phpmyadmin|phpinfo)[^'"` + "`" + `\s]*)`),
	// Git paths
	regexp.MustCompile(`['"` + "`" + `](/\.git[^'"` + "`" + `\s]*)`),
}

// AnalyzeSensitivePaths checks for exposed sensitive files
func (s *SensitivePathAnalyzer) AnalyzeSensitivePaths(ctx context.Context, target *models.Target, jsFiles []*models.JSFile, htmlContent string) ([]models.SensitiveEndpointCandidate, error) {
	var candidates []models.SensitiveEndpointCandidate
	seen := make(map[string]bool)

	// Collect potential paths from JS files
	jsPaths := s.extractPathsFromJS(jsFiles)
	for _, p := range jsPaths {
		if !seen[p] {
			seen[p] = true
			candidates = append(candidates, models.SensitiveEndpointCandidate{
				ID:        uuid.New().String(),
				TargetID:  target.ID,
				Endpoint:  p,
				FoundAt:   time.Now(),
				Source:    "js_extracted",
			})
		}
	}

	// Collect paths from HTML content
	htmlPaths := s.extractPathsFromHTML(htmlContent, target.Domain)
	for _, p := range htmlPaths {
		if !seen[p] {
			seen[p] = true
			candidates = append(candidates, models.SensitiveEndpointCandidate{
				ID:        uuid.New().String(),
				TargetID:  target.ID,
				Endpoint:  p,
				FoundAt:   time.Now(),
				Source:    "html_extracted",
			})
		}
	}

	// Check common sensitive paths
	for _, path := range sensitivePaths {
		fullURL := fmt.Sprintf("%s%s", target.Domain, path)
		if !seen[fullURL] {
			seen[fullURL] = true
			candidates = append(candidates, models.SensitiveEndpointCandidate{
				ID:        uuid.New().String(),
				TargetID:  target.ID,
				Endpoint:  fullURL,
				FoundAt:   time.Now(),
				Source:    "common_path",
			})
		}
	}

	// Now probe each candidate
	log.Info().Int("candidates", len(candidates)).Str("target", target.Domain).Msg("Checking sensitive paths")

	var finalCandidates []models.SensitiveEndpointCandidate
	for _, c := range candidates {
		resp, err := s.checkPath(ctx, c.Endpoint)
		if err != nil || resp == nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024))
		bodyStr := string(body)

		// Check if response contains sensitive content
		if s.isSensitiveResponse(resp.StatusCode, bodyStr) {
			c.StatusCode = resp.StatusCode
			c.ResponseSize = len(body)
			c.MatchedPatterns = s.matchSensitivePatterns(bodyStr)
			c.FoundAt = time.Now()
			finalCandidates = append(finalCandidates, c)
			log.Warn().Str("path", c.Endpoint).Int("status", resp.StatusCode).Msg("Sensitive path found")
		}
	}

	// Store in MongoDB
	if len(finalCandidates) > 0 {
		coll := mongo.GetCollection("sensitive_endpoint_candidates")
		docs := make([]interface{}, len(finalCandidates))
		for i, c := range finalCandidates {
			docs[i] = c
		}
		_, err := coll.InsertMany(ctx, docs)
		if err != nil {
			log.Error().Err(err).Msg("Failed to store sensitive endpoint candidates")
			return finalCandidates, err
		}
		log.Info().Int("count", len(finalCandidates)).Str("target", target.Domain).Msg("Sensitive paths found and stored")
	}

	return finalCandidates, nil
}

func (s *SensitivePathAnalyzer) checkPath(ctx context.Context, endpoint string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Hustler/1.0 (Bug Bounty Automation - Sensitive Path Check)")
	req.Header.Set("Accept", "text/html,application/json,*/*")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *SensitivePathAnalyzer) isSensitiveResponse(statusCode int, body string) bool {
	// Return true for:
	// - 200 OK with content (config, env files, source code)
	// - 403 Forbidden (means it exists but access denied)
	// - 401 Unauthorized
	if statusCode == 200 && len(body) > 100 {
		return true
	}
	if statusCode == 403 || statusCode == 401 {
		return true
	}
	// Also check for specific patterns in body
	sensitivePatterns := []string{
		"DB_PASSWORD", "DATABASE_URL", "API_KEY", "SECRET",
		"<?php", "function(", "module.exports",
		"password", "username", "email",
		"stack trace", "exception",
		"unauthorized", "forbidden",
	}
	lowerBody := strings.ToLower(body)
	for _, p := range sensitivePatterns {
		if strings.Contains(lowerBody, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func (s *SensitivePathAnalyzer) matchSensitivePatterns(body string) []string {
	patterns := []string{}
	if strings.Contains(body, "DB_PASSWORD") || strings.Contains(body, "DATABASE_URL") {
		patterns = append(patterns, "database_credentials")
	}
	if strings.Contains(body, "API_KEY") || strings.Contains(body, "SECRET") {
		patterns = append(patterns, "api_key_or_secret")
	}
	if strings.Contains(body, "<?php") {
		patterns = append(patterns, "php_source")
	}
	if strings.Contains(body, "password") {
		patterns = append(patterns, "password_in_config")
	}
	if strings.Contains(body, "stack trace") || strings.Contains(body, "exception") {
		patterns = append(patterns, "stack_trace")
	}
	return patterns
}

func (s *SensitivePathAnalyzer) extractPathsFromJS(jsFiles []*models.JSFile) []string {
	seen := make(map[string]bool)
	var paths []string

	for _, jsFile := range jsFiles {
		// Extract paths that look like sensitive files
		for _, pattern := range pathPatterns {
			matches := pattern.FindAllString(jsFile.URL, -1)
			for _, match := range matches {
				if !seen[match] {
					seen[match] = true
					paths = append(paths, match)
				}
			}
		}
	}

	return paths
}

func (s *SensitivePathAnalyzer) extractPathsFromHTML(htmlContent, domain string) []string {
	seen := make(map[string]bool)
	var paths []string

	// Look for links to sensitive files
	linkPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<a\s+[^>]*href=["']([^"']+)["']`),
		regexp.MustCompile(`(?i)<link\s+[^>]*href=["']([^"']+)["']`),
		regexp.MustCompile(`(?i)<script\s+[^>]*src=["']([^"']+)["']`),
		regexp.MustCompile(`(?i)<img\s+[^>]*src=["']([^"']+)["']`),
		regexp.MustCompile(`(?i)<iframe\s+[^>]*src=["']([^"']+)["']`),
	}

	for _, pattern := range linkPatterns {
		matches := pattern.FindAllStringSubmatch(htmlContent, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			path := match[1]
			// Skip external URLs, data URIs, javascript:
			if strings.HasPrefix(path, "http") || strings.HasPrefix(path, "data:") || strings.HasPrefix(path, "javascript:") {
				continue
			}
			// Make absolute
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			fullPath := "https://" + domain + path
			if !seen[fullPath] {
				seen[fullPath] = true
				paths = append(paths, fullPath)
			}
		}
	}

	return paths
}