package analyzers

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

// EndpointExtractor extracts API endpoints from JS content
type EndpointExtractor struct{}

// NewEndpointExtractor creates a new endpoint extractor
func NewEndpointExtractor() *EndpointExtractor {
	return &EndpointExtractor{}
}

// endpoint patterns to look for
var endpointPatterns = []*regexp.Regexp{
	// Direct URL patterns
	regexp.MustCompile(`['"]\s*(https?://[^'\"]+)['"]`),
	regexp.MustCompile(`['"]\s*(/[a-zA-Z0-9_\-./?=&#%]+)['"]`),
	// Function calls with URLs
	regexp.MustCompile(`(?:fetch|axios|request|$.get|$.post|$.ajax|XMLHttpRequest|open)\s*\(\s*['"](https?://[^'\"]+)['"]`),
	regexp.MustCompile(`(?:fetch|axios|request|$.get|$.post|$.ajax)\s*\(\s*['"](/[^'\"]+)['"]`),
	// Template literals with paths
	regexp.MustCompile("`(/[^`]+)`"),
	// String concatenation for URLs
	regexp.MustCompile(`['"]([^'\"]*\/[a-zA-Z0-9_\-./]+)['"]`),
}

// method patterns
var methodPatterns = map[string]string{
	"fetch":    "GET",
	"axios.get": "GET",
	"axios.post": "POST",
	"$ .get":  "GET",
	"$.post":  "POST",
}

// ExtractEndpoints scans JS content for API endpoints
func (e *EndpointExtractor) ExtractEndpoints(ctx context.Context, target *models.Target, jsFile *models.JSFile, content string) ([]models.Endpoint, error) {
	var endpoints []models.Endpoint
	lines := strings.Split(content, "\n")
	seen := make(map[string]bool)

	for lineNum, line := range lines {
		lineNum++ // 1-indexed

		for _, pattern := range endpointPatterns {
			matches := pattern.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) < 2 {
					continue
				}
				epURL := match[1]

				// Skip if not an API-looking path
				if !looksLikeAPI(epURL) {
					continue
				}

				// Skip if already seen
				if seen[epURL] {
					continue
				}
				seen[epURL] = true

				// Try to infer method
				method := e.inferMethod(line)

				endpoint := models.Endpoint{
					ID:        uuid.New().String(),
					TargetID:  target.ID,
					JSFileID:  jsFile.ID,
					Endpoint:  epURL,
					Method:    method,
					Context:   "extracted_from_js",
					FoundAt:   time.Now(),
				}

				endpoints = append(endpoints, endpoint)
			}
		}
	}

	// Store in MongoDB
	if len(endpoints) > 0 {
		coll := mongo.GetCollection("endpoints")
		docs := make([]interface{}, len(endpoints))
		for i, ep := range endpoints {
			docs[i] = ep
		}
		_, err := coll.InsertMany(ctx, docs)
		if err != nil {
			log.Error().Err(err).Msg("Failed to store endpoints")
			return endpoints, err
		}
		log.Info().Int("count", len(endpoints)).Str("target", target.Domain).Str("js_file", jsFile.URL).Msg("Endpoints extracted and stored")
	}

	return endpoints, nil
}

// looksLikeAPI checks if a URL looks like an API endpoint
func looksLikeAPI(u string) bool {
	lower := strings.ToLower(u)
	apiIndicators := []string{"/api/", "/graphql", "/v1/", "/v2/", "/admin", "/internal", "/query", "/mutation", "/login", "/auth", "/user", "/users", "/data", "/endpoint"}
	for _, indicator := range apiIndicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}

// inferMethod tries to infer the HTTP method from the context
func (e *EndpointExtractor) inferMethod(line string) string {
	lower := strings.ToLower(line)
	for method, inferred := range methodPatterns {
		if strings.Contains(lower, method) {
			return inferred
		}
	}
	return ""
}