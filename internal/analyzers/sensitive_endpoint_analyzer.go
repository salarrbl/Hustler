package analyzers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"hustler/internal/config"
	"hustler/internal/models"
)

// SensitiveEndpointAnalyzer checks extracted endpoints for potential sensitive data leaks
type SensitiveEndpointAnalyzer struct {
	cfg          config.SensitiveEndpointCheckConfig
	client       *http.Client
	pathPattern  *regexp.Regexp
	sensitiveRe  []*regexp.Regexp
	inited       bool
}

// NewSensitiveEndpointAnalyzer creates a new sensitive endpoint checker
func NewSensitiveEndpointAnalyzer(cfg config.SensitiveEndpointCheckConfig, httpClient *http.Client) *SensitiveEndpointAnalyzer {
	if !cfg.Enabled {
		log.Info().Msg("Sensitive endpoint check is disabled (default)")
		return nil
	}

	// Build path matching regex from configured heuristic paths
	parts := make([]string, len(cfg.HeuristicPaths))
	for i, p := range cfg.HeuristicPaths {
		parts[i] = regexp.QuoteMeta(p)
	}
	pathRegex := "(?i)(?:" + strings.Join(parts, "|") + ")"
	pathRe, err := regexp.Compile(pathRegex)
	if err != nil {
		log.Error().Err(err).Msg("Failed to compile sensitive endpoint path regex")
		return nil
	}

	// Compile sensitive patterns
	var sensRe []*regexp.Regexp
	for _, pat := range cfg.SensitivePatterns {
		re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(pat))
		if err != nil {
			continue
		}
		sensRe = append(sensRe, re)
	}

	return &SensitiveEndpointAnalyzer{
		cfg:         cfg,
		client:      httpClient,
		pathPattern: pathRe,
		sensitiveRe: sensRe,
		inited:      true,
	}
}

// Check runs the sensitive endpoint check on extracted endpoints (read-only GET only)
func (s *SensitiveEndpointAnalyzer) Check(ctx context.Context, target *models.Target, endpoints []models.Endpoint) ([]models.SensitiveEndpointCandidate, error) {
	if !s.inited {
		return nil, fmt.Errorf("sensitive endpoint checker is disabled")
	}

	var candidates []models.SensitiveEndpointCandidate
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, ep := range endpoints {
		// Only check if path matches heuristic
		if !s.pathPattern.MatchString(ep.Endpoint) {
			continue
		}

		wg.Add(1)
		go func(e models.Endpoint) {
			defer wg.Done()
			candidate := s.checkOne(ctx, target, e)
			if candidate != nil {
				mu.Lock()
				candidates = append(candidates, *candidate)
				mu.Unlock()
			}
		}(ep)
	}

	wg.Wait()
	return candidates, nil
}

func (s *SensitiveEndpointAnalyzer) checkOne(ctx context.Context, target *models.Target, ep models.Endpoint) *models.SensitiveEndpointCandidate {
	// Resolve to full URL if possible
	fullURL := ep.Endpoint
	if !strings.HasPrefix(fullURL, "http") {
		// For relative paths, we'd need the origin - use a best-effort approach
		fullURL = "https://" + target.Domain + ep.Endpoint
	}

	// Parse and validate
	parsed, err := url.Parse(fullURL)
	if err != nil {
		return nil
	}

	// Only GET requests - never mutate
	req, err := http.NewRequestWithContext(ctx, "GET", parsed.String(), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Hustler/1.0 (Bug Bounty Automation - Sensitive Endpoint Check)")
	req.Header.Set("Accept", "application/json, text/html, */*")

	resp, err := s.client.Do(req)
	if err != nil {
		log.Debug().Err(err).Str("url", fullURL).Msg("Request failed")
		return nil
	}
	defer resp.Body.Close()

	// Read body with size limit
	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024)) // 50KB cap
	if err != nil {
		return nil
	}

	bodyStr := string(body)
	responseSize := utf8.RuneCountInString(bodyStr)

	// Check for sensitive patterns
	var matched []string
	for _, re := range s.sensitiveRe {
		if re.MatchString(bodyStr) {
			matched = append(matched, re.String())
		}
	}

	// If we found sensitive patterns AND got a 200 (or other non-error status), flag it
	if len(matched) > 0 && resp.StatusCode >= 200 && resp.StatusCode < 400 {
		candidate := models.SensitiveEndpointCandidate{
			ID:              uuid.New().String(),
			TargetID:        target.ID,
			Endpoint:        fullURL,
			StatusCode:      resp.StatusCode,
			ResponseSize:    responseSize,
			MatchedPatterns: matched,
			FoundAt:         time.Now(),
		}
		log.Info().
			Str("endpoint", fullURL).
			Int("status", resp.StatusCode).
			Int("size", responseSize).
			Strs("patterns", matched).
			Msg("Sensitive endpoint candidate found")
		return &candidate
	}

	return nil
}
