package analyzers

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

// BLHAnalyzer checks for Broken Link Hijacking candidates
type BLHAnalyzer struct {
	client *http.Client
}

// NewBLHAnalyzer creates a new BLH analyzer
func NewBLHAnalyzer(httpClient *http.Client) *BLHAnalyzer {
	return &BLHAnalyzer{
		client: httpClient,
	}
}

// extractDomainsFromJS extracts external domains from JS content
func (b *BLHAnalyzer) extractDomains(content string, baseURL string) []string {
	// Match script src attributes, CDN URLs, external references
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?:src|href)=["']([^"']*://[^"']+)["']`),
		regexp.MustCompile(`https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s"']*)?`),
	}

	domains := make(map[string]bool)
	baseHost := extractHost(baseURL)

	for _, pattern := range patterns {
		matches := pattern.FindAllString(content, -1)
		for _, match := range matches {
			match = strings.TrimSpace(match)
			match = strings.TrimPrefix(match, "https://")
			match = strings.TrimPrefix(match, "http://")
			match = strings.Split(match, "/")[0]
			match = strings.Split(match, ":")[0]
			if match != "" && match != baseHost {
				domains[match] = true
			}
		}
	}

	var result []string
	for d := range domains {
		result = append(result, d)
	}
	return result
}

func extractHost(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return parsed.Host
}

// checkDomain checks if a domain has issues indicating possible hijacking
func (b *BLHAnalyzer) checkDomain(ctx context.Context, domain string) (*models.BLHCandidate, error) {
	candidate := &models.BLHCandidate{
		ID:               uuid.New().String(),
		ReferencedDomain: domain,
		ResolutionStatus: "checking",
	}

	// DNS lookup
	ips, err := net.LookupIP(domain)
	if err != nil {
		candidate.ResolutionStatus = "nxdomain"
		candidate.RiskLevel = "critical"
		candidate.CloudProvider = "unknown"
		return candidate, nil
	}

	if len(ips) == 0 {
		candidate.ResolutionStatus = "unreachable"
		candidate.RiskLevel = "medium"
		return candidate, nil
	}

	// Check if it's a known cloud provider
	cloudPatterns := map[string]*regexp.Regexp{
		"S3":     regexp.MustCompile(`s3[\w-]*amazonaws\.com`),
		"Azure":  regexp.MustCompile(`blob\.core\.windows\.net|azurewebsites\.net`),
		"GitHub": regexp.MustCompile(`raw\.githubusercontent\.com|github\.io`),
	}
	for provider, pattern := range cloudPatterns {
		if pattern.MatchString(domain) {
			candidate.CloudProvider = provider
			break
		}
	}

	// HTTP check
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+domain+"/", nil)
	if err != nil {
		return candidate, err
	}
	req.Header.Set("User-Agent", "Hustler/1.0 (Bug Bounty Automation)")

	resp, err := b.client.Do(req)
	if err != nil {
		candidate.ResolutionStatus = "http_error"
		candidate.Evidence = err.Error()
		return candidate, nil
	}
	defer resp.Body.Close()

	// Check for unclaimed bucket patterns
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	bodyStr := string(body)

	switch {
	case strings.Contains(bodyStr, "NoSuchBucket"):
		candidate.ResolutionStatus = "unclaimed_s3"
		candidate.RiskLevel = "critical"
		candidate.Evidence = "S3 bucket appears unclaimed"
	case strings.Contains(bodyStr, "404") && strings.Contains(domain, "github.io"):
		candidate.ResolutionStatus = "github_pages_missing"
		candidate.RiskLevel = "high"
		candidate.Evidence = "GitHub Pages 404 pattern"
	case resp.StatusCode == 404:
		candidate.ResolutionStatus = "missing"
		candidate.RiskLevel = "medium"
	default:
		candidate.ResolutionStatus = "resolved"
		candidate.RiskLevel = "low"
	}

	return candidate, nil
}

// AnalyzeBLH runs broken link hijacking checks on external domains from JS
func (b *BLHAnalyzer) AnalyzeBLH(ctx context.Context, target *models.Target, jsFiles []*models.JSFile, contentMap map[string]string) ([]models.BLHCandidate, error) {
	var allCandidates []models.BLHCandidate
	seen := make(map[string]bool)

	for _, jsFile := range jsFiles {
		content := contentMap[jsFile.URL]
		if content == "" {
			continue
		}

		domains := b.extractDomains(content, jsFile.URL)
		for _, domain := range domains {
			if seen[domain] {
				continue
			}
			seen[domain] = true

			candidate, err := b.checkDomain(ctx, domain)
			if err != nil {
				log.Warn().Err(err).Str("domain", domain).Msg("Failed to check domain")
				continue
			}

			candidate.TargetID = target.ID
			candidate.JSFileID = jsFile.ID
			candidate.FoundAt = time.Now()
			allCandidates = append(allCandidates, *candidate)
		}
	}

	// Store in MongoDB
	if len(allCandidates) > 0 {
		coll := mongo.GetCollection("blh_candidates")
		docs := make([]interface{}, len(allCandidates))
		for i, c := range allCandidates {
			docs[i] = c
		}
		_, err := coll.InsertMany(ctx, docs)
		if err != nil {
			log.Error().Err(err).Msg("Failed to store BLH candidates")
			return allCandidates, err
		}
		log.Info().Int("count", len(allCandidates)).Str("target", target.Domain).Msg("BLH candidates stored")
	}

	return allCandidates, nil
}