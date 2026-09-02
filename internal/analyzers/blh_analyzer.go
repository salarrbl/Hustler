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

type BLHAnalyzer struct {
	client         *http.Client
	htmlClient     *http.Client
	denylist       map[string]bool
	targetRootDomain string
}

func NewBLHAnalyzer(httpClient *http.Client) *BLHAnalyzer {
	denylist := map[string]bool{
		"github.com":          true,
		"reactjs.org":         true,
		"nextjs.org":          true,
		"w3.org":              true,
		"schema.org":          true,
		"example.com":         true,
		"aomedia.org":         true,
		"web.dev":             true,
		"developer.mozilla.org": true,
		"nodejs.org":          true,
		"webpack.js.org":      true,
		"babeljs.io":          true,
		"eslint.org":          true,
		"typescriptlang.org":  true,
		"redux.js.org":        true,
		"vuejs.org":           true,
		"angular.io":          true,
		"svelte.dev":          true,
		"tailwindcss.com":     true,
		"jestjs.io":           true,
		"vitest.dev":          true,
		"playwright.dev":      true,
		"cypress.io":          true,
		"storybook.js.org":    true,
		"chromium.org":        true,
		"mozilla.org":         true,
		"webkit.org":          true,
		"khronos.org":         true,
		"ecma-international.org": true,
		"whatwg.org":          true,
		"tc39.es":             true,
		"unicode.org":         true,
		"iana.org":            true,
		"ietf.org":            true,
		"rfc-editor.org":      true,
		"openid.net":          true,
		"oauth.net":           true,
		"jwt.io":              true,
		"oauth2.net":          true,
		"openid-foundation.org": true,
		"fidoalliance.org":    true,
		"w3c.github.io":       true,
		"whatwg.github.io":    true,
		"tc39.github.io":      true,
		"github.io":           true, // GitHub Pages often referenced in docs
	}

	return &BLHAnalyzer{
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		htmlClient: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		denylist: denylist,
	}
}

func (b *BLHAnalyzer) SetTargetRootDomain(domain string) {
	b.targetRootDomain = b.extractRootDomain(domain)
}

func (b *BLHAnalyzer) extractRootDomain(domain string) string {
	// Strip to registrable domain (e.g., wallet.basalam.com -> basalam.com)
	// Simple heuristic: take last two labels for common TLDs
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		// Check for known multi-label TLDs
		twoLabelTLDs := map[string]bool{
			"co.uk": true, "com.au": true, "co.nz": true, "co.za": true,
			"com.br": true, "com.mx": true, "com.tr": true, "com.tw": true,
			"com.cn": true, "com.hk": true, "com.sg": true, "com.my": true,
			"com.vn": true, "com.ph": true, "com.pk": true, "com.bd": true,
			"org.uk": true, "org.au": true, "org.nz": true, "org.za": true,
			"net.au": true, "net.nz": true, "gov.uk": true, "gov.au": true,
			"edu.au": true, "ac.uk": true, "ac.nz": true, "ac.za": true,
			"mil.nz": true, "ne.jp": true, "or.jp": true, "ac.jp": true,
			"co.jp": true, "com.cn": true, "net.cn": true, "org.cn": true,
			"gov.cn": true, "mil.cn": true, "co.kr": true, "or.kr": true,
			"ne.kr": true, "re.kr": true, "pe.kr": true, "seoul.kr": true,
			"go.jp": true, "lg.jp": true, "ed.jp": true, "ac.th": true,
			"co.th": true, "or.th": true, "go.th": true, "mi.th": true,
			"co.id": true, "or.id": true, "ac.id": true, "sch.id": true,
			"web.id": true, "my.id": true, "biz.id": true, "co.in": true,
			"firm.in": true, "gen.in": true, "ind.in": true, "net.in": true,
			"org.in": true, "co.il": true, "org.il": true, "net.il": true,
			"ac.il": true, "co.za": true, "org.za": true, "net.za": true,
			"co.zw": true, "org.zw": true, "ac.zw": true, "gov.zw": true,
			"co.ve": true, "org.ve": true, "net.ve": true, "co.za": true,
		}
		if len(parts) >= 3 {
			lastTwo := parts[len(parts)-2] + "." + parts[len(parts)-1]
			if twoLabelTLDs[lastTwo] {
				return strings.Join(parts[len(parts)-3:], ".")
			}
		}
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}

func (b *BLHAnalyzer) isValidDomain(domain string) bool {
	if domain == "" {
		return false
	}
	// Reject domains with invalid characters
	if strings.ContainsAny(domain, "\"' \t\n\r") {
		return false
	}
	// Must have at least one dot (FQDN)
	if !strings.Contains(domain, ".") {
		return false
	}
	// Each label must be valid
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		// Label must start and end with alphanumeric, can contain hyphens in middle
		if !regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`).MatchString(label) {
			return false
		}
	}
	// Reject if it looks like a URL fragment or malformed
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	return true
}

func (b *BLHAnalyzer) isDenylisted(domain string) bool {
	lower := strings.ToLower(domain)
	// Check exact match
	if b.denylist[lower] {
		return true
	}
	// Check if it's a subdomain of a denylisted domain
	for d := range b.denylist {
		if strings.HasSuffix(lower, "."+d) {
			return true
		}
	}
	return false
}

func (b *BLHAnalyzer) isTargetSubdomain(domain string) bool {
	if b.targetRootDomain == "" {
		return false
	}
	lower := strings.ToLower(domain)
	root := strings.ToLower(b.targetRootDomain)
	return lower == root || strings.HasSuffix(lower, "."+root)
}

func (b *BLHAnalyzer) extractDomains(content string, baseURL string) []string {
	patterns := []*regexp.Regexp{
		// script src, link href, img src, iframe src, form action
		regexp.MustCompile(`(?i)(?:src|href|action)\s*=\s*["']([^"']*://[^"']+)["']`),
		// meta tags, etc.
		regexp.MustCompile(`(?i)content\s*=\s*["']([^"']*://[^"']+)["']`),
		// Full URLs in text (but not in quotes - those are caught above)
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
			// Split by / and take host part
			match = strings.Split(match, "/")[0]
			match = strings.Split(match, ":")[0] // remove port
			match = strings.ToLower(match) // Case-insensitive dedup
			if match != "" && match != baseHost && b.isValidDomain(match) {
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
	return strings.ToLower(parsed.Hostname())
}

func (b *BLHAnalyzer) checkDomain(ctx context.Context, domain string, foundIn string) (*models.BLHCandidate, error) {
	candidate := &models.BLHCandidate{
		ID:               uuid.New().String(),
		ReferencedDomain: domain,
		ResolutionStatus: "checking",
		FoundIn:          foundIn,
		IsTargetSubdomain: b.isTargetSubdomain(domain),
	}

	// DNS lookup
	ips, err := net.LookupIP(domain)
	if err != nil {
		candidate.ResolutionStatus = "nxdomain"
		if b.isTargetSubdomain(domain) {
			candidate.RiskLevel = "info" // Target's own subdomain, not takeover
			candidate.Evidence = "Target subdomain - NXDOMAIN (may be unrouted service)"
		} else {
			candidate.RiskLevel = "critical"
			candidate.Evidence = "NXDOMAIN - domain can be registered"
		}
		candidate.CloudProvider = "unknown"
		return candidate, nil
	}

	if len(ips) == 0 {
		candidate.ResolutionStatus = "unreachable"
		if b.isTargetSubdomain(domain) {
			candidate.RiskLevel = "info"
			candidate.Evidence = "Target subdomain - no IP addresses"
		} else {
			candidate.RiskLevel = "medium"
			candidate.Evidence = "No IP addresses resolved"
		}
		return candidate, nil
	}

	// Check if it's a known cloud provider
	cloudPatterns := map[string]*regexp.Regexp{
		"S3":      regexp.MustCompile(`s3[\w-]*amazonaws\.com`),
		"Azure":   regexp.MustCompile(`blob\.core\.windows\.net|azurewebsites\.net|cloudapp\.net|trafficmanager\.net|azureedge\.net`),
		"GitHub":  regexp.MustCompile(`raw\.githubusercontent\.com|github\.io`),
		"Heroku":  regexp.MustCompile(`herokuapp\.com|herokudns\.com|herokussl\.com`),
		"Shopify": regexp.MustCompile(`myshopify\.com`),
		"Fastly":  regexp.MustCompile(`fastly\.net`),
		"Netlify": regexp.MustCompile(`netlify\.app|netlify\.com`),
		"Vercel":  regexp.MustCompile(`vercel\.app|now\.sh`),
		"Cloudflare": regexp.MustCompile(`cloudflare\.com|cloudflareinsights\.com`),
	}
	for provider, pattern := range cloudPatterns {
		if pattern.MatchString(domain) {
			candidate.CloudProvider = provider
			break
		}
	}

	// HTTP check with Host header for accurate takeover testing
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+domain+"/", nil)
	if err != nil {
		return candidate, err
	}
	req.Header.Set("User-Agent", "Hustler/1.0 (Bug Bounty Automation - BLH Check)")
	req.Host = domain // Important: test with correct Host header

	resp, err := b.client.Do(req)
	if err != nil {
		candidate.ResolutionStatus = "http_error"
		candidate.Evidence = err.Error()
		if b.isTargetSubdomain(domain) {
			candidate.RiskLevel = "info"
		} else {
			candidate.RiskLevel = "medium"
		}
		return candidate, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	bodyStr := string(body)

	// Check for unclaimed patterns
	switch {
	case strings.Contains(bodyStr, "NoSuchBucket"):
		candidate.ResolutionStatus = "unclaimed_s3"
		if b.isTargetSubdomain(domain) {
			candidate.RiskLevel = "info"
			candidate.Evidence = "Target subdomain pointing to S3 (internal config)"
		} else {
			candidate.RiskLevel = "critical"
			candidate.Evidence = "S3 bucket appears unclaimed"
		}
	case strings.Contains(bodyStr, "There isn't a GitHub Pages site here") || 
		(strings.Contains(bodyStr, "404") && strings.Contains(domain, "github.io")):
		candidate.ResolutionStatus = "github_pages_missing"
		if b.isTargetSubdomain(domain) {
			candidate.RiskLevel = "info"
			candidate.Evidence = "Target subdomain - GitHub Pages 404"
		} else {
			candidate.RiskLevel = "high"
			candidate.Evidence = "GitHub Pages 404 pattern"
		}
	case strings.Contains(bodyStr, "No such app") && strings.Contains(domain, "heroku"):
		candidate.ResolutionStatus = "heroku_missing"
		if b.isTargetSubdomain(domain) {
			candidate.RiskLevel = "info"
		} else {
			candidate.RiskLevel = "high"
		}
		candidate.Evidence = "Heroku app not found"
	case strings.Contains(bodyStr, "Sorry, this shop is currently unavailable") && strings.Contains(domain, "myshopify.com"):
		candidate.ResolutionStatus = "shopify_missing"
		if b.isTargetSubdomain(domain) {
			candidate.RiskLevel = "info"
		} else {
			candidate.RiskLevel = "high"
		}
		candidate.Evidence = "Shopify store unavailable"
	case strings.Contains(bodyStr, "project not found") && strings.Contains(domain, "surge.sh"):
		candidate.ResolutionStatus = "surge_missing"
		if b.isTargetSubdomain(domain) {
			candidate.RiskLevel = "info"
		} else {
			candidate.RiskLevel = "medium"
		}
		candidate.Evidence = "Surge.sh project not found"
	case strings.Contains(bodyStr, "Not Found - Request ID") && strings.Contains(domain, "netlify"):
		candidate.ResolutionStatus = "netlify_missing"
		if b.isTargetSubdomain(domain) {
			candidate.RiskLevel = "info"
		} else {
			candidate.RiskLevel = "medium"
		}
		candidate.Evidence = "Netlify site not found"
	case strings.Contains(bodyStr, "404 Web Site not found") && (strings.Contains(domain, "azurewebsites.net") || strings.Contains(domain, "cloudapp.net")):
		candidate.ResolutionStatus = "azure_missing"
		if b.isTargetSubdomain(domain) {
			candidate.RiskLevel = "info"
		} else {
			candidate.RiskLevel = "high"
		}
		candidate.Evidence = "Azure Web App 404 pattern"
	case resp.StatusCode == 404:
		candidate.ResolutionStatus = "missing"
		if b.isTargetSubdomain(domain) {
			candidate.RiskLevel = "info"
			candidate.Evidence = "Target subdomain returns 404 (unrouted or missing)"
		} else {
			candidate.RiskLevel = "medium"
			candidate.Evidence = "HTTP 404 - resource not found"
		}
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		candidate.ResolutionStatus = "http_error"
		if b.isTargetSubdomain(domain) {
			candidate.RiskLevel = "info"
		} else {
			candidate.RiskLevel = "low"
		}
		candidate.Evidence = "HTTP " + httpStatusText(resp.StatusCode)
	default:
		candidate.ResolutionStatus = "resolved"
		if b.isTargetSubdomain(domain) {
			candidate.RiskLevel = "info"
			candidate.Evidence = "Target subdomain - active and responding"
		} else {
			candidate.RiskLevel = "low"
		}
	}

	return candidate, nil
}

func httpStatusText(code int) string {
	switch code {
	case 400: return "Bad Request"
	case 401: return "Unauthorized"
	case 403: return "Forbidden"
	case 404: return "Not Found"
	case 429: return "Too Many Requests"
	case 500: return "Internal Server Error"
	case 502: return "Bad Gateway"
	case 503: return "Service Unavailable"
	case 504: return "Gateway Timeout"
	default: return "Error"
	}
}

func (b *BLHAnalyzer) AnalyzeBLH(ctx context.Context, target *models.Target, jsFiles []*models.JSFile, contentMap map[string]string, htmlContents map[string]string) ([]models.BLHCandidate, error) {
	var allCandidates []models.BLHCandidate
	seen := make(map[string]bool)

	// Set target root domain for subdomain detection
	b.SetTargetRootDomain(target.Domain)

	// 1. Analyze JS files
	for _, jsFile := range jsFiles {
		content := contentMap[jsFile.URL]
		if content == "" {
			continue
		}

		domains := b.extractDomains(content, jsFile.URL)
		for _, domain := range domains {
			lower := strings.ToLower(domain)
			if seen[lower] {
				continue
			}
			if b.isDenylisted(domain) {
				log.Debug().Str("domain", domain).Msg("Skipping denylisted domain in BLH")
				continue
			}
			seen[lower] = true

			candidate, err := b.checkDomain(ctx, domain, "js_file")
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

	// 2. Analyze HTML pages
	for pageURL, content := range htmlContents {
		if content == "" {
			continue
		}

		domains := b.extractDomains(content, pageURL)
		for _, domain := range domains {
			lower := strings.ToLower(domain)
			if seen[lower] {
				continue
			}
			if b.isDenylisted(domain) {
				log.Debug().Str("domain", domain).Msg("Skipping denylisted domain in BLH (from HTML)")
				continue
			}
			seen[lower] = true

			candidate, err := b.checkDomain(ctx, domain, "html_page")
			if err != nil {
				log.Warn().Err(err).Str("domain", domain).Msg("Failed to check domain from HTML")
				continue
			}

			candidate.TargetID = target.ID
			// JSFileID will be empty for HTML-sourced findings
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