package analyzers

import (
	"context"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"hustler/internal/config"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// SecretScanner scans JS content for secrets using regex patterns and entropy analysis
type SecretScanner struct {
	cfg       config.JSConfig
	patterns  []SecretPattern
	// Patterns that are generic high-entropy catch-alls (not anchored to keywords)
	genericPatterns map[string]bool
}

// SecretPattern defines a regex pattern for secret detection
type SecretPattern struct {
	Name        string
	Regex       *regexp.Regexp
	Description string
	HighConf    bool // high confidence patterns (API keys, etc.)
	IsGeneric   bool // true for generic entropy patterns (high_entropy_string, base64_string)
}

// NewSecretScanner creates a new secret scanner with comprehensive regex bank
func NewSecretScanner(cfg config.JSConfig) *SecretScanner {
	patterns := []SecretPattern{
		// AWS
		{Name: "aws_access_key_id", Regex: regexp.MustCompile(`(?i)(?:aws|amazon)[_\s-]?(?:access[_\\s-]?key[_\\s-]?id|secret[_\\s-]?access[_\\s-]?key)\s*[:=]\s*['\"]?([A-Z0-9]{20})['\"]?`), Description: "AWS Access Key ID", HighConf: true, IsGeneric: false},
		{Name: "aws_secret_access_key", Regex: regexp.MustCompile(`(?i)(?:aws|amazon)[_\s-]?secret[_\\s-]?access[_\\s-]?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?`), Description: "AWS Secret Access Key", HighConf: true, IsGeneric: false},
		{Name: "aws_session_token", Regex: regexp.MustCompile(`(?i)aws[_\\s-]?session[_\\s-]?token\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?`), Description: "AWS Session Token", HighConf: true, IsGeneric: false},

		// Generic API Keys
		{Name: "generic_api_key", Regex: regexp.MustCompile(`(?i)(?:api[_\\s-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?`), Description: "Generic API Key", HighConf: false, IsGeneric: false},
		{Name: "generic_secret", Regex: regexp.MustCompile(`(?i)(?:secret|secret[_\\s-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?`), Description: "Generic Secret", HighConf: false, IsGeneric: false},

		// Heroku
		{Name: "heroku_api_key", Regex: regexp.MustCompile(`(?i)heroku[_\\s-]?api[_\\s-]?key\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?`), Description: "Heroku API Key", HighConf: true, IsGeneric: false},

		// Slack
		{Name: "slack_token", Regex: regexp.MustCompile(`(?i)xox[baprs]-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-z0-9]{32}`), Description: "Slack Token", HighConf: true, IsGeneric: false},
		{Name: "slack_webhook", Regex: regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[a-zA-Z0-9]{24}`), Description: "Slack Webhook URL", HighConf: true, IsGeneric: false},

		// Firebase
		{Name: "firebase_config", Regex: regexp.MustCompile(`(?i)firebase[_\\s-]?config\s*[:=]\s*\{[^}]*apiKey\s*[:=]\s*['\"]([A-Za-z0-9_\-]{30,})['\"]`), Description: "Firebase Config", HighConf: true, IsGeneric: false},
		{Name: "firebase_database_url", Regex: regexp.MustCompile(`https://[a-z0-9\-]+\.firebaseio\.com`), Description: "Firebase Database URL", HighConf: false, IsGeneric: false},

		// GCP
		{Name: "gcp_api_key", Regex: regexp.MustCompile(`(?i)gcp[_\\s-]?api[_\\s-]?key\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{30,})['\"]?`), Description: "GCP API Key", HighConf: true, IsGeneric: false},
		{Name: "gcp_service_account", Regex: regexp.MustCompile(`"type"\s*:\s*"service_account"`), Description: "GCP Service Account JSON", HighConf: true, IsGeneric: false},

		// Swagger/OpenAPI
		{Name: "swagger_json", Regex: regexp.MustCompile(`(?i)(?:swagger|openapi)\s*[:=]\s*['\"]?[0-9]+\.[0-9]+\.[0-9]+['\"]?`), Description: "Swagger/OpenAPI Version", HighConf: false, IsGeneric: false},
		{Name: "swagger_spec_url", Regex: regexp.MustCompile(`https?://[^/]+/(?:swagger|openapi|api-docs)\.json`), Description: "Swagger Spec URL", HighConf: false, IsGeneric: false},

		// Database Connection Strings
		{Name: "jdbc_url", Regex: regexp.MustCompile(`jdbc:(?:mysql|postgresql|oracle|sqlserver|mariadb)://[^/\s]+/[^\s"']+`), Description: "JDBC Connection URL", HighConf: true, IsGeneric: false},
		{Name: "mongodb_uri", Regex: regexp.MustCompile(`mongodb(?:\+srv)?://[^/\s]+/[^\s"']+`), Description: "MongoDB Connection URI", HighConf: true, IsGeneric: false},
		{Name: "redis_url", Regex: regexp.MustCompile(`redis://[^/\s]+`), Description: "Redis Connection URL", HighConf: true, IsGeneric: false},
		{Name: "postgres_url", Regex: regexp.MustCompile(`postgres(?:ql)?://[^/\s]+`), Description: "PostgreSQL Connection URL", HighConf: true, IsGeneric: false},
		{Name: "mysql_url", Regex: regexp.MustCompile(`mysql://[^/\s]+`), Description: "MySQL Connection URL", HighConf: true, IsGeneric: false},

		// Config/Admin/PWD patterns
		{Name: "password_in_code", Regex: regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{8,})['"]`), Description: "Hardcoded Password", HighConf: false, IsGeneric: false},
		{Name: "admin_password", Regex: regexp.MustCompile(`(?i)admin[_\\s-]?password\s*[:=]\s*['"]([^'"]{4,})['"]`), Description: "Admin Password", HighConf: false, IsGeneric: false},
		{Name: "config_password", Regex: regexp.MustCompile(`(?i)config[_\\s-]?password\s*[:=]\s*['"]([^'"]{4,})['"]`), Description: "Config Password", HighConf: false, IsGeneric: false},

		// JSON secrets
		{Name: "json_api_key", Regex: regexp.MustCompile(`"api[_\\s-]?key"\s*:\s*"([^"]{20,})"`), Description: "JSON API Key", HighConf: false, IsGeneric: false},
		{Name: "json_secret", Regex: regexp.MustCompile(`"secret"\s*:\s*"([^"]{20,})"`), Description: "JSON Secret", HighConf: false, IsGeneric: false},
		{Name: "json_token", Regex: regexp.MustCompile(`"token"\s*:\s*"([^"]{20,})"`), Description: "JSON Token", HighConf: false, IsGeneric: false},

		// OAuth / Tokens
		{Name: "oauth_token", Regex: regexp.MustCompile(`(?i)oauth[_\\s-]?token\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?`), Description: "OAuth Token", HighConf: true, IsGeneric: false},
		{Name: "bearer_token", Regex: regexp.MustCompile(`(?i)bearer\s+([A-Za-z0-9_\-\.]{20,})`), Description: "Bearer Token", HighConf: true, IsGeneric: false},
		{Name: "access_token", Regex: regexp.MustCompile(`(?i)access[_\\s-]?token\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?`), Description: "Access Token", HighConf: true, IsGeneric: false},
		{Name: "refresh_token", Regex: regexp.MustCompile(`(?i)refresh[_\\s-]?token\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?`), Description: "Refresh Token", HighConf: true, IsGeneric: false},
		{Name: "jwt_token", Regex: regexp.MustCompile(`eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`), Description: "JWT Token", HighConf: true, IsGeneric: false},

		// .htaccess / .env / SSH
		{Name: "htaccess_auth", Regex: regexp.MustCompile(`(?i)authuserfile\s+[^\s]+`), Description: ".htaccess Auth", HighConf: false, IsGeneric: false},
		{Name: "env_file", Regex: regexp.MustCompile(`(?i)^[A-Z_][A-Z0-9_]*\s*=\s*['\"]?[^'"]{8,}['\"]?`), Description: ".env File Pattern", HighConf: false, IsGeneric: false},
		{Name: "ssh_private_key", Regex: regexp.MustCompile(`-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`), Description: "SSH Private Key", HighConf: true, IsGeneric: false},
		{Name: "ssh_public_key", Regex: regexp.MustCompile(`ssh-(?:rsa|dss|ed25519)\s+[A-Za-z0-9+/]+[=]{0,2}`), Description: "SSH Public Key", HighConf: false, IsGeneric: false},
		{Name: "git_credentials", Regex: regexp.MustCompile(`https?://[^:]+:[^@]+@github\.com`), Description: "Git Credentials in URL", HighConf: true, IsGeneric: false},

		// Generic high-entropy strings (will be filtered by entropy threshold AND keyword proximity)
		{Name: "high_entropy_string", Regex: regexp.MustCompile(`['\"]([A-Za-z0-9/+=]{30,})['\"]`), Description: "High Entropy String", HighConf: false, IsGeneric: true},
		{Name: "base64_string", Regex: regexp.MustCompile(`['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]`), Description: "Base64 Encoded String", HighConf: false, IsGeneric: true},
	}

	genericPatterns := map[string]bool{
		"high_entropy_string": true,
		"base64_string":       true,
	}

	return &SecretScanner{
		cfg:             cfg,
		patterns:        patterns,
		genericPatterns: genericPatterns,
	}
}

// Scan scans JS content for secrets and stores findings
func (s *SecretScanner) Scan(ctx context.Context, target *models.Target, jsFile *models.JSFile, content string) ([]models.Secret, error) {
	var secrets []models.Secret
	lines := strings.Split(content, "\n")

	// Detect if file is minified (few lines but large, or very long average line length)
	isMinified := s.isMinifiedFile(content, lines)

	// Pre-compute keyword lines for proximity check
	keywordLines := s.findKeywordLines(lines)

	for lineNum, line := range lines {
		lineNum++ // 1-indexed
		for _, pattern := range s.patterns {
			matches := pattern.Regex.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) < 2 {
					continue
				}
				matched := match[1]

				// Calculate entropy
				entropy := s.calculateEntropy(matched)

				// For generic patterns, apply additional filtering
				if pattern.IsGeneric {
					// 1. Skip if entropy below raised threshold for generic patterns
					genericThreshold := s.cfg.EntropyThreshold + 1.0 // e.g., 3.5 -> 4.5
					if entropy < genericThreshold {
						continue
					}

					// 2. Skip webpack/build artifacts: hex strings of exactly 8, 16, 20 chars
					if s.isBuildArtifact(matched) {
						continue
					}

					// 3. Skip CSS-module class hash patterns: _[a-zA-Z0-9]{5,8}$
					if s.isCSSModuleHash(matched) {
						continue
					}

					// 4. Require keyword proximity for generic patterns (within 5 lines)
					if !s.hasKeywordProximity(keywordLines, lineNum, 5) {
						continue
					}
				}

				// Determine confidence
				confidence := s.calculateConfidence(pattern, entropy, matched)

				// Skip if confidence too low (unless high confidence pattern)
				if !pattern.HighConf && confidence < 0.3 {
					continue
				}

				// Redact matched string for storage (keep first 4 + last 4 chars)
				redacted := s.redactString(matched)

				secret := models.Secret{
					ID:         uuid.New().String(),
					TargetID:   target.ID,
					JSFileID:   jsFile.ID,
					Pattern:    pattern.Name,
					Matched:    redacted,
					Line:       lineNum,
					Column:     strings.Index(line, matched) + 1,
					Entropy:    entropy,
					Confidence: confidence,
					Context:    s.getContext(line, matched),
					FoundAt:    time.Now(),
					IsMinified: isMinified,
				}

				secrets = append(secrets, secret)
			}
		}
	}

	// Store in MongoDB
	if len(secrets) > 0 {
		coll := mongo.GetCollection("secrets")
		docs := make([]interface{}, len(secrets))
		for i, sec := range secrets {
			docs[i] = sec
		}
		_, err := coll.InsertMany(ctx, docs)
		if err != nil {
			log.Error().Err(err).Msg("Failed to store secrets")
			return secrets, err
		}
		log.Info().Int("count", len(secrets)).Str("target", target.Domain).Str("js_file", jsFile.URL).Bool("minified", isMinified).Msg("Secrets found and stored")
	}

	return secrets, nil
}

// isMinifiedFile detects if a JS file is minified (few lines but large, or very long lines)
func (s *SecretScanner) isMinifiedFile(content string, lines []string) bool {
	if len(lines) < 20 && len(content) > 5000 {
		return true
	}
	// Check average line length
	totalLen := 0
	for _, line := range lines {
		totalLen += len(line)
	}
	if len(lines) > 0 && totalLen/len(lines) > 500 {
		return true
	}
	return false
}

// isBuildArtifact checks if a string looks like a webpack/build artifact
func (s *SecretScanner) isBuildArtifact(matched string) bool {
	// Hex strings of exactly 8, 16, or 20 chars (common chunk-hash lengths)
	hexPattern := regexp.MustCompile(`^[a-fA-F0-9]{8}$|^[a-fA-F0-9]{16}$|^[a-fA-F0-9]{20}$`)
	if hexPattern.MatchString(matched) {
		return true
	}
	return false
}

// isCSSModuleHash checks for CSS-module class hash patterns: _[a-zA-Z0-9]{5,8}$
func (s *SecretScanner) isCSSModuleHash(matched string) bool {
	cssModulePattern := regexp.MustCompile(`_[a-zA-Z0-9]{5,8}$`)
	if cssModulePattern.MatchString(matched) {
		return true
	}
	return false
}

// findKeywordLines finds lines containing secret-related keywords
func (s *SecretScanner) findKeywordLines(lines []string) map[int]bool {
	keywordLines := make(map[int]bool)
	keywords := []string{"key", "token", "secret", "auth", "password", "credential", "apikey", "api_key", "access", "refresh", "private"}
	for i, line := range lines {
		lower := strings.ToLower(line)
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				keywordLines[i+1] = true // 1-indexed
				break
			}
		}
	}
	return keywordLines
}

// hasKeywordProximity checks if there's a keyword line within N lines
func (s *SecretScanner) hasKeywordProximity(keywordLines map[int]bool, lineNum, radius int) bool {
	start := max(1, lineNum-radius)
	end := lineNum + radius
	for l := start; l <= end; l++ {
		if keywordLines[l] {
			return true
		}
	}
	return false
}

// calculateEntropy calculates Shannon entropy of a string
func (s *SecretScanner) calculateEntropy(str string) float64 {
	if len(str) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, r := range str {
		freq[r]++
	}

	entropy := 0.0
	length := float64(len(str))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// calculateConfidence determines confidence score based on pattern type and entropy
func (s *SecretScanner) calculateConfidence(pattern SecretPattern, entropy float64, matched string) float64 {
	baseConf := 0.5
	if pattern.HighConf {
		baseConf = 0.85
	}

	// Boost confidence for high entropy
	if entropy > s.cfg.EntropyThreshold {
		baseConf += 0.15
	} else if entropy < 2.5 {
		baseConf -= 0.2 // Low entropy = likely false positive
	}

	// Boost for known prefixes
	knownPrefixes := []string{"sk_", "pk_", "AKIA", "xoxb-", "xoxp-", "ya29.", "eyJ"}
	for _, prefix := range knownPrefixes {
		if strings.HasPrefix(matched, prefix) {
			baseConf += 0.1
			break
		}
	}

	// Cap at 1.0
	if baseConf > 1.0 {
		baseConf = 1.0
	}
	if baseConf < 0 {
		baseConf = 0
	}

	return baseConf
}

// redactString redacts a string for safe storage
func (s *SecretScanner) redactString(str string) string {
	if len(str) <= 8 {
		return strings.Repeat("*", len(str))
	}
	return str[:4] + strings.Repeat("*", len(str)-8) + str[len(str)-4:]
}

// getContext returns surrounding context for a match
func (s *SecretScanner) getContext(line, matched string) string {
	idx := strings.Index(line, matched)
	if idx == -1 {
		return line
	}
	start := max(0, idx-20)
	end := min(len(line), idx+len(matched)+20)
	return "..." + line[start:end] + "..."
}