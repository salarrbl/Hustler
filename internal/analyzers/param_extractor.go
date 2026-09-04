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

// ParamExtractor extracts parameter names from JS content
type ParamExtractor struct{}

// NewParamExtractor creates a new param extractor
func NewParamExtractor() *ParamExtractor {
	return &ParamExtractor{}
}

// param patterns
var paramPatterns = []*regexp.Regexp{
	// Query string params
	regexp.MustCompile(`(?:URLSearchParams|new\s+URL|location\.search)\s*[^;]*\.get\s*\(\s*['"]([a-zA-Z0-9_]+)['"]\s*\)`),
	regexp.MustCompile(`['"]([a-zA-Z0-9_]+)=['"]\s*\?\s*['"]([^'"]+)['"]`),
	// Form fields
	regexp.MustCompile(`(?:name|id)\s*[:=]\s*['"]([a-zA-Z0-9_]+)['"]`),
	// fetch/axios body params
	regexp.MustCompile(`(?:fetch|axios|post)\s*\(.*?\{[^}]*["']([a-zA-Z0-9_]+)["']\s*:`),
	// Object property access
	regexp.MustCompile(`(?:req|request|data|body|params|query)\s*\.([a-zA-Z0-9_]+)`),
}

// ExtractParams scans JS content for parameter names
func (p *ParamExtractor) ExtractParams(ctx context.Context, target *models.Target, jsFile *models.JSFile, content string, foundIn string) ([]models.Param, error) {
	var params []models.Param
	seen := make(map[string]bool)
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		lineNum++ // 1-indexed

		for _, pattern := range paramPatterns {
			matches := pattern.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) < 2 {
					continue
				}
				paramName := match[1]

				// Skip if too short or common non-param string
				if len(paramName) < 2 || isCommonWord(paramName) {
					continue
				}

				// Dedupe
				key := paramName + "|" + line
				if seen[key] {
					continue
				}
				seen[key] = true

				contextType := p.deduceContext(line, paramName)

				param := models.Param{
								ID:        uuid.New().String(),
								TargetID:  target.ID,
								JSFileID:  jsFile.ID,
								ParamName: paramName,
								Context:   contextType,
								Location:  contextType,
								FoundIn:   foundIn,
								FoundAt:   time.Now(),
							}
				params = append(params, param)
			}
		}
	}

	// Store in MongoDB
	if len(params) > 0 {
		coll := mongo.GetCollection("params")
		docs := make([]interface{}, len(params))
		for i, pm := range params {
			docs[i] = pm
		}
		_, err := coll.InsertMany(ctx, docs)
		if err != nil {
			log.Error().Err(err).Msg("Failed to store params")
			return params, err
		}
		log.Info().Int("count", len(params)).Str("target", target.Domain).Str("js_file", jsFile.URL).Msg("Parameters extracted and stored")
	}

	return params, nil
}

// deduceContext tries to determine where the parameter is used
func (p *ParamExtractor) deduceContext(line, paramName string) string {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "query") || strings.Contains(lower, "search") {
		return "query"
	}
	if strings.Contains(lower, "form") || strings.Contains(lower, "submit") {
		return "form"
	}
	if strings.Contains(lower, "header") || strings.Contains(lower, "headers") {
		return "header"
	}
	if strings.Contains(lower, "body") || strings.Contains(lower, "json") {
		return "body"
	}
	return "unknown"
}

// isCommonWord checks if a string is a common word that's unlikely a parameter
func isCommonWord(word string) bool {
	commonWords := []string{"var", "let", "const", "function", "return", "if", "else", "for", "while", "class", "new", "this", "null", "true", "false"}
	for _, w := range commonWords {
		if w == word {
			return true
		}
	}
	return false
}