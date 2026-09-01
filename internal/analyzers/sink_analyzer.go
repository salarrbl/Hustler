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

// SinkAnalyzer performs source/sink analysis using regex patterns
// TODO: Revisit AST-based analysis when goja provides better position tracking
type SinkAnalyzer struct{}

// NewSinkAnalyzer creates a new sink analyzer
func NewSinkAnalyzer() *SinkAnalyzer {
	return &SinkAnalyzer{}
}

// Sink patterns - sink functions/methods that can lead to vulnerabilities
var sinkPatterns = map[string]*regexp.Regexp{
	"eval":              regexp.MustCompile(`\beval\s*\(`),
	"innerHTML":         regexp.MustCompile(`\.innerHTML\s*=`),
	"outerHTML":         regexp.MustCompile(`\.outerHTML\s*=`),
	"document_write":    regexp.MustCompile(`document\.write\s*\(`),
	"document_writeln":  regexp.MustCompile(`document\.writeln\s*\(`),
	"insertAdjacentHTML": regexp.MustCompile(`insertAdjacentHTML\s*\(`),
	"execScript":        regexp.MustCompile(`execScript\s*\(`),
	"setTimeout":        regexp.MustCompile(`setTimeout\s*\(`),
	"setInterval":       regexp.MustCompile(`setInterval\s*\(`),
	"Function":          regexp.MustCompile(`new\s+Function\s*\(`),
	"postMessage":       regexp.MustCompile(`postMessage\s*\(`),
	"location_href":     regexp.MustCompile(`location\.href\s*=`),
	"location_assign":   regexp.MustCompile(`location\.assign\s*\(`),
	"location_replace":  regexp.MustCompile(`location\.replace\s*\(`),
	"open":              regexp.MustCompile(`window\.open\s*\(`),
}

// Source patterns - sources of user-controlled input
var sourcePatterns = map[string]*regexp.Regexp{
	"url_params":        regexp.MustCompile(`(?:new\s+)?URLSearchParams\s*\(|location\.search|\.search\s*\)`),
	"url_hash":          regexp.MustCompile(`location\.hash`),
	"url_pathname":      regexp.MustCompile(`location\.pathname`),
	"postMessage_data":  regexp.MustCompile(`event\.data|message\.data`),
	"document_referrer": regexp.MustCompile(`document\.referrer`),
	"localStorage":      regexp.MustCompile(`localStorage\.(?:getItem|getAllKeys)`),
	"sessionStorage":    regexp.MustCompile(`sessionStorage\.(?:getItem|getAllKeys)`),
	"cookie":            regexp.MustCompile(`document\.cookie`),
	"input_value":       regexp.MustCompile(`\.(?:value|textContent|innerText)\s*=`),
	"fetch_response":    regexp.MustCompile(`fetch\s*\([^)]+\)\s*\.\s*then\s*\(`),
	"xhr_response":      regexp.MustCompile(`XMLHttpRequest|onreadystatechange|responseText`),
	"axios_response":    regexp.MustCompile(`axios\.(?:get|post|put|delete|patch)\s*\(`),
	"jquery_html":       regexp.MustCompile(`\$\s*\([^)]+\)\s*\.\s*html\s*\(`),
	"jquery_append":     regexp.MustCompile(`\$\s*\([^)]+\)\s*\.\s*append\s*\(`),
}

// Origin check pattern for postMessage
var originCheckPattern = regexp.MustCompile(`(?i)(?:event\.origin|message\.origin)\s*(?:===|==)\s*['\"]`)

// Scan analyzes JS content for source/sink vulnerabilities using regex patterns
func (s *SinkAnalyzer) Scan(ctx context.Context, target *models.Target, jsFile *models.JSFile, content string) ([]models.Sink, error) {
	var sinks []models.Sink
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		lineNum++ // 1-indexed

		// Check for sinks
		for sinkType, pattern := range sinkPatterns {
			matches := pattern.FindAllStringIndex(line, -1)
			for _, match := range matches {
				// Check if any source is nearby (within 10 lines)
				sourceType := s.findNearbySource(lines, lineNum, 10)
				confidence := 0.5
				if sourceType != "" {
					confidence = 0.75
				}

				hasOriginCheck := false
				if sinkType == "postMessage" {
					hasOriginCheck = s.hasOriginCheck(content)
				}

				snippet := s.getSnippet(lines, lineNum, 2)

				sink := models.Sink{
					ID:              uuid.New().String(),
					TargetID:        target.ID,
					JSFileID:        jsFile.ID,
					SinkType:        sinkType,
					SourceType:      sourceType,
					Line:            lineNum,
					Column:          match[0] + 1,
					Snippet:         snippet,
					Confidence:      confidence,
					HasOriginCheck:  hasOriginCheck,
					FoundAt:         time.Now(),
				}
				sinks = append(sinks, sink)
			}
		}
	}

	// Store in MongoDB
	if len(sinks) > 0 {
		coll := mongo.GetCollection("sinks")
		docs := make([]interface{}, len(sinks))
		for i, sk := range sinks {
			docs[i] = sk
		}
		_, err := coll.InsertMany(ctx, docs)
		if err != nil {
			log.Error().Err(err).Msg("Failed to store sinks")
			return sinks, err
		}
		log.Info().Int("count", len(sinks)).Str("target", target.Domain).Str("js_file", jsFile.URL).Msg("Source/sink findings stored")
	}

	return sinks, nil
}

// findNearbySource looks for sources near a line (within radius lines)
func (s *SinkAnalyzer) findNearbySource(lines []string, lineNum, radius int) string {
	start := max(0, lineNum-radius-1)
	end := min(len(lines), lineNum+radius)
	for i := start; i < end; i++ {
		for sourceType, pattern := range sourcePatterns {
			if pattern.MatchString(lines[i]) {
				return sourceType
			}
		}
	}
	return ""
}

// hasOriginCheck checks if postMessage has origin validation
func (s *SinkAnalyzer) hasOriginCheck(content string) bool {
	return originCheckPattern.MatchString(content)
}

// getSnippet gets code snippet around a line
func (s *SinkAnalyzer) getSnippet(lines []string, lineNum, radius int) string {
	start := max(0, lineNum-radius-1)
	end := min(len(lines), lineNum+radius)
	var parts []string
	for i := start; i < end; i++ {
		prefix := "  "
		if i == lineNum-1 {
			prefix = "> "
		}
		parts = append(parts, prefix+lines[i])
	}
	return strings.Join(parts, "\n")
}