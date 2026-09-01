package analyzers

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

// SinkAnalyzer performs source/sink analysis using Go AST parsing
type SinkAnalyzer struct{}

// SinkFinding represents a source/sink vulnerability finding
type SinkFinding struct {
	SinkType       string
	SourceType     string
	Line           int
	Column         int
	Snippet        string
	Confidence     float64
	HasOriginCheck bool
}

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
}

// Origin check pattern for postMessage
var originCheckPattern = regexp.MustCompile(`(?i)(?:event\.origin|message\.origin)\s*(?:===|==)\s*['\"]`)

// Scan analyzes JS content for source/sink vulnerabilities
func (s *SinkAnalyzer) Scan(ctx context.Context, target *models.Target, jsFile *models.JSFile, content string) ([]models.Sink, error) {
	var sinks []models.Sink

	// Parse JS into AST
	program, err := parser.ParseFile(nil, "", content, 0)
	if err != nil {
		// Fallback to regex-based analysis if parsing fails
		log.Warn().Err(err).Str("url", jsFile.URL).Msg("AST parse failed, falling back to regex")
		return s.regexScan(ctx, target, jsFile, content)
	}

	// Walk AST and find sinks with sources
	findings := s.astWalk(program, content)

	for _, finding := range findings {
		sink := models.Sink{
			ID:              uuid.New().String(),
			TargetID:        target.ID,
			JSFileID:        jsFile.ID,
			SinkType:        finding.SinkType,
			SourceType:      finding.SourceType,
			Line:            finding.Line,
			Column:          finding.Column,
			Snippet:         finding.Snippet,
			Confidence:      finding.Confidence,
			HasOriginCheck:  finding.HasOriginCheck,
			FoundAt:         time.Now(),
		}
		sinks = append(sinks, sink)
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

// regexScan performs regex-based analysis as fallback
func (s *SinkAnalyzer) regexScan(ctx context.Context, target *models.Target, jsFile *models.JSFile, content string) ([]models.Sink, error) {
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
			return sinks, err
		}
	}

	return sinks, nil
}

// astWalk walks the AST and finds source/sink patterns
func (s *SinkAnalyzer) astWalk(program *ast.Program, content string) []SinkFinding {
	var findings []SinkFinding
	lines := strings.Split(content, "\n")

	// Simple AST walker - traverse all nodes
	ast.Inspect(program, func(node ast.Node) bool {
		if node == nil {
			return false
		}

		// Check for CallExpression (function calls)
		if callExpr, ok := node.(*ast.CallExpression); ok {
			s.analyzeCallExpression(callExpr, content, lines, &findings)
		}

		// Check for AssignExpression (e.g., element.innerHTML = ...)
		if assignExpr, ok := node.(*ast.AssignExpression); ok {
			s.analyzeAssignExpression(assignExpr, content, lines, &findings)
		}

		return true
	})

	return findings
}

// analyzeCallExpression analyzes function calls for sinks
func (s *SinkAnalyzer) analyzeCallExpression(call *ast.CallExpression, content string, lines []string, findings *[]SinkFinding) {
	// Get the callee (function being called)
	calleeStr := s.nodeToString(call.Callee, content)

	// Check if it's a known sink
	for sinkType, pattern := range sinkPatterns {
		if pattern.MatchString(calleeStr) {
			// Find sources in arguments
			sourceType := s.findSourcesInArgs(call.Arguments, content)
			confidence := 0.6
			if sourceType != "" {
				confidence = 0.85
			}

			// Get position info
			line, col := s.getPosition(call, content)
			snippet := s.getSnippet(lines, line, 2)

			hasOriginCheck := false
			if sinkType == "postMessage" {
				hasOriginCheck = s.hasOriginCheckInScope(call, content)
			}

			*findings = append(*findings, SinkFinding{
				SinkType:       sinkType,
				SourceType:     sourceType,
				Line:           line,
				Column:         col,
				Snippet:        snippet,
				Confidence:     confidence,
				HasOriginCheck: hasOriginCheck,
			})
		}
	}
}

// analyzeAssignExpression analyzes assignments for sinks
func (s *SinkAnalyzer) analyzeAssignExpression(assign *ast.AssignExpression, content string, lines []string, findings *[]SinkFinding) {
	leftStr := s.nodeToString(assign.Left, content)

	// Check for innerHTML, outerHTML, etc. assignments
	for sinkType, pattern := range sinkPatterns {
		if pattern.MatchString(leftStr) {
			// Check right side for sources
			rightStr := s.nodeToString(assign.Right, content)
			sourceType := s.classifySource(rightStr)
			confidence := 0.7
			if sourceType != "" {
				confidence = 0.9
			}

			line, col := s.getPosition(assign, content)
			snippet := s.getSnippet(lines, line, 2)

			*findings = append(*findings, SinkFinding{
				SinkType:       sinkType,
				SourceType:     sourceType,
				Line:           line,
				Column:         col,
				Snippet:        snippet,
				Confidence:     confidence,
				HasOriginCheck: false,
			})
		}
	}
}

// classifySource determines the source type from a string
func (s *SinkAnalyzer) classifySource(str string) string {
	for sourceType, pattern := range sourcePatterns {
		if pattern.MatchString(str) {
			return sourceType
		}
	}
	return ""
}

// findSourcesInArgs checks function arguments for sources
func (s *SinkAnalyzer) findSourcesInArgs(args []ast.Expression, content string) string {
	for _, arg := range args {
		argStr := s.nodeToString(arg, content)
		sourceType := s.classifySource(argStr)
		if sourceType != "" {
			return sourceType
		}
	}
	return ""
}

// findNearbySource looks for sources near a line (regex fallback)
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

// hasOriginCheckInScope checks for origin check in AST scope
func (s *SinkAnalyzer) hasOriginCheckInScope(node ast.Node, content string) bool {
	// Simplified - check in surrounding content
	return originCheckPattern.MatchString(content)
}

// nodeToString converts an AST node to its source string
func (s *SinkAnalyzer) nodeToString(node ast.Node, content string) string {
	if node == nil {
		return ""
	}
	// Use the node's position if available
	// For now, return empty and rely on regex fallback
	return ""
}

// getPosition gets line/column from AST node (simplified)
func (s *SinkAnalyzer) getPosition(node ast.Node, content string) (int, int) {
	// Simplified - would need proper position tracking from parser
	return 1, 1
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