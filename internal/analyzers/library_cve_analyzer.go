package analyzers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

// signatures for library fingerprinting
type libSignature struct {
	name string
	re   *regexp.Regexp
}

// LibraryCVEAnalyzer fingerprints JS libraries and checks for known CVEs
type LibraryCVEAnalyzer struct {
	signatures []libSignature
	cveMap     map[string][]LibraryCVE
}

// LibraryCVE represents a CVE match for a library version
type LibraryCVE struct {
	CVEID       string
	Severity    string
	Description string
	Reference   string
}

// NewLibraryCVEAnalyzer creates a new CVE analyzer with known signatures
func NewLibraryCVEAnalyzer() *LibraryCVEAnalyzer {
	// Initialize with some common library signatures (could be loaded from file)
	signatures := []libSignature{
		{"jQuery", regexp.MustCompile(`jquery\s*[:=]\s*['"]([12]\.\d+\.\d+)['"]`)},
		{"jQuery", regexp.MustCompile(`jQuery JavaScript Library v?([12]\.\d+\.\d+)`)},
		{"Bootstrap", regexp.MustCompile(`Bootstrap v?([345]\.\d+\.\d+)`)},
		{"Vue.js", regexp.MustCompile(`Vue.{0,30}version\s*[:=]\s*['"]([\d.]+)['"]`)},
		{"React", regexp.MustCompile(`react\s*[:=]\s*['"]([\d.]+)['"]`)},
		{"Angular", regexp.MustCompile(`angular[^a-z]?([\d.]+)`)},
		{"Lodash", regexp.MustCompile(`lodash[@/ ]([\d.]+)`)},
		{"moment.js", regexp.MustCompile(`moment\.version\s*=\s*['"]([\d.]+)['"]`)},
		{"axios", regexp.MustCompile(`axios[@/ ]([\d.]+)`)},
	}

	// Known CVEs (simplified - would normally load from retire.js database)
	cveMap := map[string][]LibraryCVE{
		"jQuery": {
			{CVEID: "CVE-2020-11022", Severity: "medium", Description: "XSS via htmlPrefilter", Reference: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11022"},
			{CVEID: "CVE-2020-11023", Severity: "medium", Description: "XSS via DOM manipulation", Reference: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11023"},
		},
		"Bootstrap": {
			{CVEID: "CVE-2024-6484", Severity: "medium", Description: "XSS in data-target/tooltip", Reference: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6484"},
		},
		"moment.js": {
			{CVEID: "CVE-2022-24785", Severity: "medium", Description: "Path traversal in locale", Reference: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24785"},
			{CVEID: "CVE-2022-31129", Severity: "low", Description: "ReDoS", Reference: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-31129"},
		},
		"Lodash": {
			{CVEID: "CVE-2021-23337", Severity: "high", Description: "Prototype Pollution", Reference: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23337"},
		},
	}

	return &LibraryCVEAnalyzer{
		signatures: signatures,
		cveMap:     cveMap,
	}
}

// LoadCVEDatabase loads CVE database from file
func (l *LibraryCVEAnalyzer) LoadCVEDatabase(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read CVE database: %w", err)
	}

	// Expected format: JSON array of {library, version, cve_id, severity, description, reference}
	var cves []struct {
		Library     string `json:"library"`
		Version     string `json:"version"`
		CVEID       string `json:"cve_id"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Reference   string `json:"reference"`
	}

	if err := json.Unmarshal(data, &cves); err != nil {
		return fmt.Errorf("failed to parse CVE database: %w", err)
	}

	// Build CVE map
	for _, c := range cves {
		library := strings.ToLower(c.Library)
		l.cveMap[library] = append(l.cveMap[library], LibraryCVE{
			CVEID:       c.CVEID,
			Severity:    c.Severity,
			Description: c.Description,
			Reference:   c.Reference,
		})
	}

	log.Info().Int("cves_loaded", len(cves)).Msg("CVE database loaded")
	return nil
}

// AnalyzeLibraries fingerprints JS libraries and checks for CVEs
func (l *LibraryCVEAnalyzer) AnalyzeLibraries(ctx context.Context, target *models.Target, jsFiles []*models.JSFile, contentMap map[string]string) ([]models.LibraryCVE, error) {
	var allCVEs []models.LibraryCVE
	seen := make(map[string]bool) // key: library+version

	for _, jsFile := range jsFiles {
		content := contentMap[jsFile.URL]
		if content == "" {
			continue
		}

		for _, sig := range l.signatures {
			pattern := sig.re
			matches := pattern.FindAllStringSubmatch(content, -1)
			for _, match := range matches {
				if len(match) < 2 {
					continue
				}
				version := match[1]
				key := sig.name + "|" + version

				if seen[key] {
					continue
				}
				seen[key] = true

				// Check for CVEs
				for _, cve := range l.cveMap[sig.name] {
					cveRecord := models.LibraryCVE{
						ID:          uuid.New().String(),
						TargetID:    target.ID,
						JSFileID:    jsFile.ID,
						LibraryName: sig.name,
						Version:     version,
						CVEID:       cve.CVEID,
						Severity:    cve.Severity,
						Description: cve.Description,
						Reference:   cve.Reference,
						FoundAt:     time.Now(),
					}
					allCVEs = append(allCVEs, cveRecord)
				}
			}
		}
	}

	// Store in MongoDB
	if len(allCVEs) > 0 {
		coll := mongo.GetCollection("library_cves")
		docs := make([]interface{}, len(allCVEs))
		for i, c := range allCVEs {
			docs[i] = c
		}
		_, err := coll.InsertMany(ctx, docs)
		if err != nil {
			log.Error().Err(err).Msg("Failed to store CVE findings")
			return allCVEs, err
		}
		log.Info().Int("count", len(allCVEs)).Str("target", target.Domain).Msg("Library CVEs found and stored")
	}

	return allCVEs, nil
}