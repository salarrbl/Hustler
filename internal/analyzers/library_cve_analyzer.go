package analyzers

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"hustler/internal/cve"
	"hustler/internal/models"
	"hustler/internal/mongo"
)

// LibraryCVEAnalyzer fingerprints JS libraries and matches known CVEs.
//
// Detection (banners, globals, script-URL pins, package.json manifests),
// range matching ([atOrAbove, below)), KEV/EPSS enrichment and
// exploitability verdicts are delegated to the cve package (RunScan).
// This type keeps the pipeline-facing API stable and persists findings.
type LibraryCVEAnalyzer struct {
	dataDir string
	db      map[string][]cve.LocalCVEEntry
}

// NewLibraryCVEAnalyzer creates an analyzer using ./data/cve.
func NewLibraryCVEAnalyzer() *LibraryCVEAnalyzer {
	return NewLibraryCVEAnalyzerWithDB("./data/cve")
}

// NewLibraryCVEAnalyzerWithDB creates an analyzer using a custom data dir.
func NewLibraryCVEAnalyzerWithDB(dataDir string) *LibraryCVEAnalyzer {
	a := &LibraryCVEAnalyzer{dataDir: dataDir}
	a.Reload()
	return a
}

// Reload (re)loads the local CVE database (call after `cve update`).
func (l *LibraryCVEAnalyzer) Reload() {
	db, err := cve.LoadEntriesFromDir(l.dataDir)
	if err != nil {
		log.Warn().Err(err).Str("dir", l.dataDir).Msg("CVE local DB unavailable, analyzer will find nothing")
		db = make(map[string][]cve.LocalCVEEntry)
	}
	l.db = db
}

// LoadCVEDatabase loads extra CVE records from a single JSON file.
// It accepts the legacy [{library, version, cve_id, ...}] shape as well as
// []cve.LocalCVEEntry, and merges them into the in-memory database.
func (l *LibraryCVEAnalyzer) LoadCVEDatabase(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Try the rich shape first.
	var rich []cve.LocalCVEEntry
	if err := json.Unmarshal(data, &rich); err == nil && len(rich) > 0 && rich[0].CVEID != "" {
		for _, e := range rich {
			l.db[strings.ToLower(e.Library)] = append(l.db[strings.ToLower(e.Library)], e)
		}
		log.Info().Int("cves_loaded", len(rich)).Msg("CVE database loaded")
		return nil
	}
	// Fall back to the legacy shape.
	var legacy []struct {
		Library     string `json:"library"`
		Version     string `json:"version"`
		CVEID       string `json:"cve_id"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Reference   string `json:"reference"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}
	for _, item := range legacy {
		e := cve.LocalCVEEntry{
			Library:    cve.NormalizeLibName(item.Library),
			MaxVersion: item.Version,
			CVEID:      item.CVEID,
			Severity:   strings.ToUpper(item.Severity),
			Summary:    item.Description,
			References: []string{item.Reference},
			Source:     "custom",
		}
		l.db[strings.ToLower(e.Library)] = append(l.db[strings.ToLower(e.Library)], e)
	}
	log.Info().Int("cves_loaded", len(legacy)).Msg("CVE database loaded")
	return nil
}

// AnalyzeLibraries fingerprints libraries in contentMap and stores matches.
func (l *LibraryCVEAnalyzer) AnalyzeLibraries(ctx context.Context, target *models.Target, jsFiles []*models.JSFile, contentMap map[string]string) ([]models.LibraryCVE, error) {
	var sources []cve.JSSource
	for _, jsFile := range jsFiles {
		if jsFile == nil {
			continue
		}
		content := contentMap[jsFile.URL]
		if content == "" {
			continue
		}
		sources = append(sources, cve.JSSource{URL: jsFile.URL, Content: content})
	}
	if len(sources) == 0 {
		return nil, nil
	}

	opts := cve.DefaultScanOptions(l.dataDir)
	// Offline inside the pipeline: no live lookups during hunts.
	opts.EnableOnlineLookup = false

	// Map URL -> JSFile ID for storage linkage.
	idByURL := make(map[string]string)
	for _, jsFile := range jsFiles {
		if jsFile != nil && jsFile.URL != "" {
			if _, ok := idByURL[jsFile.URL]; !ok {
				idByURL[jsFile.URL] = jsFile.ID
			}
		}
	}

	findings := cve.RunScan(ctx, l.db, nil, opts, cve.ScanInput{JSFiles: sources})

	allCVEs := make([]models.LibraryCVE, 0, len(findings))
	for _, f := range findings {
		rec := cve.ToLibraryCVE(target.ID, idByURL[f.Context], f)
		// f.Context is the JS URL here; resolve the stored file ID.
		rec.JSFileID = idByURL[f.Context]
		rec.ID = uuid.New().String()
		rec.FoundAt = time.Now()
		allCVEs = append(allCVEs, rec)
	}

	if len(allCVEs) > 0 {
		coll := mongo.GetCollection("library_cves")
		docs := make([]interface{}, len(allCVEs))
		for i, c := range allCVEs {
			docs[i] = c
		}
		if _, err := coll.InsertMany(ctx, docs); err != nil {
			log.Error().Err(err).Msg("Failed to store CVE findings")
			return allCVEs, err
		}
		log.Info().Int("count", len(allCVEs)).Str("target", target.Domain).Msg("Library CVEs found and stored")
	}

	return allCVEs, nil
}
