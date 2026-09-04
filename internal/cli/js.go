package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"go.mongodb.org/mongo-driver/bson"
	"hustler/internal/config"
	"hustler/internal/js"
	"hustler/internal/analyzers"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

var jsCmd = &cobra.Command{
	Use:   "js",
	Short: "JavaScript hunting commands",
	Long:  `Commands for JavaScript file hunting and analysis.`,
}

var jsHuntCmd = &cobra.Command{
	Use:   "hunt <domain>",
	Short: "Show findings and job status for a target",
	Long: `Display existing findings (secrets, sinks, etc.) and current hunt job status for a target.
This is a read-only command - it does not start or re-run scans.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		ctx := context.Background()

		// Find target
		coll := mongo.GetCollection("targets")
		var target models.Target
		err := coll.FindOne(ctx, map[string]interface{}{"domain": domain}).Decode(&target)
		if err != nil {
			return fmt.Errorf("target not found: %s", domain)
		}

		color.New(color.FgHiYellow).Printf("=== Target: %s (ID: %s) ===\n", target.Domain, target.ID)

		// Get latest job status
		jobColl := mongo.GetCollection("jobs")
		cursor, err := jobColl.Find(ctx, bson.M{"target_id": target.ID})
		if err != nil {
			return fmt.Errorf("failed to query jobs: %w", err)
		}
		defer cursor.Close(ctx)

		var jobs []models.Job
		if err := cursor.All(ctx, &jobs); err != nil {
			return fmt.Errorf("failed to decode jobs: %w", err)
		}

		if len(jobs) > 0 {
			latestJob := jobs[0]
			fmt.Printf("\nLast Hunt Job:\n")
			fmt.Printf("  ID:     %s\n", latestJob.ID)

			sc := statusColor(string(latestJob.Status))
			fmt.Printf("  Status: %s\n", sc.Sprintf("%s", latestJob.Status))

			fmt.Printf("  Queued: %s\n", latestJob.QueuedAt.Format(time.RFC3339))
			if latestJob.StartedAt != nil {
				fmt.Printf("  Started: %s\n", latestJob.StartedAt.Format(time.RFC3339))
			}
			if latestJob.FinishedAt != nil {
				fmt.Printf("  Finished: %s\n", latestJob.FinishedAt.Format(time.RFC3339))
			}
			if latestJob.Error != "" {
				color.New(color.FgRed).Printf("  Error: %s\n", latestJob.Error)
			}
			if latestJob.Source != "" {
				fmt.Printf("  Source: %s\n", latestJob.Source)
			}
		} else {
			fmt.Println("\nNo hunt job has ever run for this target.")
		}

		// Show findings
		fmt.Printf("\n=== Findings ===\n")

		// Build JSFile ID -> URL map for resolving source files
		jsFileColl := mongo.GetCollection("js_files")
		jsFileCursor, _ := jsFileColl.Find(ctx, bson.M{"target_id": target.ID})
		defer jsFileCursor.Close(ctx)
		var jsFiles []models.JSFile
		jsFileCursor.All(ctx, &jsFiles)
		jsFileMap := make(map[string]string)
		for _, jf := range jsFiles {
			jsFileMap[jf.ID] = jf.URL
		}

		// Secrets
		secretColl := mongo.GetCollection("secrets")
		scursor, _ := secretColl.Find(ctx, bson.M{"target_id": target.ID})
		defer scursor.Close(ctx)
		var secrets []models.Secret
		scursor.All(ctx, &secrets)
		if len(secrets) > 0 {
			fmt.Printf("\n%s\n", color.New(color.FgHiYellow, color.Bold).Sprintf("=== SECRETS (%d) ===", len(secrets)))
			for _, s := range secrets {
				c := statusColorByConfidence(s.Confidence)
				minifiedTag := ""
				if s.IsMinified {
					minifiedTag = color.New(color.FgHiBlack).Sprintf(" [minified]")
				}
				fileURL := jsFileMap[s.JSFileID]
				if fileURL == "" {
					fileURL = "(unknown file)"
				}
				// Color the pattern name by confidence
				patternColored := c.Sprintf("%s", bold(s.Pattern))
				// Show URL in cyan
				urlColored := color.New(color.FgHiCyan).Sprintf("%s", fileURL)
				// Show matched value in yellow (full value, no redaction)
				matchedColored := color.New(color.FgHiYellow).Sprintf("%s", s.Matched)
				fmt.Printf("  %s: %s  (line %d, conf: %.2f, entropy: %.2f%s) → %s\n",
					patternColored, matchedColored, s.Line, s.Confidence, s.Entropy, minifiedTag, urlColored)
			}
		}

		// Sinks
		sinkColl := mongo.GetCollection("sinks")
		sinkCursor, _ := sinkColl.Find(ctx, bson.M{"target_id": target.ID})
		defer sinkCursor.Close(ctx)
		var sinks []models.Sink
		sinkCursor.All(ctx, &sinks)
		if len(sinks) > 0 {
			fmt.Printf("\n%s\n", color.New(color.FgHiMagenta, color.Bold).Sprintf("=== SINKS (%d) ===", len(sinks)))
			for _, sk := range sinks {
				c := sinkColor(sk.HasOriginCheck, sk.SinkType, sk.SourceType)
				minifiedTag := ""
				if sk.IsMinified {
					minifiedTag = color.New(color.FgHiBlack).Sprintf(" [minified]")
				}
				lowConfTag := ""
				if sk.LowConfidence {
					lowConfTag = color.New(color.FgHiRed).Sprintf(" [LOW_CONF]")
				}
				fileURL := jsFileMap[sk.JSFileID]
				if fileURL == "" {
					fileURL = "(unknown file)"
				}
				sinkColored := c.Sprintf("%s", bold(sk.SinkType))
				sourceColored := color.New(color.FgHiWhite).Sprintf("%s", sk.SourceType)
				urlColored := color.New(color.FgHiCyan).Sprintf("%s", fileURL)
				originCheck := "✓"
				if !sk.HasOriginCheck {
					originCheck = color.New(color.FgHiRed).Sprintf("✗")
				}
				fmt.Printf("  %s  from %s  (line %d, conf: %.2f, origin: %s%s%s) → %s\n",
					sinkColored, sourceColored, sk.Line, sk.Confidence, originCheck, minifiedTag, lowConfTag, urlColored)
			}
		}

		// BLH candidates - split into real vulnerabilities vs target subdomains
		blhColl := mongo.GetCollection("blh_candidates")
		
		// First, get ALL candidates to separate them properly
		allCursor, _ := blhColl.Find(ctx, bson.M{"target_id": target.ID})
		defer allCursor.Close(ctx)
		var allBLH []models.BLHCandidate
		allCursor.All(ctx, &allBLH)
		
		// Separate: real takeover candidates vs target's own subdomains
		var vulnBLH []models.BLHCandidate
		var targetSubdomains []models.BLHCandidate
		for _, b := range allBLH {
			if b.IsTargetSubdomain {
				targetSubdomains = append(targetSubdomains, b)
			} else {
				// Only show actionable vulnerability states for third-party domains
				actionableStatuses := map[string]bool{
					"unclaimed_s3":          true,
					"github_pages_missing":  true,
					"heroku_missing":        true,
					"shopify_missing":       true,
					"surge_missing":         true,
					"netlify_missing":       true,
					"azure_missing":         true,
					"nxdomain":              true,
				}
				if actionableStatuses[b.ResolutionStatus] {
					vulnBLH = append(vulnBLH, b)
				}
			}
		}
		
		// Print REAL BLH vulnerabilities (third-party takeover candidates)
		if len(vulnBLH) > 0 {
			fmt.Printf("\n%s\n", color.New(color.FgHiRed, color.Bold).Sprintf("=== BLH VULNERABILITIES (%d) ===", len(vulnBLH)))
			for _, b := range vulnBLH {
				c := riskColor(b.RiskLevel)
				source := b.FoundIn
				if source == "" {
					source = "js_file"
				}
				fmt.Printf("  %s  %s %s %s %s\n",
					c.Sprintf("[%s]", b.ResolutionStatus),
					color.New(color.FgHiWhite).Sprintf("%s", b.ReferencedDomain),
					c.Sprintf("(%s)", b.RiskLevel),
					color.New(color.FgHiCyan).Sprintf("cloud: %s", func() string { if b.CloudProvider != "" { return b.CloudProvider }; return "unknown" }()),
					color.New(color.FgHiBlack).Sprintf("— %s", b.Evidence))
				fmt.Printf("    Source: %s | Found in: %s\n", source, b.FoundIn)
			}
		} else {
			fmt.Printf("\n%s\n", color.New(color.FgHiGreen).Sprintf("BLH: No takeover vulnerabilities found."))
		}

		// Print TARGET SUBDOMAINS (internal subdomains referenced in JS/HTML)
		if len(targetSubdomains) > 0 {
			fmt.Printf("\n%s\n", color.New(color.FgHiBlue, color.Bold).Sprintf("=== TARGET SUBDOMAINS FOUND (%d) ===", len(targetSubdomains)))
			for _, b := range targetSubdomains {
				source := b.FoundIn
				if source == "" {
					source = "js_file"
				}
				fmt.Printf("  %s  %s %s\n",
					color.New(color.FgHiCyan).Sprintf("%s", b.ReferencedDomain),
					color.New(color.FgHiWhite).Sprintf("(%s)", b.ResolutionStatus),
					color.New(color.FgHiBlack).Sprintf("— %s", b.Evidence))
				fmt.Printf("    Source: %s | Found in: %s\n", source, b.FoundIn)
			}
		} else {
			fmt.Printf("\n%s\n", color.New(color.FgHiGreen).Sprintf("Target Subdomains: None found."))
		}

		// Library CVEs
				cveColl := mongo.GetCollection("library_cves")
				cveCursor, _ := cveColl.Find(ctx, bson.M{"target_id": target.ID})
				defer cveCursor.Close(ctx)
				var cves []models.LibraryCVE
				cveCursor.All(ctx, &cves)
				if len(cves) > 0 {
					fmt.Printf("\n%s\n", color.New(color.FgHiCyan, color.Bold).Sprintf("=== LIBRARY CVEs (%d) ===", len(cves)))
					for _, c := range cves {
						sev := severityColor(c.Severity)
						libColored := color.New(color.FgHiWhite).Sprintf("%s", bold(c.LibraryName))
						verColored := color.New(color.FgHiYellow).Sprintf("v%s", c.Version)
						cveColored := color.New(color.FgHiRed).Sprintf("%s", c.CVEID)
						sevColored := sev.Sprintf("(%s)", c.Severity)
						extra := ""
						if c.FixedVersion != "" {
							extra += color.New(color.FgHiGreen).Sprintf(" fix: >=%s", c.FixedVersion)
						}
						switch c.Exploitable {
						case "confirmed":
							extra += color.New(color.FgHiRed, color.Bold).Sprintf(" 🎯CONFIRMED")
						case "likely":
							extra += color.New(color.FgHiYellow).Sprintf(" ⚠likely")
						}
						if c.KEVListed {
							extra += color.New(color.FgHiRed).Sprintf(" [KEV]")
						} else if c.EPSS >= 0.5 {
							extra += color.New(color.FgHiYellow).Sprintf(" [EPSS %.2f]", c.EPSS)
						}
						fmt.Printf("  %s %s  %s %s%s — %s\n",
							libColored, verColored, cveColored, sevColored, extra, c.Description)
					}
				}

		// Sensitive endpoint candidates
				senColl := mongo.GetCollection("sensitive_endpoint_candidates")
				sensCursor, _ := senColl.Find(ctx, bson.M{"target_id": target.ID})
				defer sensCursor.Close(ctx)
				var sensCands []models.SensitiveEndpointCandidate
				sensCursor.All(ctx, &sensCands)
				if len(sensCands) > 0 {
					fmt.Printf("\n%s\n", color.New(color.FgHiBlue, color.Bold).Sprintf("=== SENSITIVE ENDPOINTS (%d) ===", len(sensCands)))
					for _, sc := range sensCands {
						endpointColored := color.New(color.FgHiCyan).Sprintf("%s", sc.Endpoint)
						statusColored := color.New(color.FgHiWhite).Sprintf("HTTP %d", sc.StatusCode)
						patternsColored := color.New(color.FgHiYellow).Sprintf("%v", sc.MatchedPatterns)
						fmt.Printf("  %s  %s  size: %d  patterns: %s\n",
							endpointColored, statusColored, sc.ResponseSize, patternsColored)
					}
				}

		if len(secrets) == 0 && len(sinks) == 0 {
			fmt.Println("\nNo findings yet. Run a scan with `hustler js scan <domain> <js-url>` to generate findings.")
		}

		return nil
	},
}

func sinkColor(hasOriginCheck bool, sinkType, sourceType string) *color.Color {
	if !hasOriginCheck && (sinkType == "postMessage" || sourceType == "postMessage_data") {
		return color.New(color.FgHiRed)
	}
	return color.New(color.Reset)
}

var jsScanCmd = &cobra.Command{
	Use:   "scan <domain> <js-url>",
	Short: "Scan a single JS file URL for a target",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		jsURL := args[1]
		ctx := context.Background()

		// Load config
		cfg, err := config.Load("config.yaml")
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Find target
		coll := mongo.GetCollection("targets")
		var target models.Target
		err = coll.FindOne(ctx, map[string]interface{}{"domain": domain}).Decode(&target)
		if err != nil {
			return fmt.Errorf("target not found: %s", domain)
		}

		log.Info().Str("target", domain).Str("js_url", jsURL).Msg("Starting JS scan")

		// Create JS module
		jsModule := js.NewJSModule(cfg.JS, cfg.Sensitive)

		// Fetch and process
		results, err := jsModule.FetchAndProcess(ctx, &target, []string{jsURL}, nil)
		if err != nil {
			return fmt.Errorf("JS fetch failed: %w", err)
		}

		for _, result := range results {
			if result.Skipped {
				fmt.Printf("Skipped: %s (%s)\n", jsURL, result.SkipReason)
				continue
			}
			if result.Error != nil {
				fmt.Printf("Error: %v\n", result.Error)
				continue
			}

			fmt.Printf("Fetched: %s (hash: %s, size: %d bytes)\n", jsURL, result.JSFile.JSHash[:16], result.JSFile.ContentLength)

			// Run analyzers if content available
			if result.Content != "" {
				runAnalyzers(ctx, &target, result.JSFile, result.Content, cfg.JS)
			}
		}

		return nil
	},
}

func runAnalyzers(ctx context.Context, target *models.Target, jsFile *models.JSFile, content string, jsCfg config.JSConfig) {
	fmt.Println("\n--- Running Analyzers ---")

	// Secret Scanner
	secretScanner := analyzers.NewSecretScanner(jsCfg)
	secrets, err := secretScanner.Scan(ctx, target, jsFile, content)
	if err != nil {
		log.Error().Err(err).Msg("Secret scanner failed")
	} else {
		fmt.Printf("Secrets found: %d\n", len(secrets))
		for _, s := range secrets {
			c := statusColorByConfidence(s.Confidence)
			fmt.Printf("  - %s (line %d, confidence: %.2f, entropy: %.2f)\n",
				c.Sprintf("%s", bold(s.Pattern)), s.Line, s.Confidence, s.Entropy)
		}
	}

	// Sink Analyzer
	sinkAnalyzer := analyzers.NewSinkAnalyzer()
	sinks, err := sinkAnalyzer.Scan(ctx, target, jsFile, content)
	if err != nil {
		log.Error().Err(err).Msg("Sink analyzer failed")
	} else {
		fmt.Printf("Sink findings: %d\n", len(sinks))
		for _, sk := range sinks {
			c := sinkColor(sk.HasOriginCheck, sk.SinkType, sk.SourceType)
			fmt.Printf("  - %s from %s (line %d, confidence: %.2f)\n",
				c.Sprintf("%s", bold(sk.SinkType)), sk.SourceType, sk.Line, sk.Confidence)
		}
	}

	fmt.Println("\n--- Scan Complete ---")
}

func init() {
	jsCmd.AddCommand(jsHuntCmd)
	GetRootCmd().AddCommand(jsCmd)

	// Shell completion for JS commands
	_ = jsHuntCmd.RegisterFlagCompletionFunc("domain", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		ctx := context.Background()
		coll := mongo.GetCollection("targets")
		cursor, err := coll.Find(ctx, bson.M{})
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		defer cursor.Close(ctx)
		var targets []models.Target
		if err := cursor.All(ctx, &targets); err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		var domains []string
		for _, t := range targets {
			domains = append(domains, t.Domain)
		}
		return domains, cobra.ShellCompDirectiveDefault
	})
}