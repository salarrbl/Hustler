package cli

import (
	"context"
	"fmt"
	"time"

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
	Args:  cobra.ExactArgs(1),
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

		fmt.Printf("=== Target: %s (ID: %s) ===\n", target.Domain, target.ID)

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
			fmt.Printf("  Status: %s\n", latestJob.Status)
			fmt.Printf("  Queued: %s\n", latestJob.QueuedAt.Format(time.RFC3339))
			if latestJob.StartedAt != nil {
				fmt.Printf("  Started: %s\n", latestJob.StartedAt.Format(time.RFC3339))
			}
			if latestJob.FinishedAt != nil {
				fmt.Printf("  Finished: %s\n", latestJob.FinishedAt.Format(time.RFC3339))
			}
			if latestJob.Error != "" {
				fmt.Printf("  Error: %s\n", latestJob.Error)
			}
			if latestJob.Source != "" {
				fmt.Printf("  Source: %s\n", latestJob.Source)
			}
		} else {
			fmt.Println("\nNo hunt job has ever run for this target.")
		}

		// Show findings
		fmt.Printf("\n=== Findings ===\n")

		// Secrets
		secretColl := mongo.GetCollection("secrets")
		scursor, _ := secretColl.Find(ctx, bson.M{"target_id": target.ID})
		defer scursor.Close(ctx)
		var secrets []models.Secret
		scursor.All(ctx, &secrets)
		if len(secrets) > 0 {
			fmt.Printf("\nSecrets (%d):\n", len(secrets))
			for _, s := range secrets {
				fmt.Printf("  - %s (line %d, confidence: %.2f, entropy: %.2f)\n",
					s.Pattern, s.Line, s.Confidence, s.Entropy)
			}
		}

		// Sinks
		sinkColl := mongo.GetCollection("sinks")
		sinkCursor, _ := sinkColl.Find(ctx, bson.M{"target_id": target.ID})
		defer sinkCursor.Close(ctx)
		var sinks []models.Sink
		sinkCursor.All(ctx, &sinks)
		if len(sinks) > 0 {
			fmt.Printf("\nSinks (%d):\n", len(sinks))
			for _, sk := range sinks {
				fmt.Printf("  - %s from %s (line %d, confidence: %.2f, origin_check: %v)\n",
					sk.SinkType, sk.SourceType, sk.Line, sk.Confidence, sk.HasOriginCheck)
			}
		}

		if len(secrets) == 0 && len(sinks) == 0 {
			fmt.Println("\nNo findings yet. Run a scan with `hustler js scan <domain> <js-url>` to generate findings.")
		}

		return nil
	},
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
		results, err := jsModule.FetchAndProcess(ctx, &target, []string{jsURL})
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
			fmt.Printf("  - %s (line %d, confidence: %.2f, entropy: %.2f)\n", s.Pattern, s.Line, s.Confidence, s.Entropy)
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
			fmt.Printf("  - %s from %s (line %d, confidence: %.2f)\n", sk.SinkType, sk.SourceType, sk.Line, sk.Confidence)
		}
	}

	// TODO: Add other analyzers (endpoints, params, BLH, CDN blocklist, library CVE, source-map)
	fmt.Println("\n--- Scan Complete ---")
}

func init() {
	jsCmd.AddCommand(jsHuntCmd, jsScanCmd)
	GetRootCmd().AddCommand(jsCmd)
}