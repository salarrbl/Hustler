package cli

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

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
	Short: "Run JS hunting pipeline on a target",
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

		// For now, we need JS URLs to hunt. In future, this would crawl for JS files.
		// For testing, we can pass JS URLs via a file or flags.
		// This is a placeholder - real implementation would discover JS files first.
		
		fmt.Printf("Target: %s (ID: %s)\n", target.Domain, target.ID)
		fmt.Println("JS hunting pipeline would run here.")
		fmt.Println("Need to discover JS files first (from Watchdogs or crawling).")
		
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
		jsModule := js.NewJSModule(cfg.JS)

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