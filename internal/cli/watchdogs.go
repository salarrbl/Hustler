package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"hustler/internal/config"
	"hustler/internal/models"
	"hustler/internal/watchdogs"
)

var (
	watchdogsPlatform   string
	watchdogsProgram    string
	watchdogsLiveOnly   bool
	watchdogsNewOnly    bool
	watchdogsShowTree   bool
	watchdogsLimit      int
	watchdogsShowCount  bool
)

// watchdogsCmd represents the base watchdogs command
var watchdogsCmd = &cobra.Command{
	Use:   "watchdogs",
	Short: "Watchdogs integration commands",
	Long:  `Commands for syncing targets from Watchdogs MongoDB.`,
}

// watchdogsSyncCmd represents the old sync command (kept for backward compatibility)
var watchdogsSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync targets from Watchdogs (legacy command)",
	Long: `Pull targets from Watchdogs' MongoDB into Hustler's target queue.
This command is deprecated. Use 'hustler watchdogs fetch' instead.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("⚠️  This command is deprecated. Use 'hustler watchdogs fetch' instead.")
		fmt.Println("   The new fetch command has better filtering options.")
		return nil
	},
}

// watchdogsFetchCmd represents the new fetch command
var watchdogsFetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch live subdomains from Watchdogs",
	Long: `Fetch live subdomains from Watchdogs MongoDB and sync to Hustler.

This command connects to the Watchdogs database, retrieves HTTP records,
and organizes them as: Platform → Program → Assets.

Filters:
  - Use --platform to fetch only assets for a specific platform
  - Use --program to fetch only assets for a specific program
  - Use --live-only to only fetch subdomains with valid HTTP responses (default: true)
  - Use --new-only to only fetch subdomains not already in Hustler

Examples:
  # Fetch all live subdomains
  hustler watchdogs fetch

  # Fetch only from HackerOne
  hustler watchdogs fetch --platform hackerone

  # Fetch only for a specific program
  hustler watchdogs fetch --program "Google"

  # Fetch only new assets (not already in Hustler)
  hustler watchdogs fetch --new-only

  # Fetch from multiple filters
  hustler watchdogs fetch --platform bugcrowd --program "Shopify"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load("config.yaml")
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		if !cfg.Watchdogs.Enabled {
			return fmt.Errorf("Watchdogs integration is disabled - set watchdogs.enabled: true in config.yaml")
		}

		// Create fetcher
		fetcher, err := watchdogs.NewFetcher(cfg.Watchdogs)
		if err != nil {
			return fmt.Errorf("failed to create Watchdogs fetcher: %w", err)
		}
		defer fetcher.Close()

		// Build fetch options
		opts := watchdogs.FetchOptions{
			Platform: watchdogsPlatform,
			Program:  watchdogsProgram,
			LiveOnly: watchdogsLiveOnly,
			NewOnly:  watchdogsNewOnly,
		}

		// Default to live-only if not specified
		if !cmd.Flags().Changed("live-only") {
			opts.LiveOnly = true
		}

		ctx := context.Background()
		log.Info().Msg("Starting Watchdogs fetch...")

		result, err := fetcher.Fetch(ctx, opts)
		if err != nil {
			return fmt.Errorf("fetch failed: %w", err)
		}

		// Print summary
		fmt.Println("\n✅ Fetch completed!")
		fmt.Printf("   Platforms: %d\n", result.Platforms)
		fmt.Printf("   Programs: %d\n", result.Programs)
		fmt.Printf("   Total Assets: %d\n", result.Assets)
		if result.NewAssets > 0 {
			fmt.Printf("   New Assets: %d\n", result.NewAssets)
		}
		if result.Skipped > 0 {
			fmt.Printf("   Skipped: %d\n", result.Skipped)
		}

		// Show tree if requested
		if watchdogsShowTree {
			fmt.Println("\n📊 Target Tree (Platform → Program → Assets):")
			tree, err := fetcher.GetTargetTree(ctx)
			if err != nil {
				return fmt.Errorf("failed to get target tree: %w", err)
			}
			limit := watchdogsLimit
			if limit == 0 {
				limit = 7 // default limit
			}
			printWatchdogsTree(tree, limit)
		}

		return nil
	},
}

// watchdogsTreeCmd shows the hierarchy of targets
var watchdogsTreeCmd = &cobra.Command{
	Use:   "tree",
	Short: "Show target hierarchy from Watchdogs",
	Long: `Display the target hierarchy as: Platform → Program → Assets.

Use --limit to control how many assets to show per program (default: 7).
Use --all to show all targets without limiting.

Examples:
  hustler watchdogs tree                    # Show 7 targets per program
  hustler watchdogs tree --limit 10         # Show 10 targets per program
  hustler watchdogs tree --platform hackerone  # Show only HackerOne platform`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load("config.yaml")
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		if !cfg.Watchdogs.Enabled {
			return fmt.Errorf("Watchdogs integration is disabled - set watchdogs.enabled: true in config.yaml")
		}

		fetcher, err := watchdogs.NewFetcher(cfg.Watchdogs)
		if err != nil {
			return fmt.Errorf("failed to create Watchdogs fetcher: %w", err)
		}
		defer fetcher.Close()

		ctx := context.Background()
		tree, err := fetcher.GetTargetTree(ctx)
		if err != nil {
			return fmt.Errorf("failed to get target tree: %w", err)
		}

		if len(tree) == 0 {
			fmt.Println("No targets from Watchdogs found. Run 'hustler watchdogs fetch' first.")
			return nil
		}

		// Filter by platform if specified
		if watchdogsPlatform != "" {
			tree = filterTargetTreeByPlatform(tree, watchdogsPlatform)
			if len(tree) == 0 {
				fmt.Printf("No data found for platform: %s\n", watchdogsPlatform)
				return nil
			}
		}

		limit := watchdogsLimit
		if limit == 0 {
			limit = 7 // default limit
		}
		printWatchdogsTree(tree, limit)
		return nil
	},
}

// watchdogsListPlatformsCmd lists available platforms
var watchdogsListPlatformsCmd = &cobra.Command{
	Use:   "platforms",
	Short: "List available platforms",
	Long: `List all platforms that have targets from Watchdogs.

Shows the count of assets per platform.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load("config.yaml")
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		fetcher, err := watchdogs.NewFetcher(cfg.Watchdogs)
		if err != nil {
			return fmt.Errorf("failed to create Watchdogs fetcher: %w", err)
		}
		defer fetcher.Close()

		ctx := context.Background()
		tree, err := fetcher.GetTargetTree(ctx)
		if err != nil {
			return fmt.Errorf("failed to get target tree: %w", err)
		}

		if len(tree) == 0 {
			fmt.Println("No platforms found.")
			return nil
		}

		// Calculate totals
		totalAssets := 0
		totalPrograms := 0

		fmt.Println("Available Platforms:")
		fmt.Println("───────────────────")
		for platform, programs := range tree {
			assetCount := 0
			for _, assets := range programs {
				assetCount += len(assets)
				totalPrograms++
			}
			totalAssets += assetCount
			fmt.Printf("  📁 %s: %d programs, %d assets\n", platform, len(programs), assetCount)
		}
		fmt.Printf("\n  Total: %d platforms, %d programs, %d assets\n", len(tree), totalPrograms, totalAssets)
		return nil
	},
}

// watchdogsListProgramsCmd lists programs (optionally filtered by platform)
var watchdogsListProgramsCmd = &cobra.Command{
	Use:   "programs",
	Short: "List programs",
	Long: `List all programs. Use --platform to filter by platform.

Shows asset count per program.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load("config.yaml")
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		fetcher, err := watchdogs.NewFetcher(cfg.Watchdogs)
		if err != nil {
			return fmt.Errorf("failed to create Watchdogs fetcher: %w", err)
		}
		defer fetcher.Close()

		ctx := context.Background()
		tree, err := fetcher.GetTargetTree(ctx)
		if err != nil {
			return fmt.Errorf("failed to get target tree: %w", err)
		}

		// Filter by platform if specified
		if watchdogsPlatform != "" {
			tree = filterTargetTreeByPlatform(tree, watchdogsPlatform)
			if len(tree) == 0 {
				fmt.Printf("No programs found for platform: %s\n", watchdogsPlatform)
				return nil
			}
		}

		if len(tree) == 0 {
			fmt.Println("No programs found.")
			return nil
		}

		fmt.Println("Available Programs:")
		fmt.Println("───────────────────")
		
		shownPlatform := ""
		for platform, programs := range tree {
			// Show platform header only if not filtered
			if watchdogsPlatform == "" && platform != shownPlatform {
				fmt.Printf("\n[%s]\n", platform)
				shownPlatform = platform
			}
			for programName, assets := range programs {
				fmt.Printf("  📂 %s: %d assets\n", programName, len(assets))
			}
		}
		return nil
	},
}

// watchdogsListAssetsCmd lists assets (targets) with pagination
var watchdogsListAssetsCmd = &cobra.Command{
	Use:   "assets",
	Short: "List assets/targets",
	Long: `List all assets (subdomains) with pagination.

Use --limit to control how many to show per program (default: 7).
Use --platform and --program to filter.

Examples:
  hustler watchdogs assets                  # Show 7 assets per program
  hustler watchdogs assets --limit 10       # Show 10 assets per program
  hustler watchdogs assets --platform hackerone  # Only HackerOne
  hustler watchdogs assets --program "Google"   # Only Google program`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load("config.yaml")
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		fetcher, err := watchdogs.NewFetcher(cfg.Watchdogs)
		if err != nil {
			return fmt.Errorf("failed to create Watchdogs fetcher: %w", err)
		}
		defer fetcher.Close()

		ctx := context.Background()
		tree, err := fetcher.GetTargetTree(ctx)
		if err != nil {
			return fmt.Errorf("failed to get target tree: %w", err)
		}

		// Apply filters
		if watchdogsPlatform != "" || watchdogsProgram != "" {
			tree = filterTargetTree(tree, watchdogsPlatform, watchdogsProgram)
		}

		if len(tree) == 0 {
			fmt.Println("No assets found.")
			return nil
		}

		limit := watchdogsLimit
		if limit == 0 {
			limit = 7
		}
		printAssetsList(tree, limit, watchdogsShowCount)
		return nil
	},
}

func init() {
	// Add flags to fetch command
	watchdogsFetchCmd.Flags().StringVar(&watchdogsPlatform, "platform", "", "Filter by platform (e.g., hackerone, bugcrowd)")
	watchdogsFetchCmd.Flags().StringVar(&watchdogsProgram, "program", "", "Filter by program name")
	watchdogsFetchCmd.Flags().BoolVar(&watchdogsLiveOnly, "live-only", true, "Only fetch live subdomains (HTTP responses)")
	watchdogsFetchCmd.Flags().BoolVar(&watchdogsNewOnly, "new-only", false, "Only fetch subdomains not already in Hustler")
	watchdogsFetchCmd.Flags().BoolVar(&watchdogsShowTree, "tree", false, "Show target hierarchy after fetch")

	// Add flags to tree command
	watchdogsTreeCmd.Flags().StringVar(&watchdogsPlatform, "platform", "", "Filter by platform")
	watchdogsTreeCmd.Flags().IntVar(&watchdogsLimit, "limit", 7, "Number of assets to show per program (0 = show all)")

	// Add flags to programs command
	watchdogsListProgramsCmd.Flags().StringVar(&watchdogsPlatform, "platform", "", "Filter by platform")

	// Add flags to assets command
	watchdogsListAssetsCmd.Flags().StringVar(&watchdogsPlatform, "platform", "", "Filter by platform")
	watchdogsListAssetsCmd.Flags().StringVar(&watchdogsProgram, "program", "", "Filter by program name")
	watchdogsListAssetsCmd.Flags().IntVar(&watchdogsLimit, "limit", 7, "Number of assets to show per program (0 = show all)")
	watchdogsListAssetsCmd.Flags().BoolVar(&watchdogsShowCount, "count", false, "Show only counts, not the actual targets")

	// Build command hierarchy
	watchdogsCmd.AddCommand(watchdogsSyncCmd)
	watchdogsCmd.AddCommand(watchdogsFetchCmd)
	watchdogsCmd.AddCommand(watchdogsTreeCmd)
	watchdogsCmd.AddCommand(watchdogsListPlatformsCmd)
	watchdogsCmd.AddCommand(watchdogsListProgramsCmd)
	watchdogsCmd.AddCommand(watchdogsListAssetsCmd)

	GetRootCmd().AddCommand(watchdogsCmd)
}

// filterTargetTreeByPlatform filters the tree by platform
func filterTargetTreeByPlatform(tree map[string]map[string][]models.Target, platform string) map[string]map[string][]models.Target {
	platform = strings.ToLower(platform)
	filtered := make(map[string]map[string][]models.Target)
	
	for p, programs := range tree {
		if strings.ToLower(p) == platform {
			filtered[p] = programs
			break
		}
	}
	
	return filtered
}

// filterTargetTree filters the tree by platform and/or program
func filterTargetTree(tree map[string]map[string][]models.Target, platform, program string) map[string]map[string][]models.Target {
	if platform == "" && program == "" {
		return tree
	}

	filtered := make(map[string]map[string][]models.Target)
	
	for p, programs := range tree {
		if platform != "" && strings.ToLower(p) != strings.ToLower(platform) {
			continue
		}
		
		for progName, assets := range programs {
			if program != "" && strings.ToLower(progName) != strings.ToLower(program) {
				continue
			}
			
			if _, ok := filtered[p]; !ok {
				filtered[p] = make(map[string][]models.Target)
			}
			filtered[p][progName] = assets
		}
	}
	
	return filtered
}

// printWatchdogsTree prints the hierarchy with limited assets per program
func printWatchdogsTree(tree map[string]map[string][]models.Target, limit int) {
	// Calculate totals
	totalPlatforms := len(tree)
	totalPrograms := 0
	totalAssets := 0
	
	for _, programs := range tree {
		totalPrograms += len(programs)
		for _, assets := range programs {
			totalAssets += len(assets)
		}
	}

	// Header
	fmt.Printf("📊 Target Hierarchy (%d platforms, %d programs, %d assets)\n", totalPlatforms, totalPrograms, totalAssets)
	fmt.Println("═══════════════════════════════════════════════════════════")

	for platform, programs := range tree {
		platformAssets := 0
		for _, assets := range programs {
			platformAssets += len(assets)
		}
		fmt.Printf("\n📁 %s (%d programs, %d assets)\n", platform, len(programs), platformAssets)
		
		for programName, assets := range programs {
			fmt.Printf("  📂 %s (%d)\n", programName, len(assets))
			
			if limit > 0 && len(assets) > limit {
				// Show limited assets + "more" message
				for i := 0; i < limit; i++ {
					fmt.Printf("      ├── %s\n", assets[i].Domain)
				}
				remaining := len(assets) - limit
				if remaining > 0 {
					fmt.Printf("      └── ... %d more targets\n", remaining)
				}
			} else {
				// Show all assets
				for i, asset := range assets {
					prefix := "      └──"
					if i < len(assets)-1 {
						prefix = "      ├──"
					}
					fmt.Printf("%s %s\n", prefix, asset.Domain)
				}
			}
		}
	}
	fmt.Println()
}

// printAssetsList prints assets with pagination
func printAssetsList(tree map[string]map[string][]models.Target, limit int, showCountOnly bool) {
	// Calculate totals
	totalAssets := 0
	for _, programs := range tree {
		for _, assets := range programs {
			totalAssets += len(assets)
		}
	}

	fmt.Printf("📋 Assets List (%d total)\n", totalAssets)
	fmt.Println("═══════════════════════════════════════════════════════════")

	for platform, programs := range tree {
		platformAssets := 0
		for _, assets := range programs {
			platformAssets += len(assets)
		}
		
		if showCountOnly {
			fmt.Printf("\n📁 %s: %d assets\n", platform, platformAssets)
			continue
		}

		fmt.Printf("\n📁 %s (%d assets)\n", platform, platformAssets)
		
		for programName, assets := range programs {
			fmt.Printf("  📂 %s\n", programName)
			
			if limit > 0 && len(assets) > limit {
				// Show limited assets + "more" message
				for i := 0; i < limit; i++ {
					fmt.Printf("      ├── %s\n", assets[i].Domain)
				}
				remaining := len(assets) - limit
				if remaining > 0 {
					fmt.Printf("      └── ... %d more targets\n", remaining)
				}
			} else {
				// Show all assets
				for i, asset := range assets {
					prefix := "      └──"
					if i < len(assets)-1 {
						prefix = "      ├──"
					}
					fmt.Printf("%s %s\n", prefix, asset.Domain)
				}
			}
		}
	}
}
