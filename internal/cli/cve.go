package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"hustler/internal/cve"
)

var cveUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update CVE database from online sources",
	Long: `Download the latest CVE data from retire.js, osv.dev, and npm advisories.
The database is stored locally in ./data/cve/ and cached for 7 days.

Sources:
- retire.js: JavaScript library CVEs (5000+ entries)
- osv.dev: Open Source Vulnerabilities (npm, Go, Rust, PyPI, etc.)
- npm: npm security advisories`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("🔍 Initializing CVE module...\n")

		cfg := cve.DefaultCVEConfig()
		cfg.DataDir = "./data/cve"

		mod, err := cve.NewCVEModule(cfg)
		if err != nil {
			return fmt.Errorf("failed to initialize CVE module: %w", err)
		}

		fmt.Printf("📥 Downloading CVE database from online sources...\n")
		startTime := time.Now()

		result, err := mod.ForceUpdate(context.Background())
		if err != nil {
			return fmt.Errorf("CVE database update failed: %w", err)
		}

		elapsed := time.Since(startTime)
		fmt.Printf("✅ CVE database updated successfully (%.1fs)\n", elapsed.Seconds())

		// Show new CVEs found
		if len(result.NewCVEs) > 0 {
			fmt.Printf("\n🆕 New CVEs added: %d\n", len(result.NewCVEs))
			fmt.Printf("📚 New libraries: %d\n", result.NewLibraries)
			fmt.Printf("📦 Updated sources: %d\n", result.UpdatedSources)
			
			// Group by library
			byLib := make(map[string][]cve.LocalCVEEntry)
			for _, c := range result.NewCVEs {
				byLib[strings.ToLower(c.Library)] = append(byLib[strings.ToLower(c.Library)], c)
			}
			
			for lib, entries := range byLib {
				if len(entries) > 0 {
					fmt.Printf("  %s: %d new CVE(s)\n", lib, len(entries))
					// Show first few
					for i, e := range entries {
						if i >= 3 {
							fmt.Printf("    ... and %d more\n", len(entries)-3)
							break
						}
						fmt.Printf("    %s %s (≤ %s)\n", severityIcon(e.Severity), e.CVEID, e.MaxVersion)
					}
				}
			}
		}

		if len(result.Errors) > 0 {
			fmt.Printf("\n⚠ Errors:\n")
			for _, e := range result.Errors {
				fmt.Printf("  • %s\n", e)
			}
		}

		// Show stats
		// Note: Can't access internal methods directly, but module is loaded
		fmt.Printf("\nSources:\n")
		fmt.Printf("  • retire.js: JavaScript library CVEs\n")
		fmt.Printf("  • osv.dev: Open source vulnerabilities\n")
		fmt.Printf("  • npm: npm package advisories\n")
		fmt.Printf("\nLocal cache: ./data/cve/\n")
		fmt.Printf("Next auto-update: in 7 days\n")

		return nil
	},
}

var cveStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show CVE database status",
	Long:  `Display the current CVE database status, including last update time and source counts.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("📊 CVE Database Status\n")
		fmt.Println("════════════════════════════════════════════════════")

		cfg := cve.DefaultCVEConfig()
		cfg.DataDir = "./data/cve"

		mod, err := cve.NewCVEModule(cfg)
		if err != nil {
			return fmt.Errorf("failed to initialize CVE module: %w", err)
		}

		// Load local DB
		if err := mod.LoadLocalDB(); err != nil {
			fmt.Printf("  ⚠ Failed to load local DB: %v\n", err)
		} else {
			libCount := len(mod.GetLocalDB())
			entryCount := 0
			for _, entries := range mod.GetLocalDB() {
				entryCount += len(entries)
			}

			fmt.Printf("\n  Local Database:\n")
			fmt.Printf("    • Libraries tracked: %d\n", libCount)
			fmt.Printf("    • Total CVE entries: %d\n", entryCount)
		}

		// Check last update
		updateFile := cfg.DataDir + "/.last_update"
		if data, err := os.ReadFile(updateFile); err == nil {
			if lastUpdate, err := time.Parse(time.RFC3339, string(data)); err == nil {
				fmt.Printf("\n  Last Update:\n")
				fmt.Printf("    • Timestamp: %s\n", lastUpdate.Format("2006-01-02 15:04:05"))
				fmt.Printf("    • Age: %s ago\n", formatDuration(time.Since(lastUpdate)))
			}
		} else {
			fmt.Printf("\n  Last Update: Never\n")
		}

		fmt.Printf("\n  Auto-Update: ")
		if cfg.EnableOnlineLookup {
			fmt.Printf("Enabled (every %d days)\n", cfg.UpdateIntervalDays)
		} else {
			fmt.Printf("Disabled\n")
		}

		return nil
	},
}

var cveListCmd = &cobra.Command{
	Use:   "list",
	Short: "List CVE entries from local database",
	Long: `List all CVE entries from the local database with optional filtering.

Examples:
  hustler cve list                          # List all CVEs
  hustler cve list --library lodash         # Filter by library name
  hustler cve list --severity high          # Filter by severity (critical, high, medium, low)
  hustler cve list --source retire.js       # Filter by source
  hustler cve list --cve CVE-2021-44228     # Search by CVE ID
  hustler cve list --format json            # Output as JSON`,
	RunE: func(cmd *cobra.Command, args []string) error {
		libraryFilter, _ := cmd.Flags().GetString("library")
		severityFilter, _ := cmd.Flags().GetString("severity")
		sourceFilter, _ := cmd.Flags().GetString("source")
		cveFilter, _ := cmd.Flags().GetString("cve")
		format, _ := cmd.Flags().GetString("format")
		limit, _ := cmd.Flags().GetInt("limit")

		cfg := cve.DefaultCVEConfig()
		cfg.DataDir = "./data/cve"

		mod, err := cve.NewCVEModule(cfg)
		if err != nil {
			return fmt.Errorf("failed to initialize CVE module: %w", err)
		}

		if err := mod.LoadLocalDB(); err != nil {
			return fmt.Errorf("failed to load local DB: %w", err)
		}

		db := mod.GetLocalDB()
		var results []cve.LocalCVEEntry

		for _, entries := range db {
			for _, e := range entries {
				// Apply filters
				if libraryFilter != "" && !strings.Contains(strings.ToLower(e.Library), strings.ToLower(libraryFilter)) {
					continue
				}
				if severityFilter != "" && !strings.EqualFold(e.Severity, severityFilter) {
					continue
				}
				if sourceFilter != "" && !strings.EqualFold(e.Source, sourceFilter) {
					continue
				}
				if cveFilter != "" && !strings.Contains(e.CVEID, cveFilter) {
					continue
				}
				results = append(results, e)
				if limit > 0 && len(results) >= limit {
					break
				}
			}
			if limit > 0 && len(results) >= limit {
				break
			}
		}

		if format == "json" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(results)
		}

		// Table format
		if len(results) == 0 {
			fmt.Printf("No CVE entries found matching criteria.\n")
			return nil
		}

		fmt.Printf("📋 CVE Entries (%d shown)\n", len(results))
		fmt.Println("════════════════════════════════════════════════════════════════════════════════════")
		
		for i, e := range results {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("  %s %s\n", severityIcon(e.Severity), e.CVEID)
			fmt.Printf("    Library:    %s\n", e.Library)
			fmt.Printf("    Version:    ≤ %s\n", e.MaxVersion)
			fmt.Printf("    Severity:   %s\n", e.Severity)
			if e.CVSS > 0 {
				fmt.Printf("    CVSS:       %.1f\n", e.CVSS)
			}
			if e.FixedVersion != "" {
				fmt.Printf("    Fixed:      %s\n", e.FixedVersion)
			}
			fmt.Printf("    Source:     %s\n", e.Source)
			if e.Summary != "" {
				summary := e.Summary
				if len(summary) > 120 {
					summary = summary[:120] + "..."
				}
				fmt.Printf("    Summary:    %s\n", summary)
			}
		}

		fmt.Printf("\nTotal: %d entries\n", len(results))
		if limit > 0 && len(results) >= limit {
			fmt.Printf("(limited to %d results, use --limit to increase)\n", limit)
		}

		return nil
	},
}

func severityIcon(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "🔴"
	case "HIGH":
		return "🟠"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🔵"
	default:
		return "⚪"
	}
}

// Helper functions
func formatDuration(d time.Duration) string {
	if d < 24*time.Hour {
		return fmt.Sprintf("%.0f hours", d.Hours())
	}
	days := int(d.Hours() / 24)
	return fmt.Sprintf("%d days", days)
}

func init() {
	cveCmd := &cobra.Command{
		Use:   "cve",
		Short: "CVE management commands",
		Long:  `Manage and update the CVE database for JavaScript hunting.`,
	}

	cveListCmd.Flags().String("library", "", "Filter by library name (partial match)")
	cveListCmd.Flags().String("severity", "", "Filter by severity: critical, high, medium, low")
	cveListCmd.Flags().String("source", "", "Filter by source: retire.js, osv, npm, github, snare")
	cveListCmd.Flags().String("cve", "", "Search by CVE ID (e.g., CVE-2021-44228)")
	cveListCmd.Flags().String("format", "table", "Output format: table, json")
	cveListCmd.Flags().Int("limit", 50, "Maximum results to show (0 = unlimited)")

	cveCmd.AddCommand(cveUpdateCmd, cveStatusCmd, cveListCmd)
	GetRootCmd().AddCommand(cveCmd)
}