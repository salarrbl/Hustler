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
	Long: `Download the latest CVE data from online sources.
The database is stored locally in ./data/cve/ and cached for 7 days.

Sources (default: retirejs, osv, kev, epss):
- retirejs: JavaScript library CVEs with version ranges
- osv:      osv.dev package ranges (npm seed list, CVSS via NVD enrich)
- nvd:      server products via NVD CPE cache (opt-in, slow without API key)
- kev:      CISA Known Exploited Vulnerabilities catalog
- epss:      FIRST EPSS exploit-probability scores

Examples:
  hustler cve update
  hustler cve update --source retirejs,osv
  hustler cve update --source nvd
  hustler cve update --source osv --packages jquery,lodash,axios`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("🔍 Initializing CVE module...\n")

		cfg := cve.DefaultCVEConfig()
		cfg.DataDir = "./data/cve"
		if key := os.Getenv("NVD_API_KEY"); key != "" {
			cfg.NVDAPIKey = key
		}

		mod, err := cve.NewCVEModule(cfg)
		if err != nil {
			return fmt.Errorf("failed to initialize CVE module: %w", err)
		}

		sources, _ := cmd.Flags().GetStringSlice("source")
		pkgFlag, _ := cmd.Flags().GetString("packages")
		var packages []string
		if pkgFlag != "" {
			for _, p := range strings.Split(pkgFlag, ",") {
				if p = strings.TrimSpace(p); p != "" {
					packages = append(packages, p)
				}
			}
		}

		fmt.Printf("📥 Downloading CVE database from online sources...\n")
		startTime := time.Now()

		result, err := mod.UpdateWithSources(context.Background(), sources, packages)
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
						fmt.Printf("    %s %s (%s)\n", severityIcon(e.Severity), e.CVEID, versionRangeString(e))
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
		fmt.Printf("\nSources:\n")
		fmt.Printf("  • retirejs: JavaScript library CVEs (ranges)\n")
		fmt.Printf("  • osv:      osv.dev package ranges + NVD CVSS enrich\n")
		fmt.Printf("  • nvd:      server products via NVD CPE (opt-in)\n")
		fmt.Printf("  • kev:      CISA exploited-vulns catalog\n")
		fmt.Printf("  • epss:      FIRST exploit-probability scores\n")
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

		// Per-source manifest
		if manifest, err := cve.ReadManifest(cfg.DataDir); err == nil {
			fmt.Printf("\n  Sources (last update: %s):\n", manifest.UpdatedAt)
			names := []string{"retirejs", "osv", "nvd", "kev", "epss"}
			for _, n := range names {
				st, ok := manifest.Sources[n]
				if !ok {
					fmt.Printf("    • %-9s never updated\n", n)
					continue
				}
				if st.Error != "" {
					fmt.Printf("    • %-9s error: %s\n", n, st.Error)
					continue
				}
				if n == "kev" || n == "epss" {
					fmt.Printf("    • %-9s ok (%s)\n", n, st.UpdatedAt)
				} else {
					fmt.Printf("    • %-9s %d entries (%s)\n", n, st.Entries, st.UpdatedAt)
				}
			}
			fmt.Printf("\n  Totals: %d libraries, %d entries\n", manifest.Libraries, manifest.Entries)
		}

		// Exploit-intel freshness
		for _, f := range []struct{ name, file, source string }{{"KEV", "kev.json", "kev"}, {"EPSS", "epss.json", "epss"}, {"NVD cache", "nvd_cache.json", "osv"}} {
			if fi, err := os.Stat(cfg.DataDir + "/" + f.file); err == nil {
				fmt.Printf("  %-9s %s (%s old)\n", f.name+":", f.file, formatDuration(time.Since(fi.ModTime())))
			} else {
				fmt.Printf("  %-9s missing (run: hustler cve update --source %s)\n", f.name+":", f.source)
			}
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
			fmt.Printf("    Affected:   %s\n", versionRangeString(e))
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

var cveScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Live CVE scan of a target (no MongoDB needed)",
	Long: `Fetch the target homepage, fingerprint server tech from headers/body,
discover <script src> URLs, fetch them, fingerprint JS libraries, and match
everything against the local CVE database with KEV/EPSS exploit triage.

Detection is passive (plain GETs). No exploit payloads are ever sent.

Examples:
  hustler cve scan --target example.com
  hustler cve scan --target https://example.com --online --json
  hustler cve scan --target example.com --js-limit 30 --min-confidence 0.7`,
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		if target == "" {
			return fmt.Errorf("--target is required (e.g. --target example.com)")
		}
		jsLimit, _ := cmd.Flags().GetInt("js-limit")
		online, _ := cmd.Flags().GetBool("online")
		asJSON, _ := cmd.Flags().GetBool("json")
		minConf, _ := cmd.Flags().GetFloat64("min-confidence")

		cfg := cve.DefaultCVEConfig()
		cfg.DataDir = "./data/cve"
		if minConf > 0 {
			cfg.MinConfidence = minConf
		}
		mod, err := cve.NewCVEModule(cfg)
		if err != nil {
			return fmt.Errorf("failed to initialize CVE module: %w", err)
		}
		if len(mod.GetLocalDB()) == 0 {
			fmt.Printf("⚠ Local CVE database is empty — run `hustler cve update` first for full coverage.\n\n")
		}

		opts := cve.DefaultScanOptions(cfg.DataDir)
		opts.EnableOnlineLookup = online
		opts.MinConfidence = cfg.MinConfidence

		ctx := context.Background()
		findings, libs, techs, err := cve.ScanTargetLive(ctx, mod, opts, target, jsLimit)
		if err != nil {
			return err
		}

		if asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]interface{}{
				"target":   target,
				"libs":     libs,
				"tech":     techs,
				"findings": findings,
			})
		}

		fmt.Printf("\n🎯 %s\n", target)
		fmt.Printf("   Detected: %d libraries, %d server techs\n", len(libs), len(techs))
		if len(techs) > 0 {
			fmt.Printf("\n🖥 Server tech:\n")
			for _, t := range techs {
				ver := t.Version
				if ver == "" {
					ver = "(version unknown)"
				}
				fmt.Printf("   • %s %s  [%s]\n", t.Tech, ver, t.Evidence)
			}
		}
		if len(libs) > 0 {
			fmt.Printf("\n📦 JS libraries:\n")
			for _, l := range libs {
				fmt.Printf("   • %s@%s  (%s)\n", l.Library, l.Version, l.Origin)
			}
		}
		if len(findings) == 0 {
			fmt.Printf("\n✅ No CVE matches above confidence %.2f.\n", cfg.MinConfidence)
			return nil
		}
		fmt.Printf("\n🚨 CVE matches (%d):\n", len(findings))
		fmt.Println("════════════════════════════════════════════════════════════════════════════════════")
		for i, f := range findings {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("  %s %s  %s\n", severityIcon(f.Severity), f.CVEID, exploitBadge(f.Exploitable, f.KEV, f.EPSS))
			fmt.Printf("    Library:    %s@%s\n", f.Library, f.DetectedVer)
			fmt.Printf("    Severity:   %s", f.Severity)
			if f.CVSS > 0 {
				fmt.Printf(" (CVSS %.1f)", f.CVSS)
			}
			fmt.Printf("  Confidence: %.2f\n", f.Confidence)
			if f.FixedVer != "" {
				fmt.Printf("    Fixed in:   >= %s\n", f.FixedVer)
			}
			if f.Source != "" {
				fmt.Printf("    Source:     %s\n", f.Source)
			}
			if f.Summary != "" {
				summary := f.Summary
				if len(summary) > 150 {
					summary = summary[:150] + "..."
				}
				fmt.Printf("    Summary:    %s\n", summary)
			}
			if f.Nuclei != "" && (f.Exploitable == "confirmed" || f.Exploitable == "likely") {
				fmt.Printf("    Verify:     %s\n", f.Nuclei)
			}
		}
		return nil
	},
}

var cveVerifyCmd = &cobra.Command{
	Use:   "verify <CVE-ID>",
	Short: "Show everything known about one CVE + how to verify it",
	Long: `Look up a CVE/GHSA/OSV ID in the local database and print affected
libraries and version ranges, KEV/EPSS exploitability, safe verification
steps, the matching nuclei template, and remediation.

Examples:
  hustler cve verify CVE-2021-23337
  hustler cve verify GHSA-4xc9-xhrj-v574 --json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		asJSON, _ := cmd.Flags().GetBool("json")
		dataDir := "./data/cve"

		db, err := cve.LoadEntriesFromDir(dataDir)
		if err != nil {
			return fmt.Errorf("failed to load local DB (run `hustler cve update` first): %w", err)
		}
		records := cve.FindByCVE(db, id)
		if len(records) == 0 {
			return fmt.Errorf("no records for %s in the local database", id)
		}
		kev := cve.LoadKEVMap(dataDir)
		epss := cve.LoadEPSSMap(dataDir)

		type enriched struct {
			Entry cve.LocalCVEEntry
			Verdict cve.ExploitAssessment
		}
		var out []enriched
		for _, e := range records {
			out = append(out, enriched{Entry: e, Verdict: cve.AssessExploitability(e, kev, epss)})
		}

		if asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		}

		first := out[0]
		fmt.Printf("\n%s %s  %s\n", severityIcon(first.Entry.Severity), first.Entry.CVEID, exploitBadge(first.Verdict.Exploitable, first.Verdict.KEV, first.Verdict.EPSS))
		fmt.Printf("  Severity: %s", first.Entry.Severity)
		if first.Entry.CVSS > 0 {
			fmt.Printf(" (CVSS %.1f)", first.Entry.CVSS)
		}
		fmt.Printf("\n")
		if len(first.Entry.CWE) > 0 {
			fmt.Printf("  CWE:      %s\n", strings.Join(first.Entry.CWE, ", "))
		}
		if first.Entry.Summary != "" {
			fmt.Printf("  Summary:  %s\n", first.Entry.Summary)
		}
		fmt.Printf("\n  Affected (%d records):\n", len(out))
		for _, r := range out {
			rng := versionRangeString(r.Entry)
			fmt.Printf("    • %-16s %-24s [%s]", r.Entry.Library, rng, r.Entry.Source)
			if r.Entry.FixedVersion != "" {
				fmt.Printf(" fix: >= %s", r.Entry.FixedVersion)
			}
			fmt.Printf("\n")
		}
		v := first.Verdict
		fmt.Printf("\n  Exploitability: %s\n", v.Exploitable)
		if v.EPSS > 0 {
			fmt.Printf("  EPSS: %.3f\n", v.EPSS)
		}
		if v.KEV {
			fmt.Printf("  KEV: listed (actively exploited)\n")
		}
		if v.HasPoC && v.PoCRef != "" {
			fmt.Printf("  PoC:  %s\n", v.PoCRef)
		}
		if v.Note != "" {
			fmt.Printf("  Note: %s\n", v.Note)
		}
		if len(v.VerifySteps) > 0 {
			fmt.Printf("\n  Safe verification:\n")
			for i, s := range v.VerifySteps {
				fmt.Printf("    %d. %s\n", i+1, s)
			}
		}
		if v.Nuclei != "" {
			fmt.Printf("\n  Nuclei: %s\n", v.Nuclei)
		}
		fmt.Printf("\n  Remediation: upgrade affected packages to the fixed releases above.\n")
		return nil
	},
}

func versionRangeString(e cve.LocalCVEEntry) string {
	below := e.FixedVersion
	if below == "" {
		below = e.MaxVersion
	}
	switch {
	case e.AtOrAbove != "" && below != "":
		if e.AtOrAbove == below {
			return "== " + below
		}
		return ">= " + e.AtOrAbove + ", < " + below
	case e.AtOrAbove != "":
		return ">= " + e.AtOrAbove
	case below != "":
		return "< " + below
	default:
		return "(version range unknown)"
	}
}

func exploitBadge(verdict string, kev bool, epss float64) string {
	switch verdict {
	case "confirmed":
		return "🎯 CONFIRMED (KEV)"
	case "likely":
		if epss >= 0.5 {
			return fmt.Sprintf("⚠ LIKELY (EPSS %.2f)", epss)
		}
		return "⚠ LIKELY (PoC)"
	case "possible":
		return "• possible"
	default:
		return "○ unknown"
	}
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
	cveListCmd.Flags().String("source", "", "Filter by source: retire.js, osv.dev, nvd, seed")
	cveListCmd.Flags().String("cve", "", "Search by CVE ID (e.g., CVE-2021-44228)")
	cveListCmd.Flags().String("format", "table", "Output format: table, json")
	cveListCmd.Flags().Int("limit", 50, "Maximum results to show (0 = unlimited)")

	cveUpdateCmd.Flags().StringSlice("source", nil, "Sources to update: retirejs,osv,nvd,kev,epss (default all but nvd)")
	cveUpdateCmd.Flags().String("packages", "", "Comma-separated npm packages for the osv source (overrides seed)")

	cveScanCmd.Flags().String("target", "", "Target domain or URL (required)")
	cveScanCmd.Flags().Int("js-limit", 20, "Max <script> files to fetch")
	cveScanCmd.Flags().Bool("online", false, "Confirm npm package@version hits via live osv.dev queries")
	cveScanCmd.Flags().Bool("json", false, "Output as JSON")
	cveScanCmd.Flags().Float64("min-confidence", 0, "Minimum confidence to report (default from module: 0.5)")

	cveVerifyCmd.Flags().Bool("json", false, "Output as JSON")

	cveCmd.AddCommand(cveUpdateCmd, cveStatusCmd, cveListCmd, cveScanCmd, cveVerifyCmd)
	GetRootCmd().AddCommand(cveCmd)
}