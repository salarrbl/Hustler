package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"go.mongodb.org/mongo-driver/bson"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

var targetCmd = &cobra.Command{
	Use:   "target",
	Short: "Manage targets",
	Long:  `Add, list, and manage targets in Hustler.`,
}

var targetAddCmd = &cobra.Command{
	Use:   "add <domain>",
	Short: "Add a target manually and enqueue hunt job",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		platform, _ := cmd.Flags().GetString("platform")
		programName, _ := cmd.Flags().GetString("program")
		ctx := context.Background()

		// Check if target already exists
		coll := mongo.GetCollection("targets")
		var existing models.Target
		err := coll.FindOne(ctx, map[string]interface{}{"domain": domain}).Decode(&existing)
		if err == nil {
			return fmt.Errorf("target already exists: %s (ID: %s)", domain, existing.ID)
		}

		// Require platform and program
		if platform == "" || programName == "" {
			fmt.Println("Missing categorization. Specify where this target belongs:")
			fmt.Println("  hustler target add <domain> --platform hackerone --program walmart")
			fmt.Println("  hustler target add <domain> --platform freelance --program <client-name>")
			fmt.Println()
			fmt.Println("Existing programs: hustler program list")
			return fmt.Errorf("both --platform and --program are required")
		}

		// Get or create program
		programID, err := getOrCreateProgram(ctx, programName, platform)
		if err != nil {
			return fmt.Errorf("failed to create program: %w", err)
		}

		target := models.NewTarget(domain, models.SourceManual)
		target.Platform = models.TargetPlatform(platform)
		target.ProgramID = programID
		_, err = coll.InsertOne(ctx, target)
		if err != nil {
			return fmt.Errorf("failed to insert target: %w", err)
		}

		// Enqueue hunt job
		jobColl := mongo.GetCollection("jobs")
		job := &models.Job{
			ID:       uuid.New().String(),
			TargetID: target.ID,
			Status:   models.JobStatusQueued,
			QueuedAt: time.Now(),
			Source:   "manual",
		}
		_, err = jobColl.InsertOne(ctx, job)
		if err != nil {
			log.Warn().Err(err).Str("target_id", target.ID).Msg("Failed to enqueue hunt job")
			fmt.Printf("Warning: Failed to enqueue hunt job: %v\n", err)
			fmt.Printf("Make sure the daemon is running: hustler daemon start\n")
		} else {
			fmt.Printf("Enqueued hunt job: %s\n", job.ID)
		}

		log.Info().Str("domain", domain).Str("id", target.ID).Str("platform", platform).Str("program", programName).Msg("Target added successfully")
		fmt.Printf("Added target: %s (ID: %s) [%s / %s]\n", domain, target.ID, platform, programName)
		return nil
	},
}

var targetListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all targets grouped by platform",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		coll := mongo.GetCollection("targets")

		cursor, err := coll.Find(ctx, map[string]interface{}{})
		if err != nil {
			return fmt.Errorf("failed to query targets: %w", err)
		}
		defer cursor.Close(ctx)

		var targets []models.Target
		if err := cursor.All(ctx, &targets); err != nil {
			return fmt.Errorf("failed to decode targets: %w", err)
		}

		if len(targets) == 0 {
			fmt.Println("No targets found")
			return nil
		}

		// Group by platform and program
		byPlatform := make(map[string][]models.Target)
		var uncategorized []models.Target
		for _, t := range targets {
			platform := string(t.Platform)
			if platform == "" {
				platform = string(models.PlatformFreelance)
			}
			if t.ProgramID == "" {
				uncategorized = append(uncategorized, t)
			} else {
				byPlatform[platform] = append(byPlatform[platform], t)
			}
		}

		// Get programs for names
		programColl := mongo.GetCollection("programs")
		progCursor, _ := programColl.Find(ctx, bson.M{})
		var programs []models.Program
		progCursor.All(ctx, &programs)

		// Build program name lookup
		programNames := make(map[string]string)
		for _, p := range programs {
			programNames[p.ID] = p.Name
		}

		// Order platforms
		platformOrder := []string{
			string(models.PlatformHackerOne),
			string(models.PlatformBugcrowd),
			string(models.PlatformIntigriti),
			string(models.PlatformYesWeHack),
			string(models.PlatformOpenBugBounty),
			string(models.PlatformFreelance),
		}

		// Group by platform and program
		type platformProgramKey struct {
			platform string
			program  string
		}
		programTargets := make(map[platformProgramKey][]models.Target)

		for _, t := range targets {
			platform := string(t.Platform)
			if platform == "" {
				platform = string(models.PlatformFreelance)
			}
			key := platformProgramKey{platform: platform, program: t.ProgramID}
			programTargets[key] = append(programTargets[key], t)
		}

		for _, platform := range platformOrder {
			// Collect programs for this platform (only those with targets)
			platformProgs := make(map[string]bool)
			for key := range programTargets {
				if key.platform == platform && key.program != "" {
					platformProgs[key.program] = true
				}
			}

			// Skip platform if no programs with targets and no uncategorized targets with this platform
			hasUncatInPlatform := false
			for _, t := range uncategorized {
				p := string(t.Platform)
				if p == "" {
					p = string(models.PlatformFreelance)
				}
				if p == platform {
					hasUncatInPlatform = true
					break
				}
			}

			if len(platformProgs) == 0 && !hasUncatInPlatform {
				continue
			}

			fmt.Printf("\n%s %s:\n", color.New(color.FgHiCyan, color.Bold).Sprintf(platformIcon(platform)), platform)
			fmt.Println(strings.Repeat("─", 60))

			// Print programs
			for progID := range platformProgs {
				progName := progID
				if name, ok := programNames[progID]; ok {
					progName = name
				}
				targs := programTargets[platformProgramKey{platform: platform, program: progID}]
				fmt.Printf("  %s %s (%d)\n", color.New(color.FgHiWhite).Sprintf("◆"), progName, len(targs))
				for _, t := range targs {
					sc := statusColor(string(t.Status))
					src := sourceColor(string(t.Source))
					fmt.Printf("    %-36s %-12s %s\n",
						t.Domain,
						src.Sprintf("%s", t.Source),
						sc.Sprintf("%s", t.Status))
				}
			}

			// Print uncategorized for THIS platform only
			platformUncat := []models.Target{}
			for _, t := range uncategorized {
				p := string(t.Platform)
				if p == "" {
					p = string(models.PlatformFreelance)
				}
				if p == platform {
					platformUncat = append(platformUncat, t)
				}
			}
			if len(platformUncat) > 0 {
				fmt.Printf("  ⚠ Uncategorized (%d)\n", len(platformUncat))
				for _, t := range platformUncat {
					fmt.Printf("    %s\n", t.Domain)
				}
			}
		}
		return nil
	},
}

func platformIcon(platform string) string {
	switch platform {
	case string(models.PlatformHackerOne):
		return "◆"
	case string(models.PlatformBugcrowd):
		return "◇"
	case string(models.PlatformIntigriti):
		return "⬢"
	case string(models.PlatformYesWeHack):
		return "⚡"
	case string(models.PlatformOpenBugBounty):
		return "⬟"
	case string(models.PlatformFreelance):
		return "◆"
	default:
		return "◆"
	}
}

var targetRemoveCmd = &cobra.Command{
	Use:   "remove <domain-or-id>",
	Short: "Remove a target by domain or ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		input := args[0]
		ctx := context.Background()
		coll := mongo.GetCollection("targets")

		filter := map[string]interface{}{}
		if len(input) == 36 { // UUID length
			filter["_id"] = input
		} else {
			filter["domain"] = input
		}

		result, err := coll.DeleteOne(ctx, filter)
		if err != nil {
			return fmt.Errorf("failed to delete target: %w", err)
		}

		if result.DeletedCount == 0 {
			fmt.Println("Target not found")
			return nil
		}

		fmt.Printf("Removed target: %s\n", input)
		return nil
	},
}

// TargetImportCmd imports targets from a file
var TargetImportCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import multiple targets from a file (one domain per line, or JSON array)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		platform, _ := cmd.Flags().GetString("platform")
		programName, _ := cmd.Flags().GetString("program")
		ctx := context.Background()

		if platform == "" || programName == "" {
			return fmt.Errorf("both --platform and --program are required for bulk import")
		}

		// Get or create program
		programID, err := getOrCreateProgram(ctx, programName, platform)
		if err != nil {
			return fmt.Errorf("failed to create program: %w", err)
		}

		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}

		var domains []string
		// Try to parse as JSON first
		if strings.TrimSpace(string(content))[0] == '[' {
			if err := json.Unmarshal(content, &domains); err != nil {
				return fmt.Errorf("failed to parse JSON: %w", err)
			}
		} else {
			// Parse as lines
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					domains = append(domains, line)
				}
			}
		}

		if platform == "" {
			platform = string(models.PlatformFreelance)
		}

		coll := mongo.GetCollection("targets")
		added := 0
		skipped := 0

		for _, domain := range domains {
			var existing models.Target
			err := coll.FindOne(ctx, map[string]interface{}{"domain": domain}).Decode(&existing)
			if err == nil {
				fmt.Printf("Skipped (exists): %s\n", domain)
				skipped++
				continue
			}

			target := models.NewTarget(domain, models.SourceManual)
			target.Platform = models.TargetPlatform(platform)
			target.ProgramID = programID
			_, err = coll.InsertOne(ctx, target)
			if err != nil {
				fmt.Printf("Failed to add %s: %v\n", domain, err)
				continue
			}

			// Enqueue job
			jobColl := mongo.GetCollection("jobs")
			job := &models.Job{
				ID:       uuid.New().String(),
				TargetID: target.ID,
				Status:   models.JobStatusQueued,
				QueuedAt: time.Now(),
				Source:   "manual",
			}
			jobColl.InsertOne(ctx, job)

			fmt.Printf("Added: %s [Platform: %s]\n", domain, platform)
			added++
		}

		fmt.Printf("\nDone. Added: %d, Skipped: %d\n", added, skipped)
		return nil
	},
}

func init() {
	targetCmd.AddCommand(targetAddCmd, targetListCmd, targetRemoveCmd, TargetImportCmd)
	GetRootCmd().AddCommand(targetCmd)

	// Platform flag for target add
	targetAddCmd.Flags().StringP("platform", "p", "", "Bug bounty platform (hackerone, bugcrowd, intigriti, yeswehack, openbugbounty, freelance)")
	targetAddCmd.Flags().StringP("program", "", "", "Program name under the platform")
	TargetImportCmd.Flags().StringP("platform", "p", "", "Bug bounty platform for imported targets (hackerone, bugcrowd, intigriti, yeswehack, openbugbounty, freelance)")
	TargetImportCmd.Flags().StringP("program", "", "", "Program name under the platform")

	// Shell completion for platform
	_ = targetAddCmd.RegisterFlagCompletionFunc("platform", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"hackerone", "bugcrowd", "intigriti", "yeswehack", "openbugbounty", "freelance"}, cobra.ShellCompDirectiveNoFileComp
	})
	_ = TargetImportCmd.RegisterFlagCompletionFunc("platform", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"hackerone", "bugcrowd", "intigriti", "yeswehack", "openbugbounty", "freelance"}, cobra.ShellCompDirectiveNoFileComp
	})

	// Shell completion for target add
	_ = targetAddCmd.RegisterFlagCompletionFunc("domain", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{".com", ".io", ".org", ".net", ".xyz", ".app"}, cobra.ShellCompDirectiveNoFileComp
	})

	// Shell completion for target remove (list existing domains)
	_ = targetRemoveCmd.RegisterFlagCompletionFunc("domain-or-id", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
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
