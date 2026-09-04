package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"go.mongodb.org/mongo-driver/bson"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

// ProgramListCmd lists all programs grouped by platform
var ProgramListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all programs",
	Long:  `Shows all configured bug bounty programs grouped by platform.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		// Get all programs
		programColl := mongo.GetCollection("programs")
		cursor, err := programColl.Find(ctx, bson.M{})
		if err != nil {
			return fmt.Errorf("failed to query programs: %w", err)
		}
		defer cursor.Close(ctx)

		var programs []models.Program
		if err := cursor.All(ctx, &programs); err != nil {
			return fmt.Errorf("failed to decode programs: %w", err)
		}

		// Get all targets to associate with programs
		targetColl := mongo.GetCollection("targets")
		targetCursor, _ := targetColl.Find(ctx, bson.M{})
		defer targetCursor.Close(ctx)

		var targets []models.Target
		targetCursor.All(ctx, &targets)

		// Group targets by program
		programTargets := make(map[string][]models.Target)
		uncategorizedByPlatform := make(map[string][]models.Target)

		for _, t := range targets {
			if t.ProgramID == "" {
				platform := string(t.Platform)
				if platform == "" {
					platform = string(models.PlatformFreelance)
				}
				uncategorizedByPlatform[platform] = append(uncategorizedByPlatform[platform], t)
				continue
			}
			programTargets[t.ProgramID] = append(programTargets[t.ProgramID], t)
		}

		// Group programs by platform
		platformOrder := []string{
			string(models.PlatformHackerOne),
			string(models.PlatformBugcrowd),
			string(models.PlatformIntigriti),
			string(models.PlatformYesWeHack),
			string(models.PlatformOpenBugBounty),
			string(models.PlatformFreelance),
		}

		platformPrograms := make(map[string][]models.Program)
		for _, p := range programs {
			platformPrograms[p.Platform] = append(platformPrograms[p.Platform], p)
		}

		// Print tree
		for _, platform := range platformOrder {
			progs := platformPrograms[platform]
			hasTargets := false
			for _, p := range progs {
				if len(programTargets[p.ID]) > 0 {
					hasTargets = true
					break
				}
			}
			hasUncat := len(uncategorizedByPlatform[platform]) > 0

			if !hasTargets && !hasUncat {
				continue
			}

			fmt.Printf("\n%s %s Programs:\n", platformIcon(platform), platform)
			fmt.Println(strings.Repeat("─", 60))

			for _, p := range progs {
				pTargets := programTargets[p.ID]
				if len(pTargets) == 0 {
					// Print empty program
					fmt.Printf("  %s %s (0 domains)\n", color.New(color.FgHiWhite).Sprintf("◆"), p.Name)
					continue
				}
				domainList := make([]string, len(pTargets))
				for i, t := range pTargets {
					domainList[i] = t.Domain
				}

				fmt.Printf("  %s %s (%d domains)\n", color.New(color.FgHiWhite).Sprintf("◆"), p.Name, len(domainList))
				for _, d := range domainList {
					fmt.Printf("    %s\n", color.New(color.FgHiBlue).Sprintf("%s", d))
				}
			}

			// Print Uncategorized for this platform
			if hasUncat {
				fmt.Printf("  ⚠ Uncategorized (%d domains)\n", len(uncategorizedByPlatform[platform]))
				for _, t := range uncategorizedByPlatform[platform] {
					fmt.Printf("    %s\n", t.Domain)
				}
			}
		}

		return nil
	},
}

// ProgramAddCmd adds a new program
var ProgramAddCmd = &cobra.Command{
	Use:   "add <name> --platform <platform>",
	Short: "Add a new program",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		platform, _ := cmd.Flags().GetString("platform")

		if platform == "" {
			return fmt.Errorf("platform is required (hackerone, bugcrowd, intigriti, yeswehack, openbugbounty, freelance)")
		}

		ctx := context.Background()
		programColl := mongo.GetCollection("programs")

		// Check if program already exists
		var existing models.Program
		err := programColl.FindOne(ctx, bson.M{"name": name, "platform": platform}).Decode(&existing)
		if err == nil {
			fmt.Printf("Program already exists: %s [%s] (ID: %s)\n", name, platform, existing.ID)
			return nil
		}

		program := &models.Program{
			ID:       uuid.New().String(),
			Name:     name,
			Platform: platform,
			AddedAt:  time.Now(),
		}

		_, err = programColl.InsertOne(ctx, program)
		if err != nil {
			return fmt.Errorf("failed to add program: %w", err)
		}

		fmt.Printf("Added program: %s [%s] (ID: %s)\n", name, platform, program.ID)
		return nil
	},
}

// ProgramRemoveCmd removes a program and all its targets
var ProgramRemoveCmd = &cobra.Command{
	Use:   "remove <name> --platform <platform>",
	Short: "Remove a program and all its targets",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		platform, _ := cmd.Flags().GetString("platform")

		if platform == "" {
			return fmt.Errorf("platform is required (hackerone, bugcrowd, intigriti, yeswehack, openbugbounty, freelance)")
		}

		ctx := context.Background()

		// Find the program
		programColl := mongo.GetCollection("programs")
		var program models.Program
		err := programColl.FindOne(ctx, bson.M{"name": name, "platform": platform}).Decode(&program)
		if err != nil {
			return fmt.Errorf("program not found: %s [%s]", name, platform)
		}

		// First, remove all targets that reference this program
		targetColl := mongo.GetCollection("targets")
		filter := bson.M{"program_id": program.ID}
		result, err := targetColl.DeleteMany(ctx, filter)
		if err != nil {
			return fmt.Errorf("failed to remove targets for program: %w", err)
		}
		fmt.Printf("Removed %d targets associated with program: %s [%s]\n", result.DeletedCount, name, platform)

		// Now remove the program itself
		programResult, err := programColl.DeleteOne(ctx, bson.M{"_id": program.ID})
		if err != nil {
			return fmt.Errorf("failed to remove program: %w", err)
		}

		if programResult.DeletedCount == 0 {
			return fmt.Errorf("program not found: %s [%s]", name, platform)
		}

		fmt.Printf("Removed program: %s [%s] (ID: %s)\n", name, platform, program.ID)
		return nil
	},
}

// getOrCreateProgram finds or creates a program and returns its ID
func getOrCreateProgram(ctx context.Context, name, platform string) (string, error) {
	programColl := mongo.GetCollection("programs")

	// Check if exists
	var existing models.Program
	err := programColl.FindOne(ctx, bson.M{"name": name, "platform": platform}).Decode(&existing)
	if err == nil {
		return existing.ID, nil
	}

	// Create new
	program := &models.Program{
		ID:       uuid.New().String(),
		Name:     name,
		Platform: platform,
		AddedAt:  time.Now(),
	}

	result, err := programColl.InsertOne(ctx, program)
	if err != nil {
		return "", err
	}

	return result.InsertedID.(string), nil
}

// buildTargetTree builds a tree structure for API responses
func buildTargetTree(ctx context.Context) (map[string]*models.TargetTree, error) {
	targetColl := mongo.GetCollection("targets")
	programColl := mongo.GetCollection("programs")

	cursor, err := targetColl.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var targets []models.Target
	if err := cursor.All(ctx, &targets); err != nil {
		return nil, err
	}

	// Get all programs
	progCursor, _ := programColl.Find(ctx, bson.M{})
	var programs []models.Program
	progCursor.All(ctx, &programs)

	// Group by platform and program
	result := make(map[string]*models.TargetTree)

	// Define platform icons
	icons := map[string]string{
		"hackerone":     "◆",
		"bugcrowd":      "◇",
		"intigriti":     "⬢",
		"yeswehack":     "⚡",
		"openbugbounty": "⬟",
		"freelance":     "◆",
	}

	// Build program name lookup
	programNames := make(map[string]string)
	for _, p := range programs {
		programNames[p.ID] = p.Name
	}

	// Build tree
	for _, t := range targets {
		platform := string(t.Platform)
		if platform == "" {
			platform = "freelance"
		}

		if _, ok := result[platform]; !ok {
			result[platform] = &models.TargetTree{
				Platform: platform,
				Icon:     icons[platform],
				Programs: make(map[string][]models.Target),
			}
		}

		tree := result[platform]
		if t.ProgramID == "" {
			tree.Uncategorized = append(tree.Uncategorized, t)
		} else {
			// Find program name
			programName := t.ProgramID // fallback to ID if name not found
			if name, ok := programNames[t.ProgramID]; ok {
				programName = name
			}
			tree.Programs[programName] = append(tree.Programs[programName], t)
		}
	}

	return result, nil
}

func init() {
	// Program commands
	programCmd := &cobra.Command{
		Use:   "program",
		Short: "Manage programs",
		Long:  `Add, list, and remove bug bounty programs grouped by platform.`,
	}
	programCmd.AddCommand(ProgramListCmd, ProgramAddCmd, ProgramRemoveCmd)
	GetRootCmd().AddCommand(programCmd)

	// Platform flag for program add
	ProgramAddCmd.Flags().StringP("platform", "p", "", "Bug bounty platform (hackerone, bugcrowd, intigriti, yeswehack, openbugbounty, freelance)")
	_ = ProgramAddCmd.RegisterFlagCompletionFunc("platform", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"hackerone", "bugcrowd", "intigriti", "yeswehack", "openbugbounty", "freelance"}, cobra.ShellCompDirectiveNoFileComp
	})

	// Platform flag for program remove
	ProgramRemoveCmd.Flags().StringP("platform", "p", "", "Bug bounty platform (hackerone, bugcrowd, intigriti, yeswehack, openbugbounty, freelance)")
	_ = ProgramRemoveCmd.RegisterFlagCompletionFunc("platform", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"hackerone", "bugcrowd", "intigriti", "yeswehack", "openbugbounty", "freelance"}, cobra.ShellCompDirectiveNoFileComp
	})
}
