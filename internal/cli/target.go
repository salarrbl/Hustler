package cli

import (
	"context"
	"fmt"
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
		ctx := context.Background()

		// Check if target already exists
		coll := mongo.GetCollection("targets")
		var existing models.Target
		err := coll.FindOne(ctx, map[string]interface{}{"domain": domain}).Decode(&existing)
		if err == nil {
			return fmt.Errorf("target already exists: %s (ID: %s)", domain, existing.ID)
		}

		target := models.NewTarget(domain, models.SourceManual)
		_, err = coll.InsertOne(ctx, target)
		if err != nil {
			return fmt.Errorf("failed to insert target: %w", err)
		}

		// Enqueue hunt job (write to MongoDB for daemon to pick up)
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

		log.Info().Str("domain", domain).Str("id", target.ID).Msg("Target added successfully")
		fmt.Printf("Added target: %s (ID: %s)\n", domain, target.ID)
		return nil
	},
}

var targetListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all targets",
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

		// Header
		fmt.Printf("%-36s %-20s %-12s %-15s %s\n",
			color.New(color.Bold).Sprintf("ID"),
			color.New(color.Bold).Sprintf("DOMAIN"),
			color.New(color.Bold).Sprintf("SOURCE"),
			color.New(color.Bold).Sprintf("STATUS"),
			color.New(color.Bold).Sprintf("ADDED AT"),
		)
		fmt.Println("--------------------------------------------------------------------------------")

		for _, t := range targets {
			sc := statusColor(string(t.Status))
			src := sourceColor(string(t.Source))
			fmt.Printf("%-36s %-20s ", t.ID, t.Domain)
			fmt.Printf("%-12s ", src.Sprintf("%s", t.Source))
			fmt.Printf("%-15s", sc.Sprintf("%s", t.Status))
			fmt.Printf("%s\n", t.AddedAt.Format(time.RFC3339))
		}
		return nil
	},
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

func init() {
	targetCmd.AddCommand(targetAddCmd, targetListCmd, targetRemoveCmd)
	GetRootCmd().AddCommand(targetCmd)

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
