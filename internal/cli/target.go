package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

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
	Short: "Add a target manually",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		ctx := context.Background()

		target := models.NewTarget(domain, models.SourceManual)
		coll := mongo.GetCollection("targets")
		_, err := coll.InsertOne(ctx, target)
		if err != nil {
			return fmt.Errorf("failed to insert target: %w", err)
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

		fmt.Printf("%-36s %-20s %-12s %-15s %s\n", "ID", "DOMAIN", "SOURCE", "STATUS", "ADDED AT")
		fmt.Println("--------------------------------------------------------------------------------")
		for _, t := range targets {
			fmt.Printf("%-36s %-20s %-12s %-15s %s\n",
				t.ID, t.Domain, t.Source, t.Status, t.AddedAt.Format(time.RFC3339))
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
}