package cli

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"hustler/internal/config"
	"hustler/internal/watchdogs"
)

var watchdogsCmd = &cobra.Command{
	Use:   "watchdogs",
	Short: "Watchdogs integration commands",
	Long:  `Commands for syncing targets from Watchdogs (disabled by default).`,
}

var watchdogsSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync targets from Watchdogs MongoDB (requires explicit invocation)",
	Long: `Pull targets from Watchdogs' MongoDB into Hustler's target queue.
This command MUST be explicitly invoked - it never runs automatically.
Requires watchdogs.enabled=true in config.yaml.
Sync is incremental: only new domains (not already in Hustler) are added.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load("config.yaml")
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		if !cfg.Watchdogs.Enabled {
			return fmt.Errorf("Watchdogs sync is disabled - set watchdogs.enabled: true in config.yaml")
		}

		connector, err := watchdogs.NewConnector(cfg.Watchdogs, GetWorkerPool())
		if err != nil {
			return fmt.Errorf("failed to create Watchdogs connector: %w", err)
		}
		defer connector.Close()

		ctx := context.Background()
		log.Info().Msg("Starting Watchdogs sync...")

		count, err := connector.Sync(ctx)
		if err != nil {
			return fmt.Errorf("sync failed: %w", err)
		}

		log.Info().Int("synced", count).Msg("Watchdogs sync completed")
		fmt.Printf("Synced %d new targets from Watchdogs\n", count)
		return nil
	},
}

func init() {
	watchdogsCmd.AddCommand(watchdogsSyncCmd)
	GetRootCmd().AddCommand(watchdogsCmd)
}