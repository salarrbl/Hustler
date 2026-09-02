package cli

import (
	"github.com/spf13/cobra"
	"hustler/internal/jobqueue"
)

var rootCmd = &cobra.Command{
	Use:   "hustler",
	Short: "Hustler - Bug bounty automation for JavaScript hunting",
	Long: `Hustler is a Go-based bug bounty automation tool focused on deep JavaScript analysis.
It ingests targets from Watchdogs or manual entry, then runs targeted analysis modules
starting with JavaScript hunting (secrets, endpoints, source/sink analysis, BLH, library CVEs).`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var workerPool *jobqueue.WorkerPool

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringP("config", "c", "config.yaml", "Config file path")
	rootCmd.PersistentFlags().StringP("mongo-uri", "", "", "MongoDB URI (overrides config)")
	rootCmd.PersistentFlags().StringP("mongo-db", "", "", "MongoDB database (overrides config)")
}

func GetRootCmd() *cobra.Command {
	return rootCmd
}

func SetWorkerPool(wp *jobqueue.WorkerPool) {
	workerPool = wp
}

func GetWorkerPool() *jobqueue.WorkerPool {
	return workerPool
}