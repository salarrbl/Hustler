package cli

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"

	"hustler/internal/config"
	"hustler/internal/mongo"
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Daemon management commands",
	Long:  `Commands for managing the Hustler background daemon.`,
}

var daemonStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the background daemon",
	Long: `Starts the Hustler daemon that processes hunt jobs in the background. 
This command runs indefinitely until killed with Ctrl+C.

Usage:
  hustler daemon start          # Start daemon in foreground
  hustler daemon start --detach # Start daemon in background (requires tmux/screen)

After starting the daemon, add targets and they will be processed automatically:
  hustler target add <domain>
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Fork to daemon process
		os.Args = append([]string{"hustler", "daemon"}, args...)
		return nil
	},
}

var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show daemon status",
	Long:  `Shows whether the daemon is running and basic stats.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load("config.yaml")
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		if err := mongo.Connect(cfg.Mongo); err != nil {
			return fmt.Errorf("failed to connect to MongoDB: %w", err)
		}
		defer mongo.Disconnect()

		jobColl := mongo.GetCollection("jobs")

		var queuedCount int64
		queuedCount, err = jobColl.CountDocuments(nil, map[string]interface{}{
			"status": "queued",
		})
		if err != nil {
			return fmt.Errorf("failed to count queued jobs: %w", err)
		}

		var runningCount int64
		runningCount, err = jobColl.CountDocuments(nil, map[string]interface{}{
			"status": "running",
		})
		if err != nil {
			return fmt.Errorf("failed to count running jobs: %w", err)
		}

		pidRunning := false
		if pidBytes, err := os.ReadFile("/tmp/hustler-daemon.pid"); err == nil {
			if pid, err := strconv.Atoi(string(pidBytes)); err == nil {
				if proc, err := os.FindProcess(pid); err == nil {
					pidRunning = proc.Signal(syscall.Signal(0)) == nil
				}
			}
		}

		fmt.Printf("Hustler Daemon Status:\n")
		fmt.Printf("  Process: %s\n", map[bool]string{true: "RUNNING", false: "NOT RUNNING"}[pidRunning])
		fmt.Printf("  Queued jobs: %d\n", queuedCount)
		fmt.Printf("  Running jobs: %d\n", runningCount)

		return nil
	},
}

var daemonStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the daemon",
	Long:  `Sends a graceful shutdown signal to the running daemon.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		pidBytes, err := os.ReadFile("/tmp/hustler-daemon.pid")
		if err != nil {
			return fmt.Errorf("daemon PID file not found, is the daemon running?")
		}

		pid, err := strconv.Atoi(string(pidBytes))
		if err != nil {
			return fmt.Errorf("invalid PID in file: %w", err)
		}

		proc, err := os.FindProcess(pid)
		if err != nil {
			return fmt.Errorf("failed to find process: %w", err)
		}

		if err := proc.Signal(syscall.SIGTERM); err != nil {
			return fmt.Errorf("failed to send signal: %w", err)
		}

		fmt.Printf("Sent SIGTERM to daemon (PID %d). It should stop gracefully.\n", pid)
		return nil
	},
}

func init() {
	daemonCmd.AddCommand(daemonStartCmd, daemonStatusCmd, daemonStopCmd)
	GetRootCmd().AddCommand(daemonCmd)
}