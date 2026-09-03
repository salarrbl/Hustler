package cli

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"go.mongodb.org/mongo-driver/bson"
	"hustler/internal/config"
	"hustler/internal/models"
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
	Long:  `Shows whether the daemon is running and detailed runtime information.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load("config.yaml")
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		if err := mongo.Connect(cfg.Mongo); err != nil {
			return fmt.Errorf("failed to connect to MongoDB: %w", err)
		}
		defer mongo.Disconnect()

		// Check PID file
		pidRunning := false
		var daemonPID int
		if pidBytes, err := os.ReadFile("/tmp/hustler-daemon.pid"); err == nil {
			if pid, err := strconv.Atoi(string(pidBytes)); err == nil {
				daemonPID = pid
				if proc, err := os.FindProcess(pid); err == nil {
					pidRunning = proc.Signal(syscall.Signal(0)) == nil
				}
			}
		}

		// Query job statistics
		jobColl := mongo.GetCollection("jobs")
		targetColl := mongo.GetCollection("targets")

		queuedCount, _ := jobColl.CountDocuments(nil, bson.M{"status": "queued"})
		totalTargets, _ := targetColl.CountDocuments(nil, bson.M{})

		// Get currently running job details
		cursor, _ := jobColl.Find(nil, bson.M{"status": "running"})
		var runningJobs []models.Job
		cursor.All(nil, &runningJobs)

		fmt.Printf("Hustler Daemon Status:\n")
		if pidRunning {
			color.New(color.FgGreen).Printf("  Process: RUNNING (PID %d)\n", daemonPID)
		} else {
			color.New(color.FgRed).Printf("  Process: NOT RUNNING\n")
		}

		fmt.Printf("\n📊 Active Jobs:\n")
		for _, job := range runningJobs {
			var target models.Target
			targetColl.FindOne(nil, bson.M{"_id": job.TargetID}).Decode(&target)
			step := job.CurrentStep
			if step == "" {
				elapsed := time.Since(*job.StartedAt)
				if elapsed < 30*time.Second {
					step = "🔍 Discovery"
				} else if elapsed < 5*time.Minute {
					step = "📄 Analyzing JS"
				} else {
					step = "💾 Storing"
				}
			}
			fmt.Printf("  🎯 %s [%s] → %s\n", target.Domain, target.Platform, step)
		}

		if queuedCount > 0 {
			fmt.Printf("\n📥 Queued (%d):\n", queuedCount)
			cursor, _ := jobColl.Find(nil, bson.M{"status": "queued"})
			var queuedJobs []models.Job
			cursor.All(nil, &queuedJobs)
			for _, job := range queuedJobs {
				var target models.Target
				targetColl.FindOne(nil, bson.M{"_id": job.TargetID}).Decode(&target)
				fmt.Printf("  ⏳ %s [%s]\n", target.Domain, target.Platform)
			}
		}

		fmt.Printf("\nTargets: %d total\n", totalTargets)

		// XSS Source Categories Reference
		fmt.Printf("\nXSS Risk Sources (DOM-based):\n")
		color.New(color.FgHiCyan).Printf("  # Source-XSS\n")
		fmt.Printf("    URL-based DOM Properties: location, location.href, location.pathname, location.search, location.hash, document.URL, document.documentURI, document.baseURI\n")
		fmt.Printf("    Navigation-based: window.name, document.referrer\n")
		fmt.Printf("    Communication: Ajax (XMLHTTPRequest/Fetch), WebSocket, Window Messaging\n")
		fmt.Printf("    Storage: Cookie, LocalStorage, SessionStorage\n")
		fmt.Printf("    Reference: https://domgo.at\n")

		if !pidRunning {
			color.New(color.FgRed).Printf("\n⚠ Daemon is not running! Start it with: hustler daemon start\n")
			color.New(color.FgRed).Printf("   Targets added with 'hustler target add' will NOT be processed.\n")
		}

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
