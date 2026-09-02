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

		var queuedCount int64
		queuedCount, _ = jobColl.CountDocuments(nil, bson.M{"status": "queued"})

		var runningCount int64
		runningCount, _ = jobColl.CountDocuments(nil, bson.M{"status": "running"})

		var doneCount int64
		doneCount, _ = jobColl.CountDocuments(nil, bson.M{"status": "done"})

		var errorCount int64
		errorCount, _ = jobColl.CountDocuments(nil, bson.M{"status": "error"})

		var totalTargets int64
		targetColl := mongo.GetCollection("targets")
		totalTargets, _ = targetColl.CountDocuments(nil, bson.M{})

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

		fmt.Printf("\nDaemon Function:\n")
		fmt.Printf("  • Polls MongoDB every 3 seconds for queued hunt jobs\n")
		fmt.Printf("  • Discovery: Katana (active crawl) + Wayback CDX + Gau (disabled)\n")
		fmt.Printf("  • Analysis: Secret scanning, Sink analysis, Endpoint extraction, Param extraction\n")
		fmt.Printf("  • BLH checks, CVE mapping, Library fingerprinting, Sensitive endpoint check (disabled)\n")
		fmt.Printf("  • Stores findings in MongoDB collections\n")

		fmt.Printf("\nJob Statistics:\n")
		color.New(color.FgYellow).Printf("  Queued:   %d\n", queuedCount)
		color.New(color.FgBlue).Printf("  Running:  %d\n", runningCount)
		color.New(color.FgGreen).Printf("  Completed: %d\n", doneCount)
		color.New(color.FgRed).Printf("  Errors:   %d\n", errorCount)

		if len(runningJobs) > 0 {
			fmt.Printf("\nCurrently Processing (%d jobs):\n", len(runningJobs))
			for _, job := range runningJobs {
				// Get target domain
				var target models.Target
				targetColl.FindOne(nil, bson.M{"_id": job.TargetID}).Decode(&target)
				fmt.Printf("  • Job: %s\n", job.ID)
				fmt.Printf("    Target: %s (%s)\n", target.Domain, target.ID)
				fmt.Printf("    Started: %s\n", job.StartedAt.Format(time.RFC3339))
				fmt.Printf("    Phase: ")
				// Try to infer phase from job start time
				elapsed := time.Since(*job.StartedAt)
				if elapsed < 30*time.Second {
					fmt.Printf("Discovery (Katana/Wayback/Gau)\n")
				} else if elapsed < 5*time.Minute {
					fmt.Printf("Fetching & Analyzing JS files\n")
				} else {
					fmt.Printf("Finalizing / Storing findings\n")
				}
			}
		}

		// Show queued jobs
		if queuedCount > 0 {
			cursor, _ := jobColl.Find(nil, bson.M{"status": "queued"})
			var queuedJobs []models.Job
			cursor.All(nil, &queuedJobs)
			if len(queuedJobs) > 0 {
				fmt.Printf("\nQueued Jobs (%d):\n", len(queuedJobs))
				for _, job := range queuedJobs {
					var target models.Target
					targetColl.FindOne(nil, bson.M{"_id": job.TargetID}).Decode(&target)
					fmt.Printf("  • %s → %s (queued %s)\n", job.ID[:8], target.Domain, job.QueuedAt.Format("15:04:05"))
				}
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
