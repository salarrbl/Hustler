package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson"
	"hustler/internal/cli"
	"hustler/internal/config"
	"hustler/internal/discovery"
	"hustler/internal/js"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

func main() {
	configPath := "config.yaml"
	for i, arg := range os.Args {
		if arg == "-c" || arg == "--config" {
			if i+1 < len(os.Args) {
				configPath = os.Args[i+1]
			}
		}
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Setup logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})

	// Connect to MongoDB
	if err := mongo.Connect(cfg.Mongo); err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to MongoDB")
	}
	defer mongo.Disconnect()

	log.Info().Str("database", cfg.Mongo.Database).Msg("Connected to MongoDB")

	// Check if running as daemon
	if len(os.Args) > 1 && os.Args[1] == "daemon" {
		if len(os.Args) > 2 {
			switch os.Args[2] {
			case "start":
				runDaemon(cfg)
				return
			case "status":
				runDaemonStatus()
				return
			case "stop":
				runDaemonStop()
				return
			}
		}
	}

	// CLI mode - use cobra commands
	if err := cli.Execute(); err != nil {
		log.Fatal().Err(err).Msg("Command failed")
	}
}

func runDaemon(cfg *config.FullConfig) {
	// Save PID
	os.WriteFile("/tmp/hustler-daemon.pid", []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
	defer os.Remove("/tmp/hustler-daemon.pid")

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n🛡️  Shutting down Hustler daemon...")
		os.Exit(0)
	}()

	fmt.Println("🛡️  Hustler Daemon Initializing...")
	fmt.Println("✅ Connected to MongoDB")
	fmt.Println("\n⚡ Daemon started. Ready to process hunt jobs.")
	fmt.Println("   Commands:")
	fmt.Println("     • Add target:  hustler target add <domain> [--platform hackerone]")
	fmt.Println("     • Status:      hustler daemon status")
	fmt.Println("     • Stop:        hustler daemon stop")

	ctx := context.Background()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		processQueuedJobs(ctx, cfg)
	}
}

// phaseCounter tracks per-target phase counts for summary display
type phaseCounter struct {
	secrets  atomic.Int64
	sinks    atomic.Int64
	endpoints atomic.Int64
	params   atomic.Int64
	blh      atomic.Int64
	cves     atomic.Int64
	fetched  atomic.Int64
	skipped  atomic.Int64
}

func processQueuedJobs(ctx context.Context, cfg *config.FullConfig) {
	jobColl := mongo.GetCollection("jobs")
	cursor, err := jobColl.Find(ctx, bson.M{"status": string(models.JobStatusQueued)})
	if err != nil {
		log.Warn().Err(err).Msg("Failed to query queued jobs")
		return
	}
	defer cursor.Close(ctx)

	var jobs []models.Job
	if err := cursor.All(ctx, &jobs); err != nil {
		log.Warn().Err(err).Msg("Failed to decode jobs")
		return
	}

	if len(jobs) == 0 {
		return
	}

	log.Info().Int("queued_jobs", len(jobs)).Msg("Processing queued jobs")

	for i := range jobs {
		go processJob(ctx, &jobs[i], cfg)
	}
}

func processJob(ctx context.Context, job *models.Job, cfg *config.FullConfig) {
	// Update to running
	now := time.Now()
	job.StartedAt = &now
	job.Status = models.JobStatusRunning
	updateJobStatus(job)

	// Get target
	targetColl := mongo.GetCollection("targets")
	var target models.Target
	err := targetColl.FindOne(ctx, bson.M{"_id": job.TargetID}).Decode(&target)
	if err != nil {
		job.Status = models.JobStatusError
		job.Error = fmt.Errorf("target not found: %w", err).Error()
		updateJobStatus(job)
		log.Error().Err(err).Str("target_id", job.TargetID).Msg("Target not found")
		return
	}

	startTime := time.Now()
	pc := &phaseCounter{}

	fmt.Printf("\n🎯 Hunt started: %s [%s]\n", target.Domain, target.Platform)

	// Discovery - Katana
	job.CurrentStep = "discovery.katana"
	updateJobStatus(job)
	fmt.Printf("🔍 [katana] Crawling...\n")
	httpClient := &http.Client{Timeout: 60 * time.Second}
	discoveryRunner := discovery.NewDiscoveryRunner(cfg.Discovery, httpClient)
	jsURLs, err := discoveryRunner.DiscoverJSURLs(ctx, &target)
	if err != nil {
		job.Status = models.JobStatusError
		job.Error = fmt.Errorf("discovery failed: %w", err).Error()
		updateJobStatus(job)
		fmt.Printf("❌ [katana] Failed: %v\n", err)
		return
	}
	fmt.Printf("✅ [katana] Found %d JS URLs\n", len(jsURLs))

	// Discovery - Wayback CDX
	job.CurrentStep = "discovery.wayback"
	updateJobStatus(job)
	fmt.Printf("🔍 [wayback] Querying CDX...\n")
	waybackURLs, wbErr := discoveryRunner.DiscoverViaWaybackCDX(ctx, &target)
	if wbErr != nil {
		fmt.Printf("❌ [wayback] Failed: %v\n", wbErr)
	} else {
		fmt.Printf("✅ [wayback] Found %d JS URLs\n", len(waybackURLs))
		// Merge URLs
		jsURLs = append(jsURLs, waybackURLs...)
	}

	if len(jsURLs) == 0 {
		job.Status = models.JobStatusDone
		updateJobStatus(job)
		elapsed := time.Since(startTime)
		fmt.Printf("🏁 Hunt complete: %s (no JS URLs found — %.0fs)\n", target.Domain, elapsed.Seconds())
		return
	}

	// Fetch and analyze
	job.CurrentStep = "analyzing.js"
	updateJobStatus(job)
	fmt.Printf("📥 Fetching %d unique JS files...\n", len(jsURLs))
	jsModule := js.NewJSModule(cfg.JS, cfg.Sensitive)
	results, err := jsModule.FetchAndProcessWithCounter(ctx, &target, jsURLs, nil, pc)
	if err != nil {
		job.Status = models.JobStatusError
		job.Error = fmt.Errorf("analysis failed: %w", err).Error()
		updateJobStatus(job)
		fmt.Printf("❌ Analysis failed: %v\n", err)
		return
	}

	fetched, skipped := summarizeResults(results)
	fmt.Printf("✅ Fetched %d files (%d skipped, already known)\n", fetched, skipped)

	// Phase results
	secretsCount := pc.secrets.Load()
	sinksCount := pc.sinks.Load()
	endpointsCount := pc.endpoints.Load()
	paramsCount := pc.params.Load()
	blhCount := pc.blh.Load()
	cveCount := pc.cves.Load()

	fmt.Printf("🔬 [secrets]   %d findings\n", secretsCount)
	fmt.Printf("🔬 [sinks]     %d findings\n", sinksCount)
	fmt.Printf("🔬 [endpoints] %d found\n", endpointsCount)
	fmt.Printf("🔬 [params]    %d found\n", paramsCount)
	fmt.Printf("🔬 [blh]       %d candidates\n", blhCount)
	fmt.Printf("🔬 [cve]       %d matches\n", cveCount)

	// Complete
	finishedAt := time.Now()
	job.FinishedAt = &finishedAt
	job.Status = models.JobStatusDone
	job.CurrentStep = "complete"
	updateJobStatus(job)

	elapsed := time.Since(startTime)
	fmt.Printf("🏁 Hunt complete: %s (%.0fs)\n", target.Domain, elapsed.Seconds())

	targetColl.UpdateOne(ctx,
		bson.M{"_id": target.ID},
		bson.M{"$set": bson.M{"status": models.StatusCompleted, "updated_at": time.Now()}},
	)
}

func updateJobStatus(job *models.Job) {
	ctx := context.Background()
	coll := mongo.GetCollection("jobs")
	update := bson.M{"status": job.Status}
	if job.StartedAt != nil {
		update["started_at"] = *job.StartedAt
	}
	if job.FinishedAt != nil {
		update["finished_at"] = *job.FinishedAt
	}
	if job.Error != "" {
		update["error"] = job.Error
	}
	if job.CurrentStep != "" {
		update["current_step"] = job.CurrentStep
	}
	coll.UpdateOne(ctx, bson.M{"_id": job.ID}, bson.M{"$set": update})
}

func summarizeResults(results []js.JSFileResult) (fetched, skipped int) {
	for _, r := range results {
		if r.Skipped {
			skipped++
		} else if r.Error == nil {
			fetched++
		}
	}
	return
}

func runDaemonStatus() {
	cfg, err := config.Load("config.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	if err := mongo.Connect(cfg.Mongo); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to MongoDB: %v\n", err)
		os.Exit(1)
	}
	defer mongo.Disconnect()

	jobColl := mongo.GetCollection("jobs")

	queuedCount, _ := jobColl.CountDocuments(nil, bson.M{"status": "queued"})

	var runningCount int64
	runningCount, _ = jobColl.CountDocuments(nil, bson.M{"status": "running"})

	pidRunning := false
	if pidBytes, err := os.ReadFile("/tmp/hustler-daemon.pid"); err == nil {
		if pid, err := strconv.Atoi(string(pidBytes)); err == nil {
			if proc, err := os.FindProcess(pid); err == nil {
				pidRunning = proc.Signal(syscall.Signal(0)) == nil
			}
		}
	}

	fmt.Printf("Hustler Daemon Status:\n")
	if pidRunning {
		color.New(color.FgGreen).Printf("  Process: RUNNING (PID %d)\n", daemonPID)
	} else {
		color.New(color.FgRed).Printf("  Process: NOT RUNNING\n")
	}

	fmt.Printf("\n📊 Active Jobs:\n")
	cursor, _ := jobColl.Find(nil, bson.M{"status": "running"})
	var runningJobs []models.Job
	cursor.All(nil, &runningJobs)
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
}

func runDaemonStop() {
	pidBytes, err := os.ReadFile("/tmp/hustler-daemon.pid")
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon PID file not found, is the daemon running?\n")
		os.Exit(1)
	}

	pid, err := strconv.Atoi(string(pidBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid PID in file: %v\n", err)
		os.Exit(1)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to find process: %v\n", err)
		os.Exit(1)
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "failed to send signal: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Sent SIGTERM to daemon (PID %d). It should stop gracefully.\n", pid)
}
