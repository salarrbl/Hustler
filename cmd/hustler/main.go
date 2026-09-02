package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
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
		log.Info().Msg("Shutdown signal received")
		os.Exit(0)
	}()

	log.Info().Msg("Starting Hustler daemon...")
	fmt.Println("Daemon started. Add targets with: hustler target add <domain>")
	fmt.Println("Status: hustler daemon status")
	fmt.Println("Stop: hustler daemon stop")

	ctx := context.Background()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		processQueuedJobs(ctx, cfg)
	}
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

	log.Info().Str("job_id", job.ID).Str("target_id", job.TargetID).Msg("Job started")

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

	log.Info().Str("domain", target.Domain).Msg("Starting discovery")

	// Discovery
	httpClient := &http.Client{Timeout: 60 * time.Second}
	discoveryRunner := discovery.NewDiscoveryRunner(cfg.Discovery, httpClient)
	jsURLs, err := discoveryRunner.DiscoverJSURLs(ctx, &target)
	if err != nil {
		job.Status = models.JobStatusError
		job.Error = fmt.Errorf("discovery failed: %w", err).Error()
		updateJobStatus(job)
		log.Error().Err(err).Str("domain", target.Domain).Msg("Discovery failed")
		return
	}

	log.Info().
		Str("domain", target.Domain).
		Int("js_urls_found", len(jsURLs)).
		Msg("Discovery complete")

	if len(jsURLs) == 0 {
		job.Status = models.JobStatusDone
		updateJobStatus(job)
		return
	}

	// Analyze
	jsModule := js.NewJSModule(cfg.JS, cfg.Sensitive)
	results, err := jsModule.FetchAndProcess(ctx, &target, jsURLs)
	if err != nil {
		job.Status = models.JobStatusError
		job.Error = fmt.Errorf("analysis failed: %w", err).Error()
		updateJobStatus(job)
		log.Error().Err(err).Str("domain", target.Domain).Msg("Analysis failed")
		return
	}

	fetched, skipped := summarizeResults(results)
	log.Info().
		Str("domain", target.Domain).
		Int("fetched", fetched).
		Int("skipped", skipped).
		Msg("Hunt complete")

	finishedAt := time.Now()
	job.FinishedAt = &finishedAt
	job.Status = models.JobStatusDone
	updateJobStatus(job)

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

	var queuedCount int64
	queuedCount, _ = jobColl.CountDocuments(nil, bson.M{"status": "queued"})

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
	fmt.Printf("  Process: %s\n", map[bool]string{true: "RUNNING", false: "NOT RUNNING"}[pidRunning])
	fmt.Printf("  Queued jobs: %d\n", queuedCount)
	fmt.Printf("  Running jobs: %d\n", runningCount)
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