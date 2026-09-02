package daemon

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson"
	"hustler/internal/config"
	"hustler/internal/discovery"
	"hustler/internal/js"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

// Daemon manages the long-running background job processing
type Daemon struct {
	cfg     config.FullConfig
	running bool
	cancel  context.CancelFunc
}

// NewDaemon creates a new daemon instance
func NewDaemon(cfg config.FullConfig) *Daemon {
	return &Daemon{cfg: cfg}
}

// Start begins the daemon loop
func (d *Daemon) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel

	// Setup logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})

	// Save PID for stop command
	pidFile := "/tmp/hustler-daemon.pid"
	os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
	defer os.Remove(pidFile)

	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info().Msg("Shutdown signal received, stopping daemon...")
		d.stop()
	}()

	// Main polling loop
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			log.Info().Msg("Shutdown signal received, stopping daemon...")
			d.stop()
			return nil
		case <-ticker.C:
			if !d.running {
				return nil
			}
			d.pollJobs(ctx)
		case <-ctx.Done():
			return nil
		}
	}
}

// stop gracefully stops the daemon
func (d *Daemon) stop() {
	d.running = false
	if d.cancel != nil {
		d.cancel()
	}
	log.Info().Msg("Daemon stopped")
}

// pollJobs checks for new queued jobs and processes them
func (d *Daemon) pollJobs(ctx context.Context) {
	coll := mongo.GetCollection("jobs")

	// Find queued jobs
	cursor, err := coll.Find(ctx, bson.M{"status": string(models.JobStatusQueued)})
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

	log.Info().Int("queued_jobs_found", len(jobs)).Msg("Processing queued jobs")

	for i := range jobs {
		if !d.running {
			return
		}

		job := &jobs[i]
		d.processJob(ctx, job)
	}
}

// processJob processes a single hunt job
func (d *Daemon) processJob(ctx context.Context, job *models.Job) {
	// Update status to running
	now := time.Now()
	job.StartedAt = &now
	job.Status = models.JobStatusRunning
	d.updateJobStatus(job)

	log.Info().Str("job_id", job.ID).Str("target_id", job.TargetID).Msg("Job started")

	// Get target
	coll := mongo.GetCollection("targets")
	var target models.Target
	err := coll.FindOne(ctx, bson.M{"_id": job.TargetID}).Decode(&target)
	if err != nil {
		job.Status = models.JobStatusError
		job.Error = fmt.Errorf("target not found: %w", err).Error()
		d.updateJobStatus(job)
		log.Error().Err(err).Str("job_id", job.ID).Msg("Job failed: target not found")
		return
	}

	log.Info().Str("domain", target.Domain).Msg("Starting discovery for target")

	// Run discovery to find JS URLs and fetch HTML content
	httpClient := &http.Client{Timeout: 60 * time.Second}
	discoveryRunner := discovery.NewDiscoveryRunner(d.cfg.Discovery, httpClient)
	discoverResult, err := discoveryRunner.Discover(ctx, &target)
	if err != nil {
		job.Status = models.JobStatusError
		job.Error = fmt.Errorf("discovery failed: %w", err).Error()
		d.updateJobStatus(job)
		log.Error().Err(err).Str("domain", target.Domain).Msg("Job failed: discovery error")
		return
	}

	jsURLs := discoverResult.JSURLs
	htmlContent := discoverResult.HTMLContent

	log.Info().
		Str("domain", target.Domain).
		Int("js_urls_discovered", len(jsURLs)).
		Int("html_pages", len(htmlContent)).
		Msg("Discovery complete, starting analysis")

	if len(jsURLs) == 0 {
		log.Warn().Str("domain", target.Domain).Msg("No JS URLs discovered")
		job.Status = models.JobStatusDone
		d.updateJobStatus(job)
		return
	}

	// Run JS analysis pipeline
	jsModule := js.NewJSModule(d.cfg.JS, d.cfg.Sensitive)
	results, err := jsModule.FetchAndProcess(ctx, &target, jsURLs, htmlContent)
	if err != nil {
		job.Status = models.JobStatusError
		job.Error = fmt.Errorf("JS analysis failed: %w", err).Error()
		d.updateJobStatus(job)
		log.Error().Err(err).Str("domain", target.Domain).Msg("Job failed: analysis error")
		return
	}

	// Summarize results
	fetched := 0
	skipped := 0
	for _, r := range results {
		if r.Skipped {
			skipped++
		} else if r.Error == nil {
			fetched++
		}
	}

	log.Info().
		Str("domain", target.Domain).
		Int("total_discovered", len(jsURLs)).
		Int("fetched", fetched).
		Int("skipped", skipped).
		Msg("Hunt complete")

	// Update job status to done
	finishedAt := time.Now()
	job.FinishedAt = &finishedAt
	job.Status = models.JobStatusDone
	d.updateJobStatus(job)

	// Update target status
	coll.UpdateOne(ctx,
		bson.M{"_id": target.ID},
		bson.M{"$set": bson.M{
			"status":     models.StatusCompleted,
			"updated_at": time.Now(),
		}},
	)
}

// updateJobStatus updates a job's status in MongoDB
func (d *Daemon) updateJobStatus(job *models.Job) {
	ctx := context.Background()
	coll := mongo.GetCollection("jobs")
	update := bson.M{
		"status": job.Status,
	}
	if job.StartedAt != nil {
		update["started_at"] = *job.StartedAt
	}
	if job.FinishedAt != nil {
		update["finished_at"] = *job.FinishedAt
	}
	if job.Error != "" {
		update["error"] = job.Error
	}
	coll.UpdateOne(ctx,
		bson.M{"_id": job.ID},
		bson.M{"$set": update},
	)
}

// IsRunning checks if the daemon is currently running
func (d *Daemon) IsRunning() bool {
	return d.running
}