package jobqueue

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson"
	"hustler/internal/config"
	"hustler/internal/discovery"
	"hustler/internal/js"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

// WorkerPool manages a pool of workers that process hunt jobs
type WorkerPool struct {
	cfg          config.HustlerConfig
	discoveryCfg config.DiscoveryConfig
	jobQueue     chan *models.Job
	workers      int
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	running      map[string]*models.Job // jobID -> job
	stopped      bool
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(cfg config.HustlerConfig, discoveryCfg config.DiscoveryConfig) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		cfg:          cfg,
		discoveryCfg: discoveryCfg,
		jobQueue:     make(chan *models.Job, 1000),
		workers:      cfg.MaxConcurrentHunts,
		ctx:          ctx,
		cancel:       cancel,
		running:      make(map[string]*models.Job),
	}
}

// Start starts the worker pool and recovers any pending jobs from MongoDB
func (wp *WorkerPool) Start() {
	// Recover any pending jobs from MongoDB
	wp.recoverPendingJobs()

	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}
	log.Info().Int("workers", wp.workers).Msg("Worker pool started")
}

// recoverPendingJobs recovers any jobs that were queued or running before shutdown
func (wp *WorkerPool) recoverPendingJobs() {
	ctx := context.Background()
	coll := mongo.GetCollection("jobs")

	// Find all queued or running jobs
	cursor, err := coll.Find(ctx, bson.M{"status": bson.M{"$in": []string{
		string(models.JobStatusQueued),
		string(models.JobStatusRunning),
	}}})
	if err != nil {
		log.Warn().Err(err).Msg("Failed to recover pending jobs")
		return
	}
	defer cursor.Close(ctx)

	var pendingJobs []models.Job
	if err := cursor.All(ctx, &pendingJobs); err != nil {
		log.Warn().Err(err).Msg("Failed to decode pending jobs")
		return
	}

	if len(pendingJobs) == 0 {
		return
	}

	log.Info().Int("recovered_jobs", len(pendingJobs)).Msg("Recovering pending jobs from MongoDB")

	// Re-enqueue recovered jobs
	for i := range pendingJobs {
		// Reset status to queued for recovery
		pendingJobs[i].Status = models.JobStatusQueued
		if err := wp.EnqueueJob(&pendingJobs[i]); err != nil {
			log.Warn().Err(err).Str("job_id", pendingJobs[i].ID).Msg("Failed to enqueue recovered job")
		}
	}
}

// Stop stops the worker pool gracefully
func (wp *WorkerPool) Stop() {
	wp.mu.Lock()
	if wp.stopped {
		wp.mu.Unlock()
		return
	}
	wp.stopped = true
	wp.mu.Unlock()

	wp.cancel()
	close(wp.jobQueue)
	wp.wg.Wait()
	log.Info().Msg("Worker pool stopped")
}

// EnqueueJob adds a job to the queue
func (wp *WorkerPool) EnqueueJob(job *models.Job) error {
	select {
	case wp.jobQueue <- job:
		log.Debug().Str("job_id", job.ID).Str("target_id", job.TargetID).Msg("Job enqueued")
		return nil
	case <-wp.ctx.Done():
		return fmt.Errorf("worker pool shutting down")
	}
}

// EnqueueJobForTarget creates and enqueues a hunt job for a target
func (wp *WorkerPool) EnqueueJobForTarget(ctx context.Context, targetID, source string) (*models.Job, error) {
	job := &models.Job{
		ID:       uuid.New().String(),
		TargetID: targetID,
		Status:   models.JobStatusQueued,
		QueuedAt: time.Now(),
		Source:   source,
	}

	// Store in MongoDB
	coll := mongo.GetCollection("jobs")
	_, err := coll.InsertOne(ctx, job)
	if err != nil {
		return nil, fmt.Errorf("failed to insert job: %w", err)
	}

	// Enqueue for processing
	if err := wp.EnqueueJob(job); err != nil {
		// Update job status to error
		coll.UpdateOne(ctx,
			map[string]interface{}{"_id": job.ID},
			map[string]interface{}{"$set": map[string]interface{}{
				"status": models.JobStatusError,
				"error":  err.Error(),
			}},
		)
		return nil, err
	}

	return job, nil
}

// worker processes jobs from the queue
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()
	log.Debug().Int("worker_id", id).Msg("Worker started")

	for job := range wp.jobQueue {
		if wp.ctx.Err() != nil {
			return
		}

		// Track running job
		wp.mu.Lock()
		wp.running[job.ID] = job
		wp.mu.Unlock()

		// Update job status to running
		now := time.Now()
		job.StartedAt = &now
		job.Status = models.JobStatusRunning
		wp.updateJobStatus(job)

		log.Info().Str("job_id", job.ID).Str("target_id", job.TargetID).Int("worker", id).Msg("Job started")

		// Process the job (hunt)
		err := wp.processHunt(job)

		// Update final status
		finishedAt := time.Now()
		job.FinishedAt = &finishedAt
		if err != nil {
			job.Status = models.JobStatusError
			job.Error = err.Error()
			log.Error().Err(err).Str("job_id", job.ID).Str("target_id", job.TargetID).Msg("Job failed")
		} else {
			job.Status = models.JobStatusDone
			log.Info().Str("job_id", job.ID).Str("target_id", job.TargetID).Msg("Job completed")
		}
		wp.updateJobStatus(job)

		// Remove from running
		wp.mu.Lock()
		delete(wp.running, job.ID)
		wp.mu.Unlock()
	}
}

// processHunt runs the actual hunt for a target - discovers JS files and analyzes them
func (wp *WorkerPool) processHunt(job *models.Job) error {
	ctx := context.Background()

	// Get target
	coll := mongo.GetCollection("targets")
	var target models.Target
	err := coll.FindOne(ctx, map[string]interface{}{"_id": job.TargetID}).Decode(&target)
	if err != nil {
		return fmt.Errorf("target not found: %w", err)
	}

	log.Info().Str("domain", target.Domain).Msg("Starting discovery for target")

	// Run discovery to find JS URLs
	httpClient := &http.Client{Timeout: 60 * time.Second}
	discoveryRunner := discovery.NewDiscoveryRunner(wp.discoveryCfg, httpClient)
	jsURLs, err := discoveryRunner.DiscoverJSURLs(ctx, &target)
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

	log.Info().
		Str("domain", target.Domain).
		Int("js_urls_discovered", len(jsURLs)).
		Msg("Discovery complete, starting analysis")

	if len(jsURLs) == 0 {
		log.Warn().Str("domain", target.Domain).Msg("No JS URLs discovered - check domain or discovery config")
		return nil
	}

	// Run JS analysis pipeline
	jsModule := js.NewJSModule(config.JSConfig{
		FetchTimeoutSec:    15,
		MaxConcurrentFetch: 5,
		EntropyThreshold:   3.5,
		EnableSourceMaps:   true,
	}, config.SensitiveEndpointCheckConfig{})

	results, err := jsModule.FetchAndProcess(ctx, &target, jsURLs)
	if err != nil {
		return fmt.Errorf("JS analysis failed: %w", err)
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

	// Update target status
	coll.UpdateOne(ctx,
		map[string]interface{}{"_id": target.ID},
		map[string]interface{}{"$set": map[string]interface{}{
			"status":     models.StatusCompleted,
			"updated_at": time.Now(),
		}},
	)

	return nil
}

// updateJobStatus updates a job's status in MongoDB
func (wp *WorkerPool) updateJobStatus(job *models.Job) {
	ctx := context.Background()
	coll := mongo.GetCollection("jobs")
	update := map[string]interface{}{
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
		map[string]interface{}{"_id": job.ID},
		map[string]interface{}{"$set": update},
	)
}

// GetRunningCount returns the number of currently running jobs
func (wp *WorkerPool) GetRunningCount() int {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	return len(wp.running)
}

// GetQueuedCount returns the number of queued jobs (approximate)
func (wp *WorkerPool) GetQueuedCount() int {
	return len(wp.jobQueue)
}
