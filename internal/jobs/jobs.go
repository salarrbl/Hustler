package jobs

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/qarqa/hustler/internal/database"
	"github.com/qarqa/hustler/internal/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// JobRepository handles job persistence
type JobRepository struct {
	db   *database.DB
	coll *mongo.Collection
}

// NewJobRepository creates a new job repository
func NewJobRepository(db *database.DB) *JobRepository {
	return &JobRepository{
		db:   db,
		coll: db.GetHustlerCollection("jobs"),
	}
}

// Create inserts a new job
func (r *JobRepository) Create(ctx context.Context, job *models.Job) error {
	now := time.Now()
	job.CreatedAt = now
	job.UpdatedAt = now
	job.Status = models.JobStatusQueued
	job.Progress = 0

	_, err := r.coll.InsertOne(ctx, job)
	if err != nil {
		return fmt.Errorf("failed to create job: %w", err)
	}
	return nil
}

// GetByID retrieves a job by ID
func (r *JobRepository) GetByID(ctx context.Context, id primitive.ObjectID) (*models.Job, error) {
	var job models.Job
	err := r.coll.FindOne(ctx, bson.M{"_id": id}).Decode(&job)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("job not found")
		}
		return nil, fmt.Errorf("failed to get job: %w", err)
	}
	return &job, nil
}

// GetByTarget retrieves jobs for a target
func (r *JobRepository) GetByTarget(ctx context.Context, targetID primitive.ObjectID, limit, offset int) ([]*models.Job, error) {
	opts := options.Find().
		SetSort(bson.M{"created_at": -1}).
		SetLimit(int64(limit)).
		SetSkip(int64(offset))

	cursor, err := r.coll.Find(ctx, bson.M{"target_id": targetID}, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list jobs: %w", err)
	}
	defer cursor.Close(ctx)

	var jobs []*models.Job
	if err := cursor.All(ctx, &jobs); err != nil {
		return nil, fmt.Errorf("failed to decode jobs: %w", err)
	}
	return jobs, nil
}

// GetRecent retrieves recent jobs across all targets
func (r *JobRepository) GetRecent(ctx context.Context, limit int) ([]*models.Job, error) {
	opts := options.Find().
		SetSort(bson.M{"created_at": -1}).
		SetLimit(int64(limit))

	cursor, err := r.coll.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list recent jobs: %w", err)
	}
	defer cursor.Close(ctx)

	var jobs []*models.Job
	if err := cursor.All(ctx, &jobs); err != nil {
		return nil, fmt.Errorf("failed to decode jobs: %w", err)
	}
	return jobs, nil
}

// UpdateStatus updates job status and progress
func (r *JobRepository) UpdateStatus(ctx context.Context, id primitive.ObjectID, status string, progress int, errMsg string) error {
	now := time.Now()
	update := bson.M{
		"$set": bson.M{
			"status":      status,
			"progress":    progress,
			"updated_at":  now,
		},
	}

	if status == models.JobStatusRunning {
		update["$set"].(bson.M)["started_at"] = now
	}
	if status == models.JobStatusCompleted || status == models.JobStatusFailed || status == models.JobStatusCancelled {
		update["$set"].(bson.M)["finished_at"] = now
	}
	if errMsg != "" {
		update["$set"].(bson.M)["error"] = errMsg
	}

	_, err := r.coll.UpdateOne(ctx, bson.M{"_id": id}, update)
	if err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}
	return nil
}

// UpdateResults updates job results
func (r *JobRepository) UpdateResults(ctx context.Context, id primitive.ObjectID, results map[string]interface{}) error {
	_, err := r.coll.UpdateOne(ctx, bson.M{"_id": id}, bson.M{
		"$set": bson.M{
			"results":     results,
			"updated_at":  time.Now(),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to update job results: %w", err)
	}
	return nil
}

// JobRunner manages job execution
type JobRunner struct {
	db         *database.DB
	jobRepo    *JobRepository
	handlers   map[string]JobHandler
}

// JobHandler defines the interface for job handlers
type JobHandler interface {
	Run(ctx context.Context, job *models.Job) error
}

// NewJobRunner creates a new job runner
func NewJobRunner(db *database.DB, jobRepo *JobRepository) *JobRunner {
	return &JobRunner{
		db:       db,
		jobRepo:  jobRepo,
		handlers: make(map[string]JobHandler),
	}
}

// RegisterHandler registers a job handler for a job type
func (r *JobRunner) RegisterHandler(jobType string, handler JobHandler) {
	r.handlers[jobType] = handler
}

// RunJob executes a job
func (r *JobRunner) RunJob(ctx context.Context, jobID primitive.ObjectID) error {
	job, err := r.jobRepo.GetByID(ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to get job: %w", err)
	}

	handler, ok := r.handlers[job.Type]
	if !ok {
		err := fmt.Errorf("no handler registered for job type: %s", job.Type)
		r.jobRepo.UpdateStatus(ctx, jobID, models.JobStatusFailed, 0, err.Error())
		return err
	}

	// Update status to running
	if err := r.jobRepo.UpdateStatus(ctx, jobID, models.JobStatusRunning, 0, ""); err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}

	// Run the handler
	err = handler.Run(ctx, job)

	if err != nil {
		log.Printf("Job %s failed: %v", jobID.Hex(), err)
		r.jobRepo.UpdateStatus(ctx, jobID, models.JobStatusFailed, 0, err.Error())
		return err
	}

	// Update status to completed
	r.jobRepo.UpdateStatus(ctx, jobID, models.JobStatusCompleted, 100, "")
	log.Printf("Job %s completed successfully", jobID.Hex())
	return nil
}

// StartJob creates and starts a new job
func (r *JobRunner) StartJob(ctx context.Context, targetID primitive.ObjectID, jobType string, metadata map[string]interface{}) (*models.Job, error) {
	job := &models.Job{
		TargetID: targetID,
		Type:     jobType,
		Status:   models.JobStatusQueued,
		Progress: 0,
		Results:  metadata,
	}

	if err := r.jobRepo.Create(ctx, job); err != nil {
		return nil, fmt.Errorf("failed to create job: %w", err)
	}

	// Run asynchronously
	go func() {
		runCtx := context.Background()
		r.RunJob(runCtx, job.ID)
	}()

	return job, nil
}