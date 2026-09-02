package web

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

// Server holds the HTTP server and data
type Server struct {
	mu      sync.Mutex
	targets map[string]*models.Target
}

// NewServer creates a new web server
func NewServer() *Server {
	return &Server{
		targets: make(map[string]*models.Target),
	}
}

// Start starts the web server on the configured port
func (s *Server) Start(cfg *Config) error {
	mux := http.NewServeMux()

	// Static files
	fs := http.FileServer(http.Dir(filepath.Join("internal", "web")))
	mux.Handle("/", fs)

	// API routes
	mux.HandleFunc("/api/targets", s.handleTargets)
	mux.HandleFunc("/api/findings/", s.handleFindings)
	mux.HandleFunc("/api/jobs", s.handleJobs)

	addr := ":" + cfg.Port
	log.Info().Str("addr", addr).Msg("Web dashboard starting")
	
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Web server error")
		}
	}()
	
	return nil
}

// Stop gracefully stops the server
func (s *Server) Stop() error {
	// Nothing to do - server is managed separately
	return nil
}

// Config for the web server
type Config struct {
	Port string `yaml:"port"`
}

func defaultConfig() *Config {
	return &Config{Port: "8080"}
}

// Handle GET /api/targets - list all targets
func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleTargetsPost(w, r)
		return
	}
	// GET - list targets
	ctx := r.Context()
	coll := mongo.GetCollection("targets")
	
	cursor, err := coll.Find(ctx, bson.M{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)
	
	var targets []models.Target
	if err := cursor.All(ctx, &targets); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Get latest job status for each target
	opt := options.FindOne().SetSort(bson.M{"queued_at": -1})
	for i := range targets {
		jobColl := mongo.GetCollection("jobs")
		var job models.Job
		err := jobColl.FindOne(ctx, bson.M{"target_id": targets[i].ID}, opt).Decode(&job)
		if err == nil {
			targets[i].JobStatus = string(job.Status)
			targets[i].JobStartedAt = job.StartedAt
			targets[i].JobFinishedAt = job.FinishedAt
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(targets)
}

// Handle POST /api/targets - add new target
func (s *Server) handleTargetsPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	coll := mongo.GetCollection("targets")
	
	// Check if target exists
	var existing models.Target
	err := coll.FindOne(ctx, bson.M{"domain": req.Domain}).Decode(&existing)
	if err == nil {
		// Target exists, enqueue job
		s.enqueueJob(existing.ID, "webui")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(existing)
		return
	}
	
	// Create new target
	target := &models.Target{
		ID:       uuid.New().String(),
		Domain:   req.Domain,
		Source:   models.SourceManual,
		Status:   models.StatusPending,
		AddedAt:  time.Now(),
		UpdatedAt: time.Now(),
	}
	
	result, err := coll.InsertOne(ctx, target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	target.ID = result.InsertedID.(string)
	
	// Enqueue job
	s.enqueueJob(target.ID, "webui")
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(target)
}

func (s *Server) handleTargetsGet(w http.ResponseWriter, r *http.Request) {
	// Delegate to main handler
	s.handleTargets(w, r)
}

func (s *Server) handleTargetsPostOnly(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleTargetsPost(w, r)
	} else {
		s.handleTargets(w, r)
	}
}

// Handle GET /api/findings/:targetId - get findings for a target
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	// Extract target ID from URL path
	parts := splitPath(r.URL.Path)
	if len(parts) < 3 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	targetID := parts[2]
	
	// Verify target exists
	coll := mongo.GetCollection("targets")
	var target models.Target
	err := coll.FindOne(ctx, bson.M{"_id": targetID}).Decode(&target)
	if err != nil {
		http.Error(w, "Target not found", http.StatusNotFound)
		return
	}
	
	// Collect all findings
	result := struct {
		Target       *models.Target          `json:"target"`
		Jobs         []models.Job            `json:"jobs"`
		Secrets      []models.Secret         `json:"secrets"`
		Sinks        []models.Sink           `json:"sinks"`
		Endpoints    []models.Endpoint       `json:"endpoints"`
		BLH          []models.BLHCandidate   `json:"blh"`
		CVEs         []models.LibraryCVE     `json:"cves"`
	}{
		Target: &target,
	}
	
	// Get jobs
	jobColl := mongo.GetCollection("jobs")
	jobCursor, _ := jobColl.Find(ctx, bson.M{"target_id": targetID})
	jobCursor.All(ctx, &result.Jobs)
	
	// Get secrets
	secretColl := mongo.GetCollection("secrets")
	secretCursor, _ := secretColl.Find(ctx, bson.M{"target_id": targetID})
	secretCursor.All(ctx, &result.Secrets)
	
	// Get sinks
	sinkColl := mongo.GetCollection("sinks")
	sinkCursor, _ := sinkColl.Find(ctx, bson.M{"target_id": targetID})
	sinkCursor.All(ctx, &result.Sinks)
	
	// Get endpoints
	epColl := mongo.GetCollection("endpoints")
	epCursor, _ := epColl.Find(ctx, bson.M{"target_id": targetID})
	epCursor.All(ctx, &result.Endpoints)
	
	// Get BLH candidates
	blhColl := mongo.GetCollection("blh_candidates")
	blhCursor, _ := blhColl.Find(ctx, bson.M{"target_id": targetID})
	blhCursor.All(ctx, &result.BLH)
	
	// Get CVEs
	cveColl := mongo.GetCollection("library_cves")
	cveCursor, _ := cveColl.Find(ctx, bson.M{"target_id": targetID})
	cveCursor.All(ctx, &result.CVEs)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// Handle POST /api/jobs - create new job
func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	var req struct {
		TargetID string `json:"target_id"`
		Source   string `json:"source"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	if req.TargetID == "" || req.Source == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}
	
	// Verify target exists
	coll := mongo.GetCollection("targets")
	var target models.Target
	err := coll.FindOne(ctx, bson.M{"_id": req.TargetID}).Decode(&target)
	if err != nil {
		http.Error(w, "Target not found", http.StatusNotFound)
		return
	}
	
	// Create job
	job := &models.Job{
		ID:       uuid.New().String(),
		TargetID: req.TargetID,
		Status:   models.JobStatusQueued,
		QueuedAt: time.Now(),
		Source:   req.Source,
	}
	
	jobColl := mongo.GetCollection("jobs")
	_, err = jobColl.InsertOne(ctx, job)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Update target status
	coll.UpdateOne(ctx,
		bson.M{"_id": req.TargetID},
		bson.M{"$set": bson.M{"status": models.StatusActive}},
	)
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(job)
}

// Helper: enqueue a job by target ID
func (s *Server) enqueueJob(targetID, source string) {
	ctx := context.Background()
	job := &models.Job{
		ID:       uuid.New().String(),
		TargetID: targetID,
		Status:   models.JobStatusQueued,
		QueuedAt: time.Now(),
		Source:   source,
	}
	
	jobColl := mongo.GetCollection("jobs")
	_, err := jobColl.InsertOne(ctx, job)
	if err != nil {
		log.Error().Err(err).Str("target_id", targetID).Msg("Failed to enqueue job")
	}
}

func splitPath(p string) []string {
	result := []string{}
	start := 0
	for i, c := range p {
		if c == '/' {
			result = append(result, p[start:i])
			start = i + 1
		}
	}
	result = append(result, p[start:])
	return result
}