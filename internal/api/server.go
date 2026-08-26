package api

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/qarqa/hustler/internal/config"
	"github.com/qarqa/hustler/internal/database"
	"github.com/qarqa/hustler/internal/ingestion"
	"github.com/qarqa/hustler/internal/jobs"
	"github.com/qarqa/hustler/internal/models"
	"github.com/qarqa/hustler/internal/repository"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Server holds the API server
type Server struct {
	Cfg        *config.Config
	DB         *database.DB
	Router     *gin.Engine
	Server     *http.Server
	TargetRepo *repository.TargetRepository
	AssetRepo  *ingestion.AssetRepository
	URLRepo    *ingestion.URLRepository
	JobRepo    *jobs.JobRepository
	JobRunner  *jobs.JobRunner
	WatchDogs  *ingestion.WatchDogsIngestion
}

// NewServer creates a new API server
func NewServer(cfg *config.Config, db *database.DB) *Server {
	// Set Gin mode
	if cfg.LogLevel == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// Session store
	store := cookie.NewStore([]byte(cfg.Auth.SessionSecret))
	store.Options(sessions.Options{
		MaxAge:   cfg.Auth.SessionMaxAgeHours * 3600,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
	})
	router.Use(sessions.Sessions("hustler_session", store))

	// Initialize repositories
	targetRepo := repository.NewTargetRepository(db)
	assetRepo := ingestion.NewAssetRepository(db)
	urlRepo := ingestion.NewURLRepository(db)
	jobRepo := jobs.NewJobRepository(db)
	jobRunner := jobs.NewJobRunner(db, jobRepo)
	watchdogs := ingestion.NewWatchDogsIngestion(db, targetRepo, assetRepo, urlRepo)

	s := &Server{
		Cfg:        cfg,
		DB:         db,
		Router:     router,
		TargetRepo: targetRepo,
		AssetRepo:  assetRepo,
		URLRepo:    urlRepo,
		JobRepo:    jobRepo,
		JobRunner:  jobRunner,
		WatchDogs:  watchdogs,
	}

	s.setupRoutes()
	return s
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes() {
	// Health check
	s.Router.GET("/health", s.healthCheck)

	// Auth routes
	auth := s.Router.Group("/auth")
	{
		auth.POST("/login", s.login)
		auth.POST("/logout", s.logout)
		auth.GET("/me", s.me)
	}

	// Protected routes
	api := s.Router.Group("/api")
	api.Use(s.authMiddleware())
	{
		// Targets
		targets := api.Group("/targets")
		{
			targets.POST("", s.createTarget)
			targets.GET("", s.listTargets)
			targets.GET("/:id", s.getTarget)
			targets.DELETE("/:id", s.deleteTarget)
			targets.POST("/:id/import", s.importFromWatchDogs)
		}

		// Assets
		assets := api.Group("/assets")
		{
			assets.GET("", s.listAssets)
			assets.GET("/:id", s.getAsset)
		}

		// URLs
		urls := api.Group("/urls")
		{
			urls.GET("", s.listURLs)
		}

		// Jobs
		jobsGroup := api.Group("/jobs")
		{
			jobsGroup.GET("", s.listJobs)
			jobsGroup.GET("/:id", s.getJob)
			jobsGroup.POST("", s.createJob)
		}

		// Dashboard stats
		api.GET("/dashboard/stats", s.dashboardStats)
	}
}

// Start starts the API server
func (s *Server) Start() error {
	addr := s.Cfg.APIAddr()
	s.Server = &http.Server{
		Addr:    addr,
		Handler: s.Router,
	}

	log.Printf("Starting API server on %s", addr)
	return s.Server.ListenAndServe()
}

// Stop stops the API server
func (s *Server) Stop(ctx context.Context) error {
	if s.Server != nil {
		return s.Server.Shutdown(ctx)
	}
	return nil
}

// Health check
func (s *Server) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// Auth middleware
func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("user")
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Set("user", user)
		c.Next()
	}
}

// Login handler
func (s *Server) login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if req.Username != s.Cfg.API.Username || req.Password != s.Cfg.API.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	session := sessions.Default(c)
	session.Set("user", req.Username)
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "logged in"})
}

// Logout handler
func (s *Server) logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

// Me handler
func (s *Server) me(c *gin.Context) {
	user, _ := c.Get("user")
	c.JSON(http.StatusOK, gin.H{"user": user})
}

// Target handlers

func (s *Server) createTarget(c *gin.Context) {
	var req struct {
		Domain      string   `json:"domain" binding:"required"`
		Name        string   `json:"name,omitempty"`
		Description string   `json:"description,omitempty"`
		InScope     []string `json:"in_scope,omitempty"`
		OutOfScope  []string `json:"out_of_scope,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Basic domain validation
	if req.Domain == "" || strings.Contains(req.Domain, " ") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid domain"})
		return
	}

	// Check if target already exists
	exists, err := s.TargetRepo.Exists(c.Request.Context(), req.Domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if exists {
		c.JSON(http.StatusConflict, gin.H{"error": "target already exists"})
		return
	}

	target := &models.Target{
		Domain:      req.Domain,
		Name:        req.Name,
		Description: req.Description,
		InScope:     req.InScope,
		OutOfScope:  req.OutOfScope,
	}

	if err := s.TargetRepo.Create(c.Request.Context(), target); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, target)
}

func (s *Server) listTargets(c *gin.Context) {
	limit := 50
	offset := 0

	targets, err := s.TargetRepo.List(c.Request.Context(), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	total, _ := s.TargetRepo.Count(c.Request.Context())

	c.JSON(http.StatusOK, gin.H{
		"targets": targets,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

func (s *Server) getTarget(c *gin.Context) {
	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid target ID"})
		return
	}

	target, err := s.TargetRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "target not found"})
		return
	}

	c.JSON(http.StatusOK, target)
}

func (s *Server) deleteTarget(c *gin.Context) {
	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid target ID"})
		return
	}

	if err := s.TargetRepo.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "target deleted"})
}

func (s *Server) importFromWatchDogs(c *gin.Context) {
	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid target ID"})
		return
	}

	// Get target to verify it exists
	target, err := s.TargetRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "target not found"})
		return
	}

	// Start import job
	job, err := s.JobRunner.StartJob(c.Request.Context(), id, models.JobTypeImport, map[string]interface{}{
		"source": "watchdogs",
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Run import in background
	go func() {
		ctx := context.Background()
		result, err := s.WatchDogs.ImportTargetAssets(ctx, target.Domain)
		if err != nil {
			s.JobRepo.UpdateStatus(ctx, job.ID, models.JobStatusFailed, 0, err.Error())
			return
		}
		s.JobRepo.UpdateResults(ctx, job.ID, map[string]interface{}{
			"total_found": result.TotalFound,
			"imported":    result.Imported,
			"updated":     result.Updated,
			"errors":      result.Errors,
		})
		s.JobRepo.UpdateStatus(ctx, job.ID, models.JobStatusCompleted, 100, "")
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"job_id": job.ID,
		"status": "started",
	})
}

// Asset handlers

func (s *Server) listAssets(c *gin.Context) {
	targetIDStr := c.Query("target_id")
	if targetIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target_id required"})
		return
	}

	targetID, err := primitive.ObjectIDFromHex(targetIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid target_id"})
		return
	}

	limit := 100
	offset := 0

	assets, err := s.AssetRepo.GetByTarget(c.Request.Context(), targetID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	total, _ := s.AssetRepo.CountByTarget(c.Request.Context(), targetID)

	c.JSON(http.StatusOK, gin.H{
		"assets": assets,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func (s *Server) getAsset(c *gin.Context) {
	idStr := c.Param("id")
	_, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid asset ID"})
		return
	}

	// For simplicity, we'll search across all targets
	// In production, add a proper GetByID method
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

// URL handlers

func (s *Server) listURLs(c *gin.Context) {
	targetIDStr := c.Query("target_id")
	if targetIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target_id required"})
		return
	}

	targetID, err := primitive.ObjectIDFromHex(targetIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid target_id"})
		return
	}

	limit := 100
	offset := 0

	urls, err := s.URLRepo.GetByTarget(c.Request.Context(), targetID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	total, _ := s.URLRepo.CountByTarget(c.Request.Context(), targetID)

	c.JSON(http.StatusOK, gin.H{
		"urls":  urls,
		"total": total,
		"limit": limit,
		"offset": offset,
	})
}

// Job handlers

func (s *Server) listJobs(c *gin.Context) {
	targetIDStr := c.Query("target_id")
	limit := 50

	var jobsList []*models.Job
	var err error

	if targetIDStr != "" {
		targetID, parseErr := primitive.ObjectIDFromHex(targetIDStr)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid target_id"})
			return
		}
		jobsList, err = s.JobRepo.GetByTarget(c.Request.Context(), targetID, limit, 0)
	} else {
		jobsList, err = s.JobRepo.GetRecent(c.Request.Context(), limit)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"jobs": jobsList})
}

func (s *Server) getJob(c *gin.Context) {
	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid job ID"})
		return
	}

	job, err := s.JobRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "job not found"})
		return
	}

	c.JSON(http.StatusOK, job)
}

func (s *Server) createJob(c *gin.Context) {
	var req struct {
		TargetID string                 `json:"target_id" binding:"required"`
		Type     string                 `json:"type" binding:"required"`
		Metadata map[string]interface{} `json:"metadata,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	targetID, err := primitive.ObjectIDFromHex(req.TargetID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid target_id"})
		return
	}

	job, err := s.JobRunner.StartJob(c.Request.Context(), targetID, req.Type, req.Metadata)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, job)
}

// Dashboard stats
func (s *Server) dashboardStats(c *gin.Context) {
	ctx := c.Request.Context()

	// Total targets
	targetsCount, _ := s.TargetRepo.Count(ctx)

	// Recent targets for asset counts
	targets, _ := s.TargetRepo.List(ctx, 100, 0)

	totalAssets := int64(0)
	totalURLs := int64(0)

	for _, t := range targets {
		assetsCount, _ := s.AssetRepo.CountByTarget(ctx, t.ID)
		urlsCount, _ := s.URLRepo.CountByTarget(ctx, t.ID)
		totalAssets += assetsCount
		totalURLs += urlsCount
	}

	recentJobs, _ := s.JobRepo.GetRecent(ctx, 100)
	totalJobs := int64(len(recentJobs))

	runningJobs := 0
	completedJobs := 0
	failedJobs := 0

	for _, j := range recentJobs {
		switch j.Status {
		case models.JobStatusRunning:
			runningJobs++
		case models.JobStatusCompleted:
			completedJobs++
		case models.JobStatusFailed:
			failedJobs++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"targets":      targetsCount,
		"assets":       totalAssets,
		"urls":         totalURLs,
		"jobs_total":   totalJobs,
		"jobs_running": runningJobs,
		"jobs_done":    completedJobs,
		"jobs_failed":  failedJobs,
	})
}