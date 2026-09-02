package cli

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

// WebCmd is the "hustler web" command
var WebCmd = &cobra.Command{
	Use:   "web",
	Short: "Start the web dashboard",
	Long:  `Start a local HTTP server serving the Hustler web dashboard on port 8080.`,
	Run: func(cmd *cobra.Command, args []string) {
		port := "8080"
		if len(args) > 0 {
			port = args[0]
		}

		mux := http.NewServeMux()

		// Serve static files from internal/web/
		fs := http.FileServer(http.Dir("internal/web"))
		mux.Handle("/", fs)

		// API routes
		mux.HandleFunc("/api/targets", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				listTargets(w, r)
			case http.MethodPost:
				addTarget(w, r)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		mux.HandleFunc("/api/findings/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			getFindings(w, r)
		})

		mux.HandleFunc("/api/jobs", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			createJob(w, r)
		})

		addr := ":" + port
		log.Info().Str("addr", addr).Msg("Web dashboard starting")
		fmt.Printf("\n%s Dashboard available at http://localhost%s\n", color.New(color.FgHiCyan).Sprintf("✓"), addr)
		fmt.Println("Press Ctrl+C to stop")

		server := &http.Server{Addr: addr, Handler: mux}
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Web server failed")
		}
	},
}

func listTargets(w http.ResponseWriter, r *http.Request) {
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
	
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(targets)
}

func addTarget(w http.ResponseWriter, r *http.Request) {
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(existing)
		return
	}
	
	// Create new target
	target := &models.Target{
		ID:        primitive.NewObjectID().Hex(),
		Domain:    req.Domain,
		Source:    models.SourceManual,
		Status:    models.StatusPending,
		AddedAt:   time.Now(),
		UpdatedAt: time.Now(),
	}
	
	result, err := coll.InsertOne(ctx, target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	target.ID = result.InsertedID.(string)
	
	// Enqueue job
	enqueueJob(target.ID, "webui")
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(target)
}

func getFindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	// Extract target ID from URL path
	path := strings.TrimPrefix(r.URL.Path, "/api/findings/")
	targetID := path
	if targetID == "" {
		http.Error(w, "Missing target ID", http.StatusBadRequest)
		return
	}
	
	// Verify target exists
	coll := mongo.GetCollection("targets")
	var target models.Target
	err := coll.FindOne(ctx, bson.M{"_id": targetID}).Decode(&target)
	if err != nil {
		http.Error(w, "Target not found", http.StatusNotFound)
		return
	}
	
	// Build response
	result := map[string]interface{}{
		"target": target,
		"jobs":   []interface{}{},
		"secrets": []interface{}{},
		"sinks":  []interface{}{},
		"endpoints": []interface{}{},
		"blh":    []interface{}{},
		"cves":   []interface{}{},
	}
	
	// Get jobs
	jobColl := mongo.GetCollection("jobs")
	jobCursor, _ := jobColl.Find(ctx, bson.M{"target_id": targetID})
	var jobs []models.Job
	if jobCursor != nil {
		defer jobCursor.Close(ctx)
		jobCursor.All(ctx, &jobs)
	}
	result["jobs"] = jobs
	
	// Get secrets
	secretColl := mongo.GetCollection("secrets")
	secretCursor, _ := secretColl.Find(ctx, bson.M{"target_id": targetID})
	if secretCursor != nil {
		defer secretCursor.Close(ctx)
		secretCursor.All(ctx, &result["secrets"])
	}
	
	// Get sinks
	sinkColl := mongo.GetCollection("sinks")
	sinkCursor, _ := sinkColl.Find(ctx, bson.M{"target_id": targetID})
	if sinkCursor != nil {
		defer sinkCursor.Close(ctx)
		sinkCursor.All(ctx, &result["sinks"])
	}
	
	// Get endpoints
	epColl := mongo.GetCollection("endpoints")
	epCursor, _ := epColl.Find(ctx, bson.M{"target_id": targetID})
	if epCursor != nil {
		defer epCursor.Close(ctx)
		epCursor.All(ctx, &result["endpoints"])
	}
	
	// Get BLH
	blhColl := mongo.GetCollection("blh_candidates")
	blhCursor, _ := blhColl.Find(ctx, bson.M{"target_id": targetID})
	if blhCursor != nil {
		defer blhCursor.Close(ctx)
		blhCursor.All(ctx, &result["blh"])
	}
	
	// Get CVEs
	cveColl := mongo.GetCollection("library_cves")
	cveCursor, _ := cveColl.Find(ctx, bson.M{"target_id": targetID})
	if cveCursor != nil {
		defer cveCursor.Close(ctx)
		cveCursor.All(ctx, &result["cves"])
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func createJob(w http.ResponseWriter, r *http.Request) {
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
	
	enqueueJob(req.TargetID, req.Source)
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"status":"queued","target_id":"%s"}`, req.TargetID)
}

func enqueueJob(targetID, source string) {
	ctx := context.Background()
	job := &models.Job{
		ID:       primitive.NewObjectID().Hex(),
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