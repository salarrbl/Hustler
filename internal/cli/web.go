package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

// WebCmd is the "hustler web" command
var WebCmd = &cobra.Command{
	Use:   "web [port]",
	Short: "Start the web dashboard",
	Long:  `Start a local HTTP server serving the Hustler web dashboard on port 8080 (default). The dashboard is protected by credentials (default: rebel / crow).`,
	Run: func(cmd *cobra.Command, args []string) {
		port := "8080"
		if len(args) > 0 {
			port = args[0]
		}

		mux := http.NewServeMux()

		// API routes (all behind auth)
		mux.HandleFunc("/api/targets", requireAuth(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				listTargets(w, r)
			case http.MethodPost:
				addTarget(w, r)
			case http.MethodOptions:
				w.WriteHeader(http.StatusNoContent)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		}))

		mux.HandleFunc("/api/dashboard", requireAuth(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if r.Method != http.MethodGet {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			serveDashboardStats(w, r)
		}))

		// Lightweight authenticated endpoint used by the login screen to
		// validate credentials and by the UI to confirm the session is live.
		mux.HandleFunc("/api/session", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				withCORS(w, r)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			user := authorizeBasic(r)
			if user == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"authenticated":false}`))
				return
			}
			withCORS(w, r)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"authenticated": true,
				"user":          user,
				"time":          time.Now(),
			})
		})

		mux.HandleFunc("/api/findings/", requireAuth(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if r.Method != http.MethodGet {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			getFindings(w, r)
		}))

		mux.HandleFunc("/api/jobs", requireAuth(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			createJob(w, r)
		}))

		// Serve the SPA shell. The page itself is public so the in-UI login
		// screen can render; every /api data route above is what enforces auth.
		// "/" also 404s for any other unmatched path. Because it is registered
		// once it does not collide with the /api routes (Go's ServeMux prefers
		// the longest matching pattern).
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			switch r.URL.Path {
			case "/", "/dashboard", "/dashboard.html", "/index.html":
				http.ServeFile(w, r, "public/dashboard.html")
			default:
				http.NotFound(w, r)
			}
		})

		addr := ":" + port
		log.Info().Str("addr", addr).Msg("Web dashboard starting")
		fmt.Printf("\n✓ Dashboard available at http://localhost%s\n", addr)
		fmt.Printf("  Credentials: rebel / crow\n")
		fmt.Println("Press Ctrl+C to stop")

		server := &http.Server{Addr: addr, Handler: corsWrapper(mux)}
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Web server failed")
		}
	},
}

// corsWrapper injects permissive CORS headers so the dashboard can be reached
// from the Arena live-preview origin (which differs from the local host).
// Cross-origin OPTIONS preflight requests are answered directly here, before
// auth runs, because the browser sends them without credentials.
func corsWrapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		withCORS(w, r)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
	h.Set("Access-Control-Expose-Headers", "X-Auth-Status")
	h.Set("Vary", "Origin")
}

// ---------------------------------------------------------------- Dashboard --
// DashboardStats holds aggregate figures computed across every collection so
// the overview can be drawn with a single request.
type dashboardStats struct {
	Totals struct {
		Targets  int64 `json:"targets"`
		Programs int64 `json:"programs"`
		JSFiles  int64 `json:"js_files"`
		Secrets  int64 `json:"secrets"`
		Sinks    int64 `json:"sinks"`
		Endpoints int64 `json:"endpoints"`
		Params   int64 `json:"params"`
		BLH      int64 `json:"blh"`
		CVEs     int64 `json:"cves"`
		Jobs     int64 `json:"jobs"`
	} `json:"totals"`

	CVEBySeverity struct {
		Critical int64 `json:"critical"`
		High     int64 `json:"high"`
		Medium   int64 `json:"medium"`
		Low      int64 `json:"low"`
		Other    int64 `json:"other"`
	} `json:"cve_by_severity"`

	JobsByStatus struct {
		Queued  int64 `json:"queued"`
		Running int64 `json:"running"`
		Done    int64 `json:"done"`
		Error   int64 `json:"error"`
	} `json:"jobs_by_status"`

	TargetsByStatus struct {
		Pending   int64 `json:"pending"`
		Active    int64 `json:"active"`
		Completed int64 `json:"completed"`
		Error     int64 `json:"error"`
	} `json:"targets_by_status"`

	PlatformCounts map[string]int64 `json:"platform_counts"`

	HighConfidenceSecrets int64 `json:"high_confidence_secrets"`
	RiskySinks            int64 `json:"risky_sinks"`

	Targets []perTargetStat `json:"targets"`
}

type perTargetStat struct {
	Target    models.Target `json:"target"`
	Program   string        `json:"program"`
	Platform  string        `json:"platform"`
	Secrets   int64         `json:"secrets"`
	Sinks     int64         `json:"sinks"`
	Endpoints int64         `json:"endpoints"`
	Params    int64         `json:"params"`
	BLH       int64         `json:"blh"`
	CVEs      int64         `json:"cves"`
	JSFiles   int64         `json:"js_files"`
	Critical  int64         `json:"critical"`
	High      int64         `json:"high"`
	Medium    int64         `json:"medium"`
	Low       int64         `json:"low"`
}

func serveDashboardStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := computeDashboardStats(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

func countColl(ctx context.Context, name string, filter bson.M) (int64, error) {
	if mongo.Database == nil {
		return 0, nil
	}
	return mongo.GetCollection(name).CountDocuments(ctx, filter)
}

func computeDashboardStats(ctx context.Context) (*dashboardStats, error) {
	var st dashboardStats
	st.PlatformCounts = map[string]int64{}

	var err error
	if st.Totals.Targets, err = countColl(ctx, "targets", bson.M{}); err != nil {
		return nil, err
	}
	if st.Totals.Programs, err = countColl(ctx, "programs", bson.M{}); err != nil {
		return nil, err
	}
	if st.Totals.JSFiles, err = countColl(ctx, "js_files", bson.M{}); err != nil {
		return nil, err
	}
	if st.Totals.Secrets, err = countColl(ctx, "secrets", bson.M{}); err != nil {
		return nil, err
	}
	if st.Totals.Sinks, err = countColl(ctx, "sinks", bson.M{}); err != nil {
		return nil, err
	}
	if st.Totals.Endpoints, err = countColl(ctx, "endpoints", bson.M{}); err != nil {
		return nil, err
	}
	if st.Totals.Params, err = countColl(ctx, "params", bson.M{}); err != nil {
		return nil, err
	}
	if st.Totals.BLH, err = countColl(ctx, "blh_candidates", bson.M{}); err != nil {
		return nil, err
	}
	if st.Totals.CVEs, err = countColl(ctx, "library_cves", bson.M{}); err != nil {
		return nil, err
	}
	if st.Totals.Jobs, err = countColl(ctx, "jobs", bson.M{}); err != nil {
		return nil, err
	}

	// CVE severity buckets
	sev := map[string]*int64{
		"critical": &st.CVEBySeverity.Critical,
		"high":     &st.CVEBySeverity.High,
		"medium":   &st.CVEBySeverity.Medium,
		"low":      &st.CVEBySeverity.Low,
	}
	for k, p := range sev {
		if *p, err = countColl(ctx, "library_cves", bson.M{"severity": k}); err != nil {
			return nil, err
		}
	}
	if st.CVEBySeverity.Other, err = countColl(ctx, "library_cves", bson.M{
		"severity": bson.M{"$nin": []string{"critical", "high", "medium", "low"}},
	}); err != nil {
		return nil, err
	}

	// Job status buckets
	jobStatus := map[string]*int64{
		"queued":  &st.JobsByStatus.Queued,
		"running": &st.JobsByStatus.Running,
		"done":    &st.JobsByStatus.Done,
		"error":   &st.JobsByStatus.Error,
	}
	for k, p := range jobStatus {
		if *p, err = countColl(ctx, "jobs", bson.M{"status": k}); err != nil {
			return nil, err
		}
	}

	// Target status buckets
	tgtStatus := map[string]*int64{
		"pending":   &st.TargetsByStatus.Pending,
		"active":    &st.TargetsByStatus.Active,
		"completed": &st.TargetsByStatus.Completed,
		"error":     &st.TargetsByStatus.Error,
	}
	for k, p := range tgtStatus {
		if *p, err = countColl(ctx, "targets", bson.M{"status": k}); err != nil {
			return nil, err
		}
	}

	// High-confidence findings
	if st.HighConfidenceSecrets, err = countColl(ctx, "secrets", bson.M{"confidence": bson.M{"$gte": 0.8}}); err != nil {
		return nil, err
	}
	if st.RiskySinks, err = countColl(ctx, "sinks", bson.M{"has_origin_check": bson.M{"$ne": true}}); err != nil {
		return nil, err
	}

	// Per-platform target counts + flattened per-target rows
	rows, platformCounts, err := targetRows(ctx)
	if err != nil {
		return nil, err
	}
	st.Targets = rows
	st.PlatformCounts = platformCounts

	return &st, nil
}

// targetRows flattens the platform/program tree into per-target rows while also
// returning per-platform target counts, attaching a per-target finding summary.
func targetRows(ctx context.Context) ([]perTargetStat, map[string]int64, error) {
	rows := []perTargetStat{}
	platformCounts := map[string]int64{}

	// Look up program -> platform/name for grouping by ID
	programByName := map[string]models.Program{}
	if mongo.Database != nil {
		pc := mongo.GetCollection("programs")
		pcursor, err := pc.Find(ctx, bson.M{})
		if err == nil {
			var programs []models.Program
			if err := pcursor.All(ctx, &programs); err == nil {
				for _, p := range programs {
					programByName[p.ID] = p
				}
			}
			pcursor.Close(ctx)
		}
	}

	nameOf := map[string]string{} // programID -> name
	for id, p := range programByName {
		nameOf[id] = p.Name
	}

	cur, err := countCollTargets(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, t := range cur {
		platform := string(t.Platform)
		if platform == "" {
			platform = "freelance"
		}
		platformCounts[platform]++

		row := perTargetStat{
			Target:   t,
			Platform: platform,
			Program:  t.ProgramID,
		}
		if name, ok := nameOf[t.ProgramID]; ok && name != "" {
			row.Program = name
		} else if row.Program == "" {
			row.Program = "Uncategorized"
		}

		id := t.ID
		if row.Secrets, err = countColl(ctx, "secrets", bson.M{"target_id": id}); err != nil {
			return nil, nil, err
		}
		if row.Sinks, err = countColl(ctx, "sinks", bson.M{"target_id": id}); err != nil {
			return nil, nil, err
		}
		if row.Endpoints, err = countColl(ctx, "endpoints", bson.M{"target_id": id}); err != nil {
			return nil, nil, err
		}
		if row.Params, err = countColl(ctx, "params", bson.M{"target_id": id}); err != nil {
			return nil, nil, err
		}
		if row.BLH, err = countColl(ctx, "blh_candidates", bson.M{"target_id": id}); err != nil {
			return nil, nil, err
		}
		if row.JSFiles, err = countColl(ctx, "js_files", bson.M{"target_id": id}); err != nil {
			return nil, nil, err
		}
		// CVE counts by severity
		for _, sev := range []struct{ name string; dst *int64 }{
			{"critical", &row.Critical}, {"high", &row.High},
			{"medium", &row.Medium}, {"low", &row.Low},
		} {
			if *sev.dst, err = countColl(ctx, "library_cves", bson.M{"target_id": id, "severity": sev.name}); err != nil {
				return nil, nil, err
			}
		}
		// Total CVEs without extra query: sum severities (+ anything unmatched)
		row.CVEs = row.Critical + row.High + row.Medium + row.Low
		if extra, err := countColl(ctx, "library_cves", bson.M{"target_id": id, "severity": bson.M{"$nin": []string{"critical", "high", "medium", "low"}}}); err == nil {
			row.CVEs += extra
		}

		rows = append(rows, row)
	}
	return rows, platformCounts, nil
}

func countCollTargets(ctx context.Context) ([]models.Target, error) {
	if mongo.Database == nil {
		return nil, nil
	}
	cursor, err := mongo.GetCollection("targets").Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var targets []models.Target
	if err := cursor.All(ctx, &targets); err != nil {
		return nil, err
	}
	return targets, nil
}

// ------------------------------------------------------------ Existing API ----

func listTargets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tree, err := buildTargetTree(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tree)
}

func addTarget(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		Domain   string `json:"domain"`
		Platform string `json:"platform"`
		Program  string `json:"program"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Platform == "" || req.Program == "" {
		http.Error(w, "Both platform and program are required", http.StatusBadRequest)
		return
	}

	// Get or create program
	programID, err := getOrCreateProgram(ctx, req.Program, req.Platform)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create program: %v", err), http.StatusInternalServerError)
		return
	}

	coll := mongo.GetCollection("targets")

	// Check if target exists
	var existing models.Target
	err = coll.FindOne(ctx, bson.M{"domain": req.Domain}).Decode(&existing)
	if err == nil {
		// Target exists, enqueue job
		enqueueJob(existing.ID, "webui")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(existing)
		return
	}

	// Create new target
	target := &models.Target{
		ID:        primitive.NewObjectID().Hex(),
		Domain:    req.Domain,
		Source:    models.SourceManual,
		Platform:  models.TargetPlatform(req.Platform),
		ProgramID: programID,
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

	path := strings.TrimPrefix(r.URL.Path, "/api/findings/")
	targetID := path
	if targetID == "" {
		http.Error(w, "Missing target ID", http.StatusBadRequest)
		return
	}

	coll := mongo.GetCollection("targets")
	var target models.Target
	err := coll.FindOne(ctx, bson.M{"_id": targetID}).Decode(&target)
	if err != nil {
		http.Error(w, "Target not found", http.StatusNotFound)
		return
	}

	load := func(name string) []bson.M {
		if mongo.Database == nil {
			return []bson.M{}
		}
		cc := mongo.GetCollection(name)
		cur, err := cc.Find(ctx, bson.M{"target_id": targetID})
		if err != nil {
			return []bson.M{}
		}
		defer cur.Close(ctx)
		var docs []bson.M
		if err := cur.All(ctx, &docs); err != nil {
			return []bson.M{}
		}
		return docs
	}

	result := map[string]interface{}{
		"target":    target,
		"jobs":      load("jobs"),
		"js_files":  load("js_files"),
		"secrets":   load("secrets"),
		"sinks":     load("sinks"),
		"endpoints": load("endpoints"),
		"params":    load("params"),
		"blh":       load("blh_candidates"),
		"cves":      load("library_cves"),
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
	json.NewEncoder(w).Encode(map[string]string{"status": "queued", "target_id": req.TargetID})
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

	if mongo.Database == nil {
		return
	}
	jobColl := mongo.GetCollection("jobs")
	_, err := jobColl.InsertOne(ctx, job)
	if err != nil {
		log.Error().Err(err).Str("target_id", targetID).Msg("Failed to enqueue job")
	}
}
