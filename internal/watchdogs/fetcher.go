package watchdogs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson"
	wmongo "go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"hustler/internal/config"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

// Fetcher handles fetching and syncing data from Watchdogs MongoDB
type Fetcher struct {
	client      *wmongo.Client
	watchdogsDb *wmongo.Database
	cfg         config.WatchdogsConfig
	hustlerDb   *mongo.Database
}

// WatchdogsAsset represents a subdomain/asset from Watchdogs
type WatchdogsAsset struct {
	Subdomain    string    `bson:"subdomain" json:"subdomain"`
	RootDomain   string    `bson:"root_domain" json:"root_domain"`
	StatusCode   int       `bson:"status_code" json:"status_code"`
	Title        string    `bson:"title" json:"title"`
	Technologies []string  `bson:"technologies" json:"technologies"`
	Ports        []string  `bson:"ports" json:"ports"`
	CDN          string    `bson:"cdn" json:"cdn"`
	DiscoveredAt time.Time `bson:"discovered_at" json:"discovered_at"`
	ProgramName  string    `bson:"program_name,omitempty" json:"program_name,omitempty"`
	Platform     string    `bson:"platform,omitempty" json:"platform,omitempty"`
}

// FetchOptions defines filtering options for fetching from Watchdogs
type FetchOptions struct {
	// Filter by specific platform (e.g., "hackerone", "bugcrowd")
	Platform string
	// Filter by specific program name
	Program string
	// Only fetch live subs (HTTP records with status code > 0)
	LiveOnly bool
	// Only fetch subs that are not already in Hustler
	NewOnly bool
}

// FetchResult contains the results of a fetch operation
type FetchResult struct {
	Platforms int `json:"platforms"`
	Programs  int `json:"programs"`
	Assets    int `json:"assets"`
	NewAssets int `json:"new_assets"`
	Skipped   int `json:"skipped"`
}

// NewFetcher creates a new Watchdogs fetcher
func NewFetcher(cfg config.WatchdogsConfig) (*Fetcher, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Client().
		ApplyURI(cfg.MongoURI).
		SetMaxPoolSize(10).
		SetMinPoolSize(1)

	client, err := wmongo.Connect(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Watchdogs MongoDB: %w", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping Watchdogs MongoDB: %w", err)
	}

	// Get Hustler's database connection
	hustlerDb := mongo.Database
	if hustlerDb == nil {
		return nil, fmt.Errorf("Hustler MongoDB not connected")
	}

	return &Fetcher{
		client:      client,
		watchdogsDb: client.Database(cfg.Database),
		cfg:         cfg,
		hustlerDb:   hustlerDb,
	}, nil
}

// Close closes the Watchdogs MongoDB connection
func (f *Fetcher) Close() error {
	return f.client.Disconnect(context.Background())
}

// Fetch retrieves assets from Watchdogs based on the provided options
func (f *Fetcher) Fetch(ctx context.Context, opts FetchOptions) (*FetchResult, error) {
	result := &FetchResult{}

	// Build the query filter for HTTP collection
	filter := bson.M{}
	
	// Filter for live subs (status code > 0)
	if opts.LiveOnly {
		filter["status_code"] = bson.M{"$gt": 0}
	}

	// Execute the query
	collection := f.watchdogsDb.Collection("http")
	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to query HTTP collection: %w", err)
	}
	defer cursor.Close(ctx)

	// Track stats
	platformsMap := make(map[string]bool)
	programsMap := make(map[string]bool)
	existingSubs := make(map[string]bool)

	// Pre-load existing subdomains if NewOnly is set
	if opts.NewOnly {
		existing, err := f.getExistingSubdomains(ctx)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to load existing subdomains, will sync all")
		} else {
			existingSubs = existing
		}
	}

	// Process each HTTP record
	for cursor.Next(ctx) {
		var asset WatchdogsAsset
		if err := cursor.Decode(&asset); err != nil {
			continue
		}

		// Normalize the asset
		asset.Subdomain = strings.ToLower(strings.TrimSpace(asset.Subdomain))
		asset.RootDomain = strings.ToLower(strings.TrimSpace(asset.RootDomain))

		// Skip empty subdomains
		if asset.Subdomain == "" {
			continue
		}

		// Determine platform and program
		platform := asset.Platform
		programName := asset.ProgramName

		// If not set in Watchdogs, try to derive from Hustler's existing data
		if platform == "" || programName == "" {
			derived, err := f.deriveFromHustler(ctx, asset.RootDomain)
			if err == nil && derived != nil {
				if platform == "" {
					platform = derived.Platform
				}
				if programName == "" {
					programName = derived.ProgramName
				}
			}
		}

		// Default platform if still empty
		if platform == "" {
			platform = "freelance"
		}

		// Apply platform filter
		if opts.Platform != "" && !strings.EqualFold(platform, opts.Platform) {
			continue
		}

		// Apply program filter
		if opts.Program != "" && !strings.EqualFold(programName, opts.Program) {
			continue
		}

		// Track platforms and programs
		platformsMap[strings.ToLower(platform)] = true
		if programName != "" {
			programsMap[strings.ToLower(programName)] = true
		}

		// Check if already exists
		if opts.NewOnly && existingSubs[asset.Subdomain] {
			result.Skipped++
			continue
		}

		// Upsert into Hustler
		err := f.upsertAsset(ctx, &asset, platform, programName)
		if err != nil {
			log.Warn().Err(err).Str("subdomain", asset.Subdomain).Msg("Failed to upsert asset")
			result.Skipped++
			continue
		}

		if !existingSubs[asset.Subdomain] {
			result.NewAssets++
		}
		result.Assets++
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	result.Platforms = len(platformsMap)
	result.Programs = len(programsMap)

	log.Info().
		Int("platforms", result.Platforms).
		Int("programs", result.Programs).
		Int("assets", result.Assets).
		Int("new_assets", result.NewAssets).
		Int("skipped", result.Skipped).
		Msg("Watchdogs fetch completed")

	return result, nil
}

// deriveFromHustler looks up platform/program from Hustler's existing data
func (f *Fetcher) deriveFromHustler(ctx context.Context, rootDomain string) (*struct {
	Platform    string
	ProgramName string
}, error) {
	coll := f.hustlerDb.Collection("targets")
	
	var target models.Target
	err := coll.FindOne(ctx, bson.M{"root_domain": rootDomain}).Decode(&target)
	if err != nil {
		return nil, err
	}

	// Get program name if ProgramID exists
	programName := ""
	if target.ProgramID != "" {
		program, err := f.getProgramByID(ctx, target.ProgramID)
		if err == nil && program != nil {
			programName = program.Name
		}
	}

	return &struct {
		Platform    string
		ProgramName string
	}{
		Platform:    string(target.Platform),
		ProgramName: programName,
	}, nil
}

// getProgramByID retrieves a program by its ID
func (f *Fetcher) getProgramByID(ctx context.Context, programID string) (*models.Program, error) {
	coll := f.hustlerDb.Collection("programs")
	
	var program models.Program
	err := coll.FindOne(ctx, bson.M{"_id": programID}).Decode(&program)
	if err != nil {
		return nil, err
	}
	return &program, nil
}

// getExistingSubdomains returns a map of existing subdomains in Hustler
func (f *Fetcher) getExistingSubdomains(ctx context.Context) (map[string]bool, error) {
	coll := f.hustlerDb.Collection("targets")
	cursor, err := coll.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	result := make(map[string]bool)
	for cursor.Next(ctx) {
		var target models.Target
		if err := cursor.Decode(&target); err != nil {
			continue
		}
		result[strings.ToLower(target.Domain)] = true
	}
	return result, nil
}

// upsertAsset inserts or updates an asset in Hustler
func (f *Fetcher) upsertAsset(ctx context.Context, asset *WatchdogsAsset, platform, programName string) error {
	coll := f.hustlerDb.Collection("targets")

	// Get or create program
	var programID string
	if programName != "" {
		var err error
		programID, err = f.getOrCreateProgram(ctx, programName, platform)
		if err != nil {
			log.Warn().Err(err).Str("program", programName).Msg("Failed to get/create program")
		}
	}

	now := time.Now()
	filter := bson.M{"domain": asset.Subdomain}
	
	update := bson.M{
		"$set": bson.M{
			"root_domain":    asset.RootDomain,
			"source":         models.SourceWatchdogs,
			"platform":       models.TargetPlatform(platform),
			"program_id":     programID,
			"status_code":    asset.StatusCode,
			"title":          asset.Title,
			"technologies":   asset.Technologies,
			"ports":          asset.Ports,
			"cdn":            asset.CDN,
			"updated_at":     now,
		},
		"$setOnInsert": bson.M{
			"domain":     asset.Subdomain,
			"status":     models.StatusPending,
			"added_at":   now,
		},
	}

	opts := options.Update().SetUpsert(true)
	_, err := coll.UpdateOne(ctx, filter, update, opts)
	return err
}

// getOrCreateProgram finds or creates a program and returns its ID
func (f *Fetcher) getOrCreateProgram(ctx context.Context, name, platform string) (string, error) {
	coll := f.hustlerDb.Collection("programs")
	now := time.Now()

	// Check if exists
	var existing models.Program
	err := coll.FindOne(ctx, bson.M{"name": name, "platform": platform}).Decode(&existing)
	if err == nil {
		return existing.ID, nil
	}

	// Create new
	program := &models.Program{
		ID:       uuid.New().String(),
		Name:     name,
		Platform: platform,
		AddedAt:  now,
	}

	result, err := coll.InsertOne(ctx, program)
	if err != nil {
		return "", err
	}

	return result.InsertedID.(string), nil
}

// TargetTreeNode represents a node in the target hierarchy
type TargetTreeNode struct {
	ProgramName string           `json:"program_name"`
	Assets     []models.Target  `json:"assets"`
}

// GetTargetTree returns the hierarchy: Platform → Program → Assets
func (f *Fetcher) GetTargetTree(ctx context.Context) (map[string]map[string][]models.Target, error) {
	coll := f.hustlerDb.Collection("targets")
	
	// Fetch all targets with source=watchdogs
	cursor, err := coll.Find(ctx, bson.M{"source": string(models.SourceWatchdogs)})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	tree := make(map[string]map[string][]models.Target)
	programCache := make(map[string]string) // programID -> programName

	for cursor.Next(ctx) {
		var target models.Target
		if err := cursor.Decode(&target); err != nil {
			continue
		}

		platform := string(target.Platform)
		if platform == "" {
			platform = "freelance"
		}

		// Get program name if we have a programID
		programName := "uncategorized"
		if target.ProgramID != "" {
			if name, ok := programCache[target.ProgramID]; ok {
				programName = name
			} else {
				program, err := f.getProgramByID(ctx, target.ProgramID)
				if err == nil && program != nil {
					programName = program.Name
					programCache[target.ProgramID] = programName
				}
			}
		}

		// Initialize nested maps
		if _, ok := tree[platform]; !ok {
			tree[platform] = make(map[string][]models.Target)
		}
		if _, ok := tree[platform][programName]; !ok {
			tree[platform][programName] = []models.Target{}
		}

		tree[platform][programName] = append(tree[platform][programName], target)
	}

	return tree, nil
}
