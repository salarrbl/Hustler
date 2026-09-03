package watchdogs

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson"
	wmongo "go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"hustler/internal/config"
	"hustler/internal/mongo"
	"hustler/internal/models"
)

// Connector handles read-only sync from Watchdogs MongoDB
type Connector struct {
	client       *wmongo.Client
	watchdogsDb  *wmongo.Database
	hustlerColl  *wmongo.Collection
	cfg          config.WatchdogsConfig
}

// NewConnector creates a new Watchdogs connector
func NewConnector(cfg config.WatchdogsConfig) (*Connector, error) {
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

	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		return nil, fmt.Errorf("failed to ping Watchdogs MongoDB: %w", err)
	}

	db := client.Database(cfg.Database)

	return &Connector{
		client:      client,
		watchdogsDb: db,
		cfg:         cfg,
		hustlerColl: mongo.GetCollection("targets"),
	}, nil
}

// Close closes the Watchdogs MongoDB connection
func (c *Connector) Close() error {
	return c.client.Disconnect(context.Background())
}

// Sync pulls targets from Watchdogs and upserts into Hustler's targets collection.
// Sync is incremental: only domains NOT already in Hustler are created as new targets.
// Each new target gets a hunt job enqueued directly into MongoDB.
// This is EXPLICITLY INVOKED via CLI - never auto-runs.
func (c *Connector) Sync(ctx context.Context) (int, error) {
	if !c.cfg.Enabled {
		return 0, fmt.Errorf("Watchdogs sync is disabled - set watchdogs.enabled: true in config.yaml")
	}

	mapping := c.cfg.FieldMapping
	if mapping.Collection == "" {
		return 0, fmt.Errorf("Watchdogs field mapping not configured - TODO: confirm Watchdogs schema")
	}

	// Query Watchdogs collection
	coll := c.watchdogsDb.Collection(mapping.Collection)
	cursor, err := coll.Find(ctx, bson.M{})
	if err != nil {
		return 0, fmt.Errorf("failed to query Watchdogs collection %s: %w", mapping.Collection, err)
	}
	defer cursor.Close(ctx)

	// Track stats
	var synced, skipped int

	for cursor.Next(ctx) {
		var doc bson.M
		if err := cursor.Decode(&doc); err != nil {
			continue
		}

		// Extract domain using configurable field mapping
		domainVal, ok := doc[mapping.DomainField]
		if !ok {
			skipped++
			continue
		}
		domain, ok := domainVal.(string)
		if !ok || domain == "" {
			skipped++
			continue
		}

		// Dedupe: check if domain already exists in Hustler
		filter := bson.M{"domain": domain}
		err := c.hustlerColl.FindOne(ctx, filter).Decode(new(models.Target))
		if err == nil {
			// Domain already exists — update it with latest Watchdogs data
			var existing models.Target
			c.hustlerColl.FindOne(ctx, filter).Decode(&existing)
			c.updateTargetFromWatchdogs(ctx, &existing, doc, mapping)
			skipped++
			continue
		}

		// Create new target
		target := models.NewTarget(domain, models.SourceWatchdogs)
		c.populateTargetFromWatchdogs(target, doc, mapping)

		result, err := c.hustlerColl.InsertOne(ctx, target)
		if err != nil {
			if IsDuplicateKeyError(err) {
				skipped++
				continue
			}
			log.Warn().Err(err).Str("domain", domain).Msg("Failed to insert target from Watchdogs")
			continue
		}
		target.ID = result.InsertedID.(string)
		synced++

		// Enqueue hunt job directly into MongoDB (daemon will pick it up)
		job := &models.Job{
			ID:       uuid.New().String(),
			TargetID: target.ID,
			Status:   models.JobStatusQueued,
			QueuedAt: time.Now(),
			Source:   "watchdogs",
		}
		jobColl := mongo.GetCollection("jobs")
		_, err = jobColl.InsertOne(ctx, job)
		if err != nil {
			log.Warn().Err(err).Str("domain", domain).Msg("Failed to enqueue hunt job for Watchdogs target")
		} else {
			log.Info().Str("job_id", job.ID).Str("domain", domain).Msg("Hunt job enqueued for Watchdogs target")
		}
	}

	if err := cursor.Err(); err != nil {
		return synced, fmt.Errorf("cursor error: %w", err)
	}

	log.Info().Int("synced", synced).Int("skipped", skipped).Msg("Watchdogs sync completed")
	fmt.Printf("Watchdogs sync: %d new targets, %d skipped (already known)\n", synced, skipped)
	return synced, nil
}

// updateTargetFromWatchdogs updates an existing target with latest Watchdogs data
func (c *Connector) updateTargetFromWatchdogs(ctx context.Context, target *models.Target, doc bson.M, mapping config.WatchdogsMapping) error {
	c.populateTargetFromWatchdogs(target, doc, mapping)
	target.UpdatedAt = time.Now()

	update := bson.M{
		"$set": bson.M{
			"root_domain":    target.RootDomain,
			"status_code":    target.StatusCode,
			"technologies":   target.Technologies,
			"title":          target.Title,
			"ports":          target.Ports,
			"cdn":            target.CDN,
			"providers":      target.Providers,
			"discovered_at":  target.DiscoveredAt,
			"updated_at":     target.UpdatedAt,
		},
	}
	_, err := c.hustlerColl.UpdateOne(ctx, bson.M{"_id": target.ID}, update)
	return err
}

// populateTargetFromWatchdogs fills target fields from Watchdogs document using field mapping
func (c *Connector) populateTargetFromWatchdogs(target *models.Target, doc bson.M, mapping config.WatchdogsMapping) {
	if v, ok := doc[mapping.RootDomainField]; ok {
		if s, ok := v.(string); ok {
			target.RootDomain = s
		}
	}
	if v, ok := doc[mapping.StatusField]; ok {
		switch val := v.(type) {
		case int32:
			target.StatusCode = int(val)
		case int64:
			target.StatusCode = int(val)
		case int:
			target.StatusCode = val
		}
	}
	if v, ok := doc[mapping.TechField]; ok {
		if arr, ok := v.(bson.A); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok {
					target.Technologies = append(target.Technologies, s)
				}
			}
		}
	}
	if v, ok := doc[mapping.TitleField]; ok {
		if s, ok := v.(string); ok {
			target.Title = s
		}
	}
	if v, ok := doc[mapping.PortsField]; ok {
		if arr, ok := v.(bson.A); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok {
					target.Ports = append(target.Ports, s)
				}
			}
		}
	}
	if v, ok := doc[mapping.CDNField]; ok {
		if s, ok := v.(string); ok {
			target.CDN = s
		}
	}
	if v, ok := doc[mapping.ProviderField]; ok {
		if arr, ok := v.(bson.A); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok {
					target.Providers = append(target.Providers, s)
				}
			}
		}
	}
	if v, ok := doc[mapping.DiscoveredAtField]; ok {
		if t, ok := v.(time.Time); ok {
			target.DiscoveredAt = &t
		}
	}

	// Handle program and platform mapping
	var programName string
	if mapping.ProgramField != "" {
		if v, ok := doc[mapping.ProgramField]; ok {
			if s, ok := v.(string); ok {
				programName = s
			}
		}
	}

	var platform string
	if mapping.PlatformField != "" {
		if v, ok := doc[mapping.PlatformField]; ok {
			if s, ok := v.(string); ok {
				platform = s
			}
		}
	}

	// Default platform if not found in Watchdogs doc
	if platform == "" {
		platform = "freelance"
	}

	// Get or create program if we have a program name
	if programName != "" {
		programID, err := c.getOrCreateProgram(programName, platform)
		if err == nil {
			target.ProgramID = programID
			target.Platform = models.TargetPlatform(platform)
		}
	}
}

// IsDuplicateKeyError checks if a MongoDB error is a duplicate key error (code 11000)
func IsDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	if mongoErr, ok := err.(interface{ Code() int }); ok {
		return mongoErr.Code() == 11000
	}
	return false
}

// getOrCreateProgram finds or creates a program and returns its ID
func (c *Connector) getOrCreateProgram(name, platform string) (string, error) {
	ctx := context.Background()
	programColl := c.hustlerColl.Database().Collection("programs")

	// Check if exists
	var existing models.Program
	err := programColl.FindOne(ctx, bson.M{"name": name, "platform": platform}).Decode(&existing)
	if err == nil {
		return existing.ID, nil
	}

	// Create new
	program := &models.Program{
		ID:       uuid.New().String(),
		Name:     name,
		Platform: platform,
		AddedAt:  time.Now(),
	}

	result, err := programColl.InsertOne(ctx, program)
	if err != nil {
		return "", err
	}

	return result.InsertedID.(string), nil
}