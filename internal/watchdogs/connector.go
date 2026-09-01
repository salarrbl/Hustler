package watchdogs

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	wmongo "go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"hustler/internal/config"
	"hustler/internal/models"
)

// Connector handles read-only sync from Watchdogs MongoDB
type Connector struct {
	client      *wmongo.Client
	db          *wmongo.Database
	cfg         config.WatchdogsConfig
	hustlerColl *wmongo.Collection
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
	hustlerColl := db.Collection("targets") // Use Watchdogs DB connection but targets collection

	return &Connector{
		client:      client,
		db:          db,
		cfg:         cfg,
		hustlerColl: hustlerColl,
	}, nil
}

// Close closes the Watchdogs MongoDB connection
func (c *Connector) Close() error {
	return c.client.Disconnect(context.Background())
}

// Sync pulls targets from Watchdogs and upserts into Hustler's targets collection
// This is EXPLICITLY INVOKED via CLI - never auto-runs
func (c *Connector) Sync(ctx context.Context) (int, error) {
	if !c.cfg.Enabled {
		return 0, fmt.Errorf("Watchdogs sync is disabled - enable in config or use explicit CLI flag")
	}

	mapping := c.cfg.FieldMapping
	if mapping.Collection == "" {
		return 0, fmt.Errorf("Watchdogs field mapping not configured - TODO: confirm Watchdogs schema")
	}

	// Query Watchdogs collection
	coll := c.db.Collection(mapping.Collection)
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

		// Check if already exists in Hustler
		filter := bson.M{"domain": domain}
		var existing models.Target
		err := c.hustlerColl.FindOne(ctx, filter).Decode(&existing)
		if err == nil {
			// Update existing with latest Watchdogs data
			if err := c.updateTargetFromWatchdogs(ctx, &existing, doc, mapping); err != nil {
				continue
			}
			skipped++
			continue
		}

		// Create new target
		target := models.NewTarget(domain, models.SourceWatchdogs)
		c.populateTargetFromWatchdogs(target, doc, mapping)

		_, err = c.hustlerColl.InsertOne(ctx, target)
		if err != nil {
			continue
		}
		synced++
	}

	if err := cursor.Err(); err != nil {
		return synced, fmt.Errorf("cursor error: %w", err)
	}

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
}