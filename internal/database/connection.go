package database

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/qarqa/hustler/internal/config"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// DB holds both MongoDB connections
type DB struct {
	Hustler    *mongo.Database
	WatchDogs  *mongo.Database
	hustlerClient   *mongo.Client
	watchdogsClient *mongo.Client
}

// Connect establishes both database connections
func Connect(cfg *config.Config) (*DB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect to Hustler DB (read/write)
	hustlerClient, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.HustlerDB.URI))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Hustler DB: %w", err)
	}

	// Ping Hustler DB
	if err := hustlerClient.Ping(ctx, readpref.Primary()); err != nil {
		return nil, fmt.Errorf("failed to ping Hustler DB: %w", err)
	}

	// Connect to WatchDogs DB (read-only)
	watchdogsClient, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.WatchDogsDB.URI))
	if err != nil {
		hustlerClient.Disconnect(ctx)
		return nil, fmt.Errorf("failed to connect to WatchDogs DB: %w", err)
	}

	// Ping WatchDogs DB
	if err := watchdogsClient.Ping(ctx, readpref.Primary()); err != nil {
		hustlerClient.Disconnect(ctx)
		watchdogsClient.Disconnect(ctx)
		return nil, fmt.Errorf("failed to ping WatchDogs DB: %w", err)
	}

	db := &DB{
		Hustler:         hustlerClient.Database(cfg.HustlerDB.Database),
		WatchDogs:       watchdogsClient.Database(cfg.WatchDogsDB.Database),
		hustlerClient:   hustlerClient,
		watchdogsClient: watchdogsClient,
	}

	// Create indexes for Hustler collections
	if err := db.createIndexes(ctx); err != nil {
		log.Printf("Warning: failed to create indexes: %v", err)
	}

	log.Printf("Connected to Hustler DB: %s", cfg.HustlerDB.Database)
	log.Printf("Connected to WatchDogs DB: %s (read-only: %v)", cfg.WatchDogsDB.Database, cfg.WatchDogsDB.ReadOnly)

	return db, nil
}

// Disconnect closes both database connections
func (db *DB) Disconnect(ctx context.Context) {
	if db.hustlerClient != nil {
		db.hustlerClient.Disconnect(ctx)
	}
	if db.watchdogsClient != nil {
		db.watchdogsClient.Disconnect(ctx)
	}
}

// createIndexes creates necessary indexes for Hustler collections
func (db *DB) createIndexes(ctx context.Context) error {
	// Targets collection - unique index on domain
	targetsColl := db.Hustler.Collection("targets")
	_, err := targetsColl.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "domain", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("failed to create targets index: %w", err)
	}

	// Assets collection - compound index on target_id + subdomain
	assetsColl := db.Hustler.Collection("assets")
	_, err = assetsColl.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "target_id", Value: 1}, {Key: "subdomain", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("failed to create assets index: %w", err)
	}

	// URLs collection - compound index on target_id + url
	urlsColl := db.Hustler.Collection("urls")
	_, err = urlsColl.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "target_id", Value: 1}, {Key: "url", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("failed to create urls index: %w", err)
	}

	// Parameters collection - index on target_id + url_id + name
	paramsColl := db.Hustler.Collection("parameters")
	_, err = paramsColl.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "target_id", Value: 1}, {Key: "url_id", Value: 1}, {Key: "name", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("failed to create parameters index: %w", err)
	}

	// Jobs collection - index on target_id + status + created_at
	jobsColl := db.Hustler.Collection("jobs")
	_, err = jobsColl.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "target_id", Value: 1}, {Key: "status", Value: 1}, {Key: "created_at", Value: -1}},
	})
	if err != nil {
		return fmt.Errorf("failed to create jobs index: %w", err)
	}

	// Findings collection - index on target_id + severity + status
	findingsColl := db.Hustler.Collection("findings")
	_, err = findingsColl.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "target_id", Value: 1}, {Key: "severity", Value: 1}, {Key: "status", Value: 1}},
	})
	if err != nil {
		return fmt.Errorf("failed to create findings index: %w", err)
	}

	return nil
}

// GetHustlerCollection returns a Hustler collection (read/write)
func (db *DB) GetHustlerCollection(name string) *mongo.Collection {
	return db.Hustler.Collection(name)
}

// GetWatchDogsCollection returns a WatchDogs collection (READ ONLY)
func (db *DB) GetWatchDogsCollection(name string) *mongo.Collection {
	return db.WatchDogs.Collection(name)
}