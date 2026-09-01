package mongo

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"hustler/internal/config"
)

var (
	Client   *mongo.Client
	Database *mongo.Database
	Ctx      = context.Background()
)

// Connect establishes connection to MongoDB
func Connect(cfg config.MongoConfig) error {
	ctx, cancel := context.WithTimeout(Ctx, time.Duration(cfg.TimeoutSec)*time.Second)
	defer cancel()

	opts := options.Client().
		ApplyURI(cfg.URI).
		SetMaxPoolSize(cfg.MaxPool).
		SetMinPoolSize(cfg.MinPool).
		SetMaxConnIdleTime(30 * time.Second)

	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Ping to verify connection
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		return fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	Client = client
	Database = client.Database(cfg.Database)

	// Create indexes
	if err := createIndexes(ctx); err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	return nil
}

// Disconnect closes the MongoDB connection
func Disconnect() error {
	if Client != nil {
		return Client.Disconnect(Ctx)
	}
	return nil
}

// createIndexes creates necessary indexes for all collections
func createIndexes(ctx context.Context) error {
	indexes := map[string][]mongo.IndexModel{
		"targets": {
			{Keys: map[string]int{"domain": 1}, Options: options.Index().SetUnique(true)},
			{Keys: map[string]int{"status": 1}},
			{Keys: map[string]int{"source": 1}},
			{Keys: map[string]int{"added_at": -1}},
		},
		"js_files": {
			{Keys: map[string]int{"target_id": 1, "js_hash": 1}, Options: options.Index().SetUnique(true)},
			{Keys: map[string]int{"target_id": 1}},
			{Keys: map[string]int{"url": 1}},
			{Keys: map[string]int{"fetched_at": -1}},
		},
		"secrets": {
			{Keys: map[string]int{"target_id": 1, "js_file_id": 1}},
			{Keys: map[string]int{"pattern": 1}},
			{Keys: map[string]int{"confidence": 1}},
			{Keys: map[string]int{"found_at": -1}},
		},
		"endpoints": {
			{Keys: map[string]int{"target_id": 1, "js_file_id": 1}},
			{Keys: map[string]int{"endpoint": 1}},
			{Keys: map[string]int{"method": 1}},
			{Keys: map[string]int{"found_at": -1}},
		},
		"params": {
			{Keys: map[string]int{"target_id": 1, "js_file_id": 1}},
			{Keys: map[string]int{"param_name": 1}},
			{Keys: map[string]int{"context": 1}},
			{Keys: map[string]int{"found_at": -1}},
		},
		"sinks": {
			{Keys: map[string]int{"target_id": 1, "js_file_id": 1}},
			{Keys: map[string]int{"sink_type": 1}},
			{Keys: map[string]int{"source_type": 1}},
			{Keys: map[string]int{"confidence": 1}},
			{Keys: map[string]int{"found_at": -1}},
		},
		"blh_candidates": {
			{Keys: map[string]int{"target_id": 1}},
			{Keys: map[string]int{"referenced_domain": 1}},
			{Keys: map[string]int{"resolution_status": 1}},
			{Keys: map[string]int{"risk_level": 1}},
			{Keys: map[string]int{"found_at": -1}},
		},
		"library_cves": {
			{Keys: map[string]int{"target_id": 1, "js_file_id": 1}},
			{Keys: map[string]int{"library_name": 1}},
			{Keys: map[string]int{"version": 1}},
			{Keys: map[string]int{"cve_id": 1}},
			{Keys: map[string]int{"severity": 1}},
			{Keys: map[string]int{"found_at": -1}},
		},
	}

	for collName, models := range indexes {
		coll := Database.Collection(collName)
		if _, err := coll.Indexes().CreateMany(ctx, models); err != nil {
			return fmt.Errorf("failed to create indexes for %s: %w", collName, err)
		}
	}

	return nil
}

// GetCollection returns a collection handle
func GetCollection(name string) *mongo.Collection {
	return Database.Collection(name)
}