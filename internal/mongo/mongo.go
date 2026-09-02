package mongo

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
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
			{Keys: bson.D{{Key: "domain", Value: 1}}, Options: options.Index().SetUnique(true)},
			{Keys: bson.D{{Key: "status", Value: 1}}},
			{Keys: bson.D{{Key: "source", Value: 1}}},
			{Keys: bson.D{{Key: "added_at", Value: -1}}},
		},
		"js_files": {
			{Keys: bson.D{{Key: "target_id", Value: 1}, {Key: "js_hash", Value: 1}}, Options: options.Index().SetUnique(true)},
			{Keys: bson.D{{Key: "target_id", Value: 1}}},
			{Keys: bson.D{{Key: "url", Value: 1}}},
			{Keys: bson.D{{Key: "fetched_at", Value: -1}}},
		},
		"secrets": {
			{Keys: bson.D{{Key: "target_id", Value: 1}, {Key: "js_file_id", Value: 1}}},
			{Keys: bson.D{{Key: "pattern", Value: 1}}},
			{Keys: bson.D{{Key: "confidence", Value: 1}}},
			{Keys: bson.D{{Key: "found_at", Value: -1}}},
		},
		"endpoints": {
			{Keys: bson.D{{Key: "target_id", Value: 1}, {Key: "js_file_id", Value: 1}}},
			{Keys: bson.D{{Key: "target_id", Value: 1}}},
			{Keys: bson.D{{Key: "endpoint", Value: 1}}},
			{Keys: bson.D{{Key: "method", Value: 1}}},
			{Keys: bson.D{{Key: "found_at", Value: -1}}},
		},
		"params": {
			{Keys: bson.D{{Key: "target_id", Value: 1}, {Key: "js_file_id", Value: 1}}},
			{Keys: bson.D{{Key: "param_name", Value: 1}}},
			{Keys: bson.D{{Key: "context", Value: 1}}},
			{Keys: bson.D{{Key: "found_at", Value: -1}}},
		},
		"sinks": {
			{Keys: bson.D{{Key: "target_id", Value: 1}, {Key: "js_file_id", Value: 1}}},
			{Keys: bson.D{{Key: "sink_type", Value: 1}}},
			{Keys: bson.D{{Key: "source_type", Value: 1}}},
			{Keys: bson.D{{Key: "confidence", Value: 1}}},
			{Keys: bson.D{{Key: "found_at", Value: -1}}},
		},
		"blh_candidates": {
			{Keys: bson.D{{Key: "target_id", Value: 1}}},
			{Keys: bson.D{{Key: "referenced_domain", Value: 1}}},
			{Keys: bson.D{{Key: "resolution_status", Value: 1}}},
			{Keys: bson.D{{Key: "risk_level", Value: 1}}},
			{Keys: bson.D{{Key: "found_at", Value: -1}}},
		},
		"library_cves": {
			{Keys: bson.D{{Key: "target_id", Value: 1}, {Key: "js_file_id", Value: 1}}},
			{Keys: bson.D{{Key: "library_name", Value: 1}}},
			{Keys: bson.D{{Key: "version", Value: 1}}},
			{Keys: bson.D{{Key: "cve_id", Value: 1}}},
			{Keys: bson.D{{Key: "severity", Value: 1}}},
			{Keys: bson.D{{Key: "found_at", Value: -1}}},
		},
		"sensitive_endpoint_candidates": {
			{Keys: bson.D{{Key: "target_id", Value: 1}}},
			{Keys: bson.D{{Key: "endpoint", Value: 1}}},
			{Keys: bson.D{{Key: "checked_at", Value: -1}}},
		},
		"discovered_urls": {
			{Keys: bson.D{{Key: "target_id", Value: 1}, {Key: "url", Value: 1}}, Options: options.Index().SetUnique(true)},
			{Keys: bson.D{{Key: "target_id", Value: 1}}},
			{Keys: bson.D{{Key: "url_type", Value: 1}}},
			{Keys: bson.D{{Key: "last_seen", Value: -1}}},
		},
		"jobs": {
			{Keys: bson.D{{Key: "target_id", Value: 1}}},
			{Keys: bson.D{{Key: "status", Value: 1}}},
			{Keys: bson.D{{Key: "queued_at", Value: 1}}},
			{Keys: bson.D{{Key: "source", Value: 1}}},
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