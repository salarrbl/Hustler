package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/qarqa/hustler/internal/database"
	"github.com/qarqa/hustler/internal/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// TargetRepository handles target persistence
type TargetRepository struct {
	db *database.DB
	coll *mongo.Collection
}

// NewTargetRepository creates a new target repository
func NewTargetRepository(db *database.DB) *TargetRepository {
	return &TargetRepository{
		db:   db,
		coll: db.GetHustlerCollection("targets"),
	}
}

// Create inserts a new target
func (r *TargetRepository) Create(ctx context.Context, target *models.Target) error {
	now := time.Now()
	target.CreatedAt = now
	target.UpdatedAt = now

	_, err := r.coll.InsertOne(ctx, target)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("target with domain %s already exists", target.Domain)
		}
		return fmt.Errorf("failed to create target: %w", err)
	}
	return nil
}

// GetByID retrieves a target by ID
func (r *TargetRepository) GetByID(ctx context.Context, id primitive.ObjectID) (*models.Target, error) {
	var target models.Target
	err := r.coll.FindOne(ctx, bson.M{"_id": id}).Decode(&target)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("target not found")
		}
		return nil, fmt.Errorf("failed to get target: %w", err)
	}
	return &target, nil
}

// GetByDomain retrieves a target by domain
func (r *TargetRepository) GetByDomain(ctx context.Context, domain string) (*models.Target, error) {
	var target models.Target
	err := r.coll.FindOne(ctx, bson.M{"domain": domain}).Decode(&target)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("target not found")
		}
		return nil, fmt.Errorf("failed to get target: %w", err)
	}
	return &target, nil
}

// List returns all targets with pagination
func (r *TargetRepository) List(ctx context.Context, limit, offset int) ([]*models.Target, error) {
	opts := options.Find().
		SetSort(bson.M{"created_at": -1}).
		SetLimit(int64(limit)).
		SetSkip(int64(offset))

	cursor, err := r.coll.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list targets: %w", err)
	}
	defer cursor.Close(ctx)

	var targets []*models.Target
	if err := cursor.All(ctx, &targets); err != nil {
		return nil, fmt.Errorf("failed to decode targets: %w", err)
	}
	return targets, nil
}

// Count returns total number of targets
func (r *TargetRepository) Count(ctx context.Context) (int64, error) {
	return r.coll.CountDocuments(ctx, bson.M{})
}

// Update updates a target
func (r *TargetRepository) Update(ctx context.Context, target *models.Target) error {
	target.UpdatedAt = time.Now()

	filter := bson.M{"_id": target.ID}
	update := bson.M{"$set": target}

	_, err := r.coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update target: %w", err)
	}
	return nil
}

// Delete removes a target by ID
func (r *TargetRepository) Delete(ctx context.Context, id primitive.ObjectID) error {
	_, err := r.coll.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("failed to delete target: %w", err)
	}
	return nil
}

// DeleteByDomain removes a target by domain
func (r *TargetRepository) DeleteByDomain(ctx context.Context, domain string) error {
	_, err := r.coll.DeleteOne(ctx, bson.M{"domain": domain})
	if err != nil {
		return fmt.Errorf("failed to delete target: %w", err)
	}
	return nil
}

// Exists checks if a target with the given domain exists
func (r *TargetRepository) Exists(ctx context.Context, domain string) (bool, error) {
	count, err := r.coll.CountDocuments(ctx, bson.M{"domain": domain})
	if err != nil {
		return false, fmt.Errorf("failed to check target existence: %w", err)
	}
	return count > 0, nil
}