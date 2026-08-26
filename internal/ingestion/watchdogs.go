package ingestion

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/qarqa/hustler/internal/database"
	"github.com/qarqa/hustler/internal/models"
	"github.com/qarqa/hustler/internal/repository"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// WatchDogsIngestion handles reading recon data from WatchDogs MongoDB
type WatchDogsIngestion struct {
	db            *database.DB
	targetRepo    *repository.TargetRepository
	assetRepo     *AssetRepository
	urlRepo       *URLRepository
}

// NewWatchDogsIngestion creates a new WatchDogs ingestion handler
func NewWatchDogsIngestion(db *database.DB, targetRepo *repository.TargetRepository, assetRepo *AssetRepository, urlRepo *URLRepository) *WatchDogsIngestion {
	return &WatchDogsIngestion{
		db:         db,
		targetRepo: targetRepo,
		assetRepo:  assetRepo,
		urlRepo:    urlRepo,
	}
}

// WatchDogsHTTPRecord represents an HTTP record from WatchDogs
type WatchDogsHTTPRecord struct {
	ID             primitive.ObjectID `bson:"_id,omitempty"`
	RootDomain     string             `bson:"root_domain"`
	Subdomain      string             `bson:"subdomain"`
	StatusCode     int                `bson:"status_code,omitempty"`
	ContentLength  int64              `bson:"content_length,omitempty"`
	Title          string             `bson:"title,omitempty"`
	Technologies   []string           `bson:"technologies,omitempty"`
	CDN            string             `bson:"cdn,omitempty"`
	IP             string             `bson:"ip,omitempty"`
	CNAME          []string           `bson:"cname,omitempty"`
	Ports          []string           `bson:"ports,omitempty"`
	ProbeType      string             `bson:"probe_type"`
	DiscoveredAt   time.Time          `bson:"discovered_at,omitempty"`
	ScreenshotPath string             `bson:"screenshot_path,omitempty"`
	ScreenshotHash string             `bson:"screenshot_hash,omitempty"`
}

// ImportTargetAssets imports live assets from WatchDogs for a target
func (i *WatchDogsIngestion) ImportTargetAssets(ctx context.Context, targetDomain string) (*ImportResult, error) {
	// Get target from Hustler DB
	target, err := i.targetRepo.GetByDomain(ctx, targetDomain)
	if err != nil {
		return nil, fmt.Errorf("target not found in Hustler: %w", err)
	}

	log.Printf("Importing assets from WatchDogs for target: %s", targetDomain)

	// Query WatchDogs HTTP collection for live subdomains
	httpColl := i.db.GetWatchDogsCollection("http")
	
	filter := bson.M{
		"root_domain": targetDomain,
		"status_code": bson.M{"$gt": 0}, // Only live subdomains
	}

	opts := options.Find().SetSort(bson.M{"discovered_at": -1})
	cursor, err := httpColl.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to query WatchDogs: %w", err)
	}
	defer cursor.Close(ctx)

	var records []WatchDogsHTTPRecord
	if err := cursor.All(ctx, &records); err != nil {
		return nil, fmt.Errorf("failed to decode WatchDogs records: %w", err)
	}

	log.Printf("Found %d live assets in WatchDogs for %s", len(records), targetDomain)

	// Convert and store in Hustler DB
	result := &ImportResult{
		TargetID:     target.ID,
		TargetDomain: targetDomain,
		TotalFound:   len(records),
		Imported:     0,
		Updated:      0,
		Errors:       []string{},
	}

	for _, record := range records {
		asset := &models.Asset{
			TargetID:     target.ID,
			Subdomain:    record.Subdomain,
			StatusCode:   record.StatusCode,
			Title:        record.Title,
			Technologies: record.Technologies,
			CDN:          record.CDN,
			IP:           record.IP,
			CNAME:        record.CNAME,
			Ports:        record.Ports,
			Source:       "watchdogs",
			IsAlive:      record.StatusCode > 0,
			LastSeen:     record.DiscoveredAt,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		// Check if asset already exists
		existing, err := i.assetRepo.GetByTargetAndSubdomain(ctx, target.ID, record.Subdomain)
		if err != nil && err != mongo.ErrNoDocuments {
			result.Errors = append(result.Errors, fmt.Sprintf("Error checking asset %s: %v", record.Subdomain, err))
			continue
		}

		if existing != nil {
			// Update existing asset
			asset.ID = existing.ID
			asset.CreatedAt = existing.CreatedAt
			asset.UpdatedAt = time.Now()
			if err := i.assetRepo.Update(ctx, asset); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Error updating asset %s: %v", record.Subdomain, err))
				continue
			}
			result.Updated++
		} else {
			// Create new asset
			if err := i.assetRepo.Create(ctx, asset); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Error creating asset %s: %v", record.Subdomain, err))
				continue
			}
			result.Imported++
		}

		// Also create a base URL record for the asset
		if record.StatusCode > 0 {
			// Try both http and https
			for _, scheme := range []string{"https", "http"} {
				url := fmt.Sprintf("%s://%s", scheme, record.Subdomain)
				urlRecord := &models.URL{
					TargetID:    target.ID,
					AssetID:     asset.ID,
					URL:         url,
					Method:      "GET",
					StatusCode:  record.StatusCode,
					Source:      "watchdogs",
					IsJunk:      false,
					Interesting: false,
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
				}
				if err := i.urlRepo.Create(ctx, urlRecord); err != nil {
					if !mongo.IsDuplicateKeyError(err) {
						result.Errors = append(result.Errors, fmt.Sprintf("Error creating URL %s: %v", url, err))
					}
				}
			}
		}
	}

	log.Printf("Import complete for %s: %d imported, %d updated, %d errors", targetDomain, result.Imported, result.Updated, len(result.Errors))
	return result, nil
}

// ImportResult holds the result of an import operation
type ImportResult struct {
	TargetID     primitive.ObjectID
	TargetDomain string
	TotalFound   int
	Imported     int
	Updated      int
	Errors       []string
}

// AssetRepository handles asset persistence
type AssetRepository struct {
	db   *database.DB
	coll *mongo.Collection
}

// NewAssetRepository creates a new asset repository
func NewAssetRepository(db *database.DB) *AssetRepository {
	return &AssetRepository{
		db:   db,
		coll: db.GetHustlerCollection("assets"),
	}
}

// Create inserts a new asset
func (r *AssetRepository) Create(ctx context.Context, asset *models.Asset) error {
	_, err := r.coll.InsertOne(ctx, asset)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("asset already exists")
		}
		return fmt.Errorf("failed to create asset: %w", err)
	}
	return nil
}

// GetByTargetAndSubdomain retrieves an asset by target ID and subdomain
func (r *AssetRepository) GetByTargetAndSubdomain(ctx context.Context, targetID primitive.ObjectID, subdomain string) (*models.Asset, error) {
	var asset models.Asset
	err := r.coll.FindOne(ctx, bson.M{"target_id": targetID, "subdomain": subdomain}).Decode(&asset)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, mongo.ErrNoDocuments
		}
		return nil, fmt.Errorf("failed to get asset: %w", err)
	}
	return &asset, nil
}

// GetByTarget retrieves all assets for a target
func (r *AssetRepository) GetByTarget(ctx context.Context, targetID primitive.ObjectID, limit, offset int) ([]*models.Asset, error) {
	opts := options.Find().
		SetSort(bson.M{"subdomain": 1}).
		SetLimit(int64(limit)).
		SetSkip(int64(offset))

	cursor, err := r.coll.Find(ctx, bson.M{"target_id": targetID}, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list assets: %w", err)
	}
	defer cursor.Close(ctx)

	var assets []*models.Asset
	if err := cursor.All(ctx, &assets); err != nil {
		return nil, fmt.Errorf("failed to decode assets: %w", err)
	}
	return assets, nil
}

// CountByTarget returns total assets for a target
func (r *AssetRepository) CountByTarget(ctx context.Context, targetID primitive.ObjectID) (int64, error) {
	return r.coll.CountDocuments(ctx, bson.M{"target_id": targetID})
}

// Update updates an asset
func (r *AssetRepository) Update(ctx context.Context, asset *models.Asset) error {
	asset.UpdatedAt = time.Now()
	filter := bson.M{"_id": asset.ID}
	update := bson.M{"$set": asset}

	_, err := r.coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update asset: %w", err)
	}
	return nil
}

// URLRepository handles URL persistence
type URLRepository struct {
	db   *database.DB
	coll *mongo.Collection
}

// NewURLRepository creates a new URL repository
func NewURLRepository(db *database.DB) *URLRepository {
	return &URLRepository{
		db:   db,
		coll: db.GetHustlerCollection("urls"),
	}
}

// Create inserts a new URL
func (r *URLRepository) Create(ctx context.Context, url *models.URL) error {
	_, err := r.coll.InsertOne(ctx, url)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("URL already exists")
		}
		return fmt.Errorf("failed to create URL: %w", err)
	}
	return nil
}

// GetByTarget retrieves URLs for a target
func (r *URLRepository) GetByTarget(ctx context.Context, targetID primitive.ObjectID, limit, offset int) ([]*models.URL, error) {
	opts := options.Find().
		SetSort(bson.M{"created_at": -1}).
		SetLimit(int64(limit)).
		SetSkip(int64(offset))

	cursor, err := r.coll.Find(ctx, bson.M{"target_id": targetID}, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list URLs: %w", err)
	}
	defer cursor.Close(ctx)

	var urls []*models.URL
	if err := cursor.All(ctx, &urls); err != nil {
		return nil, fmt.Errorf("failed to decode URLs: %w", err)
	}
	return urls, nil
}

// CountByTarget returns total URLs for a target
func (r *URLRepository) CountByTarget(ctx context.Context, targetID primitive.ObjectID) (int64, error) {
	return r.coll.CountDocuments(ctx, bson.M{"target_id": targetID})
}

// GetNonJunkURLs retrieves non-junk URLs for a target
func (r *URLRepository) GetNonJunkURLs(ctx context.Context, targetID primitive.ObjectID) ([]*models.URL, error) {
	filter := bson.M{
		"target_id": targetID,
		"is_junk":   false,
	}
	cursor, err := r.coll.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list non-junk URLs: %w", err)
	}
	defer cursor.Close(ctx)

	var urls []*models.URL
	if err := cursor.All(ctx, &urls); err != nil {
		return nil, fmt.Errorf("failed to decode URLs: %w", err)
	}
	return urls, nil
}