package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Target represents a target in Hustler
type Target struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Domain      string             `bson:"domain" json:"domain"`
	Name        string             `bson:"name,omitempty" json:"name,omitempty"`
	Description string             `bson:"description,omitempty" json:"description,omitempty"`
	InScope     []string           `bson:"in_scope,omitempty" json:"in_scope,omitempty"`
	OutOfScope  []string           `bson:"out_of_scope,omitempty" json:"out_of_scope,omitempty"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// Asset represents a live asset (subdomain) in Hustler
type Asset struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	TargetID     primitive.ObjectID `bson:"target_id" json:"target_id"`
	Subdomain    string             `bson:"subdomain" json:"subdomain"`
	StatusCode   int                `bson:"status_code,omitempty" json:"status_code,omitempty"`
	Title        string             `bson:"title,omitempty" json:"title,omitempty"`
	Technologies []string           `bson:"technologies,omitempty" json:"technologies,omitempty"`
	CDN          string             `bson:"cdn,omitempty" json:"cdn,omitempty"`
	IP           string             `bson:"ip,omitempty" json:"ip,omitempty"`
	CNAME        []string           `bson:"cname,omitempty" json:"cname,omitempty"`
	Ports        []string           `bson:"ports,omitempty" json:"ports,omitempty"`
	Source       string             `bson:"source" json:"source"` // "watchdogs" or "hustler-recon"
	IsAlive      bool               `bson:"is_alive" json:"is_alive"`
	LastSeen     time.Time          `bson:"last_seen" json:"last_seen"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time          `bson:"updated_at" json:"updated_at"`
}

// URL represents a URL in Hustler
type URL struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	TargetID     primitive.ObjectID `bson:"target_id" json:"target_id"`
	AssetID      primitive.ObjectID `bson:"asset_id,omitempty" json:"asset_id,omitempty"`
	URL          string             `bson:"url" json:"url"`
	Method       string             `bson:"method,omitempty" json:"method,omitempty"`
	StatusCode   int                `bson:"status_code,omitempty" json:"status_code,omitempty"`
	ContentType  string             `bson:"content_type,omitempty" json:"content_type,omitempty"`
	ContentLength int64             `bson:"content_length,omitempty" json:"content_length,omitempty"`
	Source       string             `bson:"source" json:"source"` // "watchdogs", "hustler-recon", "javascript"
	IsJunk       bool               `bson:"is_junk" json:"is_junk"`
	Interesting  bool               `bson:"interesting" json:"interesting"`
	Classification []string         `bson:"classification,omitempty" json:"classification,omitempty"` // e.g., "api", "admin", "login"
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time          `bson:"updated_at" json:"updated_at"`
}

// Parameter represents a parameter in Hustler
type Parameter struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	TargetID  primitive.ObjectID `bson:"target_id" json:"target_id"`
	URLID     primitive.ObjectID `bson:"url_id" json:"url_id"`
	AssetID   primitive.ObjectID `bson:"asset_id,omitempty" json:"asset_id,omitempty"`
	Name      string             `bson:"name" json:"name"`
	Type      string             `bson:"type" json:"type"` // "query", "path", "form", "json"
	Value     string             `bson:"value,omitempty" json:"value,omitempty"`
	Source    string             `bson:"source" json:"source"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
}

// Endpoint represents an endpoint in Hustler
type Endpoint struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	TargetID    primitive.ObjectID `bson:"target_id" json:"target_id"`
	AssetID     primitive.ObjectID `bson:"asset_id,omitempty" json:"asset_id,omitempty"`
	Path        string             `bson:"path" json:"path"`
	Method      string             `bson:"method,omitempty" json:"method,omitempty"`
	Source      string             `bson:"source" json:"source"`
	Description string             `bson:"description,omitempty" json:"description,omitempty"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// JavaScriptFile represents a JavaScript file in Hustler
type JavaScriptFile struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	TargetID    primitive.ObjectID `bson:"target_id" json:"target_id"`
	AssetID     primitive.ObjectID `bson:"asset_id,omitempty" json:"asset_id,omitempty"`
	URL         string             `bson:"url" json:"url"`
	Content     string             `bson:"content,omitempty" json:"content,omitempty"`
	ContentHash string             `bson:"content_hash,omitempty" json:"content_hash,omitempty"`
	Source      string             `bson:"source" json:"source"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// JavaScriptSecret represents a secret found in JavaScript
type JavaScriptSecret struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	TargetID      primitive.ObjectID `bson:"target_id" json:"target_id"`
	JSFileID      primitive.ObjectID `bson:"js_file_id" json:"js_file_id"`
	Type          string             `bson:"type" json:"type"` // "aws", "gcp", "api_key", etc.
	Pattern       string             `bson:"pattern" json:"pattern"`
	Value         string             `bson:"value,omitempty" json:"value,omitempty"` // masked or full
	Severity      string             `bson:"severity" json:"severity"` // "low", "medium", "high", "critical"
	Confidence    string             `bson:"confidence" json:"confidence"` // "low", "medium", "high"
	CreatedAt     time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt     time.Time          `bson:"updated_at" json:"updated_at"`
}

// Job represents a job in Hustler
type Job struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	TargetID    primitive.ObjectID `bson:"target_id,omitempty" json:"target_id,omitempty"`
	Type        string             `bson:"type" json:"type"` // "import", "normalize", "gf", "js_analysis", etc.
	Status      string             `bson:"status" json:"status"` // "queued", "running", "completed", "failed", "cancelled"
	Progress    int                `bson:"progress" json:"progress"` // 0-100
	StartedAt   *time.Time         `bson:"started_at,omitempty" json:"started_at,omitempty"`
	FinishedAt  *time.Time         `bson:"finished_at,omitempty" json:"finished_at,omitempty"`
	Error       string             `bson:"error,omitempty" json:"error,omitempty"`
	Results     map[string]interface{} `bson:"results,omitempty" json:"results,omitempty"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// Hypothesis represents a hypothesis in Hustler
type Hypothesis struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	TargetID    primitive.ObjectID `bson:"target_id" json:"target_id"`
	AssetID     primitive.ObjectID `bson:"asset_id,omitempty" json:"asset_id,omitempty"`
	URLID       primitive.ObjectID `bson:"url_id,omitempty" json:"url_id,omitempty"`
	ParameterID primitive.ObjectID `bson:"parameter_id,omitempty" json:"parameter_id,omitempty"`
	Category    string             `bson:"category" json:"category"` // "xss", "ssrf", "sqli", etc.
	SubCategory string             `bson:"sub_category,omitempty" json:"sub_category,omitempty"`
	Title       string             `bson:"title" json:"title"`
	Description string             `bson:"description,omitempty" json:"description,omitempty"`
	Evidence    string             `bson:"evidence" json:"evidence"`
	Pattern     string             `bson:"pattern,omitempty" json:"pattern,omitempty"`
	Confidence  string             `bson:"confidence" json:"confidence"` // "low", "medium", "high"
	Severity    string             `bson:"severity" json:"severity"` // "low", "medium", "high", "critical"
	Source      string             `bson:"source" json:"source"` // "gf", "js_analysis", "postmessage", etc.
	Status      string             `bson:"status" json:"status"` // "new", "validating", "validated", "rejected", "confirmed"
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// Finding represents a confirmed finding in Hustler
type Finding struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	TargetID      primitive.ObjectID `bson:"target_id" json:"target_id"`
	AssetID       primitive.ObjectID `bson:"asset_id,omitempty" json:"asset_id,omitempty"`
	URLID         primitive.ObjectID `bson:"url_id,omitempty" json:"url_id,omitempty"`
	ParameterID   primitive.ObjectID `bson:"parameter_id,omitempty" json:"parameter_id,omitempty"`
	HypothesisID  primitive.ObjectID `bson:"hypothesis_id,omitempty" json:"hypothesis_id,omitempty"`
	Category      string             `bson:"category" json:"category"`
	SubCategory   string             `bson:"sub_category,omitempty" json:"sub_category,omitempty"`
	Title         string             `bson:"title" json:"title"`
	Description   string             `bson:"description" json:"description"`
	Severity      string             `bson:"severity" json:"severity"` // "low", "medium", "high", "critical"
	Confidence    string             `bson:"confidence" json:"confidence"` // "low", "medium", "high"
	Evidence      string             `bson:"evidence" json:"evidence"`
	DetectionSource string           `bson:"detection_source" json:"detection_source"` // "gf", "js_analysis", "manual"
	ValidationStatus string          `bson:"validation_status" json:"validation_status"` // "unvalidated", "validated", "false_positive"
	Status        string             `bson:"status" json:"status"` // "open", "reported", "fixed", "wont_fix"
	FirstSeen     time.Time          `bson:"first_seen" json:"first_seen"`
	LastSeen      time.Time          `bson:"last_seen" json:"last_seen"`
	CreatedAt     time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt     time.Time          `bson:"updated_at" json:"updated_at"`
}

// JobType constants
const (
	JobTypeImport             = "import"
	JobTypeNormalize          = "normalize"
	JobTypeParameterExtract   = "parameter_extract"
	JobTypeEndpointExtract    = "endpoint_extract"
	JobTypeGFAnalysis         = "gf_analysis"
	JobTypeJSAnalysis         = "js_analysis"
	JobTypePostMessageAnalysis = "postmessage_analysis"
	JobTypeXSSAnalysis        = "xss_analysis"
	JobTypeSSRFAnalysis       = "ssrf_analysis"
	JobTypeValidation         = "validation"
	JobTypeRecon              = "recon"
)

// JobStatus constants
const (
	JobStatusQueued     = "queued"
	JobStatusRunning    = "running"
	JobStatusCompleted  = "completed"
	JobStatusFailed     = "failed"
	JobStatusCancelled  = "cancelled"
)

// HypothesisCategory constants
const (
	HypothesisXSS             = "xss"
	HypothesisSSRF            = "ssrf"
	HypothesisSQLi            = "sqli"
	HypothesisOpenRedirect    = "open_redirect"
	HypothesisLFI             = "lfi"
	HypothesisPathTraversal   = "path_traversal"
	HypothesisSSTI            = "ssti"
	HypothesisXXE             = "xxe"
	HypothesisCORS            = "cors"
	HypothesisCRLF            = "crlf"
	HypothesisProtoPollution  = "prototype_pollution"
	HypothesisIDOR            = "idor"
	HypothesisOAuth           = "oauth"
	HypothesisJWT             = "jwt"
	HypothesisFileUpload      = "file_upload"
	HypothesisCache           = "cache"
	HypothesisRequestSmuggling = "request_smuggling"
	HypothesisGraphQL         = "graphql"
	HypothesisAPI             = "api"
	HypothesisDebugAdmin      = "debug_admin"
)

// HypothesisStatus constants
const (
	HypothesisStatusNew        = "new"
	HypothesisStatusValidating = "validating"
	HypothesisStatusValidated  = "validated"
	HypothesisStatusRejected   = "rejected"
	HypothesisStatusConfirmed  = "confirmed"
)

// FindingStatus constants
const (
	FindingStatusOpen        = "open"
	FindingStatusReported    = "reported"
	FindingStatusFixed       = "fixed"
	FindingStatusWontFix     = "wont_fix"
)

// FindingValidationStatus constants
const (
	FindingValidationUnvalidated = "unvalidated"
	FindingValidationValidated   = "validated"
	FindingValidationFalsePositive = "false_positive"
)