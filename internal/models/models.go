package models

import (
	"time"

	"github.com/google/uuid"
)

// TargetSource represents the source of a target
type TargetSource string

const (
	SourceWatchdogs TargetSource = "watchdogs"
	SourceManual    TargetSource = "manual"
)

// TargetStatus represents the status of a target
type TargetStatus string

const (
	StatusPending   TargetStatus = "pending"
	StatusActive    TargetStatus = "active"
	StatusCompleted TargetStatus = "completed"
	StatusError     TargetStatus = "error"
)

// Target represents an ingested target in Hustler
type Target struct {
	ID        string       `bson:"_id" json:"id"`
	Domain    string       `bson:"domain" json:"domain"`
	Source    TargetSource `bson:"source" json:"source"`
	Status    TargetStatus `bson:"status" json:"status"`
	AddedAt   time.Time    `bson:"added_at" json:"added_at"`
	UpdatedAt time.Time    `bson:"updated_at" json:"updated_at"`
	// Watchdogs-specific fields (populated when source=watchdogs)
	RootDomain   string   `bson:"root_domain,omitempty" json:"root_domain,omitempty"`
	StatusCode   int      `bson:"status_code,omitempty" json:"status_code,omitempty"`
	Technologies []string `bson:"technologies,omitempty" json:"technologies,omitempty"`
	Title        string   `bson:"title,omitempty" json:"title,omitempty"`
	Ports        []string `bson:"ports,omitempty" json:"ports,omitempty"`
	CDN          string   `bson:"cdn,omitempty" json:"cdn,omitempty"`
	Providers    []string `bson:"providers,omitempty" json:"providers,omitempty"`
	DiscoveredAt *time.Time `bson:"discovered_at,omitempty" json:"discovered_at,omitempty"`
}

// NewTarget creates a new target with generated ID
func NewTarget(domain string, source TargetSource) *Target {
	now := time.Now()
	return &Target{
		ID:        uuid.New().String(),
		Domain:    domain,
		Source:    source,
		Status:    StatusPending,
		AddedAt:   now,
		UpdatedAt: now,
	}
}

// JSFile represents a JavaScript file discovered for a target
type JSFile struct {
	ID        string    `bson:"_id" json:"id"`
	TargetID  string    `bson:"target_id" json:"target_id"`
	URL       string    `bson:"url" json:"url"`
	JSHash    string    `bson:"js_hash" json:"js_hash"` // SHA256 hash for dedup
	Content   string    `bson:"content,omitempty" json:"content,omitempty"` // optional, for debugging
	StatusCode int      `bson:"status_code" json:"status_code"`
	ContentType string  `bson:"content_type" json:"content_type"`
	ContentLength int64 `bson:"content_length" json:"content_length"`
	FetchedAt time.Time `bson:"fetched_at" json:"fetched_at"`
	SourceMapURL string `bson:"source_map_url,omitempty" json:"source_map_url,omitempty"`
	SourceMapHash string `bson:"source_map_hash,omitempty" json:"source_map_hash,omitempty"`
}

// Secret represents a secret found in a JS file
type Secret struct {
	ID         string    `bson:"_id" json:"id"`
	TargetID   string    `bson:"target_id" json:"target_id"`
	JSFileID   string    `bson:"js_file_id" json:"js_file_id"`
	Pattern    string    `bson:"pattern" json:"pattern"`           // regex pattern name that matched
	Matched    string    `bson:"matched" json:"matched"`           // the matched string (redacted)
	Line       int       `bson:"line" json:"line"`                 // line number in JS
	Column     int       `bson:"column,omitempty" json:"column,omitempty"`
	Entropy    float64   `bson:"entropy" json:"entropy"`           // Shannon entropy of matched string
	Confidence float64   `bson:"confidence" json:"confidence"`     // 0-1 confidence score
	Context    string    `bson:"context,omitempty" json:"context,omitempty"` // surrounding code
	FoundAt    time.Time `bson:"found_at" json:"found_at"`
}

// Endpoint represents an API endpoint extracted from JS
type Endpoint struct {
	ID        string    `bson:"_id" json:"id"`
	TargetID  string    `bson:"target_id" json:"target_id"`
	JSFileID  string    `bson:"js_file_id" json:"js_file_id"`
	Endpoint  string    `bson:"endpoint" json:"endpoint"`         // the endpoint path/URL
	Method    string    `bson:"method,omitempty" json:"method,omitempty"` // GET, POST, etc. if inferable
	FullURL   string    `bson:"full_url,omitempty" json:"full_url,omitempty"` // resolved full URL
	Context   string    `bson:"context,omitempty" json:"context,omitempty"` // e.g., "fetch", "axios", "form action"
	FoundAt   time.Time `bson:"found_at" json:"found_at"`
}

// Param represents a parameter name extracted from JS
type Param struct {
	ID        string    `bson:"_id" json:"id"`
	TargetID  string    `bson:"target_id" json:"target_id"`
	JSFileID  string    `bson:"js_file_id" json:"js_file_id"`
	ParamName string    `bson:"param_name" json:"param_name"`
	Context   string    `bson:"context" json:"context"`           // query, body, form, header, path
	Location  string    `bson:"location,omitempty" json:"location,omitempty"` // where in JS (fetch, URLSearchParams, etc.)
	FoundAt   time.Time `bson:"found_at" json:"found_at"`
}

// Sink represents a source/sink analysis hit
type Sink struct {
	ID          string    `bson:"_id" json:"id"`
	TargetID    string    `bson:"target_id" json:"target_id"`
	JSFileID    string    `bson:"js_file_id" json:"js_file_id"`
	SinkType    string    `bson:"sink_type" json:"sink_type"`       // eval, innerHTML, document.write, postMessage, etc.
	SourceType  string    `bson:"source_type" json:"source_type"`   // URL param, postMessage data, user input, etc.
	Line        int       `bson:"line" json:"line"`
	Column      int       `bson:"column,omitempty" json:"column,omitempty"`
	Snippet     string    `bson:"snippet" json:"snippet"`           // code snippet around the sink
	Confidence  float64   `bson:"confidence" json:"confidence"`     // 0-1
	HasOriginCheck bool     `bson:"has_origin_check" json:"has_origin_check"` // for postMessage
	FoundAt     time.Time `bson:"found_at" json:"found_at"`
}

// BLHCandidate represents a broken link hijacking candidate
type BLHCandidate struct {
	ID               string    `bson:"_id" json:"id"`
	TargetID         string    `bson:"target_id" json:"target_id"`
	JSFileID         string    `bson:"js_file_id" json:"js_file_id"`
	ReferencedURL    string    `bson:"referenced_url" json:"referenced_url"`
	ReferencedDomain string    `bson:"referenced_domain" json:"referenced_domain"`
	ResolutionStatus string    `bson:"resolution_status" json:"resolution_status"` // resolves, nxdomain, unclaimed, etc.
	RiskLevel        string    `bson:"risk_level" json:"risk_level"`               // critical, high, medium, low
	CloudProvider    string    `bson:"cloud_provider,omitempty" json:"cloud_provider,omitempty"` // S3, GitHub Pages, Azure, etc.
	Evidence         string    `bson:"evidence,omitempty" json:"evidence,omitempty"`
	FoundAt          time.Time `bson:"found_at" json:"found_at"`
}

// LibraryCVE represents a fingerprinted library with CVE matches
type LibraryCVE struct {
	ID          string    `bson:"_id" json:"id"`
	TargetID    string    `bson:"target_id" json:"target_id"`
	JSFileID    string    `bson:"js_file_id" json:"js_file_id"`
	LibraryName string    `bson:"library_name" json:"library_name"`
	Version     string    `bson:"version" json:"version"`
	CVEID       string    `bson:"cve_id" json:"cve_id"`
	Severity    string    `bson:"severity" json:"severity"`         // critical, high, medium, low
	Description string    `bson:"description,omitempty" json:"description,omitempty"`
	Reference   string    `bson:"reference,omitempty" json:"reference,omitempty"`
	FoundAt     time.Time `bson:"found_at" json:"found_at"`
}