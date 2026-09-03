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

// TargetPlatform represents the bug bounty platform category
type TargetPlatform string

const (
	PlatformHackerOne  TargetPlatform = "hackerone"
	PlatformBugcrowd   TargetPlatform = "bugcrowd"
	PlatformIntigriti  TargetPlatform = "intigriti"
	PlatformYesWeHack  TargetPlatform = "yeswehack"
	PlatformOpenBugBounty TargetPlatform = "openbugbounty"
	PlatformFreelance  TargetPlatform = "freelance"
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
	Platform  TargetPlatform `bson:"platform,omitempty" json:"platform,omitempty"`
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
	// Web UI job tracking fields
	JobStatus     string     `bson:"job_status,omitempty" json:"job_status,omitempty"`
	JobStartedAt  *time.Time `bson:"job_started_at,omitempty" json:"job_started_at,omitempty"`
	JobFinishedAt *time.Time `bson:"job_finished_at,omitempty" json:"job_finished_at,omitempty"`
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
	IsMinified bool      `bson:"is_minified,omitempty" json:"is_minified,omitempty"`
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
	ID              string    `bson:"_id" json:"id"`
	TargetID        string    `bson:"target_id" json:"target_id"`
	JSFileID        string    `bson:"js_file_id" json:"js_file_id"`
	SinkType        string    `bson:"sink_type" json:"sink_type"`       // eval, innerHTML, postMessage, etc.
	SourceType      string    `bson:"source_type" json:"source_type"`   // URL param, postMessage data, user input, etc.
	Line            int       `bson:"line" json:"line"`
	Column          int       `bson:"column,omitempty" json:"column,omitempty"`
	Snippet         string    `bson:"snippet" json:"snippet"`           // code snippet around the sink
	Confidence      float64   `bson:"confidence" json:"confidence"`     // 0-1
	HasOriginCheck  bool      `bson:"has_origin_check" json:"has_origin_check"` // for postMessage
	FoundAt         time.Time `bson:"found_at" json:"found_at"`
	IsMinified      bool      `bson:"is_minified,omitempty" json:"is_minified,omitempty"`
	LowConfidence   bool      `bson:"low_confidence,omitempty" json:"low_confidence,omitempty"`
}

// BLHCandidate represents a broken link hijacking candidate
type BLHCandidate struct {
	ID                string    `bson:"_id" json:"id"`
	TargetID          string    `bson:"target_id" json:"target_id"`
	JSFileID          string    `bson:"js_file_id,omitempty" json:"js_file_id,omitempty"`
	ReferencedURL     string    `bson:"referenced_url,omitempty" json:"referenced_url,omitempty"`
	ReferencedDomain  string    `bson:"referenced_domain" json:"referenced_domain"`
	ResolutionStatus  string    `bson:"resolution_status" json:"resolution_status"`
	RiskLevel         string    `bson:"risk_level" json:"risk_level"`
	CloudProvider     string    `bson:"cloud_provider,omitempty" json:"cloud_provider,omitempty"`
	Evidence          string    `bson:"evidence,omitempty" json:"evidence,omitempty"`
	FoundIn           string    `bson:"found_in,omitempty" json:"found_in,omitempty"` // "js_file" or "html_page"
	IsTargetSubdomain bool      `bson:"is_target_subdomain,omitempty" json:"is_target_subdomain,omitempty"`
	FoundAt           time.Time `bson:"found_at" json:"found_at"`
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

// JobStatus represents the status of a hunt job
type JobStatus string

const (
	JobStatusQueued   JobStatus = "queued"
	JobStatusRunning  JobStatus = "running"
	JobStatusDone     JobStatus = "done"
	JobStatusError    JobStatus = "error"
)

// Job represents a hunt job in the queue
type Job struct {
	ID          string     `bson:"_id" json:"id"`
	TargetID    string     `bson:"target_id" json:"target_id"`
	Status      JobStatus  `bson:"status" json:"status"`
	QueuedAt    time.Time  `bson:"queued_at" json:"queued_at"`
	StartedAt   *time.Time `bson:"started_at,omitempty" json:"started_at,omitempty"`
	FinishedAt  *time.Time `bson:"finished_at,omitempty" json:"finished_at,omitempty"`
	Error       string     `bson:"error,omitempty" json:"error,omitempty"`
	Source      string     `bson:"source" json:"source"` // "manual" or "watchdogs"
}

// DiscoveredURL tracks URLs that have been seen for a target to enable incremental scanning
type DiscoveredURL struct {
	ID        string    `bson:"_id" json:"id"`
	TargetID  string    `bson:"target_id" json:"target_id"`
	URL       string    `bson:"url" json:"url"`
	URLType   string    `bson:"url_type" json:"url_type"` // js_file or endpoint
	Source    string    `bson:"source" json:"source"`     // how it was discovered (katana, gau, wayback, extracted_from_js, etc.)
	FirstSeen time.Time `bson:"first_seen" json:"first_seen"`
	LastSeen  time.Time `bson:"last_seen" json:"last_seen"`
}

// SensitiveEndpointCandidate represents an endpoint that returned potentially sensitive data
type SensitiveEndpointCandidate struct {
	ID              string    `bson:"_id" json:"id"`
	TargetID        string    `bson:"target_id" json:"target_id"`
	Endpoint        string    `bson:"endpoint" json:"endpoint"`
	StatusCode      int       `bson:"status_code" json:"status_code"`
	ResponseSize    int       `bson:"response_size" json:"response_size"`
	MatchedPatterns []string  `bson:"matched_patterns" json:"matched_patterns"`
	FoundAt         time.Time `bson:"found_at" json:"found_at"`
	Source          string    `bson:"source,omitempty" json:"source,omitempty"` // "common_path", "js_extracted", "html_extracted"
}