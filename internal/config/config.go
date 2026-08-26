package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
)

// Config holds all configuration for Hustler
type Config struct {
	HustlerDB    DatabaseConfig `json:"hustler_db"`
	WatchDogsDB  DatabaseConfig `json:"watchdogs_db"`
	API          APIConfig      `json:"api"`
	WebUI        WebUIConfig    `json:"web_ui"`
	Auth         AuthConfig     `json:"auth"`
	LogLevel     string         `json:"log_level"`
}

// DatabaseConfig holds MongoDB connection settings
type DatabaseConfig struct {
	URI       string `json:"uri"`
	Database  string `json:"database"`
	ReadOnly  bool   `json:"read_only,omitempty"`
}

// APIConfig holds REST API server settings
type APIConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// WebUIConfig holds Web UI settings
type WebUIConfig struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	APIURL  string `json:"api_url"`
}

// AuthConfig holds authentication settings
type AuthConfig struct {
	SessionSecret      string `json:"session_secret"`
	SessionMaxAgeHours int    `json:"session_max_age_hours"`
}

// Load reads configuration from file and applies environment overrides
func Load() (*Config, error) {
	// Default config path
	configPath := os.Getenv("HUSTLER_CONFIG")
	if configPath == "" {
		home, _ := os.UserHomeDir()
		configPath = filepath.Join(home, ".hustler", "config.json")
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return defaults if config doesn't exist
			return defaultConfig(), nil
		}
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Apply environment variable overrides
	cfg.applyEnvOverrides()

	return &cfg, nil
}

// defaultConfig returns default configuration
func defaultConfig() *Config {
	return &Config{
		HustlerDB: DatabaseConfig{
			URI:      "mongodb://localhost:27017",
			Database: "hustler",
		},
		WatchDogsDB: DatabaseConfig{
			URI:      "mongodb://localhost:27017",
			Database: "watchdogs",
			ReadOnly: true,
		},
		API: APIConfig{
			Host:     "127.0.0.1",
			Port:     8081,
			Username: "rebel",
			Password: "krow",
		},
		WebUI: WebUIConfig{
			Host:   "127.0.0.1",
			Port:   88,
			APIURL: "http://127.0.0.1:8081",
		},
		Auth: AuthConfig{
			SessionSecret:      "change-me-in-production-32-bytes!!",
			SessionMaxAgeHours: 24,
		},
		LogLevel: "info",
	}
}

// applyEnvOverrides applies environment variable overrides
func (c *Config) applyEnvOverrides() {
	// Hustler DB
	if v := os.Getenv("HUSTLER_DB_URI"); v != "" {
		c.HustlerDB.URI = v
	}
	if v := os.Getenv("HUSTLER_DB_NAME"); v != "" {
		c.HustlerDB.Database = v
	}

	// WatchDogs DB
	if v := os.Getenv("WATCHDOGS_DB_URI"); v != "" {
		c.WatchDogsDB.URI = v
	}
	if v := os.Getenv("WATCHDOGS_DB_NAME"); v != "" {
		c.WatchDogsDB.Database = v
	}

	// API
	if v := os.Getenv("HUSTLER_API_HOST"); v != "" {
		c.API.Host = v
	}
	if v := os.Getenv("HUSTLER_API_PORT"); v != "" {
		// ignore parse error, keep default
	}
	if v := os.Getenv("HUSTLER_API_USER"); v != "" {
		c.API.Username = v
	}
	if v := os.Getenv("HUSTLER_API_PASS"); v != "" {
		c.API.Password = v
	}

	// Web UI
	if v := os.Getenv("HUSTLER_WEB_HOST"); v != "" {
		c.WebUI.Host = v
	}
	if v := os.Getenv("HUSTLER_WEB_PORT"); v != "" {
		// ignore parse error
	}
	if v := os.Getenv("HUSTLER_WEB_API_URL"); v != "" {
		c.WebUI.APIURL = v
	}

	// Auth
	if v := os.Getenv("HUSTLER_SESSION_SECRET"); v != "" {
		c.Auth.SessionSecret = v
	}
	if v := os.Getenv("HUSTLER_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
}

// APIAddr returns the API server address
func (c *Config) APIAddr() string {
	return c.API.Host + ":" + strconv.Itoa(c.API.Port)
}

// WebUIAddr returns the Web UI address
func (c *Config) WebUIAddr() string {
	return c.WebUI.Host + ":" + strconv.Itoa(c.WebUI.Port)
}