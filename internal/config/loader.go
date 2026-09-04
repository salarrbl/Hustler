package config

import (
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

// Load loads configuration from config.yaml and environment variables
func Load(configPath string) (*FullConfig, error) {
	// Load .env file if exists
	if _, err := os.Stat(".env"); err == nil {
		if err := godotenv.Load(); err != nil {
			return nil, fmt.Errorf("failed to load .env: %w", err)
		}
	}

	v := viper.New()
	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")
	v.AutomaticEnv()

	// Bind environment variables with prefix HUSTLER_
	v.SetEnvPrefix("HUSTLER")
	v.BindEnv("mongo.uri", "MONGO_URI")
	v.BindEnv("mongo.database", "MONGO_DATABASE")
	v.BindEnv("watchdogs.enabled", "WATCHDOGS_ENABLED")
	v.BindEnv("watchdogs.mongo_uri", "WATCHDOGS_MONGO_URI")
	v.BindEnv("watchdogs.database", "WATCHDOGS_DATABASE")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg FullConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Set defaults
	setDefaults(&cfg)

	return &cfg, nil
}

func setDefaults(cfg *FullConfig) {
	if cfg.Mongo.URI == "" {
		cfg.Mongo.URI = "mongodb://localhost:27017"
	}
	if cfg.Mongo.Database == "" {
		cfg.Mongo.Database = "hustler"
	}
	if cfg.Mongo.MaxPool == 0 {
		cfg.Mongo.MaxPool = 100
	}
	if cfg.Mongo.MinPool == 0 {
		cfg.Mongo.MinPool = 5
	}
	if cfg.Mongo.TimeoutSec == 0 {
		cfg.Mongo.TimeoutSec = 10
	}

	if cfg.Watchdogs.SyncInterval == 0 {
		cfg.Watchdogs.SyncInterval = 1 * time.Hour
	}

	if cfg.HTTP.TimeoutSec == 0 {
		cfg.HTTP.TimeoutSec = 30
	}
	if cfg.HTTP.MaxIdleConns == 0 {
		cfg.HTTP.MaxIdleConns = 100
	}
	if cfg.HTTP.MaxConnsPerHost == 0 {
		cfg.HTTP.MaxConnsPerHost = 20
	}
	if cfg.HTTP.UserAgent == "" {
		cfg.HTTP.UserAgent = "Hustler/1.0 (Bug Bounty Automation)"
	}

	if cfg.JS.FetchTimeoutSec == 0 {
		cfg.JS.FetchTimeoutSec = 15
	}
	if cfg.JS.MaxConcurrentFetch == 0 {
		cfg.JS.MaxConcurrentFetch = 10
	}
	if cfg.JS.EntropyThreshold == 0 {
		cfg.JS.EntropyThreshold = 3.5
	}

	// Discovery config defaults
	if cfg.Discovery.Enabled == false {
		cfg.Discovery.Enabled = true // enable discovery by default
	}
	if !cfg.Discovery.UseKatana {
		cfg.Discovery.UseKatana = true // katana enabled by default
	}
	if cfg.Discovery.UseGau == false {
		cfg.Discovery.UseGau = false // gau disabled by default
	}
	if len(cfg.Sensitive.HeuristicPaths) == 0 {
		cfg.Sensitive.HeuristicPaths = []string{
			"/api/", "/admin", "/internal", "/config", "/export", "/backup", "/debug",
		}
	}
	if len(cfg.Sensitive.SensitivePatterns) == 0 {
		cfg.Sensitive.SensitivePatterns = []string{
			"password", "token", "apiKey", "apikey", "secret", "ssn",
			"credit_card", "creditcard", "cvv", "email",
		}
	}

	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "console"
	}

	if cfg.Hustler.MaxConcurrentHunts == 0 {
		cfg.Hustler.MaxConcurrentHunts = 3
	}

	if cfg.CVE.DataDir == "" {
		cfg.CVE.DataDir = "./data/cve"
	}
	if cfg.CVE.RateLimitRPS == 0 {
		cfg.CVE.RateLimitRPS = 2.0
	}
	if cfg.CVE.UpdateIntervalDays == 0 {
		cfg.CVE.UpdateIntervalDays = 7
	}
	if cfg.CVE.MinConfidence == 0 {
		cfg.CVE.MinConfidence = 0.5
	}
}