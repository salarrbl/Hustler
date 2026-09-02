package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"hustler/internal/cli"
	"hustler/internal/config"
	"hustler/internal/jobqueue"
	"hustler/internal/mongo"
)

var workerPool *jobqueue.WorkerPool

func main() {
	// Parse flags early to get config path
	configPath := "config.yaml"
	for i, arg := range os.Args {
		if arg == "-c" || arg == "--config" {
			if i+1 < len(os.Args) {
				configPath = os.Args[i+1]
			}
		}
	}

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Override from CLI flags if provided
	if mongoURI := viper.GetString("mongo-uri"); mongoURI != "" {
		cfg.Mongo.URI = mongoURI
	}
	if mongoDB := viper.GetString("mongo-db"); mongoDB != "" {
		cfg.Mongo.Database = mongoDB
	}

	// Setup logging
	setupLogging(cfg.Logging)

	// Connect to MongoDB
	if err := mongo.Connect(cfg.Mongo); err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to MongoDB")
	}
	defer mongo.Disconnect()

	log.Info().Str("database", cfg.Mongo.Database).Msg("Connected to MongoDB")

	// Create and start worker pool
	workerPool = jobqueue.NewWorkerPool(cfg.Hustler, cfg.Discovery)
	workerPool.Start()
	defer workerPool.Stop()

	// Make worker pool available to CLI
	cli.SetWorkerPool(workerPool)

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info().Msg("Shutdown signal received, stopping worker pool...")
		workerPool.Stop()
		os.Exit(0)
	}()

	log.Info().Int("max_concurrent_hunts", cfg.Hustler.MaxConcurrentHunts).Msg("Worker pool ready")

	// Execute CLI
	if err := cli.Execute(); err != nil {
		log.Fatal().Err(err).Msg("Command failed")
	}
}

func setupLogging(cfg config.LoggingConfig) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	switch cfg.Format {
	case "json":
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: true})
	default:
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})
	}

	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
}