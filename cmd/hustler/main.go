package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"hustler/internal/cli"
	"hustler/internal/config"
	"hustler/internal/daemon"
	"hustler/internal/mongo"
)

func main() {
	configPath := "config.yaml"
	for i, arg := range os.Args {
		if arg == "-c" || arg == "--config" {
			if i+1 < len(os.Args) {
				configPath = os.Args[i+1]
			}
		}
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Setup logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})

	// Connect to MongoDB
	if err := mongo.Connect(cfg.Mongo); err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to MongoDB")
	}
	defer mongo.Disconnect()

	log.Info().Str("database", cfg.Mongo.Database).Msg("Connected to MongoDB")

	// Check if running as daemon
	if len(os.Args) > 1 && os.Args[1] == "daemon" {
		if len(os.Args) > 2 {
			switch os.Args[2] {
			case "start":
				runDaemon(cfg)
				return
			case "status":
				daemon.RunDaemonStatus()
				return
			case "stop":
				daemon.RunDaemonStop()
				return
			}
		}
	}

	// CLI mode - use cobra commands
	if err := cli.Execute(); err != nil {
		log.Fatal().Err(err).Msg("Command failed")
	}
}

func runDaemon(cfg *config.FullConfig) {
	d := daemon.NewDaemon(*cfg)
	if err := d.Start(); err != nil {
		log.Fatal().Err(err).Msg("Daemon failed")
	}
}