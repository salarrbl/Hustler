package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/qarqa/hustler/internal/api"
	"github.com/qarqa/hustler/internal/config"
	"github.com/qarqa/hustler/internal/database"
	"github.com/qarqa/hustler/internal/models"
	"github.com/spf13/cobra"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var cfg *config.Config
var db *database.DB

func main() {
	var err error
	cfg, err = config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	db, err = database.Connect(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to databases: %v", err)
	}

	rootCmd := &cobra.Command{
		Use:   "hustler",
		Short: "Hustler - Vulnerability Automation Platform",
		Long:  `Hustler is a standalone vulnerability-discovery automation platform for bug bounty work.`,
	}

	// Serve command
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the API server",
		Run:   runServe,
	}
	serveCmd.Flags().String("host", "", "API host (overrides config)")
	serveCmd.Flags().Int("port", 0, "API port (overrides config)")

	// Target commands
	targetCmd := &cobra.Command{
		Use:   "target",
		Short: "Manage targets",
	}

	targetAddCmd := &cobra.Command{
		Use:   "add [domain]",
		Short: "Add a new target",
		Args:  cobra.ExactArgs(1),
		Run:   runTargetAdd,
	}
	targetAddCmd.Flags().String("name", "", "Target name")
	targetAddCmd.Flags().String("description", "", "Target description")

	targetListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all targets",
		Run:   runTargetList,
	}

	targetImportCmd := &cobra.Command{
		Use:   "import [domain]",
		Short: "Import assets from WatchDogs for a target",
		Args:  cobra.ExactArgs(1),
		Run:   runTargetImport,
	}

	targetDeleteCmd := &cobra.Command{
		Use:   "delete [domain]",
		Short: "Delete a target",
		Args:  cobra.ExactArgs(1),
		Run:   runTargetDelete,
	}

	targetCmd.AddCommand(targetAddCmd, targetListCmd, targetImportCmd, targetDeleteCmd)

	// Job commands
	jobCmd := &cobra.Command{
		Use:   "job",
		Short: "Manage jobs",
	}

	jobListCmd := &cobra.Command{
		Use:   "list [target_id]",
		Short: "List jobs",
		Args:  cobra.MaximumNArgs(1),
		Run:   runJobList,
	}

	jobCmd.AddCommand(jobListCmd)

	rootCmd.AddCommand(serveCmd, targetCmd, jobCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runServe(cmd *cobra.Command, args []string) {
	host, _ := cmd.Flags().GetString("host")
	port, _ := cmd.Flags().GetInt("port")

	if host != "" {
		cfg.API.Host = host
	}
	if port != 0 {
		cfg.API.Port = port
	}

	// Create server (it initializes all repositories internally)
	server := api.NewServer(cfg, db)

	// Handle shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")
		cancel()
		server.Stop(ctx)
	}()

	if err := server.Start(); err != nil && err != context.Canceled {
		log.Fatalf("Server error: %v", err)
	}
}

func runTargetAdd(cmd *cobra.Command, args []string) {
	domain := args[0]
	name, _ := cmd.Flags().GetString("name")
	description, _ := cmd.Flags().GetString("description")

	server := api.NewServer(cfg, db)
	ctx := context.Background()

	exists, err := server.TargetRepo.Exists(ctx, domain)
	if err != nil {
		log.Fatalf("Error checking target: %v", err)
	}
	if exists {
		log.Fatalf("Target %s already exists", domain)
	}

	target := &models.Target{
		Domain:      domain,
		Name:        name,
		Description: description,
	}

	if err := server.TargetRepo.Create(ctx, target); err != nil {
		log.Fatalf("Failed to create target: %v", err)
	}

	log.Printf("Target created: %s (ID: %s)", target.Domain, target.ID.Hex())
}

func runTargetList(cmd *cobra.Command, args []string) {
	server := api.NewServer(cfg, db)
	ctx := context.Background()

	targets, err := server.TargetRepo.List(ctx, 100, 0)
	if err != nil {
		log.Fatalf("Failed to list targets: %v", err)
	}

	if len(targets) == 0 {
		log.Println("No targets found")
		return
	}

	for _, t := range targets {
		log.Printf("  %s (ID: %s) - %s", t.Domain, t.ID.Hex(), t.Name)
	}
}

func runTargetImport(cmd *cobra.Command, args []string) {
	domain := args[0]

	server := api.NewServer(cfg, db)
	ctx := context.Background()

	_, err := server.TargetRepo.GetByDomain(ctx, domain)
	if err != nil {
		log.Fatalf("Target not found: %v", err)
	}

	log.Printf("Importing assets from WatchDogs for %s...", domain)
	result, err := server.WatchDogs.ImportTargetAssets(ctx, domain)
	if err != nil {
		log.Fatalf("Import failed: %v", err)
	}

	log.Printf("Import complete: %d imported, %d updated, %d errors", result.Imported, result.Updated, len(result.Errors))
	for _, e := range result.Errors {
		log.Printf("  ERROR: %s", e)
	}
}

func runTargetDelete(cmd *cobra.Command, args []string) {
	domain := args[0]

	server := api.NewServer(cfg, db)
	ctx := context.Background()

	if err := server.TargetRepo.DeleteByDomain(ctx, domain); err != nil {
		log.Fatalf("Failed to delete target: %v", err)
	}

	log.Printf("Target deleted: %s", domain)
}

func runJobList(cmd *cobra.Command, args []string) {
	server := api.NewServer(cfg, db)
	ctx := context.Background()

	if len(args) > 0 {
		targetID, err := primitive.ObjectIDFromHex(args[0])
		if err != nil {
			log.Fatalf("Invalid target ID: %v", err)
		}
		jobsList, err := server.JobRepo.GetByTarget(ctx, targetID, 50, 0)
		if err != nil {
			log.Fatalf("Failed to list jobs: %v", err)
		}
		for _, j := range jobsList {
			log.Printf("  %s [%s] %s - %d%%", j.ID.Hex(), j.Type, j.Status, j.Progress)
		}
	} else {
		jobsList, err := server.JobRepo.GetRecent(ctx, 50)
		if err != nil {
			log.Fatalf("Failed to list jobs: %v", err)
		}
		for _, j := range jobsList {
			log.Printf("  %s [%s] %s - %d%% (target: %s)", j.ID.Hex(), j.Type, j.Status, j.Progress, j.TargetID.Hex())
		}
	}
}