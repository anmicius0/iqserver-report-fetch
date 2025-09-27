// cmd/iqfetch/main.go
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/anmicius0/iqserver-report-fetch-go/internal/client"
	"github.com/anmicius0/iqserver-report-fetch-go/internal/config"
	"github.com/anmicius0/iqserver-report-fetch-go/internal/services"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Load config from config/.env and environment
	cfg, err := config.Load()
	if err != nil {
		// Log fatal failure to standard error stream, as slog setup hasn't completed yet
		fmt.Fprintf(os.Stderr, "FATAL: failed to load config: %v\n", err) //nolint:errcheck
		os.Exit(1)
	}

	// Open project-root/app.log for append; create if missing
	logFile, err := os.OpenFile("app.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		// Log fatal failure to standard error stream, as logger setup hasn't completed yet
		fmt.Fprintf(os.Stderr, "FATAL: failed to open app.log: %v\n", err) //nolint:errcheck
		os.Exit(1)
	}
	defer logFile.Close()

	// Logger setup (console writer for stdout, json for file)
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	multiWriter := zerolog.MultiLevelWriter(consoleWriter, logFile)

	// Configure global logger
	log.Logger = zerolog.New(multiWriter).With().Timestamp().Logger()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	log.Info().
		Str("IQServerURL", cfg.IQServerURL).
		Str("OrganizationID", cfg.OrganizationID).
		Msg("Loaded configuration")

	// Build client
	log.Info().Str("url", cfg.IQServerURL).Msg("Creating IQ client")
	iqClient, err := client.NewClient(cfg.IQServerURL, cfg.IQUsername, cfg.IQPassword, log.Logger)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create client")
	}
	log.Info().Msg("IQ client created")

	// Service
	reportService := services.NewIQReportService(cfg, iqClient, log.Logger)
	log.Info().Str("outputDir", cfg.OutputDir).Msg("Report service initialized")

	// Context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Optional organization filter
	var orgIDPointer *string
	if cfg.OrganizationID != "" {
		orgID := cfg.OrganizationID
		orgIDPointer = &orgID
	}

	// Output filename
	filename := time.Now().Format("2006-01-02_15-04-05") + ".csv"
	log.Info().Str("filename", filename).Msg("Report filename set")

	// Ensure output directory exists
	_ = os.MkdirAll(cfg.OutputDir, 0o755)

	// Generate report
	log.Info().Str("orgID", cfg.OrganizationID).Msg("Starting report generation")
	path, err := reportService.GenerateLatestPolicyReport(ctx, orgIDPointer, filename)
	if err != nil {
		log.Fatal().Err(err).Msg("report generation failed")
	}

	log.Info().Str("path", filepath.Clean(path)).Msg("Report generation completed")
	fmt.Printf("Wrote report: %s\n", filepath.Clean(path))
}
