// internal/services/iqreport.go
package services

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/anmicius0/iqserver-report-fetch-go/internal/client"
	"github.com/anmicius0/iqserver-report-fetch-go/internal/config"
	"github.com/anmicius0/iqserver-report-fetch-go/internal/report"
	"github.com/rs/zerolog"
)

// IQReportService orchestrates fetching data and exporting CSV reports.
type IQReportService struct {
	cfg    *config.Config
	cl     *client.Client
	logger zerolog.Logger
}

// AppReportResult holds the violation rows and any error encountered
// while processing a single application concurrently.
type AppReportResult struct {
	Rows []report.Row
	Err  error
}

// NewIQReportService constructs a new service.
func NewIQReportService(cfg *config.Config, cl *client.Client, logger zerolog.Logger) *IQReportService {
	return &IQReportService{cfg: cfg, cl: cl, logger: logger}
}

// GenerateLatestPolicyReport fetches latest policy violations for applications (optionally filtered by orgID)
// and writes a CSV to cfg.OutputDir/filename. It returns the absolute file path.
func (s *IQReportService) GenerateLatestPolicyReport(ctx context.Context, orgID *string, filename string) (string, error) {
	logger := s.logger.With().Str("filename", filename).Logger()
	if orgID != nil {
		logger = logger.With().Str("orgID", *orgID).Logger()
	}

	logger.Info().Msg("GenerateLatestPolicyReport invoked")

	// =================================================================
	// 1. APPLICATION AND ORGANIZATION FETCHING (Sequential Setup)
	// =================================================================

	// Fetch application list
	apps, err := s.cl.GetApplications(ctx, orgID)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve application list")
		return "", fmt.Errorf("get applications: %w", err)
	}
	logger.Info().Int("count", len(apps)).Msg("Fetched applications")

	if len(apps) == 0 {
		logger.Warn().Msg("Task finished: no applications found matching criteria")
		return "", fmt.Errorf("no applications found")
	}

	// Fetch organizations to create an ID-to-name map
	orgs, err := s.cl.GetOrganizations(ctx)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve organization list")
		return "", fmt.Errorf("get organizations: %w", err)
	}
	orgIDToName := make(map[string]string)
	for _, org := range orgs {
		orgIDToName[org.ID] = org.Name
	}
	logger.Info().Int("count", len(orgIDToName)).Msg("Created organization ID-to-name map")

	// =================================================================
	// 2. PROCESS APPLICATIONS CONCURRENTLY
	// =================================================================

	// Setup concurrency primitives: semaphore (max 10), channel for results, WaitGroup
	sem := make(chan struct{}, 10) // Bounded semaphore: max 10 concurrent
	resultsChan := make(chan AppReportResult, len(apps))
	var wg sync.WaitGroup

	s.logger.Info().Int("appsToProcess", len(apps)).Int("maxConcurrent", 10).Msg("Starting concurrent report fetching for applications")

	// Launch a goroutine for each application
	for _, a := range apps {
		wg.Add(1)

		// Capture loop variable 'a' for use in the goroutine closure
		app := a

		go func() {
			defer wg.Done()

			// Acquire semaphore with context cancellation support
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }() // Release semaphore
			case <-ctx.Done():
				return
			}

			// Check for context cancellation/timeout early
			if ctx.Err() != nil {
				return
			}

			appLogger := s.logger.With().Str("appPublicID", app.PublicID).Str("appInternalID", app.ID).Logger()

			// 2a. Fetch latest report info
			reportInfo, err := s.cl.GetLatestReportInfo(ctx, app.ID)
			if err != nil {
				appLogger.Error().Err(err).Msg("failed to fetch latest report info")
				return
			}

			// Skip if no report available
			if reportInfo == nil || strings.TrimSpace(reportInfo.ReportHTMLURL) == "" {
				appLogger.Info().Msg("No recent report found for application, skipping")
				return
			}

			// 2b. Extract report ID and validate
			_, reportID, found := strings.Cut(reportInfo.ReportHTMLURL, "/report/")
			if !found || reportID == "" {
				appLogger.Error().Str("reportURL", reportInfo.ReportHTMLURL).Msg("failed to parse report ID from URL")
				return
			}
			appLogger.Debug().Str("reportID", reportID).Str("stage", reportInfo.Stage).Msg("Parsed report ID")

			// 2c. Look up organization name
			orgName, ok := orgIDToName[app.OrganizationID]
			if !ok {
				orgName = app.OrganizationID
				appLogger.Warn().Str("orgID", app.OrganizationID).Msg("organization name not found, using ID as fallback")
			}

			// 2d. Fetch policy violations (Returns []client.ViolationRow)
			clientRows, err := s.cl.GetPolicyViolations(ctx, app.PublicID, reportID, orgName)
			if err != nil {
				appLogger.Error().Err(err).Msg("failed to fetch policy violations")
				return
			}
			appLogger.Debug().Int("rowsCount", len(clientRows)).Msg("Fetched policy violations")

			// 2e. Convert client rows to report rows (report.Row is the expected output type)
			reportRows := make([]report.Row, len(clientRows))
			for i, r := range clientRows {
				reportRows[i] = report.Row{
					Application:    r.Application,
					Organization:   r.Organization,
					Policy:         r.Policy,
					Format:         r.Format,
					Component:      r.Component,
					Threat:         r.Threat,
					PolicyAction:   r.PolicyAction,
					ConstraintName: r.ConstraintName,
					Condition:      r.Condition,
					CVE:            r.CVE,
				}
			}

			// 2f. Send successful results to the channel
			select {
			case resultsChan <- AppReportResult{Rows: reportRows}:
			case <-ctx.Done():
			}
		}()
	}

	// Wait for all goroutines to finish, then close the channel in a non-blocking way
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Aggregate results
	var allViolationRows []report.Row

	for res := range resultsChan {
		// Only collect successful rows, errors are already logged in goroutines
		allViolationRows = append(allViolationRows, res.Rows...)
	}

	// =================================================================
	// 3. CSV GENERATION AND FINAL PATH RETURN
	// =================================================================

	target := filepath.Join(s.cfg.OutputDir, filename)
	s.logger.Info().Str("path", target).Int("totalRows", len(allViolationRows)).Msg("Writing CSV report")

	if err := report.WriteCSV(target, allViolationRows, s.logger); err != nil {
		return "", fmt.Errorf("write csv: %w", err)
	}

	s.logger.Info().Str("path", target).Msg("Report written successfully")

	return target, nil
}
