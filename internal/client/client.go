// internal/client/client.go
package client

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
)

// Client holds the HTTP client configuration and logger.
type Client struct {
	baseURL string
	logger  zerolog.Logger
	http    *resty.Client
}

// =================================================================
// IQ Server API Model Definitions (Input/Output)
// =================================================================

// Application represents a single application returned by IQ Server.
type Application struct {
	ID             string `json:"id"`
	PublicID       string `json:"publicId"`
	OrganizationID string `json:"organizationId"`
}

type applicationsEnvelope struct {
	Applications []Application `json:"applications"`
}

// Organization represents a simplified IQ Server organization record.
type Organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type organizationsEnvelope struct {
	Organizations []Organization `json:"organizations"`
}

// ReportInfo contains metadata about an application's latest report.
type ReportInfo struct {
	Stage         string `json:"stage"`
	ReportHTMLURL string `json:"reportHtmlUrl"`
}

// =================================================================
// Policy Violation Report Structure (Complex API Response)
// =================================================================

// Condition is the lowest level detail within a constraint.
type Condition struct {
	ConditionSummary string `json:"conditionSummary"`
}

// Constraint is a group of conditions within a policy violation.
type Constraint struct {
	ConstraintName string      `json:"constraintName"`
	Conditions     []Condition `json:"conditions"`
}

// Violation details a specific policy break for a component.
type Violation struct {
	PolicyName        string       `json:"policyName"`
	PolicyThreatLevel float64      `json:"policyThreatLevel"` // IQ Server returns numeric fields as float64
	Constraints       []Constraint `json:"constraints"`
}

type ComponentIdentifier struct {
	Format string `json:"format"`
}

// Component is a library/asset with associated violations.
type Component struct {
	DisplayName         string      `json:"displayName"`
	Violations          []Violation `json:"violations"`
	ComponentIdentifier `json:"componentIdentifier"`
}

// PolicyViolationReport is the top-level structure for the policy violations report API.
type PolicyViolationReport struct {
	Components []Component `json:"components"`
}

// =================================================================
// Output Model
// =================================================================

// ViolationRow is the flattened structure used for CSV output.
type ViolationRow struct {
	Application    string
	Organization   string
	Policy         string
	Format         string
	Component      string
	Threat         int
	PolicyAction   string
	ConstraintName string
	Condition      string
	CVE            string
}

// =================================================================
// Client Initialization
// =================================================================

func NewClient(serverURL, username, password string, logger zerolog.Logger) (*Client, error) {
	// Defense checks
	if strings.TrimSpace(serverURL) == "" {
		return nil, fmt.Errorf("serverURL is required")
	}
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if password == "" {
		return nil, fmt.Errorf("password is required")
	}
	// The logger is a struct, so it cannot be nil. No check needed.

	// Expect serverURL to already include /api/v2
	baseURL := strings.TrimSuffix(serverURL, "/")
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid baseURL: %w", err)
	}
	u.Path = path.Clean(u.Path)
	baseURL = u.String()
	baseURL = strings.TrimRight(baseURL, "/") + "/"

	r := resty.New().
		SetBaseURL(baseURL).
		SetBasicAuth(username, password).
		SetHeader("Accept", "application/json").
		SetTimeout(30 * time.Second)

	// Resty hooks for logging
	r.OnBeforeRequest(func(c *resty.Client, req *resty.Request) error {
		logger.Debug().
			Str("method", req.Method).
			Str("url", req.URL).
			Str("query", req.QueryParam.Encode()).
			Msg("Executing request")
		return nil
	})
	r.OnAfterResponse(func(c *resty.Client, resp *resty.Response) error {
		logger.Debug().
			Int("status", resp.StatusCode()).
			Str("url", resp.Request.URL).
			Str("method", resp.Request.Method).
			Msg("Request completed")
		return nil
	})

	cl := &Client{
		baseURL: baseURL,
		logger:  logger,
		http:    r,
	}
	logger.Info().Str("baseURL", baseURL).Msg("Initialized IQServer API client")
	return cl, nil
}

// =================================================================
// Public Client Methods
// =================================================================

// GetApplications fetches a list of applications, optionally filtered by organization ID.
func (c *Client) GetApplications(ctx context.Context, orgID *string) ([]Application, error) {
	endpoint := "applications"
	logCtx := c.logger.With()
	if orgID != nil && *orgID != "" {
		endpoint = fmt.Sprintf("applications/organization/%s", *orgID)
		logCtx = logCtx.Str("orgId", *orgID)
	} else {
		logCtx = logCtx.Str("orgId", "all")
	}
	logger := logCtx.Logger()
	logger.Debug().Msg("Fetching applications")

	var env applicationsEnvelope
	resp, err := c.http.R().
		SetContext(ctx).
		SetResult(&env).
		SetError(&map[string]any{}).
		Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	c.logger.Debug().Int("status", resp.StatusCode()).Str("body", resp.String()).Msg("raw response")
	if resp.IsError() {
		c.logger.Error().
			Str("endpoint", endpoint).
			Int("status", resp.StatusCode()).
			Str("statusText", resp.Status()).
			Str("rawBodySnippet", strings.TrimSpace(resp.String())).
			Msg("Failed to fetch applications from API")
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode(), resp.String())
	}

	return env.Applications, nil
}

// GetLatestReportInfo fetches the metadata for the most recent report for a given internal application ID.
func (c *Client) GetLatestReportInfo(ctx context.Context, appID string) (*ReportInfo, error) {
	endpoint := fmt.Sprintf("reports/applications/%s", appID)
	var reports []ReportInfo

	resp, err := c.http.R().
		SetContext(ctx).
		SetResult(&reports).
		Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	if resp.IsError() {
		c.logger.Error().
			Str("appID", appID).
			Int("status", resp.StatusCode()).
			Str("statusText", resp.Status()).
			Msg("Failed to fetch latest report info")
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode(), resp.Status())
	}

	if len(reports) > 0 {
		c.logger.Debug().Int("count", len(reports)).Str("appId", appID).Msg("Found reports")
		r := reports[0]
		return &r, nil
	}

	c.logger.Debug().Str("appId", appID).Msg("No reports found")
	return nil, nil
}

// GetPolicyViolations fetches the detailed policy violation report for a specific application and report ID.
func (c *Client) GetPolicyViolations(ctx context.Context, publicID, reportID, orgName string) ([]ViolationRow, error) {
	c.logger.Debug().Str("publicId", publicID).Str("reportId", reportID).Msg("Fetching policy violations")

	endpoint := fmt.Sprintf("applications/%s/reports/%s/policy", publicID, reportID)
	params := url.Values{"includeViolationTimes": []string{"true"}}

	var report PolicyViolationReport // Use the explicit struct
	resp, err := c.http.R().
		SetContext(ctx).
		SetQueryParamsFromValues(params).
		SetResult(&report). // Unmarshal directly into struct
		Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	if resp.IsError() {
		c.logger.Error().
			Str("publicId", publicID).
			Str("reportId", reportID).
			Int("status", resp.StatusCode()).
			Msg("Failed to fetch policy violations report")
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode(), resp.Status())
	}

	// Parse and filter to ViolationRow using the structured data
	return parseToViolationRows(report, publicID, orgName), nil
}

// GetOrganizations fetches the list of all organizations.
func (c *Client) GetOrganizations(ctx context.Context) ([]Organization, error) {
	c.logger.Debug().Msg("Fetching organizations")

	var env organizationsEnvelope
	resp, err := c.http.R().
		SetContext(ctx).
		SetResult(&env).
		Get("organizations")
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	if resp.IsError() {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode(), resp.String())
	}

	c.logger.Debug().Int("count", len(env.Organizations)).Msg("Retrieved organizations")
	return env.Organizations, nil
}

// =================================================================
// Helper Functions
// =================================================================

// parseToViolationRows converts the structured API response into flat ViolationRow slice.
func parseToViolationRows(rawReport PolicyViolationReport, appPublicID string, orgName string) []ViolationRow {
	var rows []ViolationRow

	for _, comp := range rawReport.Components {
		compName := comp.DisplayName
		format := comp.ComponentIdentifier.Format
		for _, v := range comp.Violations {
			policyName := v.PolicyName
			// Threat level comes as float64, cast to int
			threat := int(v.PolicyThreatLevel)
			policyAction := fmt.Sprintf("Security-%d", threat)
			for _, constr := range v.Constraints {
				constraintName := constr.ConstraintName
				var condSummaries []string
				for _, cond := range constr.Conditions {
					condSummaries = append(condSummaries, cond.ConditionSummary)
				}
				rows = append(rows, ViolationRow{
					Application:    appPublicID,
					Organization:   orgName,
					Policy:         policyName,
					Format:         format,
					Component:      compName,
					Threat:         threat,
					PolicyAction:   policyAction,
					ConstraintName: constraintName,
					Condition:      strings.Join(condSummaries, " | "),
					CVE:            "",
				})
			}
		}
	}
	return rows
}
