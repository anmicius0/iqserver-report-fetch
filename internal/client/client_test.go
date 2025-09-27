// internal/client/client_test.go
package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func newTestLogger() zerolog.Logger {
	return zerolog.New(io.Discard)
}

func TestClient_EndToEndAgainstStub(t *testing.T) {
	mux := http.NewServeMux()

	// Register a subtree handler to avoid trailing-slash and exact-match pitfalls.
	mux.HandleFunc("/api/v2/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/applications":
			resp := map[string]any{
				"applications": []map[string]any{
					{
						"id":             "app-internal-1",
						"publicId":       "app-public-1",
						"organizationId": "org-1",
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)

		case "/api/v2/applications/organization/org-1":
			resp := map[string]any{
				"applications": []map[string]any{
					{
						"id":             "app-internal-1",
						"publicId":       "app-public-1",
						"organizationId": "org-1",
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)

		case "/api/v2/reports/applications/app-internal-1":
			resp := []map[string]any{
				{
					"stage":         "build",
					"reportHtmlUrl": "https://stub/report/rpt-1",
				},
			}
			_ = json.NewEncoder(w).Encode(resp)

		case "/api/v2/applications/app-public-1/reports/rpt-1/policy":
			resp := map[string]any{
				"components": []any{
					map[string]any{
						"displayName": "setuptools 80.9.0 (.tar.gz)",
						"componentIdentifier": map[string]any{
							"format": "pypi",
						},
						"violations": []any{
							map[string]any{
								"policyName":        "Security-Medium",
								"policyThreatLevel": 7,
								"constraints": []any{
									map[string]any{
										"constraintName": "Medium risk CVSS score",
										"conditions": []any{
											map[string]any{"conditionSummary": "Security Vulnerability Severity >= 4"},
											map[string]any{"conditionSummary": "Security Vulnerability Severity < 7"},
										},
									},
								},
							},
						},
					},
					map[string]any{
						"displayName": "setuptools (py3-none-any) 80.9.0 (.whl)",
						"componentIdentifier": map[string]any{
							"format": "pypi",
						},
						"violations": []any{
							map[string]any{
								"policyName":        "Security-Medium",
								"policyThreatLevel": 7,
								"constraints": []any{
									map[string]any{
										"constraintName": "Medium risk CVSS score",
										"conditions": []any{
											map[string]any{"conditionSummary": "Security Vulnerability Severity >= 4"},
											map[string]any{"conditionSummary": "Security Vulnerability Severity < 7"},
										},
									},
								},
							},
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)

		case "/api/v2/organizations":
			resp := map[string]any{
				"organizations": []map[string]any{
					{"id": "org-1", "name": "personal"},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)

		default:
			http.NotFound(w, r)
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	baseURL := strings.TrimRight(srv.URL, "/") + "/api/v2"
	iqClient, err := NewClient(baseURL, "u", "p", newTestLogger())
	if err != nil {
		t.Fatalf("NewClient error = %v", err)
	}

	// GetApplications all
	apps, err := iqClient.GetApplications(rCtx(t), nil)
	if err != nil {
		t.Fatalf("GetApplications error = %v", err)
	}
	if len(apps) != 1 || !strings.EqualFold(apps[0].PublicID, "app-public-1") {
		t.Fatalf("unexpected apps: %#v", apps)
	}

	// GetApplications by org
	orgID := "org-1"
	appsByOrg, err := iqClient.GetApplications(rCtx(t), &orgID)
	if err != nil {
		t.Fatalf("GetApplications(org) error = %v", err)
	}
	if len(appsByOrg) != 1 {
		t.Fatalf("unexpected apps by org: %#v", appsByOrg)
	}

	// Latest report
	reportInfo, err := iqClient.GetLatestReportInfo(rCtx(t), "app-internal-1")
	if err != nil || reportInfo == nil {
		t.Fatalf("GetLatestReportInfo error = %v ri=%v", err, reportInfo)
	}
	if !strings.Contains(reportInfo.ReportHTMLURL, "/report/rpt-1") {
		t.Errorf("ReportHTMLURL = %q", reportInfo.ReportHTMLURL)
	}

	// Policy violations
	violationRows, err := iqClient.GetPolicyViolations(rCtx(t), "app-public-1", "rpt-1", "personal")
	if err != nil {
		t.Fatalf("GetPolicyViolations error = %v", err)
	}
	if len(violationRows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(violationRows))
	}
	if violationRows[0].Threat != 7 || violationRows[0].PolicyAction != "Security-7" {
		t.Errorf("row mapping unexpected: %#v", violationRows[0])
	}
	if violationRows[0].Format != "pypi" {
		t.Errorf("expected format 'pypi', got %q", violationRows[0].Format)
	}
	if violationRows[1].Format != "pypi" {
		t.Errorf("expected format 'pypi', got %q", violationRows[1].Format)
	}

	// Orgs
	orgs, err := iqClient.GetOrganizations(rCtx(t))
	if err != nil || len(orgs) != 1 {
		t.Fatalf("GetOrganizations error=%v orgs=%v", err, orgs)
	}
}

// rCtx returns a cancellable context with a small timeout and ensures cancel via t.Cleanup.
func rCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}
