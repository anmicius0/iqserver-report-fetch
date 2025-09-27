// internal/services/iqreport_test.go
package services

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anmicius0/iqserver-report-fetch-go/internal/client"
	"github.com/anmicius0/iqserver-report-fetch-go/internal/config"
	"github.com/rs/zerolog"
)

func testLogger() zerolog.Logger {
	return zerolog.New(io.Discard)
}

func TestGenerateLatestPolicyReport_Integration(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/applications", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"applications": []map[string]any{
				{"id": "aid-1", "publicId": "apid-1", "organizationId": "org-1"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/api/v2/organizations", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"organizations": []map[string]any{
				{"id": "org-1", "name": "personal"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/api/v2/reports/applications/aid-1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := []map[string]any{
			{
				"stage":         "build",
				"reportHtmlUrl": "https://stub/report/rpt-xyz",
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/api/v2/applications/apid-1/reports/rpt-xyz/policy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"components": []any{
				map[string]any{
					"displayName": "comp-A",
					"componentIdentifier": map[string]any{
						"format": "maven",
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
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	baseURL := strings.TrimRight(srv.URL, "/") + "/api/v2"
	iqClient, err := client.NewClient(baseURL, "u", "p", testLogger())
	if err != nil {
		t.Fatalf("client init: %v", err)
	}

	tmpDir := t.TempDir()
	cfg := &config.Config{
		IQServerURL:    baseURL,
		IQUsername:     "u",
		IQPassword:     "p",
		OrganizationID: "",
		OutputDir:      tmpDir,
	}

	svc := NewIQReportService(cfg, iqClient, testLogger())

	filename := "report.csv"
	outputPath, err := svc.GenerateLatestPolicyReport(rCtx(t), nil, filename)
	if err != nil {
		t.Fatalf("GenerateLatestPolicyReport: %v", err)
	}
	if !strings.HasSuffix(outputPath, filepath.Join(tmpDir, filename)) {
		t.Errorf("unexpected path: %q", outputPath)
	}
	b, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	content := string(b)
	if !strings.Contains(content, "No.,Application,Organization,Policy,Format") {
		t.Errorf("header missing or incorrect")
	}
	if !strings.Contains(content, "Security-7") {
		t.Errorf("row content missing")
	}
	if !strings.Contains(content, "maven") {
		t.Errorf("format field 'maven' missing from output")
	}
}

// rCtx returns a cancellable context with a small timeout and ensures cancel via t.Cleanup.
func rCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}
