// internal/report/csvreport_test.go
package report

import (
	"encoding/csv"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
)

func TestWriteCSV_WritesHeaderAndRows(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.csv")

	rows := []Row{
		{
			Application:    "app-1",
			Organization:   "org-1",
			Policy:         "Security-Medium",
			Format:         "pypi",
			Component:      "comp-1",
			Threat:         7,
			PolicyAction:   "Security-7",
			ConstraintName: "Medium risk CVSS score",
			Condition:      "Security Vulnerability Severity >= 4 | Security Vulnerability Severity < 7",
			CVE:            "",
		},
		{
			Application:    "app-2",
			Organization:   "org-1",
			Policy:         "Security-High",
			Format:         "golang",
			Component:      "comp-2",
			Threat:         9,
			PolicyAction:   "Security-9",
			ConstraintName: "High risk CVSS score",
			Condition:      "Security Vulnerability Severity >= 7",
			CVE:            "CVE-2024-0001",
		},
	}

	logger := zerolog.New(io.Discard)
	if err := WriteCSV(dest, rows, logger); err != nil {
		t.Fatalf("WriteCSV error = %v", err)
	}

	f, err := os.Open(dest)
	if err != nil {
		t.Fatalf("open file: %v", err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}

	if len(records) != 1+len(rows) {
		t.Fatalf("expected %d lines, got %d", 1+len(rows), len(records))
	}
	if want, got := "No.", records[0][0]; want != got {
		t.Errorf("header[0] = %q", got)
	}
	if want, got := "Format", records[0][4]; want != got {
		t.Errorf("header[4] = %q, want %q", got, want)
	}
	if want, got := "app-1", records[1][1]; want != got {
		t.Errorf("row1 Application = %q", got)
	}
	if want, got := "pypi", records[1][4]; want != got {
		t.Errorf("row1 Format = %q, want %q", got, want)
	}
	if want, got := "golang", records[2][4]; want != got {
		t.Errorf("row2 Format = %q, want %q", got, want)
	}
	if want, got := "CVE-2024-0001", records[2][10]; want != got {
		t.Errorf("row2 CVE = %q", got)
	}
}
