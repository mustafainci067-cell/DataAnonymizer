package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReportWriteJSONAndMarkdown(t *testing.T) {
	dir := t.TempDir()
	r := &Report{
		GeneratedAt: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC),
		Driver:      "postgres",
		Format:      "sql",
		Outputs:     []string{"anonymized_dump.sql"},
		DurationMs:  125,
		TotalRows:   1000,
		Tables: []TableReport{
			{
				Name:          "customers",
				RowsProcessed: 1000,
				Columns: []ColumnReport{
					{Name: "id", DataType: "integer", Strategy: "keep", DiscoveryReason: "none"},
					{Name: "email", DataType: "text", Strategy: "fake_email", DiscoveryReason: "column_name"},
				},
			},
		},
	}

	jsonPath := filepath.Join(dir, "audit.json")
	if err := r.Write(jsonPath); err != nil {
		t.Fatalf("Write JSON: %v", err)
	}
	rawJSON, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("ReadFile JSON: %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(rawJSON, &decoded); err != nil {
		t.Fatalf("Unmarshal JSON: %v", err)
	}
	if decoded.TotalRows != 1000 || len(decoded.Tables) != 1 {
		t.Errorf("unexpected decoded report: %+v", decoded)
	}

	mdPath := filepath.Join(dir, "audit.md")
	if err := r.Write(mdPath); err != nil {
		t.Fatalf("Write Markdown: %v", err)
	}
	rawMD, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("ReadFile MD: %v", err)
	}
	md := string(rawMD)
	if !strings.Contains(md, "# Data Anonymization Audit Report") || !strings.Contains(md, "| `email` | `text` | `fake_email` | column_name |") {
		t.Errorf("unexpected markdown content:\n%s", md)
	}
}
