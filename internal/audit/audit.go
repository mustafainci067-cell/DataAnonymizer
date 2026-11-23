package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ColumnReport documents the masking rule applied to a single column.
type ColumnReport struct {
	Name            string `json:"name"`
	DataType        string `json:"data_type"`
	Strategy        string `json:"strategy"`
	DiscoveryReason string `json:"discovery_reason"`
}

// TableReport summarizes rows processed and column masking decisions for a table.
type TableReport struct {
	Name          string         `json:"name"`
	RowsProcessed int64          `json:"rows_processed"`
	Columns       []ColumnReport `json:"columns"`
}

// Report captures a GDPR/KVKK compliance audit summary for an anonymization run.
type Report struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Driver      string        `json:"driver"`
	Format      string        `json:"format"`
	Outputs     []string      `json:"outputs"`
	DurationMs  int64         `json:"duration_ms"`
	TotalRows   int64         `json:"total_rows"`
	Tables      []TableReport `json:"tables"`
}

// Write saves the report as Markdown when path ends in .md, or JSON otherwise.
func (r *Report) Write(path string) error {
	if strings.EqualFold(filepath.Ext(strings.TrimSpace(path)), ".md") {
		return r.WriteMarkdown(path)
	}
	return r.WriteJSON(path)
}

// WriteJSON serializes the audit report as indented JSON.
func (r *Report) WriteJSON(path string) error {
	if err := ensureParentDir(path); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal audit report JSON: %w", err)
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

// WriteMarkdown renders the audit report as a human-readable Markdown document.
func (r *Report) WriteMarkdown(path string) error {
	if err := ensureParentDir(path); err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString("# Data Anonymization Audit Report\n\n")
	fmt.Fprintf(&b, "- **Generated At:** %s\n", r.GeneratedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Driver:** %s\n", r.Driver)
	fmt.Fprintf(&b, "- **Format:** %s\n", r.Format)
	fmt.Fprintf(&b, "- **Outputs:** %s\n", strings.Join(r.Outputs, ", "))
	fmt.Fprintf(&b, "- **Total Rows Processed:** %d\n", r.TotalRows)
	fmt.Fprintf(&b, "- **Duration:** %d ms\n\n", r.DurationMs)

	for _, tbl := range r.Tables {
		fmt.Fprintf(&b, "## Table: `%s` (%d rows)\n\n", tbl.Name, tbl.RowsProcessed)
		b.WriteString("| Column | Data Type | Strategy | Discovery Reason |\n")
		b.WriteString("| --- | --- | --- | --- |\n")
		for _, col := range tbl.Columns {
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | %s |\n", col.Name, col.DataType, col.Strategy, col.DiscoveryReason)
		}
		b.WriteByte('\n')
	}

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create audit directory %q: %w", dir, err)
		}
	}
	return nil
}
