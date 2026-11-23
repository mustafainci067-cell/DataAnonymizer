package exporter

import (
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mustafainci067-cell/data-anonymizer/internal/db"
)

type stubAdapter struct{}

func (stubAdapter) DriverName() string                                      { return "postgres" }
func (stubAdapter) Ping(context.Context) error                              { return nil }
func (stubAdapter) ListTables(context.Context, string) ([]string, error)    { return nil, nil }
func (stubAdapter) ListColumns(context.Context, string, string) ([]db.Column, error) {
	return nil, nil
}
func (stubAdapter) GenerateDDL(_ context.Context, _, table string) (string, error) {
	return `CREATE TABLE IF NOT EXISTS "public"."` + table + `" ("id" integer NOT NULL);`, nil
}
func (stubAdapter) QuoteIdent(ident string) string {
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
}
func (stubAdapter) QueryTable(context.Context, string, string, []db.Column) (*sql.Rows, error) {
	return nil, nil
}
func (stubAdapter) SampleRows(context.Context, string, string, []db.Column, int) ([][]any, error) {
	return nil, nil
}
func (stubAdapter) Close() error { return nil }

func TestSQLCopyCSVJSONLAndGzip(t *testing.T) {
	ctx := context.Background()
	cols := []db.Column{
		{Name: "id", DataType: "integer"},
		{Name: "name", DataType: "text"},
		{Name: "score", DataType: "double precision"},
		{Name: "active", DataType: "boolean"},
		{Name: "notes", DataType: "text"},
		{Name: "created_at", DataType: "timestamp"},
	}
	ts := time.Date(2026, 11, 22, 10, 30, 0, 0, time.UTC)
	row := []any{int64(42), "O'Reilly, Inc.\nLine2", 98.5, true, nil, ts}

	t.Run("sql", func(t *testing.T) {
		outPath := filepath.Join(t.TempDir(), "dump.sql")
		sess, err := NewSession("sql", outPath, false)
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		te, err := sess.BeginTable(ctx, stubAdapter{}, "public", "users", cols, true)
		if err != nil {
			t.Fatalf("BeginTable: %v", err)
		}
		line, err := te.FormatRow(row)
		if err != nil {
			t.Fatalf("FormatRow: %v", err)
		}
		if err := te.WriteFormattedRow(line); err != nil {
			t.Fatalf("WriteFormattedRow: %v", err)
		}
		if err := te.Finish(); err != nil {
			t.Fatalf("Finish: %v", err)
		}
		if err := sess.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		data, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		s := string(data)
		if !strings.Contains(s, `CREATE TABLE IF NOT EXISTS "public"."users"`) {
			t.Errorf("missing DDL in SQL output:\n%s", s)
		}
		wantVals := `VALUES (42, 'O''Reilly, Inc.` + "\n" + `Line2', 98.5, TRUE, NULL, '2026-11-22 10:30:00');`
		if !strings.Contains(s, wantVals) {
			t.Errorf("unexpected SQL VALUES:\ngot:  %s\nwant: %s", s, wantVals)
		}
	})

	t.Run("copy", func(t *testing.T) {
		outPath := filepath.Join(t.TempDir(), "dump.copy.sql")
		sess, err := NewSession("copy", outPath, false)
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		te, err := sess.BeginTable(ctx, stubAdapter{}, "public", "users", cols, false)
		if err != nil {
			t.Fatalf("BeginTable: %v", err)
		}
		line, err := te.FormatRow([]any{int64(1), "a\tb\\c\nd\re", 1.25, false, nil, ts})
		if err != nil {
			t.Fatalf("FormatRow: %v", err)
		}
		_ = te.WriteFormattedRow(line)
		_ = te.Finish()
		_ = sess.Close()

		data, _ := os.ReadFile(outPath)
		s := string(data)
		if !strings.Contains(s, `COPY "public"."users" ("id", "name", "score", "active", "notes", "created_at") FROM stdin;`) {
			t.Errorf("missing COPY header:\n%s", s)
		}
		if !strings.Contains(s, "1\ta\\tb\\\\c\\nd\\re\t1.25\tf\t\\N\t2026-11-22 10:30:00\n") {
			t.Errorf("unexpected COPY row:\n%s", s)
		}
		if !strings.Contains(s, "\\.\n") {
			t.Errorf("missing COPY terminator:\n%s", s)
		}
	})

	t.Run("csv", func(t *testing.T) {
		outPath := filepath.Join(t.TempDir(), "dump.csv")
		sess, err := NewSession("csv", outPath, false)
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		te, err := sess.BeginTable(ctx, stubAdapter{}, "", "users", cols, false)
		if err != nil {
			t.Fatalf("BeginTable: %v", err)
		}
		line, err := te.FormatRow(row)
		if err != nil {
			t.Fatalf("FormatRow: %v", err)
		}
		_ = te.WriteFormattedRow(line)
		_ = te.Finish()
		_ = sess.Close()

		f, err := os.Open(outPath)
		if err != nil {
			t.Fatalf("Open csv: %v", err)
		}
		defer f.Close()
		recs, err := csv.NewReader(f).ReadAll()
		if err != nil {
			t.Fatalf("csv ReadAll: %v", err)
		}
		if len(recs) != 2 {
			t.Fatalf("expected 2 CSV records, got %d", len(recs))
		}
		if recs[1][1] != "O'Reilly, Inc.\nLine2" || recs[1][4] != "" {
			t.Errorf("unexpected CSV parsed row: %#v", recs[1])
		}
	})

	t.Run("jsonl_gzip", func(t *testing.T) {
		outPath := filepath.Join(t.TempDir(), "dump.jsonl.gz")
		sess, err := NewSession("jsonl", outPath, false)
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		te, err := sess.BeginTable(ctx, stubAdapter{}, "", "users", cols, false)
		if err != nil {
			t.Fatalf("BeginTable: %v", err)
		}
		line, err := te.FormatRow(row)
		if err != nil {
			t.Fatalf("FormatRow: %v", err)
		}
		_ = te.WriteFormattedRow(line)
		_ = te.Finish()
		_ = sess.Close()

		f, err := os.Open(outPath)
		if err != nil {
			t.Fatalf("open gz: %v", err)
		}
		defer f.Close()
		gr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatalf("gzip reader: %v", err)
		}
		defer gr.Close()
		raw, err := io.ReadAll(gr)
		if err != nil {
			t.Fatalf("read gz: %v", err)
		}

		var parsed map[string]any
		if err := json.Unmarshal(raw, &parsed); err != nil {
			t.Fatalf("unmarshal jsonl: %v", err)
		}
		if parsed["id"] != float64(42) || parsed["active"] != true || parsed["notes"] != nil {
			t.Errorf("native JSON types lost: %#v", parsed)
		}
	})
}

func TestMultiTablePathAndAbort(t *testing.T) {
	got := TableOutputPath("/tmp/out.csv.gz", "csv", "orders", true)
	want := filepath.FromSlash("/tmp/out_orders.csv.gz")
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Errorf("TableOutputPath = %q, want %q", got, want)
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "aborted.sql")
	sess, err := NewSession("sql", target, false)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	_, err = sess.BeginTable(context.Background(), stubAdapter{}, "public", "users", []db.Column{{Name: "id", DataType: "int"}}, false)
	if err != nil {
		t.Fatalf("BeginTable: %v", err)
	}
	sess.Abort()

	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("aborted target file should not exist")
	}
	if _, err := os.Stat(target + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("aborted temp file should be deleted")
	}
}
