package pipeline

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

	"github.com/mustafainci067-cell/data-anonymizer/internal/db"
	"github.com/mustafainci067-cell/data-anonymizer/internal/discovery"
	_ "modernc.org/sqlite"
)

func seedE2ESQLite(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "e2e.db")
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer conn.Close()

	schemaAndData := `
		CREATE TABLE customers (
			id INTEGER PRIMARY KEY,
			full_name TEXT NOT NULL,
			email TEXT NOT NULL,
			credit_card TEXT NOT NULL,
			national_doc TEXT NOT NULL,
			salary INTEGER NOT NULL,
			bonus_rate REAL NOT NULL,
			notes TEXT
		);
		CREATE TABLE orders (
			order_id INTEGER PRIMARY KEY,
			customer_email TEXT NOT NULL,
			amount INTEGER NOT NULL
		);
		INSERT INTO customers (id, full_name, email, credit_card, national_doc, salary, bonus_rate, notes) VALUES
			(1, 'Ada Lovelace', 'ada@example.com', '4111-1111-1111-1111', '10000000146', 95000, 1.25, 'VIP note'),
			(2, 'Alan Turing', 'alan@example.com', '5500-0000-0000-0004', '10000000146', 88000, 1.10, NULL);
		INSERT INTO orders (order_id, customer_email, amount) VALUES
			(10, 'ada@example.com', 250),
			(11, 'alan@example.com', 400);
	`
	if _, err := conn.Exec(schemaAndData); err != nil {
		t.Fatalf("seed sqlite: %v", err)
	}
	return dbPath
}

func TestPipelineE2ESQLiteAllFormats(t *testing.T) {
	ctx := context.Background()
	dbPath := seedE2ESQLite(t)

	adapter, err := db.Open(ctx, "sqlite", dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer adapter.Close()

	rules := map[string]map[string]string{
		"customers": {
			"notes": "redact",
		},
	}

	t.Run("sql_with_ddl_and_audit", func(t *testing.T) {
		dir := t.TempDir()
		outPath := filepath.Join(dir, "dump.sql")
		auditPath := filepath.Join(dir, "audit.md")

		rep, err := Run(ctx, Options{
			Adapter:           adapter,
			Tables:            []string{"customers", "orders"},
			Format:            "sql",
			Output:            outPath,
			AutoMask:          true,
			Salt:              "deterministic-e2e-salt",
			Workers:           4,
			IncludeDDL:        true,
			ContentSampleSize: 10,
			Rules:             rules,
		})
		if err != nil {
			t.Fatalf("pipeline.Run sql: %v", err)
		}
		if rep.TotalRows != 4 || len(rep.Tables) != 2 {
			t.Fatalf("unexpected report totals: %+v", rep)
		}
		if err := rep.Write(auditPath); err != nil {
			t.Fatalf("audit Write: %v", err)
		}

		raw, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("ReadFile sql: %v", err)
		}
		dump := string(raw)

		if !strings.Contains(dump, `CREATE TABLE IF NOT EXISTS`) {
			t.Errorf("expected DDL statements in dump:\n%s", dump)
		}
		if strings.Contains(dump, "ada@example.com") || strings.Contains(dump, "Ada Lovelace") ||
			strings.Contains(dump, "4111-1111-1111-1111") || strings.Contains(dump, "10000000146") ||
			strings.Contains(dump, "VIP note") {
			t.Errorf("unmasked PII leaked into SQL dump:\n%s", dump)
		}
		if !strings.Contains(dump, "95000, 1.25, '[REDACTED]'") {
			t.Errorf("expected unquoted numeric types + redacted note:\n%s", dump)
		}
		if !strings.Contains(dump, "88000, 1.1, NULL") {
			t.Errorf("expected NULL preserved for row 2 notes:\n%s", dump)
		}

		// Verify content-discovered TCKN and explicit rule in audit report
		foundTCKN := false
		foundNotes := false
		for _, c := range rep.Tables[0].Columns {
			if c.Name == "national_doc" && c.Strategy == "tckn" && c.DiscoveryReason == "content:tckn" {
				foundTCKN = true
			}
			if c.Name == "notes" && c.Strategy == "redact" && c.DiscoveryReason == "explicit_rule" {
				foundNotes = true
			}
		}
		if !foundTCKN || !foundNotes {
			t.Errorf("unexpected audit column plans: %+v", rep.Tables[0].Columns)
		}
	})

	t.Run("copy_format", func(t *testing.T) {
		outPath := filepath.Join(t.TempDir(), "dump.copy.sql")
		if _, err := Run(ctx, Options{
			Adapter:           adapter,
			Tables:            []string{"customers"},
			Format:            "copy",
			Output:            outPath,
			AutoMask:          true,
			Salt:              "deterministic-e2e-salt",
			Workers:           2,
			ContentSampleSize: 10,
		}); err != nil {
			t.Fatalf("pipeline.Run copy: %v", err)
		}
		raw, _ := os.ReadFile(outPath)
		s := string(raw)
		if !strings.Contains(s, `COPY "customers"`) || !strings.Contains(s, "\\.\n") {
			t.Errorf("invalid COPY output:\n%s", s)
		}
	})

	t.Run("csv_multitable_and_cross_table_determinism", func(t *testing.T) {
		dir := t.TempDir()
		base := filepath.Join(dir, "export.csv")
		rep, err := Run(ctx, Options{
			Adapter:           adapter,
			Tables:            []string{"customers", "orders"},
			Format:            "csv",
			Output:            base,
			AutoMask:          true,
			Salt:              "deterministic-e2e-salt",
			Workers:           4,
			ContentSampleSize: 10,
		})
		if err != nil {
			t.Fatalf("pipeline.Run csv: %v", err)
		}
		if len(rep.Outputs) != 2 {
			t.Fatalf("expected 2 per-table CSV files, got %v", rep.Outputs)
		}

		custFile, _ := os.Open(filepath.Join(dir, "export_customers.csv"))
		defer custFile.Close()
		custRows, err := csv.NewReader(custFile).ReadAll()
		if err != nil {
			t.Fatalf("read customers csv: %v", err)
		}
		ordFile, _ := os.Open(filepath.Join(dir, "export_orders.csv"))
		defer ordFile.Close()
		ordRows, err := csv.NewReader(ordFile).ReadAll()
		if err != nil {
			t.Fatalf("read orders csv: %v", err)
		}

		// Map customer id -> masked email, order_id -> masked customer_email
		custEmails := make(map[string]bool)
		for _, r := range custRows[1:] {
			custEmails[r[2]] = true
			if !discovery.IsValidTCKN(r[4]) {
				t.Errorf("masked TCKN in CSV invalid: %q", r[4])
			}
		}
		for _, r := range ordRows[1:] {
			if !custEmails[r[1]] {
				t.Errorf("cross-table email mismatch in orders: %q not in %v", r[1], custEmails)
			}
		}
	})

	t.Run("jsonl_gzip", func(t *testing.T) {
		outPath := filepath.Join(t.TempDir(), "customers.jsonl.gz")
		if _, err := Run(ctx, Options{
			Adapter:           adapter,
			Tables:            []string{"customers"},
			Format:            "jsonl",
			Output:            outPath,
			AutoMask:          true,
			Salt:              "deterministic-e2e-salt",
			Workers:           2,
			ContentSampleSize: 10,
		}); err != nil {
			t.Fatalf("pipeline.Run jsonl.gz: %v", err)
		}

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

		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if len(lines) != 2 {
			t.Fatalf("expected 2 JSONL lines, got %d", len(lines))
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &obj); err != nil {
			t.Fatalf("unmarshal jsonl line: %v", err)
		}
		if _, isNum := obj["salary"].(float64); !isNum {
			t.Errorf("expected numeric salary in JSONL, got %T (%v)", obj["salary"], obj["salary"])
		}
	})
}

func TestPostgresPipelineIntegration(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set")
	}

	ctx := context.Background()
	adapter, err := db.Open(ctx, "postgres", dsn)
	if err != nil {
		t.Fatalf("db.Open postgres: %v", err)
	}
	defer adapter.Close()

	tables, err := adapter.ListTables(ctx, "public")
	if err != nil || len(tables) == 0 {
		t.Fatalf("ListTables postgres failed (%v): tables=%v", err, tables)
	}

	outPath := filepath.Join(t.TempDir(), "pg_dump.sql")
	rep, err := Run(ctx, Options{
		Adapter:           adapter,
		Schema:            "public",
		Tables:            []string{tables[0]},
		Format:            "sql",
		Output:            outPath,
		AutoMask:          true,
		Salt:              "ci-pg-salt",
		Workers:           4,
		IncludeDDL:        true,
		ContentSampleSize: 50,
	})
	if err != nil {
		t.Fatalf("postgres pipeline.Run: %v", err)
	}
	if rep.TotalRows == 0 {
		t.Errorf("expected rows from postgres table %q", tables[0])
	}
}
