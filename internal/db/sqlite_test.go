package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSQLiteAdapter(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")

	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open seed sqlite: %v", err)
	}
	seedSQL := `
		CREATE TABLE customers (
			id INTEGER PRIMARY KEY,
			full_name TEXT NOT NULL,
			email TEXT,
			balance REAL
		);
		CREATE TABLE orders (
			order_id INTEGER PRIMARY KEY,
			customer_id INTEGER NOT NULL,
			total REAL NOT NULL
		);
		INSERT INTO customers (id, full_name, email, balance) VALUES
			(1, 'Alice', 'alice@example.com', 10.5),
			(2, 'Bob', NULL, 20.0),
			(3, 'Charlie', 'charlie@example.com', 30.25);
	`
	if _, err := rawDB.ExecContext(ctx, seedSQL); err != nil {
		_ = rawDB.Close()
		t.Fatalf("seed sqlite: %v", err)
	}
	_ = rawDB.Close()

	adapter, err := Open(ctx, "sqlite", dbPath)
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer adapter.Close()

	if adapter.DriverName() != "sqlite" {
		t.Errorf("expected driver sqlite, got %q", adapter.DriverName())
	}

	tables, err := adapter.ListTables(ctx, "")
	if err != nil {
		t.Fatalf("ListTables failed: %v", err)
	}
	if len(tables) != 2 || tables[0] != "customers" || tables[1] != "orders" {
		t.Errorf("unexpected tables: %v", tables)
	}

	cols, err := adapter.ListColumns(ctx, "", "customers")
	if err != nil {
		t.Fatalf("ListColumns failed: %v", err)
	}
	if len(cols) != 4 {
		t.Fatalf("expected 4 columns, got %d", len(cols))
	}
	if cols[0].Name != "id" || !cols[0].IsPrimaryKey {
		t.Errorf("expected id as primary key, got %+v", cols[0])
	}
	if cols[1].Name != "full_name" || cols[1].IsNullable {
		t.Errorf("expected full_name NOT NULL, got %+v", cols[1])
	}
	if cols[2].Name != "email" || !cols[2].IsNullable {
		t.Errorf("expected email nullable, got %+v", cols[2])
	}

	if _, err := adapter.ListColumns(ctx, "", "missing_table"); err == nil {
		t.Error("expected error for missing table")
	}

	ddl, err := adapter.GenerateDDL(ctx, "", "customers")
	if err != nil {
		t.Fatalf("GenerateDDL failed: %v", err)
	}
	if !strings.Contains(strings.ToUpper(ddl), "CREATE TABLE IF NOT EXISTS") {
		t.Errorf("expected CREATE TABLE IF NOT EXISTS in DDL, got %q", ddl)
	}

	samples, err := adapter.SampleRows(ctx, "", "customers", cols, 2)
	if err != nil {
		t.Fatalf("SampleRows failed: %v", err)
	}
	if len(samples) != 2 {
		t.Errorf("expected 2 sample rows, got %d", len(samples))
	}

	rows, err := adapter.QueryTable(ctx, "", "customers", cols)
	if err != nil {
		t.Fatalf("QueryTable failed: %v", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		vals, err := ScanRowValues(rows, len(cols))
		if err != nil {
			t.Fatalf("ScanRowValues failed: %v", err)
		}
		if len(vals) != 4 {
			t.Errorf("expected 4 values, got %d", len(vals))
		}
		count++
	}
	if count != 3 {
		t.Errorf("expected 3 streamed rows, got %d", count)
	}
}

func TestOpenErrors(t *testing.T) {
	ctx := context.Background()
	if _, err := Open(ctx, "sqlite", ""); err == nil {
		t.Error("expected error for empty DSN")
	}
	if _, err := Open(ctx, "oracle", "dsn"); err == nil {
		t.Error("expected error for unsupported driver")
	}
}
