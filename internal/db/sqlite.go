package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

type sqliteAdapter struct {
	db *sql.DB
}

func openSQLite(dsn string) (Adapter, error) {
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite connection: %w", err)
	}
	return &sqliteAdapter{db: conn}, nil
}

func (s *sqliteAdapter) DriverName() string { return "sqlite" }

func (s *sqliteAdapter) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *sqliteAdapter) Close() error { return s.db.Close() }

func (s *sqliteAdapter) QuoteIdent(ident string) string { return quoteDouble(ident) }

func (s *sqliteAdapter) ListTables(ctx context.Context, _ string) ([]string, error) {
	const query = `
		SELECT name
		FROM sqlite_master
		WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
		ORDER BY name`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list sqlite tables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan table name: %w", err)
		}
		tables = append(tables, name)
	}
	return tables, rows.Err()
}

func (s *sqliteAdapter) ListColumns(ctx context.Context, _, table string) ([]Column, error) {
	query := fmt.Sprintf("PRAGMA table_info(%s)", s.QuoteIdent(table))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("inspect sqlite table %q: %w", table, err)
	}
	defer rows.Close()

	var cols []Column
	for rows.Next() {
		var (
			cid      int
			name     string
			colType  string
			notNull  int
			dfltVal  sql.NullString
			pkIndex  int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltVal, &pkIndex); err != nil {
			return nil, fmt.Errorf("scan sqlite column for %q: %w", table, err)
		}
		if strings.TrimSpace(colType) == "" {
			colType = "TEXT"
		}
		cols = append(cols, Column{
			Name:         name,
			DataType:     colType,
			IsNullable:   notNull == 0,
			IsPrimaryKey: pkIndex > 0,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("table %q not found", table)
	}
	return cols, nil
}

func (s *sqliteAdapter) GenerateDDL(ctx context.Context, _, table string) (string, error) {
	const query = `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`
	var ddl sql.NullString
	if err := s.db.QueryRowContext(ctx, query, table).Scan(&ddl); err != nil {
		return "", fmt.Errorf("fetch sqlite DDL for %q: %w", table, err)
	}
	if !ddl.Valid || strings.TrimSpace(ddl.String) == "" {
		cols, err := s.ListColumns(ctx, "", table)
		if err != nil {
			return "", err
		}
		return buildFallbackDDL(s.QuoteIdent, "", table, cols), nil
	}

	out := strings.TrimSpace(ddl.String)
	upper := strings.ToUpper(out)
	if !strings.HasPrefix(upper, "CREATE TABLE IF NOT EXISTS") && strings.HasPrefix(upper, "CREATE TABLE ") {
		out = "CREATE TABLE IF NOT EXISTS " + out[len("CREATE TABLE "):]
	}
	if !strings.HasSuffix(out, ";") {
		out += ";"
	}
	return out, nil
}

func (s *sqliteAdapter) QueryTable(ctx context.Context, _, table string, columns []Column) (*sql.Rows, error) {
	query := buildSelectQuery(s.QuoteIdent, "", table, columns, 0)
	return s.db.QueryContext(ctx, query)
}

func (s *sqliteAdapter) SampleRows(ctx context.Context, _, table string, columns []Column, limit int) ([][]any, error) {
	return sampleRowsFromDB(ctx, s.db, s.QuoteIdent, "", table, columns, limit)
}
