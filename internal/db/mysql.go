package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

type mysqlAdapter struct {
	db *sql.DB
}

func openMySQL(dsn string) (Adapter, error) {
	conn, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("open mysql connection: %w", err)
	}
	return &mysqlAdapter{db: conn}, nil
}

func (m *mysqlAdapter) DriverName() string { return "mysql" }

func (m *mysqlAdapter) Ping(ctx context.Context) error { return m.db.PingContext(ctx) }

func (m *mysqlAdapter) Close() error { return m.db.Close() }

func (m *mysqlAdapter) QuoteIdent(ident string) string { return quoteBacktick(ident) }

func (m *mysqlAdapter) ListTables(ctx context.Context, schema string) ([]string, error) {
	const query = `
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = COALESCE(NULLIF(?, ''), DATABASE())
		  AND table_type = 'BASE TABLE'
		ORDER BY table_name`
	rows, err := m.db.QueryContext(ctx, query, strings.TrimSpace(schema))
	if err != nil {
		return nil, fmt.Errorf("list mysql tables: %w", err)
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

func (m *mysqlAdapter) ListColumns(ctx context.Context, schema, table string) ([]Column, error) {
	const query = `
		SELECT column_name,
		       column_type,
		       (is_nullable = 'YES') AS is_nullable,
		       (column_key = 'PRI') AS is_pk
		FROM information_schema.columns
		WHERE table_schema = COALESCE(NULLIF(?, ''), DATABASE())
		  AND table_name = ?
		ORDER BY ordinal_position`
	rows, err := m.db.QueryContext(ctx, query, strings.TrimSpace(schema), table)
	if err != nil {
		return nil, fmt.Errorf("list mysql columns for %s: %w", table, err)
	}
	defer rows.Close()

	var cols []Column
	for rows.Next() {
		var c Column
		if err := rows.Scan(&c.Name, &c.DataType, &c.IsNullable, &c.IsPrimaryKey); err != nil {
			return nil, fmt.Errorf("scan column for %s: %w", table, err)
		}
		cols = append(cols, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("table %q not found", table)
	}
	return cols, nil
}

func (m *mysqlAdapter) GenerateDDL(ctx context.Context, schema, table string) (string, error) {
	q := "SHOW CREATE TABLE " + qualifyTable(m.QuoteIdent, schema, table)
	var tblName, createSQL string
	if err := m.db.QueryRowContext(ctx, q).Scan(&tblName, &createSQL); err == nil && createSQL != "" {
		upper := strings.ToUpper(createSQL)
		if !strings.Contains(upper, "CREATE TABLE IF NOT EXISTS") {
			createSQL = strings.Replace(createSQL, "CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1)
		}
		if !strings.HasSuffix(strings.TrimSpace(createSQL), ";") {
			createSQL += ";"
		}
		return createSQL, nil
	}
	cols, err := m.ListColumns(ctx, schema, table)
	if err != nil {
		return "", err
	}
	return buildFallbackDDL(m.QuoteIdent, schema, table, cols), nil
}

func (m *mysqlAdapter) QueryTable(ctx context.Context, schema, table string, columns []Column) (*sql.Rows, error) {
	query := buildSelectQuery(m.QuoteIdent, schema, table, columns, 0)
	return m.db.QueryContext(ctx, query)
}

func (m *mysqlAdapter) SampleRows(ctx context.Context, schema, table string, columns []Column, limit int) ([][]any, error) {
	return sampleRowsFromDB(ctx, m.db, m.QuoteIdent, schema, table, columns, limit)
}
