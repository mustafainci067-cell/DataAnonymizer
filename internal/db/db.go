package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Column describes metadata for a database table column.
type Column struct {
	Name         string
	DataType     string
	IsNullable   bool
	IsPrimaryKey bool
}

// Adapter abstracts schema inspection and streaming queries across SQL dialects.
type Adapter interface {
	DriverName() string
	Ping(ctx context.Context) error
	ListTables(ctx context.Context, schema string) ([]string, error)
	ListColumns(ctx context.Context, schema, table string) ([]Column, error)
	GenerateDDL(ctx context.Context, schema, table string) (string, error)
	QuoteIdent(ident string) string
	QueryTable(ctx context.Context, schema, table string, columns []Column) (*sql.Rows, error)
	SampleRows(ctx context.Context, schema, table string, columns []Column, limit int) ([][]any, error)
	Close() error
}

// Open connects to a database using the selected driver adapter ("postgres", "mysql", or "sqlite")
// and verifies connectivity with Ping.
func Open(ctx context.Context, driver, dsn string) (Adapter, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, fmt.Errorf("database DSN is empty")
	}

	var (
		adapter Adapter
		err     error
	)
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "", "postgres", "postgresql", "pgx":
		adapter, err = openPostgres(dsn)
	case "mysql":
		adapter, err = openMySQL(dsn)
	case "sqlite", "sqlite3":
		adapter, err = openSQLite(dsn)
	default:
		return nil, fmt.Errorf("unsupported database driver %q (supported: postgres, mysql, sqlite)", driver)
	}
	if err != nil {
		return nil, err
	}

	if err := adapter.Ping(ctx); err != nil {
		_ = adapter.Close()
		return nil, fmt.Errorf("ping %s database: %w", adapter.DriverName(), err)
	}
	return adapter, nil
}

func quoteDouble(ident string) string {
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
}

func quoteBacktick(ident string) string {
	return "`" + strings.ReplaceAll(ident, "`", "``") + "`"
}

func qualifyTable(quote func(string) string, schema, table string) string {
	if strings.TrimSpace(schema) != "" {
		return quote(schema) + "." + quote(table)
	}
	return quote(table)
}

func buildSelectQuery(quote func(string) string, schema, table string, columns []Column, limit int) string {
	colNames := make([]string, len(columns))
	for i, c := range columns {
		colNames[i] = quote(c.Name)
	}
	q := fmt.Sprintf("SELECT %s FROM %s", strings.Join(colNames, ", "), qualifyTable(quote, schema, table))
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	return q
}

func sampleRowsFromDB(ctx context.Context, db *sql.DB, quote func(string) string, schema, table string, columns []Column, limit int) ([][]any, error) {
	if len(columns) == 0 || limit <= 0 {
		return nil, nil
	}
	query := buildSelectQuery(quote, schema, table, columns, limit)
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("sample rows from %s: %w", table, err)
	}
	defer rows.Close()

	var result [][]any
	for rows.Next() {
		vals, err := ScanRowValues(rows, len(columns))
		if err != nil {
			return nil, fmt.Errorf("scan sample row from %s: %w", table, err)
		}
		result = append(result, vals)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sample rows from %s: %w", table, err)
	}
	return result, nil
}

// ScanRowValues reads one row from rows and copies []byte slices into strings
// to avoid data races from driver buffer reuse across rows.
func ScanRowValues(rows *sql.Rows, colCount int) ([]any, error) {
	raw := make([]any, colCount)
	ptrs := make([]any, colCount)
	for i := range raw {
		ptrs[i] = &raw[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return nil, err
	}

	safe := make([]any, colCount)
	for i, v := range raw {
		if b, ok := v.([]byte); ok {
			safe[i] = string(b)
		} else {
			safe[i] = v
		}
	}
	return safe, nil
}

func buildFallbackDDL(quote func(string) string, schema, table string, columns []Column) string {
	var b strings.Builder
	b.WriteString("CREATE TABLE IF NOT EXISTS ")
	b.WriteString(qualifyTable(quote, schema, table))
	b.WriteString(" (\n")

	var pks []string
	for i, col := range columns {
		b.WriteString("    ")
		b.WriteString(quote(col.Name))
		b.WriteByte(' ')
		dt := strings.TrimSpace(col.DataType)
		if dt == "" {
			dt = "TEXT"
		}
		b.WriteString(dt)
		if !col.IsNullable {
			b.WriteString(" NOT NULL")
		}
		if col.IsPrimaryKey {
			pks = append(pks, quote(col.Name))
		}
		if i < len(columns)-1 || len(pks) > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	if len(pks) > 0 {
		b.WriteString("    PRIMARY KEY (")
		b.WriteString(strings.Join(pks, ", "))
		b.WriteString(")\n")
	}
	b.WriteString(");")
	return b.String()
}
