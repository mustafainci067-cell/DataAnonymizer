package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type postgresAdapter struct {
	db *sql.DB
}

func openPostgres(dsn string) (Adapter, error) {
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}
	return &postgresAdapter{db: conn}, nil
}

func (p *postgresAdapter) DriverName() string { return "postgres" }

func (p *postgresAdapter) Ping(ctx context.Context) error { return p.db.PingContext(ctx) }

func (p *postgresAdapter) Close() error { return p.db.Close() }

func (p *postgresAdapter) QuoteIdent(ident string) string { return quoteDouble(ident) }

func (p *postgresAdapter) effectiveSchema(schema string) string {
	if strings.TrimSpace(schema) == "" {
		return "public"
	}
	return schema
}

func (p *postgresAdapter) ListTables(ctx context.Context, schema string) ([]string, error) {
	sch := p.effectiveSchema(schema)
	const query = `
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = $1 AND table_type = 'BASE TABLE'
		ORDER BY table_name`
	rows, err := p.db.QueryContext(ctx, query, sch)
	if err != nil {
		return nil, fmt.Errorf("list postgres tables: %w", err)
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

func (p *postgresAdapter) ListColumns(ctx context.Context, schema, table string) ([]Column, error) {
	sch := p.effectiveSchema(schema)
	const query = `
		SELECT c.column_name,
		       c.data_type,
		       (c.is_nullable = 'YES') AS is_nullable,
		       EXISTS (
		           SELECT 1
		           FROM information_schema.table_constraints tc
		           JOIN information_schema.key_column_usage kcu
		             ON tc.constraint_name = kcu.constraint_name
		            AND tc.table_schema = kcu.table_schema
		            AND tc.table_name = kcu.table_name
		           WHERE tc.constraint_type = 'PRIMARY KEY'
		             AND tc.table_schema = c.table_schema
		             AND tc.table_name = c.table_name
		             AND kcu.column_name = c.column_name
		       ) AS is_pk
		FROM information_schema.columns c
		WHERE c.table_schema = $1 AND c.table_name = $2
		ORDER BY c.ordinal_position`
	rows, err := p.db.QueryContext(ctx, query, sch, table)
	if err != nil {
		return nil, fmt.Errorf("list postgres columns for %s.%s: %w", sch, table, err)
	}
	defer rows.Close()

	var cols []Column
	for rows.Next() {
		var c Column
		if err := rows.Scan(&c.Name, &c.DataType, &c.IsNullable, &c.IsPrimaryKey); err != nil {
			return nil, fmt.Errorf("scan column for %s.%s: %w", sch, table, err)
		}
		cols = append(cols, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("table %q not found in schema %q", table, sch)
	}
	return cols, nil
}

func (p *postgresAdapter) GenerateDDL(ctx context.Context, schema, table string) (string, error) {
	sch := p.effectiveSchema(schema)
	cols, err := p.ListColumns(ctx, sch, table)
	if err != nil {
		return "", err
	}
	return buildFallbackDDL(p.QuoteIdent, sch, table, cols), nil
}

func (p *postgresAdapter) QueryTable(ctx context.Context, schema, table string, columns []Column) (*sql.Rows, error) {
	sch := p.effectiveSchema(schema)
	query := buildSelectQuery(p.QuoteIdent, sch, table, columns, 0)
	return p.db.QueryContext(ctx, query)
}

func (p *postgresAdapter) SampleRows(ctx context.Context, schema, table string, columns []Column, limit int) ([][]any, error) {
	sch := p.effectiveSchema(schema)
	return sampleRowsFromDB(ctx, p.db, p.QuoteIdent, sch, table, columns, limit)
}
