# Data Anonymizer CLI

![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=for-the-badge&logo=go)
![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)

## The Problem
Testing with production data exposes sensitive Personally Identifiable Information (**PII**) and violates privacy regulations such as **GDPR** and **KVKK**.

**Data Anonymizer CLI** connects directly to **PostgreSQL**, **MySQL**, or **SQLite**, automatically discovers sensitive columns, deterministically masks PII in flight using **HMAC-SHA256**, and streams sanitized dumps in **SQL**, **PostgreSQL COPY**, **CSV**, or **JSONL** formats (with optional `.gz` compression and `stdout` piping).

## Key Features
- **Multi-Database Support:** Native adapters for PostgreSQL (`jackc/pgx/v5`), MySQL (`go-sql-driver/mysql`), and pure-Go SQLite (`modernc.org/sqlite`).
- **Smart PII Auto-Discovery:** Detects sensitive columns by column-name patterns and **content sampling** (email regex, payment cards via Luhn checksum, Turkish ID numbers via TCKN checksum, IBAN, IPv4, and phone patterns).
- **Deterministic Non-Reversible Masking:** Uses salted `HMAC-SHA256` so identical values map consistently across tables (preserving foreign-key and `UNIQUE` constraints) without exposing original data.
- **Type-Aware Streaming Exporters:**
  - `sql`: Type-aware `INSERT` statements (unquoted numbers, `TRUE`/`FALSE` booleans, `NULL`, escaped strings) + optional `CREATE TABLE IF NOT EXISTS` DDL (`--include-ddl`).
  - `copy`: High-speed PostgreSQL `COPY ... FROM stdin;` streams.
  - `csv`: RFC-4180 compliant output via `encoding/csv` (per-table files on multi-table export).
  - `jsonl`: Native-typed JSON Lines output.
  - Atomic temporary writes (`.tmp` renamed on completion), optional `.gz` compression, and `-` stdout streaming.
- **GDPR/KVKK Audit Reports:** Exports structured `.json` or `.md` compliance reports detailing every table, row count, column strategy, and discovery reason.
- **Dual Execution Modes:** Interactive terminal UI (`charmbracelet/huh`) or scriptable headless mode via `anonymizer.yaml`, environment variables (`DATABASE_URL`, `ANONYMIZER_DSN`, `ANONYMIZER_SALT`), and CLI flags.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mustafainci067-cell/data-anonymizer.git
   cd data-anonymizer
   ```

2. **Start the local Docker Sandbox (optional PostgreSQL test DB):**
   ```bash
   docker-compose up -d
   ```

3. **Build the CLI binary:**
   ```bash
   go build -o data-anonymizer .
   ```

## Usage

### 1. Inspect Connection and Schemas (`connect`)
Test connectivity and list discovered tables and column metadata:

```bash
./data-anonymizer connect \
  --driver postgres \
  --dsn "postgres://admin:password@localhost:5432/anonymizer_sandbox?sslmode=disable"
```

Use `--table <name>` to inspect a single table, or `--config anonymizer.yaml` to load settings from YAML.

### 2. Anonymize and Export (`mask`)

**Interactive TUI mode:**
```bash
./data-anonymizer mask
```

**Headless CLI mode (all tables, PostgreSQL COPY, gzipped, with Markdown audit report):**
```bash
./data-anonymizer mask \
  --driver postgres \
  --dsn "postgres://admin:password@localhost:5432/anonymizer_sandbox?sslmode=disable" \
  --table "*" \
  --format copy \
  --output sanitized.sql.gz \
  --include-ddl \
  --auto-mask \
  --salt "my-secret-salt" \
  --audit audit_report.md
```

**Stream SQL directly to stdout:**
```bash
./data-anonymizer mask --driver sqlite --dsn ./app.db --table customers --format sql --output - --auto-mask
```

**Headless YAML mode:**
Copy [anonymizer.example.yaml](anonymizer.example.yaml) to `anonymizer.yaml`, adjust your connection string and masking rules, and run:
```bash
./data-anonymizer mask
```

## Masking Strategies
Available strategies for YAML `rules`:
- `fake_name`, `fake_email`, `fake_phone`, `address`, `ip`
- `credit_card` (masked `****-****-****-XXXX` derived solely from HMAC digits)
- `tckn` (deterministic 11-digit TCKN passing official checksum validation)
- `iban`, `hmac_hash`, `password`, `nullify`, `redact`, `keep`

## Testing
```bash
go vet ./...
go test -v ./...
```

To run the live PostgreSQL integration test as well:
```bash
TEST_POSTGRES_DSN="postgres://admin:password@localhost:5432/anonymizer_sandbox?sslmode=disable" go test -v ./...
```
