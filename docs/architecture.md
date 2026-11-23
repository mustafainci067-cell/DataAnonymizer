# Data Anonymizer CLI Architecture

## Overview
Data Anonymizer CLI is a modular, GDPR/KVKK-compliant command-line tool written in Go. It connects to PostgreSQL, MySQL, or SQLite databases, discovers sensitive PII columns via schema and content inspection, deterministically masks values concurrently, and streams sanitized dumps atomically to disk or stdout.

## Package Structure
- `cmd/` — Cobra CLI commands (`root`, `connect`, `mask`), signal handling (`signal.NotifyContext`), CLI flag overrides, and interactive `charmbracelet/huh` forms.
- `internal/config/` — YAML configuration (`viper`), environment fallbacks (`ANONYMIZER_DSN`, `DATABASE_URL`, `ANONYMIZER_SALT`), rule resolution (table-specific and `"*"` wildcard), and ephemeral salt generation.
- `internal/db/` — Dialect-agnostic `Adapter` interface and implementations for PostgreSQL (`jackc/pgx/v5/stdlib`), MySQL (`go-sql-driver/mysql`), and SQLite (`modernc.org/sqlite`).
- `internal/discovery/` — Name-based regex matching and content-sampling PII classifiers (email, Luhn credit cards, TCKN checksum, IBAN, IPv4, phone).
- `internal/masker/` — Deterministic, non-reversible `HMAC-SHA256` masking engine supporting `fake_name`, `fake_email`, `fake_phone`, `credit_card`, `tckn`, `iban`, `hmac_hash`, `password`, `address`, `ip`, `nullify`, `redact`, and `keep`.
- `internal/exporter/` — Type-aware streaming serializers (`sql`, `copy`, `csv`, `jsonl`), optional DDL emission, `.gz` compression, stdout (`-`) output, and atomic `.tmp` file commits.
- `internal/pipeline/` — Context-aware streaming orchestrator linking row scanning (`rows.Next()`), bounded worker goroutines, single-writer buffered I/O, and progress reporting.
- `internal/audit/` — Compliance audit report generator writing structured `.json` and `.md` summaries.

## Streaming & Concurrency Model
1. A single reader streams rows via `rows.Next()` and safely copies `[]byte` values into bounded job channels (`O(1)` memory footprint).
2. A configurable worker pool applies column strategies and formats output records concurrently.
3. A single writer goroutine persists formatted lines through buffered I/O (and optional gzip) to an atomic `.tmp` file, cleaning up cleanly on error or `SIGINT`/`SIGTERM`.
