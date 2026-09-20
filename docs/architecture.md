# Data Anonymizer CLI Architecture

## Overview
Data Anonymizer CLI is an open-source, GDPR-compliant command-line tool written in Go (Golang). It connects to databases, streams data, masks/hashes Personally Identifiable Information (PII) on the fly, and exports a clean SQL dump. 

## Key Design Principles
- **Go routines & Channels**: Leverages Go's concurrency primitives for high-performance streaming without memory bloat.
- **Minimal Dependencies**: Relies primarily on standard library (`database/sql`) to minimize attack surface and binary size. `spf13/cobra` is used for CLI scaffolding.
- **GDPR Compliance**: Masks and hashes PII safely, ensuring exported data cannot be reverse-engineered to identify individuals.

## Local Environment
- **Docker Compose**: Spins up a PostgreSQL 15 sandbox environment with dummy data for local testing and development.
