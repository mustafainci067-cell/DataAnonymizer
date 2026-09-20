# Data Anonymizer CLI

![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=for-the-badge&logo=go)
![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)

## The Problem
In modern software development, testing with production data is a massive security and privacy risk. Regulations like **GDPR** require that Personally Identifiable Information (PII) never leaks into local developer testing environments.

The **Data Anonymizer CLI** solves this by connecting directly to a database and exporting a sanitized SQL dump, masking sensitive fields on the fly so developers can test safely with realistic data.

## Architecture & Performance
This tool is built with a highly optimized **streaming architecture**. 
By leveraging Go's `database/sql` row-by-row iteration (`rows.Next()`) and buffered I/O (`bufio`), the engine streams transformed rows directly to the disk. 

**Key benefit:** It operates with an **O(1) memory footprint**, meaning it can process massive database dumps (gigabytes or terabytes of data) without ever running out of RAM.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/data-anonymizer.git
   cd data-anonymizer
   ```

2. **Start the local Docker Sandbox (PostgreSQL):**
   ```bash
   docker-compose up -d
   ```

3. **Build the CLI binary:**
   ```bash
   go build -o data-anonymizer main.go
   ```

## Usage

### 1. Test Database Connection
Use the `connect` command to verify connectivity and inspect the schema:

```bash
./data-anonymizer connect
```
*Output:*
```text
Successfully connected to the database!

Schema for 'customers' table:
--------------------------------------------------
Column Name          | Data Type           
--------------------------------------------------
id                   | integer             
full_name            | character varying   
email                | character varying   
credit_card          | character varying   
created_at           | timestamp without time zone
--------------------------------------------------
```

### 2. Run the Anonymization Engine
Use the `mask` command to stream the data, apply GDPR masking rules, and generate the SQL dump:

```bash
./data-anonymizer mask
```
*Output snippet in `anonymized_dump.sql`:*
```sql
INSERT INTO customers (id, full_name, email, credit_card, created_at) VALUES (1, 'Anon User 1', 'user_1@masked.local', '****-****-****-3456', '2026-09-20 13:26:18');
```
