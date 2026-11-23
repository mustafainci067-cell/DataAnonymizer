package exporter

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mustafainci067-cell/data-anonymizer/internal/db"
)

// ValidateFormat checks whether format is one of sql, copy, csv, or jsonl.
func ValidateFormat(format string) (string, error) {
	f := strings.ToLower(strings.TrimSpace(format))
	switch f {
	case "sql", "copy", "csv", "jsonl":
		return f, nil
	default:
		return "", fmt.Errorf("unsupported export format %q (supported: sql, copy, csv, jsonl)", format)
	}
}

// TableOutputPath computes the destination file path for a table export.
// Single-table exports, stdout ("-"), and SQL/COPY formats share one output target;
// multi-table CSV/JSONL exports write per-table files to keep schemas separate.
func TableOutputPath(output, format, table string, multiTable bool) string {
	if !multiTable || output == "-" {
		return output
	}
	f := strings.ToLower(strings.TrimSpace(format))
	if f == "sql" || f == "copy" {
		return output
	}

	gzSuffix := ""
	base := output
	if strings.HasSuffix(strings.ToLower(base), ".gz") {
		gzSuffix = base[len(base)-3:]
		base = base[:len(base)-3]
	}

	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	safeTable := strings.NewReplacer("/", "_", "\\", "_", " ", "_").Replace(table)
	return fmt.Sprintf("%s_%s%s%s", stem, safeTable, ext, gzSuffix)
}

type sink struct {
	targetPath string
	tmpPath    string
	isStdout   bool
	file       *os.File
	gz         *gzip.Writer
	bw         *bufio.Writer
	closed     bool
}

func openSink(targetPath string) (*sink, error) {
	if targetPath == "-" {
		return &sink{
			targetPath: "-",
			isStdout:   true,
			bw:         bufio.NewWriterSize(os.Stdout, 64*1024),
		}, nil
	}

	dir := filepath.Dir(targetPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create output directory %q: %w", dir, err)
		}
	}

	tmpPath := targetPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("create temp output %q: %w", tmpPath, err)
	}

	s := &sink{
		targetPath: targetPath,
		tmpPath:    tmpPath,
		file:       f,
	}

	var underlying io.Writer = f
	if strings.HasSuffix(strings.ToLower(targetPath), ".gz") {
		s.gz = gzip.NewWriter(f)
		underlying = s.gz
	}
	s.bw = bufio.NewWriterSize(underlying, 64*1024)
	return s, nil
}

func (s *sink) WriteString(str string) error {
	_, err := s.bw.WriteString(str)
	return err
}

func (s *sink) Commit() error {
	if s.closed {
		return nil
	}
	s.closed = true

	if err := s.bw.Flush(); err != nil {
		s.cleanupTemp()
		return fmt.Errorf("flush buffer: %w", err)
	}
	if s.gz != nil {
		if err := s.gz.Close(); err != nil {
			s.cleanupTemp()
			return fmt.Errorf("close gzip stream: %w", err)
		}
	}
	if s.isStdout {
		return nil
	}
	if err := s.file.Close(); err != nil {
		_ = os.Remove(s.tmpPath)
		return fmt.Errorf("close temp file %q: %w", s.tmpPath, err)
	}
	if err := os.Rename(s.tmpPath, s.targetPath); err != nil {
		_ = os.Remove(s.tmpPath)
		return fmt.Errorf("rename %q to %q: %w", s.tmpPath, s.targetPath, err)
	}
	return nil
}

func (s *sink) Abort() {
	if s.closed {
		return
	}
	s.closed = true
	s.cleanupTemp()
}

func (s *sink) cleanupTemp() {
	if s.gz != nil {
		_ = s.gz.Close()
	}
	if s.file != nil {
		_ = s.file.Close()
	}
	if s.tmpPath != "" {
		_ = os.Remove(s.tmpPath)
	}
}

// Session manages output sinks across one or more exported tables.
type Session struct {
	format     string
	output     string
	multiTable bool
	sharedSink *sink
	sinks      []*sink
	outputs    []string
}

// NewSession initializes an export session for the requested format and destination.
func NewSession(format, output string, multiTable bool) (*Session, error) {
	f, err := ValidateFormat(format)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(output) == "" {
		return nil, fmt.Errorf("output path is empty")
	}
	return &Session{
		format:     f,
		output:     output,
		multiTable: multiTable,
	}, nil
}

// BeginTable prepares a TableExporter and writes its header (and optional DDL).
func (s *Session) BeginTable(ctx context.Context, adapter db.Adapter, schema, table string, columns []db.Column, includeDDL bool) (*TableExporter, error) {
	dest := TableOutputPath(s.output, s.format, table, s.multiTable)
	var targetSink *sink
	var ownsSink bool

	if s.format == "sql" || s.format == "copy" || !s.multiTable || dest == "-" {
		if s.sharedSink == nil {
			created, err := openSink(dest)
			if err != nil {
				return nil, err
			}
			s.sharedSink = created
			s.sinks = append(s.sinks, created)
			s.outputs = append(s.outputs, dest)
		}
		targetSink = s.sharedSink
	} else {
		created, err := openSink(dest)
		if err != nil {
			return nil, err
		}
		targetSink = created
		ownsSink = true
		s.sinks = append(s.sinks, created)
		s.outputs = append(s.outputs, dest)
	}

	te := &TableExporter{
		format:    s.format,
		adapter:   adapter,
		schema:    schema,
		table:     table,
		columns:   columns,
		sink:      targetSink,
		ownsSink:  ownsSink,
		quotedTbl: qualifyQuotedTable(adapter, schema, table),
		quotedCol: joinQuotedCols(adapter, columns),
	}

	if err := te.writeHeader(ctx, includeDDL); err != nil {
		return nil, err
	}
	return te, nil
}

// Outputs returns the resolved output file paths (or "-") created by this session.
func (s *Session) Outputs() []string {
	out := make([]string, len(s.outputs))
	copy(out, s.outputs)
	return out
}

// Close flushes and atomically commits all open output sinks.
func (s *Session) Close() error {
	for _, sk := range s.sinks {
		if err := sk.Commit(); err != nil {
			s.Abort()
			return err
		}
	}
	return nil
}

// Abort closes and deletes any temporary output files created during the session.
func (s *Session) Abort() {
	for _, sk := range s.sinks {
		sk.Abort()
	}
}

// TableExporter formats rows for a single table and writes them to its sink.
type TableExporter struct {
	format    string
	adapter   db.Adapter
	schema    string
	table     string
	columns   []db.Column
	sink      *sink
	ownsSink  bool
	quotedTbl string
	quotedCol string
}

func (te *TableExporter) writeHeader(ctx context.Context, includeDDL bool) error {
	if includeDDL && (te.format == "sql" || te.format == "copy") {
		ddl, err := te.adapter.GenerateDDL(ctx, te.schema, te.table)
		if err != nil {
			return fmt.Errorf("generate DDL for %s: %w", te.table, err)
		}
		if err := te.sink.WriteString(ddl + "\n\n"); err != nil {
			return err
		}
	}

	switch te.format {
	case "copy":
		header := fmt.Sprintf("COPY %s (%s) FROM stdin;\n", te.quotedTbl, te.quotedCol)
		return te.sink.WriteString(header)
	case "csv":
		names := make([]string, len(te.columns))
		for i, c := range te.columns {
			names[i] = c.Name
		}
		line, err := encodeCSVRecord(names)
		if err != nil {
			return err
		}
		return te.sink.WriteString(line)
	default:
		return nil
	}
}

// FormatRow converts a masked row into a serialized line for the target format.
// Safe for concurrent calls across worker goroutines.
func (te *TableExporter) FormatRow(values []any) (string, error) {
	if len(values) != len(te.columns) {
		return "", fmt.Errorf("row value count %d does not match column count %d", len(values), len(te.columns))
	}

	switch te.format {
	case "sql":
		parts := make([]string, len(values))
		for i, v := range values {
			parts[i] = formatSQLValue(v)
		}
		return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s);\n", te.quotedTbl, te.quotedCol, strings.Join(parts, ", ")), nil

	case "copy":
		parts := make([]string, len(values))
		for i, v := range values {
			parts[i] = formatCopyValue(v)
		}
		return strings.Join(parts, "\t") + "\n", nil

	case "csv":
		parts := make([]string, len(values))
		for i, v := range values {
			parts[i] = formatScalarText(v)
		}
		return encodeCSVRecord(parts)

	case "jsonl":
		obj := make(map[string]any, len(te.columns))
		for i, col := range te.columns {
			obj[col.Name] = normalizeJSONValue(values[i])
		}
		data, err := json.Marshal(obj)
		if err != nil {
			return "", fmt.Errorf("marshal jsonl row for %s: %w", te.table, err)
		}
		return string(data) + "\n", nil

	default:
		return "", fmt.Errorf("unsupported export format %q", te.format)
	}
}

// WriteFormattedRow writes a pre-formatted row line to the buffered output sink.
func (te *TableExporter) WriteFormattedRow(line string) error {
	return te.sink.WriteString(line)
}

// Finish writes any table-level footer and commits per-table sinks if owned.
func (te *TableExporter) Finish() error {
	switch te.format {
	case "copy":
		if err := te.sink.WriteString("\\.\n\n"); err != nil {
			return err
		}
	case "sql":
		if err := te.sink.WriteString("\n"); err != nil {
			return err
		}
	}
	if te.ownsSink {
		return te.sink.Commit()
	}
	return nil
}

func qualifyQuotedTable(adapter db.Adapter, schema, table string) string {
	if strings.TrimSpace(schema) != "" {
		return adapter.QuoteIdent(schema) + "." + adapter.QuoteIdent(table)
	}
	return adapter.QuoteIdent(table)
}

func joinQuotedCols(adapter db.Adapter, columns []db.Column) string {
	parts := make([]string, len(columns))
	for i, c := range columns {
		parts[i] = adapter.QuoteIdent(c.Name)
	}
	return strings.Join(parts, ", ")
}

func formatSQLValue(v any) string {
	if v == nil {
		return "NULL"
	}
	switch val := v.(type) {
	case bool:
		if val {
			return "TRUE"
		}
		return "FALSE"
	case int:
		return strconv.Itoa(val)
	case int8:
		return strconv.FormatInt(int64(val), 10)
	case int16:
		return strconv.FormatInt(int64(val), 10)
	case int32:
		return strconv.FormatInt(int64(val), 10)
	case int64:
		return strconv.FormatInt(val, 10)
	case uint:
		return strconv.FormatUint(uint64(val), 10)
	case uint8:
		return strconv.FormatUint(uint64(val), 10)
	case uint16:
		return strconv.FormatUint(uint64(val), 10)
	case uint32:
		return strconv.FormatUint(uint64(val), 10)
	case uint64:
		return strconv.FormatUint(val, 10)
	case float32:
		f := float64(val)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return "'NaN'"
		}
		return strconv.FormatFloat(f, 'g', -1, 32)
	case float64:
		if math.IsNaN(val) || math.IsInf(val, 0) {
			return "'NaN'"
		}
		return strconv.FormatFloat(val, 'g', -1, 64)
	case time.Time:
		return "'" + val.Format("2006-01-02 15:04:05") + "'"
	case []byte:
		return "'" + strings.ReplaceAll(string(val), "'", "''") + "'"
	case string:
		return "'" + strings.ReplaceAll(val, "'", "''") + "'"
	default:
		return "'" + strings.ReplaceAll(fmt.Sprintf("%v", val), "'", "''") + "'"
	}
}

var copyEscaper = strings.NewReplacer(
	`\`, `\\`,
	"\t", `\t`,
	"\n", `\n`,
	"\r", `\r`,
)

func formatCopyValue(v any) string {
	if v == nil {
		return `\N`
	}
	switch val := v.(type) {
	case bool:
		if val {
			return "t"
		}
		return "f"
	case time.Time:
		return val.Format("2006-01-02 15:04:05")
	case []byte:
		return copyEscaper.Replace(string(val))
	case string:
		return copyEscaper.Replace(val)
	default:
		return copyEscaper.Replace(fmt.Sprintf("%v", val))
	}
}

func formatScalarText(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case time.Time:
		return val.Format("2006-01-02 15:04:05")
	case []byte:
		return string(val)
	case string:
		return val
	default:
		return fmt.Sprintf("%v", val)
	}
}

func normalizeJSONValue(v any) any {
	switch val := v.(type) {
	case nil:
		return nil
	case []byte:
		return string(val)
	case time.Time:
		return val.Format(time.RFC3339)
	default:
		return val
	}
}

func encodeCSVRecord(fields []string) (string, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(fields); err != nil {
		return "", err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return "", err
	}
	return buf.String(), nil
}
