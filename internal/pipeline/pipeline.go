package pipeline

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mustafainci067-cell/data-anonymizer/internal/audit"
	"github.com/mustafainci067-cell/data-anonymizer/internal/config"
	"github.com/mustafainci067-cell/data-anonymizer/internal/db"
	"github.com/mustafainci067-cell/data-anonymizer/internal/discovery"
	"github.com/mustafainci067-cell/data-anonymizer/internal/exporter"
	"github.com/mustafainci067-cell/data-anonymizer/internal/masker"
)

// Options configures a streaming anonymization run across one or more tables.
type Options struct {
	Adapter           db.Adapter
	Schema            string
	Tables            []string
	Format            string
	Output            string
	AutoMask          bool
	Salt              string
	Workers           int
	IncludeDDL        bool
	ContentSampleSize int
	Rules             map[string]map[string]string
	ProgressWriter    io.Writer
	OnFindings        func(table string, findings []discovery.Finding) (bool, error)
}

// Run executes PII discovery, deterministic concurrent masking, and atomic export,
// returning a compliance audit report.
func Run(ctx context.Context, opts Options) (*audit.Report, error) {
	if opts.Adapter == nil {
		return nil, fmt.Errorf("database adapter is required")
	}
	if len(opts.Tables) == 0 {
		return nil, fmt.Errorf("at least one target table is required")
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
		if workers < 1 {
			workers = 1
		}
	}

	session, err := exporter.NewSession(opts.Format, opts.Output, len(opts.Tables) > 1)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	m := masker.New(opts.Salt)
	cfgLookup := &config.Config{Rules: opts.Rules}

	report := &audit.Report{
		GeneratedAt: start.UTC(),
		Driver:      opts.Adapter.DriverName(),
		Format:      opts.Format,
	}

	for _, table := range opts.Tables {
		if err := ctx.Err(); err != nil {
			session.Abort()
			return nil, err
		}

		tblReport, err := processTable(ctx, opts, cfgLookup, session, m, workers, table)
		if err != nil {
			session.Abort()
			return nil, err
		}
		report.TotalRows += tblReport.RowsProcessed
		report.Tables = append(report.Tables, tblReport)
	}

	if err := session.Close(); err != nil {
		return nil, err
	}

	report.Outputs = session.Outputs()
	report.DurationMs = time.Since(start).Milliseconds()
	return report, nil
}

type columnPlan struct {
	strategy string
	reason   string
}

func processTable(
	ctx context.Context,
	opts Options,
	cfgLookup *config.Config,
	session *exporter.Session,
	m *masker.Masker,
	workers int,
	table string,
) (audit.TableReport, error) {
	cols, err := opts.Adapter.ListColumns(ctx, opts.Schema, table)
	if err != nil {
		return audit.TableReport{}, err
	}

	var samples [][]any
	if opts.ContentSampleSize > 0 {
		samples, err = opts.Adapter.SampleRows(ctx, opts.Schema, table, cols, opts.ContentSampleSize)
		if err != nil {
			return audit.TableReport{}, err
		}
	}

	findings := discovery.Discover(table, cols, samples)
	findingMap := make(map[string]discovery.Finding, len(findings))
	for _, f := range findings {
		findingMap[f.Column] = f
	}

	allowAutoMask := opts.AutoMask
	if opts.OnFindings != nil && len(findings) > 0 {
		allowAutoMask, err = opts.OnFindings(table, findings)
		if err != nil {
			return audit.TableReport{}, err
		}
	}

	plans := make([]columnPlan, len(cols))
	colReports := make([]audit.ColumnReport, len(cols))
	for i, col := range cols {
		strat := "keep"
		reason := "none"

		if explicit, ok := cfgLookup.ResolveRule(table, col.Name); ok {
			strat = explicit
			reason = "explicit_rule"
		} else if f, ok := findingMap[col.Name]; ok && allowAutoMask {
			strat = f.Strategy
			reason = f.Reason
		}

		plans[i] = columnPlan{strategy: strat, reason: reason}
		colReports[i] = audit.ColumnReport{
			Name:            col.Name,
			DataType:        col.DataType,
			Strategy:        strat,
			DiscoveryReason: reason,
		}
	}

	tblExp, err := session.BeginTable(ctx, opts.Adapter, opts.Schema, table, cols, opts.IncludeDDL)
	if err != nil {
		return audit.TableReport{}, err
	}

	rows, err := opts.Adapter.QueryTable(ctx, opts.Schema, table, cols)
	if err != nil {
		return audit.TableReport{}, fmt.Errorf("query table %s: %w", table, err)
	}
	defer rows.Close()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		errOnce  sync.Once
		firstErr error
	)
	recordErr := func(e error) {
		if e == nil {
			return
		}
		errOnce.Do(func() {
			firstErr = e
			cancel()
		})
	}

	jobs := make(chan []any, workers*4)
	results := make(chan string, workers*4)

	var processed atomic.Int64
	var writerWg sync.WaitGroup
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		startTime := time.Now()
		lastTick := time.Now()

		for line := range results {
			if err := tblExp.WriteFormattedRow(line); err != nil {
				recordErr(err)
				return
			}
			n := processed.Add(1)
			if opts.ProgressWriter != nil && (n%5000 == 0 || time.Since(lastTick) >= 2*time.Second) {
				elapsed := time.Since(startTime).Seconds()
				rate := float64(n)
				if elapsed > 0 {
					rate = float64(n) / elapsed
				}
				fmt.Fprintf(opts.ProgressWriter, "\r[%s] processed %d rows (%.0f rows/s)...", table, n, rate)
				lastTick = time.Now()
			}
		}
	}()

	var workerWg sync.WaitGroup
	for w := 0; w < workers; w++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for {
				select {
				case <-runCtx.Done():
					return
				case vals, ok := <-jobs:
					if !ok {
						return
					}
					masked := make([]any, len(vals))
					for i, v := range vals {
						if plans[i].strategy == "keep" {
							masked[i] = v
						} else {
							masked[i] = m.Apply(plans[i].strategy, v)
						}
					}
					formatted, err := tblExp.FormatRow(masked)
					if err != nil {
						recordErr(err)
						return
					}
					select {
					case results <- formatted:
					case <-runCtx.Done():
						return
					}
				}
			}
		}()
	}

readLoop:
	for rows.Next() {
		if runCtx.Err() != nil {
			break
		}
		vals, err := db.ScanRowValues(rows, len(cols))
		if err != nil {
			recordErr(fmt.Errorf("scan row from %s: %w", table, err))
			break
		}
		select {
		case jobs <- vals:
		case <-runCtx.Done():
			break readLoop
		}
	}

	close(jobs)
	workerWg.Wait()
	close(results)
	writerWg.Wait()

	if err := rows.Err(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("iterate rows from %s: %w", table, err)
	}
	if firstErr != nil {
		return audit.TableReport{}, firstErr
	}
	if err := ctx.Err(); err != nil {
		return audit.TableReport{}, err
	}

	if err := tblExp.Finish(); err != nil {
		return audit.TableReport{}, err
	}

	total := processed.Load()
	if opts.ProgressWriter != nil {
		fmt.Fprintf(opts.ProgressWriter, "\r[%s] completed %d rows.                    \n", table, total)
	}

	return audit.TableReport{
		Name:          table,
		RowsProcessed: total,
		Columns:       colReports,
	}, nil
}
