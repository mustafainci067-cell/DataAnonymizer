package cmd

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/mustafainci067-cell/data-anonymizer/internal/config"
	"github.com/mustafainci067-cell/data-anonymizer/internal/db"
	"github.com/mustafainci067-cell/data-anonymizer/internal/discovery"
	"github.com/mustafainci067-cell/data-anonymizer/internal/pipeline"
	"github.com/spf13/cobra"
)

var maskFlags struct {
	configPath     string
	driver         string
	dsn            string
	schema         string
	table          string
	format         string
	output         string
	workers        int
	salt           string
	autoMask       bool
	includeDDL     bool
	auditOutput    string
	nonInteractive bool
}

var maskCmd = &cobra.Command{
	Use:   "mask",
	Short: "Discover PII, deterministically mask data, and stream sanitized exports",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, foundConfig, err := config.Load(maskFlags.configPath)
		if err != nil {
			return err
		}

		applyMaskFlagOverrides(cmd, cfg)
		cfg.Normalize()

		headless := foundConfig || maskFlags.nonInteractive || (len(cfg.Tables) > 0 && cfg.DSN != "")
		errOut := cmd.ErrOrStderr()

		if !headless && cfg.DSN == "" {
			if err := promptConnection(cfg); err != nil {
				return err
			}
			cfg.Normalize()
		}
		if cfg.DSN == "" {
			return fmt.Errorf("database DSN is required (set db_conn in anonymizer.yaml, DATABASE_URL, or --dsn)")
		}

		ctx := cmd.Context()
		adapter, err := db.Open(ctx, cfg.Driver, cfg.DSN)
		if err != nil {
			return err
		}
		defer adapter.Close()

		allTables, err := adapter.ListTables(ctx, cfg.Schema)
		if err != nil {
			return err
		}
		if len(allTables) == 0 {
			return fmt.Errorf("no tables found in database")
		}

		if !headless {
			ready, err := promptMaskSelection(cfg, allTables, cmd.Flags().Changed("output"))
			if err != nil {
				return err
			}
			if !ready {
				fmt.Fprintln(errOut, "Aborting anonymization.")
				return nil
			}
			cfg.Normalize()
		}

		tables, err := resolveTables(cfg.Tables, allTables)
		if err != nil {
			return err
		}
		cfg.Tables = tables

		salt, err := cfg.EffectiveSalt()
		if err != nil {
			return err
		}

		var onFindings func(table string, findings []discovery.Finding) (bool, error)
		if !headless {
			onFindings = func(table string, findings []discovery.Finding) (bool, error) {
				var names []string
				for _, f := range findings {
					names = append(names, fmt.Sprintf("%s -> %s (%s)", f.Column, f.Strategy, f.Reason))
				}
				var autoMask bool
				form := huh.NewForm(
					huh.NewGroup(
						huh.NewConfirm().
							Title(fmt.Sprintf("Table '%s': detected %d sensitive column(s):\n  %s\nAuto-mask them?", table, len(findings), strings.Join(names, "\n  "))).
							Affirmative("Yes").
							Negative("No").
							Value(&autoMask),
					),
				)
				if err := form.Run(); err != nil {
					return false, fmt.Errorf("prompt cancelled: %w", err)
				}
				return autoMask, nil
			}
		}

		if foundConfig && !maskFlags.nonInteractive {
			fmt.Fprintln(errOut, "Headless mode active: loaded configuration from YAML")
		}

		report, err := pipeline.Run(ctx, pipeline.Options{
			Adapter:           adapter,
			Schema:            cfg.Schema,
			Tables:            cfg.Tables,
			Format:            cfg.ExportFormat,
			Output:            cfg.Output,
			AutoMask:          cfg.AutoMask,
			Salt:              salt,
			Workers:           cfg.Workers,
			IncludeDDL:        cfg.IncludeDDL,
			ContentSampleSize: cfg.ContentSampleSize,
			Rules:             cfg.Rules,
			ProgressWriter:    errOut,
			OnFindings:        onFindings,
		})
		if err != nil {
			return err
		}

		if strings.TrimSpace(cfg.AuditOutput) != "" {
			if err := report.Write(cfg.AuditOutput); err != nil {
				return fmt.Errorf("write audit report: %w", err)
			}
			fmt.Fprintf(errOut, "Audit report saved to %s\n", cfg.AuditOutput)
		}

		fmt.Fprintf(errOut, "Successfully processed %d total row(s) -> %s\n", report.TotalRows, strings.Join(report.Outputs, ", "))
		return nil
	},
}

func applyMaskFlagOverrides(cmd *cobra.Command, cfg *config.Config) {
	f := cmd.Flags()
	if f.Changed("driver") {
		cfg.Driver = maskFlags.driver
	}
	if f.Changed("dsn") {
		cfg.DSN = maskFlags.dsn
	}
	if f.Changed("schema") {
		cfg.Schema = maskFlags.schema
	}
	if f.Changed("table") {
		parts := strings.Split(maskFlags.table, ",")
		var cleaned []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				cleaned = append(cleaned, p)
			}
		}
		cfg.Tables = cleaned
	}
	if f.Changed("format") {
		cfg.ExportFormat = maskFlags.format
	}
	if f.Changed("output") {
		cfg.Output = maskFlags.output
	}
	if f.Changed("workers") {
		cfg.Workers = maskFlags.workers
	}
	if f.Changed("salt") {
		cfg.Salt = maskFlags.salt
	}
	if f.Changed("auto-mask") {
		cfg.AutoMask = maskFlags.autoMask
	}
	if f.Changed("include-ddl") {
		cfg.IncludeDDL = maskFlags.includeDDL
	}
	if f.Changed("audit") {
		cfg.AuditOutput = maskFlags.auditOutput
	}
}

func resolveTables(requested, available []string) ([]string, error) {
	if len(requested) == 0 {
		return nil, fmt.Errorf("no target tables specified")
	}
	for _, r := range requested {
		if r == "*" {
			return available, nil
		}
	}
	return requested, nil
}

func promptConnection(cfg *config.Config) error {
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Select database driver:").
				Options(
					huh.NewOption("PostgreSQL", "postgres"),
					huh.NewOption("MySQL", "mysql"),
					huh.NewOption("SQLite", "sqlite"),
				).
				Value(&cfg.Driver),
			huh.NewInput().
				Title("Enter database connection string (DSN):").
				Placeholder("postgres://admin:password@localhost:5432/anonymizer_sandbox?sslmode=disable").
				Value(&cfg.DSN),
		),
	)
	if err := form.Run(); err != nil {
		return fmt.Errorf("connection prompt cancelled: %w", err)
	}
	return nil
}

func promptMaskSelection(cfg *config.Config, availableTables []string, outputExplicit bool) (bool, error) {
	opts := make([]huh.Option[string], len(availableTables))
	for i, t := range availableTables {
		opts[i] = huh.NewOption(t, t)
	}

	var selected []string
	var ready bool

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Select target table(s) to anonymize:").
				Options(opts...).
				Value(&selected),
			huh.NewSelect[string]().
				Title("Choose Export Format:").
				Options(
					huh.NewOption("SQL (INSERT statements)", "sql"),
					huh.NewOption("PostgreSQL COPY", "copy"),
					huh.NewOption("CSV", "csv"),
					huh.NewOption("JSONL", "jsonl"),
				).
				Value(&cfg.ExportFormat),
			huh.NewConfirm().
				Title("Include CREATE TABLE DDL statements?").
				Affirmative("Yes").
				Negative("No").
				Value(&cfg.IncludeDDL),
			huh.NewConfirm().
				Title("Are you ready to start streaming anonymization?").
				Affirmative("Yes").
				Negative("No").
				Value(&ready),
		),
	)
	if err := form.Run(); err != nil {
		return false, fmt.Errorf("selection prompt cancelled: %w", err)
	}
	if len(selected) > 0 {
		cfg.Tables = selected
	}
	if !outputExplicit {
		cfg.Output = "" // recompute default filename for selected format unless explicitly overridden
	}
	return ready, nil
}

func init() {
	maskCmd.Flags().StringVarP(&maskFlags.configPath, "config", "c", "", "Path to YAML config file")
	maskCmd.Flags().StringVar(&maskFlags.driver, "driver", "", "Database driver (postgres, mysql, sqlite)")
	maskCmd.Flags().StringVar(&maskFlags.dsn, "dsn", "", "Database connection string (DSN)")
	maskCmd.Flags().StringVar(&maskFlags.schema, "schema", "", "Target schema (default 'public' for postgres)")
	maskCmd.Flags().StringVarP(&maskFlags.table, "table", "t", "", "Comma-separated table names or '*' for all")
	maskCmd.Flags().StringVarP(&maskFlags.format, "format", "f", "sql", "Export format (sql, copy, csv, jsonl)")
	maskCmd.Flags().StringVarP(&maskFlags.output, "output", "o", "", "Output file path (supports .gz) or '-' for stdout")
	maskCmd.Flags().IntVarP(&maskFlags.workers, "workers", "w", 0, "Number of concurrent masking workers")
	maskCmd.Flags().StringVar(&maskFlags.salt, "salt", "", "Secret HMAC salt for deterministic masking")
	maskCmd.Flags().BoolVar(&maskFlags.autoMask, "auto-mask", false, "Automatically mask discovered PII columns")
	maskCmd.Flags().BoolVar(&maskFlags.includeDDL, "include-ddl", false, "Include CREATE TABLE DDL statements in SQL/COPY output")
	maskCmd.Flags().StringVar(&maskFlags.auditOutput, "audit", "", "Write GDPR/KVKK audit report to .json or .md path")
	maskCmd.Flags().BoolVar(&maskFlags.nonInteractive, "non-interactive", false, "Disable interactive terminal prompts")
	rootCmd.AddCommand(maskCmd)
}
