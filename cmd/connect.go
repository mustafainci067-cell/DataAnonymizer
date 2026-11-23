package cmd

import (
	"fmt"
	"strings"

	"github.com/mustafainci067-cell/data-anonymizer/internal/config"
	"github.com/mustafainci067-cell/data-anonymizer/internal/db"
	"github.com/spf13/cobra"
)

var connectFlags struct {
	configPath string
	driver     string
	dsn        string
	schema     string
	table      string
}

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Test database connection and inspect tables and schemas",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _, err := config.Load(connectFlags.configPath)
		if err != nil {
			return err
		}

		if cmd.Flags().Changed("driver") {
			cfg.Driver = connectFlags.driver
		}
		if cmd.Flags().Changed("dsn") {
			cfg.DSN = connectFlags.dsn
		}
		if cmd.Flags().Changed("schema") {
			cfg.Schema = connectFlags.schema
		}
		cfg.Normalize()

		if cfg.DSN == "" {
			return fmt.Errorf("database DSN is required (set db_conn in anonymizer.yaml, DATABASE_URL, or --dsn)")
		}

		ctx := cmd.Context()
		adapter, err := db.Open(ctx, cfg.Driver, cfg.DSN)
		if err != nil {
			return err
		}
		defer adapter.Close()

		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "Successfully connected to %s database!\n", adapter.DriverName())

		var targetTables []string
		if strings.TrimSpace(connectFlags.table) != "" {
			targetTables = []string{strings.TrimSpace(connectFlags.table)}
		} else {
			tables, err := adapter.ListTables(ctx, cfg.Schema)
			if err != nil {
				return err
			}
			targetTables = tables
			fmt.Fprintf(out, "\nDiscovered %d table(s): %s\n", len(tables), strings.Join(tables, ", "))
		}

		for _, tbl := range targetTables {
			cols, err := adapter.ListColumns(ctx, cfg.Schema, tbl)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "\nSchema for '%s':\n", tbl)
			fmt.Fprintln(out, "--------------------------------------------------------------------------")
			fmt.Fprintf(out, "%-22s | %-24s | %-8s | %-5s\n", "Column Name", "Data Type", "Nullable", "PK")
			fmt.Fprintln(out, "--------------------------------------------------------------------------")
			for _, col := range cols {
				fmt.Fprintf(out, "%-22s | %-24s | %-8t | %-5t\n", col.Name, col.DataType, col.IsNullable, col.IsPrimaryKey)
			}
			fmt.Fprintln(out, "--------------------------------------------------------------------------")
		}
		return nil
	},
}

func init() {
	connectCmd.Flags().StringVarP(&connectFlags.configPath, "config", "c", "", "Path to YAML config file")
	connectCmd.Flags().StringVar(&connectFlags.driver, "driver", "", "Database driver (postgres, mysql, sqlite)")
	connectCmd.Flags().StringVar(&connectFlags.dsn, "dsn", "", "Database connection string (DSN)")
	connectCmd.Flags().StringVar(&connectFlags.schema, "schema", "", "Target schema (default 'public' for postgres)")
	connectCmd.Flags().StringVarP(&connectFlags.table, "table", "t", "", "Inspect a specific table (defaults to all tables)")
	rootCmd.AddCommand(connectCmd)
}
