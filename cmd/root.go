package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "data-anonymizer",
	Short: "A GDPR/KVKK-compliant streaming data anonymization CLI",
	Long:  `Data Anonymizer CLI connects to PostgreSQL, MySQL, or SQLite databases, detects PII columns, deterministically masks sensitive fields on the fly, and streams clean SQL/COPY/CSV/JSONL dumps.`,
}

// Execute runs the root CLI command with OS signal cancellation handling.
func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
