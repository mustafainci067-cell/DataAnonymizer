package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "data-anonymizer",
	Short: "A GDPR-compliant data anonymization CLI",
	Long:  `Data Anonymizer CLI connects to databases, streams data, masks/hashes PII on the fly, and exports a clean .sql dump.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
