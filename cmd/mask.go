package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var maskCmd = &cobra.Command{
	Use:   "mask",
	Short: "Mask PII in the database and output SQL dump",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Mask command called. Placeholder for streaming and masking logic.")
	},
}

func init() {
	rootCmd.AddCommand(maskCmd)
}
