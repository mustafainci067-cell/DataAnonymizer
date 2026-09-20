package cmd

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
	"github.com/spf13/cobra"
)

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Test connection to the database and inspect schema",
	Run: func(cmd *cobra.Command, args []string) {
		connStr := "host=localhost port=5432 user=admin password=password dbname=anonymizer_sandbox sslmode=disable"
		db, err := sql.Open("postgres", connStr)
		if err != nil {
			log.Fatalf("Failed to connect to database: %v", err)
		}
		defer db.Close()

		err = db.Ping()
		if err != nil {
			log.Fatalf("Failed to ping database: %v", err)
		}
		fmt.Println("Successfully connected to the database!")

		query := "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'customers';"
		rows, err := db.Query(query)
		if err != nil {
			log.Fatalf("Failed to query schema: %v", err)
		}
		defer rows.Close()

		fmt.Println("\nSchema for 'customers' table:")
		fmt.Println("--------------------------------------------------")
		fmt.Printf("%-20s | %-20s\n", "Column Name", "Data Type")
		fmt.Println("--------------------------------------------------")

		for rows.Next() {
			var colName, dataType string
			if err := rows.Scan(&colName, &dataType); err != nil {
				log.Fatalf("Failed to scan row: %v", err)
			}
			fmt.Printf("%-20s | %-20s\n", colName, dataType)
		}

		if err = rows.Err(); err != nil {
			log.Fatalf("Error iterating rows: %v", err)
		}
		fmt.Println("--------------------------------------------------")
	},
}

func init() {
	rootCmd.AddCommand(connectCmd)
}
