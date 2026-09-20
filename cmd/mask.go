package cmd

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
	"github.com/spf13/cobra"
)

var maskCmd = &cobra.Command{
	Use:   "mask",
	Short: "Mask PII in the database and output SQL dump",
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

		query := "SELECT id, full_name, email, credit_card, created_at FROM customers"
		rows, err := db.Query(query)
		if err != nil {
			log.Fatalf("Failed to query database: %v", err)
		}
		defer rows.Close()

		file, err := os.Create("anonymized_dump.sql")
		if err != nil {
			log.Fatalf("Failed to create file: %v", err)
		}
		defer file.Close()

		writer := bufio.NewWriter(file)
		defer writer.Flush()

		for rows.Next() {
			var id int
			var fullName, email, creditCard string
			var createdAt time.Time

			if err := rows.Scan(&id, &fullName, &email, &creditCard, &createdAt); err != nil {
				log.Fatalf("Failed to scan row: %v", err)
			}

			// Masking logic
			maskedFullName := fmt.Sprintf("Anon User %d", id)
			maskedEmail := fmt.Sprintf("user_%d@masked.local", id)

			maskedCreditCard := creditCard
			if len(creditCard) >= 4 {
				maskedCreditCard = "****-****-****-" + creditCard[len(creditCard)-4:]
			}

			// Generate INSERT statement
			createdAtStr := createdAt.Format("2006-01-02 15:04:05")
			insertStmt := fmt.Sprintf("INSERT INTO customers (id, full_name, email, credit_card, created_at) VALUES (%d, '%s', '%s', '%s', '%s');\n",
				id, maskedFullName, maskedEmail, maskedCreditCard, createdAtStr)

			_, err = writer.WriteString(insertStmt)
			if err != nil {
				log.Fatalf("Failed to write to file: %v", err)
			}
		}

		if err = rows.Err(); err != nil {
			log.Fatalf("Error iterating rows: %v", err)
		}

		fmt.Println("Successfully masked data and exported to anonymized_dump.sql")
	},
}

func init() {
	rootCmd.AddCommand(maskCmd)
}
