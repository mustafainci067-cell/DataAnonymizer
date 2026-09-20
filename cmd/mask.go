package cmd

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/huh"
	_ "github.com/lib/pq"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var maskCmd = &cobra.Command{
	Use:   "mask",
	Short: "Mask PII in the database and output SQL dump",
	Run: func(cmd *cobra.Command, args []string) {
		var targetTable string
		var exportFormat string
		var ready bool
		headless := false
		autoMaskYAML := false

		viper.SetConfigName("anonymizer")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")

		if err := viper.ReadInConfig(); err == nil {
			headless = true
			targetTable = viper.GetString("target_table")
			exportFormat = viper.GetString("export_format")
			if exportFormat == "" {
				exportFormat = "SQL"
			}
			autoMaskYAML = viper.GetBool("auto_mask")
			ready = true
			fmt.Println("Headless mode active: reading from anonymizer.yaml")
		} else {
			exportFormat = "SQL" // default
			form := huh.NewForm(
				huh.NewGroup(
					huh.NewSelect[string]().
						Title("Choose the target table to mask:").
						Options(
							huh.NewOption("customers", "customers"),
						).
						Value(&targetTable),
					huh.NewSelect[string]().
						Title("Choose Export Format:").
						Options(
							huh.NewOption("SQL", "SQL"),
							huh.NewOption("CSV", "CSV"),
							huh.NewOption("JSONL", "JSONL"),
						).
						Value(&exportFormat),
					huh.NewConfirm().
						Title("Are you ready to start the O(1) streaming anonymization process?").
						Affirmative("Yes").
						Negative("No").
						Value(&ready),
				),
			)

			if err := form.Run(); err != nil {
				fmt.Println("\nProcess cancelled.")
				os.Exit(0)
			}
		}

		if !ready {
			fmt.Println("Aborting process.")
			return
		}

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

		// Auto-Discovery of Columns
		colQuery := fmt.Sprintf("SELECT column_name FROM information_schema.columns WHERE table_name = '%s'", targetTable)
		colRows, err := db.Query(colQuery)
		if err != nil {
			log.Fatalf("Failed to query information_schema: %v", err)
		}
		defer colRows.Close()

		var columns []string
		var sensitiveCols []string

		piiRegex := regexp.MustCompile(`(?i)name|email|card|phone|tc|password`)

		for colRows.Next() {
			var colName string
			if err := colRows.Scan(&colName); err != nil {
				log.Fatalf("Failed to scan column name: %v", err)
			}
			columns = append(columns, colName)
			if piiRegex.MatchString(colName) {
				sensitiveCols = append(sensitiveCols, colName)
			}
		}

		maskingRules := make(map[string]bool)
		for _, col := range sensitiveCols {
			maskingRules[col] = true
		}

		if len(sensitiveCols) > 0 {
			var autoMask bool

			if headless {
				autoMask = autoMaskYAML
			} else {
				promptText := fmt.Sprintf("Detected %d sensitive columns: %v. Do you want to auto-mask them?", len(sensitiveCols), sensitiveCols)

				confirmForm := huh.NewForm(
					huh.NewGroup(
						huh.NewConfirm().
							Title(promptText).
							Affirmative("Yes").
							Negative("No").
							Value(&autoMask),
					),
				)
				if err := confirmForm.Run(); err != nil {
					fmt.Println("\nProcess cancelled.")
					os.Exit(0)
				}
			}

			if !autoMask {
				// clear rules if user says no
				maskingRules = make(map[string]bool)
			}
		}

		query := fmt.Sprintf("SELECT %s FROM %s", strings.Join(columns, ", "), targetTable)
		rows, err := db.Query(query)
		if err != nil {
			log.Fatalf("Failed to query database: %v", err)
		}
		defer rows.Close()

		fileExt := strings.ToLower(exportFormat)
		if fileExt == "jsonl" || fileExt == "csv" {
			// already set
		} else {
			fileExt = "sql"
		}
		fileName := fmt.Sprintf("anonymized_dump.%s", fileExt)

		file, err := os.Create(fileName)
		if err != nil {
			log.Fatalf("Failed to create file: %v", err)
		}
		defer file.Close()

		writer := bufio.NewWriter(file)
		defer writer.Flush()

		// For formatting generic inserts and CSV headers
		colNamesStr := strings.Join(columns, ", ")

		if fileExt == "csv" {
			writer.WriteString(colNamesStr + "\n")
		}

		jobs := make(chan []interface{}, 100)
		results := make(chan string, 100)

		var workerWg sync.WaitGroup
		var writerWg sync.WaitGroup

		// Spawn writer goroutine
		writerWg.Add(1)
		go func() {
			defer writerWg.Done()
			for res := range results {
				if _, err := writer.WriteString(res); err != nil {
					log.Fatalf("Failed to write to file: %v", err)
				}
			}
		}()

		// Spawn worker goroutines
		numWorkers := 50
		for w := 0; w < numWorkers; w++ {
			workerWg.Add(1)
			go func() {
				defer workerWg.Done()
				for values := range jobs {
					var sqlStrValues []string
					var csvStrValues []string
					jsonRow := make(map[string]interface{})
					var rowIdStr string

					// Try to find the id column for deterministic masking
					for i, col := range columns {
						if strings.ToLower(col) == "id" {
							if val, ok := values[i].(int64); ok {
								rowIdStr = fmt.Sprintf("%d", val)
							} else if val, ok := values[i].(string); ok {
								rowIdStr = val
							}
						}
					}
					if rowIdStr == "" {
						rowIdStr = "X"
					}

					for i, col := range columns {
						val := values[i]

						var strVal string
						if val != nil {
							switch v := val.(type) {
							case string:
								strVal = v
							case time.Time:
								strVal = v.Format("2006-01-02 15:04:05")
							default:
								strVal = fmt.Sprintf("%v", v)
							}

							// Apply masking if rule exists
							if maskingRules[col] {
								lowerCol := strings.ToLower(col)
								if strings.Contains(lowerCol, "name") {
									strVal = "Anon User " + rowIdStr
								} else if strings.Contains(lowerCol, "email") {
									strVal = "user_" + rowIdStr + "@masked.local"
								} else if strings.Contains(lowerCol, "card") {
									if len(strVal) >= 4 {
										strVal = "****-****-****-" + strVal[len(strVal)-4:]
									} else {
										strVal = "****-****-****-0000"
									}
								} else if strings.Contains(lowerCol, "phone") {
									strVal = "555-0100"
								} else if strings.Contains(lowerCol, "password") {
									strVal = "*****"
								} else {
									strVal = "MASKED"
								}
							}
						}

						if fileExt == "jsonl" {
							if val == nil {
								jsonRow[col] = nil
							} else {
								jsonRow[col] = strVal
							}
						} else if fileExt == "csv" {
							if val == nil {
								csvStrValues = append(csvStrValues, "")
							} else {
								escaped := strVal
								if strings.Contains(escaped, ",") || strings.Contains(escaped, "\"") || strings.Contains(escaped, "\n") {
									escaped = "\"" + strings.ReplaceAll(escaped, "\"", "\"\"") + "\""
								}
								csvStrValues = append(csvStrValues, escaped)
							}
						} else {
							if val == nil {
								sqlStrValues = append(sqlStrValues, "NULL")
							} else {
								escaped := fmt.Sprintf("'%s'", strings.ReplaceAll(strVal, "'", "''"))
								sqlStrValues = append(sqlStrValues, escaped)
							}
						}
					}

					var resultStr string
					if fileExt == "jsonl" {
						jsonData, _ := json.Marshal(jsonRow)
						resultStr = string(jsonData) + "\n"
					} else if fileExt == "csv" {
						resultStr = strings.Join(csvStrValues, ",") + "\n"
					} else {
						resultStr = fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s);\n", targetTable, colNamesStr, strings.Join(sqlStrValues, ", "))
					}
					results <- resultStr
				}
			}()
		}

		for rows.Next() {
			// Create a slice of interface{} to hold generic values
			values := make([]interface{}, len(columns))
			valuePtrs := make([]interface{}, len(columns))
			for i := range columns {
				valuePtrs[i] = &values[i]
			}

			if err := rows.Scan(valuePtrs...); err != nil {
				log.Fatalf("Failed to scan row: %v", err)
			}

			// Safely copy values to avoid race conditions with driver's underlying byte array reuse
			safeValues := make([]interface{}, len(columns))
			for i, val := range values {
				if val == nil {
					safeValues[i] = nil
				} else {
					switch v := val.(type) {
					case []byte:
						safeValues[i] = string(v)
					default:
						safeValues[i] = v
					}
				}
			}

			jobs <- safeValues
		}

		close(jobs)
		workerWg.Wait()
		close(results)
		writerWg.Wait()

		if err = rows.Err(); err != nil {
			log.Fatalf("Error iterating rows: %v", err)
		}

		fmt.Printf("Successfully processed data and exported to %s\n", fileName)
	},
}

func init() {
	rootCmd.AddCommand(maskCmd)
}
