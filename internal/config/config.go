package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/viper"
)

// Config holds runtime configuration loaded from YAML, environment variables, and CLI flags.
type Config struct {
	Driver            string                       `mapstructure:"driver"`
	DSN               string                       `mapstructure:"db_conn"`
	Schema            string                       `mapstructure:"schema"`
	TargetTable       string                       `mapstructure:"target_table"`
	Tables            []string                     `mapstructure:"tables"`
	ExportFormat      string                       `mapstructure:"export_format"`
	Output            string                       `mapstructure:"output"`
	AutoMask          bool                         `mapstructure:"auto_mask"`
	Salt              string                       `mapstructure:"salt"`
	Workers           int                          `mapstructure:"workers"`
	IncludeDDL        bool                         `mapstructure:"include_ddl"`
	AuditOutput       string                       `mapstructure:"audit_output"`
	ContentSampleSize int                          `mapstructure:"content_sample_size"`
	Rules             map[string]map[string]string `mapstructure:"rules"`
}

// Load reads configuration from configPath (or ./anonymizer.yaml when empty),
// applies defaults and environment fallbacks, and reports whether a config file was loaded.
func Load(configPath string) (*Config, bool, error) {
	v := viper.New()
	v.SetDefault("driver", "postgres")
	v.SetDefault("export_format", "sql")
	v.SetDefault("workers", defaultWorkers())
	v.SetDefault("content_sample_size", 100)

	found := false
	if strings.TrimSpace(configPath) != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return nil, false, fmt.Errorf("read config %q: %w", configPath, err)
		}
		found = true
	} else {
		v.SetConfigName("anonymizer")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		if err := v.ReadInConfig(); err != nil {
			var notFound viper.ConfigFileNotFoundError
			if !errors.As(err, &notFound) {
				return nil, false, fmt.Errorf("read anonymizer.yaml: %w", err)
			}
		} else {
			found = true
		}
	}

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, found, fmt.Errorf("decode config: %w", err)
	}

	if cfg.DSN == "" {
		if env := os.Getenv("ANONYMIZER_DSN"); env != "" {
			cfg.DSN = env
		} else if env := os.Getenv("DATABASE_URL"); env != "" {
			cfg.DSN = env
		}
	}
	if cfg.Salt == "" {
		if env := os.Getenv("ANONYMIZER_SALT"); env != "" {
			cfg.Salt = env
		}
	}

	cfg.Normalize()
	return cfg, found, nil
}

// Normalize standardizes driver names, formats, table lists, schema defaults, and worker counts.
func (c *Config) Normalize() {
	c.Driver = NormalizeDriver(c.Driver)
	if c.Schema == "" && c.Driver == "postgres" {
		c.Schema = "public"
	}

	if len(c.Tables) == 0 && strings.TrimSpace(c.TargetTable) != "" {
		c.Tables = []string{strings.TrimSpace(c.TargetTable)}
	} else if len(c.Tables) > 0 {
		cleaned := make([]string, 0, len(c.Tables))
		for _, t := range c.Tables {
			t = strings.TrimSpace(t)
			if t != "" {
				cleaned = append(cleaned, t)
			}
		}
		c.Tables = cleaned
	}

	c.ExportFormat = strings.ToLower(strings.TrimSpace(c.ExportFormat))
	if c.ExportFormat == "" {
		c.ExportFormat = "sql"
	}

	if c.Workers <= 0 {
		c.Workers = defaultWorkers()
	}
	if c.ContentSampleSize < 0 {
		c.ContentSampleSize = 0
	}
	if strings.TrimSpace(c.Output) == "" {
		c.Output = DefaultOutputFilename(c.ExportFormat)
	}
}

// EffectiveSalt returns the configured salt or generates and caches a random 32-byte hex salt.
func (c *Config) EffectiveSalt() (string, error) {
	if c.Salt != "" {
		return c.Salt, nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate ephemeral salt: %w", err)
	}
	c.Salt = hex.EncodeToString(buf)
	return c.Salt, nil
}

// ResolveRule returns an explicit masking strategy for table and column,
// checking exact table matches before the "*" wildcard table (case-insensitive).
func (c *Config) ResolveRule(table, column string) (string, bool) {
	if len(c.Rules) == 0 {
		return "", false
	}
	if strat, ok := lookupColumnRule(c.Rules, table, column); ok {
		return strat, true
	}
	return lookupColumnRule(c.Rules, "*", column)
}

func lookupColumnRule(rules map[string]map[string]string, targetTable, targetCol string) (string, bool) {
	for tbl, cols := range rules {
		if !strings.EqualFold(tbl, targetTable) {
			continue
		}
		for col, strat := range cols {
			if strings.EqualFold(col, targetCol) && strings.TrimSpace(strat) != "" {
				return strings.ToLower(strings.TrimSpace(strat)), true
			}
		}
	}
	return "", false
}

// NormalizeDriver canonicalizes supported database driver aliases.
func NormalizeDriver(driver string) string {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "", "postgres", "postgresql", "pgx":
		return "postgres"
	case "mysql":
		return "mysql"
	case "sqlite", "sqlite3":
		return "sqlite"
	default:
		return strings.ToLower(strings.TrimSpace(driver))
	}
}

// DefaultOutputFilename returns the default output filename for a given export format.
func DefaultOutputFilename(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "csv":
		return "anonymized_dump.csv"
	case "jsonl":
		return "anonymized_dump.jsonl"
	case "sql", "copy", "":
		return "anonymized_dump.sql"
	default:
		return "anonymized_dump.sql"
	}
}

func defaultWorkers() int {
	n := runtime.NumCPU()
	if n < 1 {
		return 1
	}
	return n
}
