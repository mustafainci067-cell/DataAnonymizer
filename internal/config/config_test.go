package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultsWithoutFile(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("ANONYMIZER_DSN", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("ANONYMIZER_SALT", "")

	cfg, found, err := Load("")
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected found=false when anonymizer.yaml does not exist")
	}
	if cfg.Driver != "postgres" {
		t.Errorf("expected default driver postgres, got %q", cfg.Driver)
	}
	if cfg.Schema != "public" {
		t.Errorf("expected default schema public, got %q", cfg.Schema)
	}
	if cfg.ExportFormat != "sql" {
		t.Errorf("expected default export_format sql, got %q", cfg.ExportFormat)
	}
	if cfg.Output != "anonymized_dump.sql" {
		t.Errorf("expected default output anonymized_dump.sql, got %q", cfg.Output)
	}
	if cfg.ContentSampleSize != 100 {
		t.Errorf("expected default content_sample_size 100, got %d", cfg.ContentSampleSize)
	}
	if cfg.Workers < 1 {
		t.Errorf("expected workers >= 1, got %d", cfg.Workers)
	}
}

func TestLoadYAMLAndResolveRules(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "custom.yaml")
	yamlBody := `
driver: sqlite3
db_conn: ./app.db
target_table: customers
export_format: JSONL
output: out.jsonl.gz
auto_mask: true
include_ddl: true
workers: 4
salt: super-secret-salt
content_sample_size: 0
audit_output: audit.md
rules:
  customers:
    email: fake_email
    salary: keep
  "*":
    notes: redact
`
	if err := os.WriteFile(cfgFile, []byte(yamlBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, found, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if !found {
		t.Fatal("expected found=true")
	}
	if cfg.Driver != "sqlite" {
		t.Errorf("expected normalized driver sqlite, got %q", cfg.Driver)
	}
	if cfg.Schema != "" {
		t.Errorf("expected empty schema for sqlite, got %q", cfg.Schema)
	}
	if len(cfg.Tables) != 1 || cfg.Tables[0] != "customers" {
		t.Errorf("expected backward-compatible tables=[customers], got %v", cfg.Tables)
	}
	if cfg.ExportFormat != "jsonl" {
		t.Errorf("expected jsonl format, got %q", cfg.ExportFormat)
	}
	if cfg.ContentSampleSize != 0 {
		t.Errorf("expected content_sample_size=0 to be preserved, got %d", cfg.ContentSampleSize)
	}
	if strat, ok := cfg.ResolveRule("customers", "EMAIL"); !ok || strat != "fake_email" {
		t.Errorf("expected exact rule fake_email, got %q (%v)", strat, ok)
	}
	if strat, ok := cfg.ResolveRule("orders", "notes"); !ok || strat != "redact" {
		t.Errorf("expected wildcard rule redact, got %q (%v)", strat, ok)
	}
	if _, ok := cfg.ResolveRule("orders", "unknown"); ok {
		t.Error("expected no rule for orders.unknown")
	}
}

func TestEnvFallbacksAndEffectiveSalt(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("ANONYMIZER_DSN", "")
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
	t.Setenv("ANONYMIZER_SALT", "")

	cfg, _, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.DSN != "postgres://user:pass@localhost:5432/db" {
		t.Errorf("expected DATABASE_URL fallback, got %q", cfg.DSN)
	}

	salt1, err := cfg.EffectiveSalt()
	if err != nil {
		t.Fatalf("EffectiveSalt failed: %v", err)
	}
	if len(salt1) != 64 {
		t.Errorf("expected 64-char hex salt, got len %d", len(salt1))
	}
	salt2, err := cfg.EffectiveSalt()
	if err != nil {
		t.Fatalf("second EffectiveSalt failed: %v", err)
	}
	if salt1 != salt2 {
		t.Errorf("expected EffectiveSalt to remain stable on same config instance")
	}
}
