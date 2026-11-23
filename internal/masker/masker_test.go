package masker

import (
	"strings"
	"testing"

	"github.com/mustafainci067-cell/data-anonymizer/internal/discovery"
)

func TestMaskerDeterminismAndSalts(t *testing.T) {
	m1 := New("salt-alpha")
	m2 := New("salt-alpha")
	mOther := New("salt-beta")

	strategies := []string{
		"fake_name",
		"fake_email",
		"fake_phone",
		"credit_card",
		"tckn",
		"iban",
		"hmac_hash",
		"address",
		"ip",
	}

	for _, strat := range strategies {
		out1 := m1.Apply(strat, "sensitive-input-42")
		out2 := m2.Apply(strat, "sensitive-input-42")
		outOther := mOther.Apply(strat, "sensitive-input-42")

		if out1 != out2 {
			t.Errorf("strategy %s not deterministic across instances: %v != %v", strat, out1, out2)
		}
		if out1 == outOther {
			t.Errorf("strategy %s produced identical output for different salts: %v", strat, out1)
		}
	}
}

func TestMaskerFormatsAndNilPreservation(t *testing.T) {
	m := New("test-salt-123")

	for _, strat := range []string{"fake_name", "fake_email", "credit_card", "tckn", "iban", "hmac_hash", "keep", "redact"} {
		if got := m.Apply(strat, nil); got != nil {
			t.Errorf("strategy %s did not preserve nil: got %v", strat, got)
		}
	}

	if got := m.Apply("keep", "raw-value"); got != "raw-value" {
		t.Errorf("keep changed value: %v", got)
	}
	if got := m.Apply("nullify", "raw-value"); got != nil {
		t.Errorf("nullify expected nil, got %v", got)
	}
	if got := m.Apply("redact", "raw-value"); got != "[REDACTED]" {
		t.Errorf("redact expected [REDACTED], got %v", got)
	}
	if got := m.Apply("unknown_strategy", "raw-value"); got != "[REDACTED]" {
		t.Errorf("unknown strategy expected [REDACTED], got %v", got)
	}

	cc := m.Apply("credit_card", "4111-1111-1111-1111").(string)
	if !strings.HasPrefix(cc, "****-****-****-") || len(cc) != 19 {
		t.Errorf("unexpected credit_card format: %q", cc)
	}

	tckn := m.Apply("tckn", "10000000146").(string)
	if !discovery.IsValidTCKN(tckn) {
		t.Errorf("masked tckn %q failed checksum validation", tckn)
	}
	if tckn == "10000000146" {
		t.Errorf("masked tckn unexpectedly matched original")
	}

	email := m.Apply("fake_email", "alice@example.com").(string)
	if !strings.HasPrefix(email, "user_") || !strings.HasSuffix(email, "@masked.local") {
		t.Errorf("unexpected fake_email format: %q", email)
	}

	ip := m.Apply("ip", "10.20.30.40").(string)
	if !strings.HasPrefix(ip, "192.0.2.") {
		t.Errorf("expected RFC 5737 TEST-NET-1 IP, got %q", ip)
	}

	iban := m.Apply("iban", "TR330006100519786457841326").(string)
	if !strings.HasPrefix(iban, "TR") || len(iban) != 26 {
		t.Errorf("unexpected masked IBAN: %q", iban)
	}

	h := m.Apply("hmac_hash", "abc").(string)
	if len(h) != 32 {
		t.Errorf("expected 32-char hmac_hash, got len %d (%q)", len(h), h)
	}
}
