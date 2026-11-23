package discovery

import (
	"testing"

	"github.com/mustafainci067-cell/data-anonymizer/internal/db"
)

func TestIsValidLuhn(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"4111-1111-1111-1111", true},
		{"4111 1111 1111 1111", true},
		{"5500000000000004", true},
		{"4532-0151-1283-0366", true},
		{"4111-1111-1111-1118", false},
		{"0000-0000-0000-0000", false},
		{"123456", false},
		{"4532-0151-1283-036a", false},
		{"", false},
	}

	for _, tc := range tests {
		if got := IsValidLuhn(tc.input); got != tc.want {
			t.Errorf("IsValidLuhn(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestIsValidTCKN(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"10000000146", true},
		{"28475910232", false},
		{"00000000146", false}, // cannot start with 0
		{"10000000156", false}, // wrong 10th digit
		{"10000000147", false}, // wrong 11th digit
		{"1000000014", false},  // wrong length
		{"1000000014a", false}, // non-digit
	}

	for _, tc := range tests {
		if got := IsValidTCKN(tc.input); got != tc.want {
			t.Errorf("IsValidTCKN(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestDiscoverByNameAndContent(t *testing.T) {
	cols := []db.Column{
		{Name: "id", DataType: "INTEGER", IsPrimaryKey: true},
		{Name: "full_name", DataType: "TEXT"},
		{Name: "attr_a", DataType: "TEXT"},
		{Name: "attr_b", DataType: "TEXT"},
		{Name: "attr_c", DataType: "TEXT"},
		{Name: "attr_d", DataType: "TEXT"},
		{Name: "attr_e", DataType: "TEXT"},
		{Name: "attr_f", DataType: "TEXT"},
		{Name: "password_hash", DataType: "TEXT"},
		{Name: "home_address", DataType: "TEXT"},
		{Name: "notes", DataType: "TEXT"},
	}

	samples := [][]any{
		{
			int64(1),
			"Ada Lovelace",
			"ada@example.com",
			"4111-1111-1111-1111",
			"10000000146",
			"TR330006100519786457841326",
			"203.0.113.42",
			"+90 532 123 4567",
			"hash1",
			"123 Main St",
			"Regular order note",
		},
		{
			int64(2),
			"Alan Turing",
			"alan@example.org",
			"5500-0000-0000-0004",
			"10000000146",
			"DE89370400440532013000",
			"198.51.100.9",
			"+1-555-234-5678",
			"hash2",
			"456 Oak Ave",
			"alan@example.org", // only 1 out of 3 is email -> <50%
		},
		{
			int64(3),
			"Grace Hopper",
			"grace@example.net",
			"4532-0151-1283-0366",
			"10000000146",
			"TR330006100519786457841326",
			"192.0.2.55",
			"+44 20 7946 0958",
			"hash3",
			"789 Pine Rd",
			"Another non-PII note",
		},
	}

	findings := Discover("customers", cols, samples)
	got := make(map[string]Finding)
	for _, f := range findings {
		got[f.Column] = f
	}

	expectations := map[string]struct {
		strategy string
		reason   string
	}{
		"full_name":     {"fake_name", "column_name"},
		"attr_a":        {"fake_email", "content:email"},
		"attr_b":        {"credit_card", "content:credit_card_luhn"},
		"attr_c":        {"tckn", "content:tckn"},
		"attr_d":        {"iban", "content:iban"},
		"attr_e":        {"ip", "content:ipv4"},
		"attr_f":        {"fake_phone", "content:phone"},
		"password_hash": {"password", "column_name"},
		"home_address":  {"address", "column_name"},
	}

	for col, exp := range expectations {
		f, ok := got[col]
		if !ok {
			t.Errorf("expected finding for column %q, got none", col)
			continue
		}
		if f.Strategy != exp.strategy || f.Reason != exp.reason {
			t.Errorf("column %q: got (%s, %s), want (%s, %s)", col, f.Strategy, f.Reason, exp.strategy, exp.reason)
		}
	}

	if _, ok := got["id"]; ok {
		t.Error("did not expect PII finding for id column")
	}
	if _, ok := got["notes"]; ok {
		t.Error("did not expect PII finding for notes column (<50% match threshold)")
	}
}
