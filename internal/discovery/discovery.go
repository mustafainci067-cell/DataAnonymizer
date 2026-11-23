package discovery

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/mustafainci067-cell/data-anonymizer/internal/db"
)

// Finding describes a detected PII column and the recommended masking strategy.
type Finding struct {
	Table    string
	Column   string
	Strategy string
	Reason   string
}

type nameRule struct {
	pattern  *regexp.Regexp
	strategy string
}

var nameRules = []nameRule{
	{regexp.MustCompile(`(?i)(email|e_mail|\bmail\b)`), "fake_email"},
	{regexp.MustCompile(`(?i)(credit_card|cc_num|\bpan\b|card)`), "credit_card"},
	{regexp.MustCompile(`(?i)\biban\b`), "iban"},
	{regexp.MustCompile(`(?i)(tckn|tc_no|tc_kimlik|\btc\b|\bssn\b|national_id)`), "tckn"},
	{regexp.MustCompile(`(?i)(phone|mobile|\btel\b|\bgsm\b)`), "fake_phone"},
	{regexp.MustCompile(`(?i)(password|passwd|\bpwd\b|secret|token)`), "password"},
	{regexp.MustCompile(`(?i)(address|street|\baddr\b)`), "address"},
	{regexp.MustCompile(`(?i)(ip_addr|ip_address|client_ip)`), "ip"},
	{regexp.MustCompile(`(?i)(full_name|first_name|last_name|surname|\bname\b)`), "fake_name"},
}

var (
	emailRe = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]{2,}$`)
	ibanRe  = regexp.MustCompile(`^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$`)
	phoneRe = regexp.MustCompile(`^\+?[0-9][0-9\s\-\(\)]{6,18}[0-9]$`)
)

// Discover inspects column names and sampled row contents to identify PII columns.
func Discover(table string, columns []db.Column, samples [][]any) []Finding {
	var findings []Finding
	for colIdx, col := range columns {
		if strat, ok := matchColumnName(col.Name); ok {
			findings = append(findings, Finding{
				Table:    table,
				Column:   col.Name,
				Strategy: strat,
				Reason:   "column_name",
			})
			continue
		}

		if strat, reason, ok := matchColumnContent(samples, colIdx); ok {
			findings = append(findings, Finding{
				Table:    table,
				Column:   col.Name,
				Strategy: strat,
				Reason:   reason,
			})
		}
	}
	return findings
}

func matchColumnName(name string) (string, bool) {
	for _, r := range nameRules {
		if r.pattern.MatchString(name) {
			return r.strategy, true
		}
	}
	return "", false
}

type contentDetector struct {
	strategy string
	reason   string
	match    func(string) bool
}

var contentDetectors = []contentDetector{
	{"fake_email", "content:email", func(s string) bool { return emailRe.MatchString(s) }},
	{"credit_card", "content:credit_card_luhn", IsValidLuhn},
	{"tckn", "content:tckn", IsValidTCKN},
	{"iban", "content:iban", isValidIBANFormat},
	{"ip", "content:ipv4", isValidIPv4},
	{"fake_phone", "content:phone", isLikelyPhone},
}

func matchColumnContent(samples [][]any, colIdx int) (string, string, bool) {
	if len(samples) == 0 {
		return "", "", false
	}

	var values []string
	for _, row := range samples {
		if colIdx >= len(row) || row[colIdx] == nil {
			continue
		}
		var s string
		switch v := row[colIdx].(type) {
		case string:
			s = strings.TrimSpace(v)
		case []byte:
			s = strings.TrimSpace(string(v))
		default:
			continue
		}
		if s != "" {
			values = append(values, s)
		}
	}
	if len(values) == 0 {
		return "", "", false
	}

	for _, det := range contentDetectors {
		hits := 0
		for _, v := range values {
			if det.match(v) {
				hits++
			}
		}
		if hits*2 >= len(values) {
			return det.strategy, det.reason, true
		}
	}
	return "", "", false
}

// IsValidLuhn checks whether s represents a 13-to-19-digit payment card number
// passing the Luhn checksum algorithm (allowing spaces and hyphens).
func IsValidLuhn(s string) bool {
	digits, ok := extractOnlyDigitsAndSeparators(s)
	if !ok || len(digits) < 13 || len(digits) > 19 {
		return false
	}

	allZero := true
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if d != 0 {
			allZero = false
		}
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return !allZero && sum%10 == 0
}

// IsValidTCKN checks whether s is a valid 11-digit Turkish Republic Identity Number
// satisfying the official checksum rules.
func IsValidTCKN(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 11 {
		return false
	}
	var d [11]int
	for i := 0; i < 11; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		d[i] = int(s[i] - '0')
	}
	if d[0] == 0 {
		return false
	}

	oddSum := d[0] + d[2] + d[4] + d[6] + d[8]
	evenSum := d[1] + d[3] + d[5] + d[7]
	tenth := ((oddSum*7-evenSum)%10 + 10) % 10
	if tenth != d[9] {
		return false
	}
	return (oddSum+evenSum+d[9])%10 == d[10]
}

func extractOnlyDigitsAndSeparators(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			b.WriteByte(c)
		} else if c != ' ' && c != '-' {
			return "", false
		}
	}
	return b.String(), b.Len() > 0
}

func isValidIBANFormat(s string) bool {
	cleaned := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	return ibanRe.MatchString(cleaned)
}

func isValidIPv4(s string) bool {
	if !strings.Contains(s, ".") {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && ip.To4() != nil
}

func isLikelyPhone(s string) bool {
	if !phoneRe.MatchString(s) {
		return false
	}
	digitCount := 0
	hasFormatting := strings.HasPrefix(s, "+") || strings.ContainsAny(s, " -()")
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			digitCount++
		}
	}
	if digitCount < 8 || digitCount > 15 {
		return false
	}
	// Require explicit formatting or at least 10 digits to avoid matching short numeric tokens.
	return hasFormatting || digitCount >= 10
}

// FormatSummary formats discovery findings for display if needed.
func FormatSummary(findings []Finding) string {
	if len(findings) == 0 {
		return "no PII columns detected"
	}
	parts := make([]string, len(findings))
	for i, f := range findings {
		parts[i] = fmt.Sprintf("%s (%s via %s)", f.Column, f.Strategy, f.Reason)
	}
	return strings.Join(parts, ", ")
}
