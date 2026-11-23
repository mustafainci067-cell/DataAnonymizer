package masker

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

var (
	firstNames = []string{
		"Alex", "Deniz", "Jordan", "Emre", "Taylor", "Ece", "Morgan", "Kaan",
		"Casey", "Zeynep", "Riley", "Mert", "Jamie", "Selin", "Quinn", "Arda",
		"Avery", "Defne", "Parker", "Burak", "Skyler", "Elif", "Cameron", "Cem",
		"Reese", "Nehir", "Rowan", "Kerem", "Sage", "Asli", "Hayden", "Yigit",
	}
	lastNames = []string{
		"Mercer", "Yilmaz", "Vance", "Kaya", "Sterling", "Demir", "Hayes", "Celik",
		"Brooks", "Sahin", "Bennett", "Aydin", "Foster", "Ozkan", "Griffin", "Arslan",
		"Coleman", "Dogan", "Wallace", "Kilic", "Reynolds", "Aslan", "Sullivan", "Kurt",
		"Porter", "Koc", "Hunter", "Ozturk", "Spencer", "Aksoy", "Bishop", "Ersoy",
	}
)

// Masker applies deterministic, non-reversible HMAC-SHA256 data masking using a secret salt.
type Masker struct {
	key []byte
}

// New creates a Masker keyed with salt.
func New(salt string) *Masker {
	return &Masker{key: []byte(salt)}
}

// Apply transforms value according to strategy while preserving nil values.
func (m *Masker) Apply(strategy string, value any) any {
	if value == nil {
		return nil
	}

	strat := strings.ToLower(strings.TrimSpace(strategy))
	if strat == "keep" {
		return value
	}
	if strat == "nullify" {
		return nil
	}

	raw := toCanonicalString(value)
	d := m.digest(strat, raw)

	switch strat {
	case "fake_name":
		fn := firstNames[int(binary.BigEndian.Uint16(d[0:2]))%len(firstNames)]
		ln := lastNames[int(binary.BigEndian.Uint16(d[2:4]))%len(lastNames)]
		return fn + " " + ln
	case "fake_email":
		return fmt.Sprintf("user_%s@masked.local", hex.EncodeToString(d[:6]))
	case "fake_phone":
		area := binary.BigEndian.Uint16(d[0:2]) % 1000
		line := binary.BigEndian.Uint16(d[2:4]) % 10000
		return fmt.Sprintf("+1-555-%03d-%04d", area, line)
	case "credit_card":
		last4 := binary.BigEndian.Uint16(d[0:2]) % 10000
		return fmt.Sprintf("****-****-****-%04d", last4)
	case "tckn":
		return deterministicTCKN(d)
	case "iban":
		check := int(d[0]%90) + 10
		acct := binary.BigEndian.Uint64(d[1:9]) % 10000000000000000
		return fmt.Sprintf("TR%02d000610%016d", check, acct)
	case "hmac_hash":
		return hex.EncodeToString(d[:16])
	case "password":
		return "$2a$10$REDACTEDMASKEDPASSWORDHASH000000000000000000000"
	case "address":
		num := int(binary.BigEndian.Uint16(d[0:2])%9900) + 100
		apt := int(d[2]%99) + 1
		return fmt.Sprintf("%d Masked St, Apt %d, Anon City", num, apt)
	case "ip":
		return fmt.Sprintf("192.0.2.%d", int(d[0]%254)+1)
	case "redact":
		return "[REDACTED]"
	default:
		return "[REDACTED]"
	}
}

func (m *Masker) digest(strategy, input string) []byte {
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(strategy))
	mac.Write([]byte{':'})
	mac.Write([]byte(input))
	return mac.Sum(nil)
}

func deterministicTCKN(d []byte) string {
	var digits [11]int
	digits[0] = int(d[0]%9) + 1
	for i := 1; i < 9; i++ {
		digits[i] = int(d[i] % 10)
	}
	oddSum := digits[0] + digits[2] + digits[4] + digits[6] + digits[8]
	evenSum := digits[1] + digits[3] + digits[5] + digits[7]
	digits[9] = ((oddSum*7-evenSum)%10 + 10) % 10
	digits[10] = (oddSum + evenSum + digits[9]) % 10

	var b strings.Builder
	b.Grow(11)
	for _, dig := range digits {
		b.WriteByte(byte('0' + dig))
	}
	return b.String()
}

func toCanonicalString(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case []byte:
		return string(val)
	case time.Time:
		return val.UTC().Format(time.RFC3339Nano)
	default:
		return fmt.Sprintf("%v", val)
	}
}
