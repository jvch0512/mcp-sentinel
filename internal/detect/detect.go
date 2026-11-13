// Package detect holds the content checks: tool poisoning, prompt injection, secrets, path escapes and SSRF.
package detect

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Severity int

const (
	Low Severity = iota + 1
	Medium
	High
)

func (s Severity) String() string { return [...]string{"", "low", "medium", "high"}[s] }

type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"-"`
	Sev      string   `json:"severity"`
	Detail   string   `json:"detail"`
}

func finding(rule string, s Severity, detail string) Finding {
	return Finding{Rule: rule, Severity: s, Sev: s.String(), Detail: detail}
}

type injRule struct {
	name string
	sev  Severity
	re   *regexp.Regexp
	why  string
}

func ir(name string, sev Severity, why, pat string) injRule {
	return injRule{name, sev, regexp.MustCompile("(?is)" + pat), why}
}

var injection = []injRule{
	ir("override-instructions", High, "tries to override earlier instructions", `ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier)\s+(instructions|prompts?|rules)|disregard\s+(all\s+)?(previous|prior)\s+(instructions|rules)`),
	ir("hidden-tag", High, "uses an instruction-style tag that models may follow", `<\s*(important|system|instructions?|admin)\s*>|\[\s*system\s*\]`),
	ir("conceal-from-user", High, "asks the model to hide something from the user", `(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|show|let)\s+(this\s+)?(to\s+)?(the\s+)?user|without\s+(telling|informing|notifying)\s+the\s+user|user\s+(must|should)\s+not\s+(see|know)`),
	ir("sensitive-file-access", Medium, "references credential or key files", `(~|\$HOME|/home/\w+|/root)?/?\.ssh/|id_rsa|id_ed25519|\.aws/credentials|/etc/passwd|/etc/shadow|\.env\b|\.npmrc|\.netrc|keychain|wallet\.dat`),
	ir("exfiltrate", High, "asks for data to be sent elsewhere", `(send|post|upload|forward|exfiltrate|leak|email)\s+.{0,80}(to|via)\s+(https?://|[\w.-]+@[\w.-]+)`),
	ir("forced-tool-use", Medium, "tells the model to call other tools first", `(you\s+)?(must|should|need\s+to|have\s+to)\s+(first|always)?\s*(call|use|run|invoke|read)\s+(the\s+)?\w+`),
	ir("before-using", Medium, "adds conditions before the tool can be used", `before\s+(using|calling|invoking)\s+this\s+tool`),
	ir("role-hijack", Medium, "tries to assign the model a new role", `you\s+are\s+now\s+|act\s+as\s+(an?\s+)?(admin|root|developer|system)|new\s+instructions\s*:`),
	ir("markdown-exfil", Medium, "image or link that carries data in its URL", `!\[[^\]]*\]\(https?://[^)\s]*[?&](d|q|data|payload|x|s)=[^)\s]+\)`),
}

var base64Blob = regexp.MustCompile(`[A-Za-z0-9+/]{240,}={0,2}`)

// Injection scans free text (a tool description, a schema description or a tool result).
func Injection(text string) []Finding {
	var out []Finding
	for _, r := range injection {
		if loc := r.re.FindStringIndex(text); loc != nil {
			out = append(out, finding(r.name, r.sev, fmt.Sprintf("%s: %q", r.why, snippet(text, loc))))
		}
	}
	if n := countInvisible(text); n > 0 {
		out = append(out, finding("invisible-characters", High, fmt.Sprintf("%d zero-width or tag characters that a person cannot see", n)))
	}
	if loc := base64Blob.FindStringIndex(text); loc != nil {
		out = append(out, finding("encoded-blob", Medium, "long base64-looking blob that could hide instructions"))
	}
	return out
}

func snippet(s string, loc []int) string {
	a, b := loc[0], loc[1]
	if b-a > 70 {
		b = a + 70
	}
	return strings.Join(strings.Fields(s[a:b]), " ")
}

func countInvisible(s string) int {
	n := 0
	for _, r := range s {
		switch {
		case r >= 0x200B && r <= 0x200F, r >= 0x202A && r <= 0x202E, r >= 0x2060 && r <= 0x2064, r == 0xFEFF, r >= 0xE0000 && r <= 0xE007F:
			n++
		}
	}
	return n
}

// Blocking reports whether findings are serious enough to block: any high, or two or more medium.
func Blocking(fs []Finding) bool {
	med := 0
	for _, f := range fs {
		if f.Severity == High {
			return true
		}
		if f.Severity == Medium {
			med++
		}
	}
	return med >= 2
}

// Rules lists the rule names.
func Rules(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Rule)
	}
	return out
}

type secretRule struct {
	name string
	re   *regexp.Regexp
	repl string // replacement template; the default replaces the whole match
}

var secrets = []secretRule{
	{name: "aws-access-key", re: regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{name: "github-token", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	{name: "private-key", re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----(?s:.*?)(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)`)},
	{name: "jwt", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{name: "slack-token", re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{name: "api-key", re: regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`)},
	{name: "assigned-secret", re: regexp.MustCompile(`(?i)((?:api[_-]?key|secret|password|passwd|token|access[_-]?key)["']?\s*[:=]\s*["']?)[A-Za-z0-9/+_\-.]{12,}`), repl: "${1}[REDACTED:assigned-secret]"},
}

// Secrets lists secret-looking values in text.
func Secrets(text string) []Finding {
	var out []Finding
	for _, r := range secrets {
		if r.re.MatchString(text) {
			out = append(out, finding(r.name, High, "value that looks like a "+strings.ReplaceAll(r.name, "-", " ")))
		}
	}
	return out
}

// Redact replaces secret-looking values and returns the new text and the rules that fired.
func Redact(text string) (string, []string) {
	var hit []string
	for _, r := range secrets {
		if r.re.MatchString(text) {
			hit = append(hit, r.name)
			repl := r.repl
			if repl == "" {
				repl = "[REDACTED:" + r.name + "]"
			}
			text = r.re.ReplaceAllString(text, repl)
		}
	}
	return text, hit
}

// StringValue is a string found inside a JSON document together with its path.
type StringValue struct{ Path, Value string }

// Strings returns every string in a JSON value, with its dotted path.
func Strings(raw json.RawMessage) []StringValue {
	var v any
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil {
		return nil
	}
	var out []StringValue
	var walk func(p string, v any)
	walk = func(p string, v any) {
		switch t := v.(type) {
		case string:
			out = append(out, StringValue{p, t})
		case []any:
			for i, x := range t {
				walk(p+"["+strconv.Itoa(i)+"]", x)
			}
		case map[string]any:
			for k, x := range t {
				if p != "" {
					walk(p+"."+k, x)
				} else {
					walk(k, x)
				}
			}
		}
	}
	walk("", v)
	return out
}

// PathOutside reports why a path argument falls outside the allowed roots ("" if it is fine).
func PathOutside(value string, roots []string) string {
	p := value
	if strings.HasPrefix(strings.ToLower(p), "file://") {
		p = p[len("file://"):]
	}
	if dec, err := url.PathUnescape(p); err == nil {
		p = dec
	}
	if strings.ContainsRune(p, 0) {
		return "contains a NUL byte"
	}
	if strings.HasPrefix(p, "~") {
		return "refers to a home directory"
	}
	clean := filepath.Clean(p)
	for _, root := range roots {
		root = filepath.Clean(root)
		abs := clean
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(root, clean)
		}
		rel, err := filepath.Rel(root, abs)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return ""
		}
	}
	return fmt.Sprintf("%q is outside the allowed folders", clean)
}

// PrivateURL reports why a URL points at an internal address ("" if it looks public).
func PrivateURL(value string) string {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.Host == "" {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "ftp", "gopher":
	default:
		return ""
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".local") || host == "metadata.google.internal" {
		return "host " + host + " is internal"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if n, err := strconv.ParseUint(host, 0, 32); err == nil { // 2130706433, 0x7f000001
			ip = net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		}
	}
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsLinkLocalMulticast()) {
		return "address " + ip.String() + " is private or link-local"
	}
	return ""
}
