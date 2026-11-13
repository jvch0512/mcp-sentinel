package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"sort"
	"strings"
)

type Count struct {
	Name  string
	Count int
}

type Summary struct {
	Total    int
	Decision map[string]int
	Tools    []Count
	Rules    []Count
	Notable  []Event // everything that was not a plain allow, oldest first
	Monitor  int
}

// Summarise reads a JSONL log. Lines that are not valid events are counted as errors and skipped.
func Summarise(r io.Reader) (*Summary, int, error) {
	s := &Summary{Decision: map[string]int{}}
	tools, rules := map[string]int{}, map[string]int{}
	bad := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil || e.Decision == "" {
			bad++
			continue
		}
		s.Total++
		s.Decision[e.Decision]++
		if e.Monitor {
			s.Monitor++
		}
		if e.Tool != "" {
			tools[e.Tool]++
		}
		for _, ru := range e.Rules {
			rules[ru]++
		}
		if e.Decision != "allow" {
			s.Notable = append(s.Notable, e)
		}
	}
	s.Tools, s.Rules = sorted(tools), sorted(rules)
	return s, bad, sc.Err()
}

func sorted(m map[string]int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Count > out[j].Count || out[i].Count == out[j].Count && out[i].Name < out[j].Name
	})
	return out
}

func esc(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

// Markdown renders the summary.
func (s *Summary) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# MCP Sentinel report\n\n%d events: %d allowed, %d blocked, %d redacted, %d flagged, %d hidden, %d dropped.\n",
		s.Total, s.Decision["allow"], s.Decision["block"], s.Decision["redact"], s.Decision["flag"], s.Decision["hide"], s.Decision["drop"])
	if s.Monitor > 0 {
		fmt.Fprintf(&b, "\n%d decisions were logged in monitor mode and not enforced.\n", s.Monitor)
	}
	b.WriteString("\n## Rules that fired\n\n| Rule | Count |\n|---|---:|\n")
	for _, c := range s.Rules {
		fmt.Fprintf(&b, "| %s | %d |\n", c.Name, c.Count)
	}
	b.WriteString("\n## Tools\n\n| Tool | Events |\n|---|---:|\n")
	for _, c := range s.Tools {
		fmt.Fprintf(&b, "| %s | %d |\n", esc(c.Name), c.Count)
	}
	b.WriteString("\n## Notable events\n\n| Time | Direction | Tool | Decision | Rules | Detail |\n|---|---|---|---|---|---|\n")
	for _, e := range s.Notable {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", e.Time, e.Dir, esc(e.Tool), e.Decision, strings.Join(e.Rules, ", "), esc(e.Detail))
	}
	return b.String()
}

// HTML renders a self-contained page. All values are escaped.
func (s *Summary) HTML() string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><meta charset="utf-8"><title>MCP Sentinel report</title><style>
body{font:15px/1.5 system-ui,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:28px;max-width:1100px;margin:auto}
h1{margin:0 0 4px}h2{margin:28px 0 10px;font-size:17px}.sub{color:#8b98a9;margin-bottom:18px}
.cards{display:flex;gap:12px;flex-wrap:wrap}.card{background:#151b23;border:1px solid #2a3544;border-radius:10px;padding:12px 18px;min-width:120px}
.card b{display:block;font-size:26px}.allow b{color:#3fb950}.block b{color:#f85149}.redact b{color:#d29922}.flag b{color:#d29922}.hide b{color:#f85149}
table{width:100%;border-collapse:collapse;background:#151b23;border:1px solid #2a3544;border-radius:10px;overflow:hidden;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a3544;vertical-align:top}th{color:#8b98a9;font-weight:500}
.tag{border-radius:99px;padding:1px 9px;font-size:12px;border:1px solid #2a3544}.t-block,.t-hide{color:#f85149;border-color:#f85149}.t-redact,.t-flag{color:#d29922;border-color:#d29922}.t-drop{color:#8b98a9}
code{font:13px ui-monospace,monospace;color:#9ecbff}</style><body>`)
	fmt.Fprintf(&b, `<h1>MCP Sentinel report</h1><div class="sub">%d events recorded</div><div class="cards">`, s.Total)
	for _, k := range []string{"allow", "block", "redact", "flag", "hide", "drop"} {
		fmt.Fprintf(&b, `<div class="card %s"><b>%d</b>%s</div>`, k, s.Decision[k], k)
	}
	b.WriteString(`</div><h2>Rules that fired</h2><table><tr><th>Rule</th><th>Count</th></tr>`)
	for _, c := range s.Rules {
		fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td>%d</td></tr>`, html.EscapeString(c.Name), c.Count)
	}
	b.WriteString(`</table><h2>Notable events</h2><table><tr><th>Time</th><th>Direction</th><th>Tool</th><th>Decision</th><th>Rules</th><th>Detail</th></tr>`)
	for _, e := range s.Notable {
		fmt.Fprintf(&b, `<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td><span class="tag t-%s">%s</span></td><td>%s</td><td>%s</td></tr>`,
			html.EscapeString(e.Time), html.EscapeString(e.Dir), html.EscapeString(e.Tool), html.EscapeString(e.Decision), html.EscapeString(e.Decision),
			html.EscapeString(strings.Join(e.Rules, ", ")), html.EscapeString(e.Detail))
	}
	b.WriteString(`</table></body></html>`)
	return b.String()
}
