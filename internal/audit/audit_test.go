package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestLoggerWritesOneJSONLinePerEvent(t *testing.T) {
	var b bytes.Buffer
	l := NewLogger(&b)
	l.SetClock(func() time.Time { return time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC) })
	l.Log(Event{Dir: "client>server", Decision: "allow", Tool: "x"})
	l.Log(Event{Dir: "server>client", Decision: "block", Rules: []string{"r"}})
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"time":"2026-11-13T12:00:00Z"`) {
		t.Fatalf("unexpected log: %q", b.String())
	}
	var nilLogger *Logger
	nilLogger.Log(Event{}) // must not panic
}

const sample = `{"time":"t1","dir":"client>server","tool":"read_file","decision":"allow"}
{"time":"t2","dir":"client>server","tool":"fetch_url","decision":"block","rules":["private-url"],"detail":"169.254.169.254 | metadata"}
{"time":"t3","dir":"server>client","tool":"read_file","decision":"redact","rules":["aws-access-key"],"monitor":true}
not json
{"time":"t4","dir":"server>client","tool":"<script>alert(1)</script>","decision":"hide","rules":["hidden-tag","hidden-tag"]}
`

func TestSummarise(t *testing.T) {
	s, bad, err := Summarise(strings.NewReader(sample))
	if err != nil || bad != 1 {
		t.Fatalf("bad=%d err=%v", bad, err)
	}
	if s.Total != 4 || s.Decision["allow"] != 1 || s.Decision["block"] != 1 || s.Decision["redact"] != 1 || s.Decision["hide"] != 1 || s.Monitor != 1 {
		t.Fatalf("%+v", s)
	}
	if len(s.Notable) != 3 || s.Rules[0].Name != "hidden-tag" || s.Rules[0].Count != 2 {
		t.Fatalf("notable=%d rules=%v", len(s.Notable), s.Rules)
	}
}

func TestMarkdownEscapesPipes(t *testing.T) {
	s, _, _ := Summarise(strings.NewReader(sample))
	md := s.Markdown()
	if !strings.Contains(md, `169.254.169.254 \| metadata`) || !strings.Contains(md, "monitor mode") {
		t.Fatalf("%s", md)
	}
}

func TestHTMLEscapesEverything(t *testing.T) {
	s, _, _ := Summarise(strings.NewReader(sample))
	h := s.HTML()
	if strings.Contains(h, "<script>alert") || !strings.Contains(h, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("tool names from a log must be escaped in the report")
	}
}
