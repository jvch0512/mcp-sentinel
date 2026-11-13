package policy

import (
	"strings"
	"testing"
)

func TestDefaultIsSafe(t *testing.T) {
	p := Default()
	if p.Mode != "enforce" || !p.Results.Redact || !p.Server.BlockSampling || !p.BlockSecretsInArgs || !p.Descriptions.Pin {
		t.Fatalf("defaults must be restrictive: %+v", p)
	}
	if len(p.RulesFor("anything", "url")) != 1 || !p.RulesFor("anything", "url")[0].BlockPrivateURLs {
		t.Fatal("the default rule must block private URLs for every tool")
	}
}

func TestParseOverridesDefaults(t *testing.T) {
	p, err := Parse([]byte(`{"mode":"monitor","tools":{"allow":["read_*"],"deny":["read_secret"]},"rate_limit":{"per_minute":5}}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != "monitor" || p.RateLimit.PerMinute != 5 || !p.Results.Redact {
		t.Fatalf("overrides must keep the other defaults: %+v", p)
	}
	for tool, want := range map[string]bool{"read_file": true, "read_secret": false, "write_file": false} {
		if got, _ := p.ToolAllowed(tool); got != want {
			t.Errorf("%s allowed=%v want %v", tool, got, want)
		}
	}
}

func TestParseRejectsMistakes(t *testing.T) {
	for name, doc := range map[string]string{
		"typo":        `{"mod":"enforce"}`,
		"bad mode":    `{"mode":"strict"}`,
		"bad inj":     `{"results":{"injection":"maybe"}}`,
		"bad regex":   `{"arguments":[{"tool":"*","arg":"*","deny_pattern":"("}]}`,
		"bad glob":    `{"tools":{"allow":["["]}}`,
		"empty rule":  `{"arguments":[{"tool":"","arg":"x"}]}`,
		"negative":    `{"rate_limit":{"per_minute":-1}}`,
		"not json":    `mode: enforce`,
		"extra field": `{"arguments":[{"tool":"*","arg":"*","oops":true}]}`,
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: should be rejected", name)
		}
	}
}

func TestRulesForMatchesGlobs(t *testing.T) {
	p, _ := Parse([]byte(`{"arguments":[{"tool":"read_*","arg":"path","path_roots":["/w"]},{"tool":"*","arg":"*","max_length":10}]}`))
	if n := len(p.RulesFor("read_file", "path")); n != 2 {
		t.Fatalf("want 2 rules, got %d", n)
	}
	if n := len(p.RulesFor("fetch", "path")); n != 1 {
		t.Fatalf("want 1 rule, got %d", n)
	}
	if !strings.Contains(p.Arguments[0].Tool, "read") {
		t.Fatal("rule order must be preserved")
	}
}
