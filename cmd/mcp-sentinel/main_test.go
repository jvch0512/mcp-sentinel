package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jvch0512/mcp-sentinel/internal/policy"
	"github.com/jvch0512/mcp-sentinel/internal/rpc"
)

var evil string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sentinel-test")
	if err != nil {
		panic(err)
	}
	evil = filepath.Join(dir, "evil-mcp")
	if out, err := exec.Command("go", "build", "-o", evil, "../evil-mcp").CombinedOutput(); err != nil {
		panic(string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func do(args []string, stdin string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestUsageAndUnknownCommand(t *testing.T) {
	if code, _, e := do(nil, ""); code != 2 || !strings.Contains(e, "mcp-sentinel") {
		t.Fatalf("no args: %d %q", code, e)
	}
	if code, _, _ := do([]string{"frobnicate"}, ""); code != 2 {
		t.Fatalf("unknown command must exit 2, got %d", code)
	}
	if code, out, _ := do([]string{"version"}, ""); code != 0 || strings.TrimSpace(out) != version {
		t.Fatal("version")
	}
}

func TestPolicyCommandPrintsAValidPolicy(t *testing.T) {
	code, out, _ := do([]string{"policy"}, "")
	if code != 0 {
		t.Fatal(code)
	}
	if _, err := policy.Parse([]byte(out)); err != nil {
		t.Fatalf("the printed policy must parse back: %v", err)
	}
}

func TestScanFindsThePoisonedTool(t *testing.T) {
	code, out, _ := do([]string{"scan", "--", evil}, "")
	if code != 1 || !strings.Contains(out, "add") || !strings.Contains(out, "WOULD BLOCK") || !strings.Contains(out, "hidden-tag") {
		t.Fatalf("code=%d\n%s", code, out)
	}
	if !strings.Contains(out, "read_file      ok") {
		t.Fatalf("clean tools must be reported ok:\n%s", out)
	}
}

func TestScanJSON(t *testing.T) {
	code, out, _ := do([]string{"scan", "-json", "--", evil}, "")
	var rep struct {
		Server string
		Tools  []struct {
			Name        string
			Would_block bool `json:"would_block"`
		}
	}
	if code != 1 || json.Unmarshal([]byte(out), &rep) != nil || rep.Server != "evil-mcp" || len(rep.Tools) != 5 {
		t.Fatalf("code=%d %s", code, out)
	}
}

func TestScanErrors(t *testing.T) {
	if code, _, e := do([]string{"scan", "--", "/nonexistent/server"}, ""); code != 2 || e == "" {
		t.Fatalf("a server that cannot start is exit 2: %d %q", code, e)
	}
	if code, _, _ := do([]string{"scan"}, ""); code != 2 {
		t.Fatal("no command")
	}
}

func lines(in ...string) string { return strings.Join(in, "\n") + "\n" }

func TestProxyEndToEnd(t *testing.T) {
	dir := t.TempDir()
	audit, pins := filepath.Join(dir, "a.jsonl"), filepath.Join(dir, "p.json")
	stdin := lines(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/work/.env"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"http://169.254.169.254/latest"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"notes","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/list"}`,
	)
	code, out, e := do([]string{"proxy", "-audit", audit, "-pins", pins, "-name", "evil", "--", evil}, stdin)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, e)
	}
	got := map[string]*rpc.Message{}
	rd := rpc.NewReader(strings.NewReader(out))
	for {
		m, _, err := rd.Next()
		if err != nil {
			break
		}
		got[m.Key()] = m
	}
	if len(got) != 6 {
		t.Fatalf("want 6 responses, got %d:\n%s", len(got), out)
	}
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(out, "ghp_0123") || !strings.Contains(out, "[REDACTED:aws-access-key]") {
		t.Fatalf("secrets leaked or were not marked:\n%s", out)
	}
	if got["4"].Error == nil || !strings.Contains(got["4"].Error.Message, "private") {
		t.Fatalf("metadata URL must be blocked: %+v", got["4"])
	}
	if strings.Contains(out, "attacker@evil.example") {
		t.Fatal("the injected note must be withheld")
	}
	for _, id := range []string{"2", "6"} {
		if strings.Contains(string(got[id].Result), `"name":"add"`) {
			t.Fatalf("the poisoned tool must be hidden from list %s", id)
		}
	}
	if !strings.Contains(string(got["2"].Result), `"name":"weather"`) || strings.Contains(string(got["6"].Result), `"name":"weather"`) {
		t.Fatal("weather is trusted at first and hidden once its definition changes")
	}
	if b, err := os.ReadFile(audit); err != nil || !strings.Contains(string(b), `"definition-changed"`) || strings.Contains(string(b), "169.254.169.254") && strings.Contains(string(b), `"arguments"`) {
		t.Fatalf("audit log: %v %s", err, b)
	}
	if info, err := os.Stat(audit); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the audit log must be private: %v %v", err, info)
	}
	code, md, _ := do([]string{"report", "-html", filepath.Join(dir, "r.html"), audit}, "")
	if code != 0 || !strings.Contains(md, "private-url") || !strings.Contains(md, "definition-changed") {
		t.Fatalf("report: %d\n%s", code, md)
	}
	if h, err := os.ReadFile(filepath.Join(dir, "r.html")); err != nil || !strings.Contains(string(h), "MCP Sentinel report") {
		t.Fatal("html report")
	}
}

func TestProxyRefusesSampling(t *testing.T) {
	dir := t.TempDir()
	_ = dir
	code, out, _ := do([]string{"proxy", "-audit", filepath.Join(dir, "a.jsonl"), "-pins", "", "--", evil, "-sampling"},
		lines(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, `{"jsonrpc":"2.0","id":2,"method":"ping"}`))
	if code != 0 || strings.Contains(out, "sampling/createMessage") {
		t.Fatalf("the client must never see a sampling request: %d\n%s", code, out)
	}
}

func TestProxyBadPolicyAndMissingCommand(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "p.json")
	os.WriteFile(bad, []byte(`{"mod":"enforce"}`), 0o600)
	if code, _, e := do([]string{"proxy", "-policy", bad, "--", evil}, ""); code != 2 || !strings.Contains(e, "policy") {
		t.Fatalf("a typo in the policy must stop the proxy: %d %q", code, e)
	}
	if code, _, _ := do([]string{"proxy"}, ""); code != 2 {
		t.Fatal("missing command")
	}
	if code, _, _ := do([]string{"proxy", "--", "/nonexistent/server"}, ""); code != 1 {
		t.Fatal("a server that cannot start")
	}
}

func TestReportErrors(t *testing.T) {
	if code, _, _ := do([]string{"report"}, ""); code != 2 {
		t.Fatal("no file")
	}
	if code, _, _ := do([]string{"report", "/nonexistent.jsonl"}, ""); code != 2 {
		t.Fatal("missing file")
	}
}
