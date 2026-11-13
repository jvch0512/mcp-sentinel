// Package proxy sits between an MCP client and an MCP server and applies the policy to every message.
package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jvch0512/mcp-sentinel/internal/audit"
	"github.com/jvch0512/mcp-sentinel/internal/detect"
	"github.com/jvch0512/mcp-sentinel/internal/pin"
	"github.com/jvch0512/mcp-sentinel/internal/policy"
	"github.com/jvch0512/mcp-sentinel/internal/rpc"
)

const maxPending = 10000

type pending struct{ method, tool string }

type Proxy struct {
	Policy *policy.Policy
	Pins   *pin.Store
	Log    *audit.Logger
	Server string // name used for pinning and in the log

	mu      sync.Mutex
	pending map[string]pending
	calls   map[string][]time.Time
	now     func() time.Time
}

func New(p *policy.Policy, pins *pin.Store, log *audit.Logger, server string) *Proxy {
	return &Proxy{Policy: p, Pins: pins, Log: log, Server: server, pending: map[string]pending{}, calls: map[string][]time.Time{}, now: time.Now}
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) send(m *rpc.Message) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(rpc.Marshal(m))
}

func (l *lockedWriter) raw(b []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(append([]byte{}, b...), '\n'))
}

func (p *Proxy) event(e audit.Event) {
	e.Server = p.Server
	if p.Policy.Mode == "monitor" && (e.Decision == "block" || e.Decision == "hide" || e.Decision == "redact") {
		e.Monitor = true
	}
	p.Log.Log(e)
}

// Run pumps messages until the server's output ends. Closing clientIn closes serverIn.
func (p *Proxy) Run(clientIn io.Reader, clientOut io.Writer, serverIn io.WriteCloser, serverOut io.Reader) error {
	cw, sw := &lockedWriter{w: clientOut}, &lockedWriter{w: serverIn}
	go func() {
		p.clientToServer(clientIn, cw, sw)
		_ = serverIn.Close()
	}()
	return p.serverToClient(serverOut, cw, sw)
}

func (p *Proxy) clientToServer(in io.Reader, cw, sw *lockedWriter) {
	rd := rpc.NewReader(in)
	for {
		m, raw, err := rd.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			if raw == nil && err != rpc.ErrTooLong {
				return // the stream itself failed
			}
			p.event(audit.Event{Dir: "client>server", Decision: "drop", Rules: []string{"malformed-message"}, Detail: err.Error()})
			continue
		}
		if m.IsRequest() && m.Method == "tools/call" {
			if blocked := p.checkCall(m, cw); blocked {
				continue
			}
		} else if m.IsRequest() {
			if !p.track(m, "") {
				cw.send(rpc.ErrorReply(m.ID, rpc.CodeBlocked, "mcp-sentinel: too many requests in flight"))
				continue
			}
			p.event(audit.Event{Dir: "client>server", Method: m.Method, Decision: "allow"})
		}
		sw.raw(raw)
	}
}

func (p *Proxy) track(m *rpc.Message, tool string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.pending) >= maxPending {
		return false
	}
	p.pending[m.Key()] = pending{m.Method, tool}
	return true
}

func (p *Proxy) take(m *rpc.Message) (pending, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pe, ok := p.pending[m.Key()]
	delete(p.pending, m.Key())
	return pe, ok
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// checkCall applies the request-side policy. It returns true when the call was answered here and must not be forwarded.
func (p *Proxy) checkCall(m *rpc.Message, cw *lockedWriter) bool {
	var cp callParams
	if err := json.Unmarshal(m.Params, &cp); err != nil || cp.Name == "" {
		p.event(audit.Event{Dir: "client>server", Method: m.Method, Decision: "block", Rules: []string{"malformed-call"}, Detail: "tools/call without a tool name"})
		cw.send(rpc.ErrorReply(m.ID, rpc.CodeInvalid, "mcp-sentinel: malformed tools/call"))
		return true
	}
	rules, detail := p.violations(cp)
	ev := audit.Event{Dir: "client>server", Method: m.Method, Tool: cp.Name, ArgKeys: argKeys(cp.Arguments), ArgHash: argHash(cp.Arguments)}
	if len(rules) > 0 {
		ev.Decision, ev.Rules, ev.Detail = "block", rules, detail
		p.event(ev)
		if p.Policy.Enforcing() {
			cw.send(rpc.ErrorReply(m.ID, rpc.CodeBlocked, "mcp-sentinel blocked this call: "+detail))
			return true
		}
		if !p.track(m, cp.Name) {
			cw.send(rpc.ErrorReply(m.ID, rpc.CodeBlocked, "mcp-sentinel: too many requests in flight"))
			return true
		}
		return false
	}
	ev.Decision = "allow"
	p.event(ev)
	if !p.track(m, cp.Name) {
		cw.send(rpc.ErrorReply(m.ID, rpc.CodeBlocked, "mcp-sentinel: too many requests in flight"))
		return true
	}
	return false
}

func (p *Proxy) violations(cp callParams) ([]string, string) {
	var rules []string
	var detail []string
	add := func(rule, d string) {
		for _, r := range rules {
			if r == rule {
				return
			}
		}
		rules = append(rules, rule)
		detail = append(detail, d)
	}
	if ok, why := p.Policy.ToolAllowed(cp.Name); !ok {
		add("tool-not-allowed", why)
	}
	if n := p.Policy.RateLimit.PerMinute; n > 0 && !p.allowRate(cp.Name, n) {
		add("rate-limit", fmt.Sprintf("more than %d calls per minute", n))
	}
	for _, sv := range detect.Strings(cp.Arguments) {
		leaf := leafName(sv.Path)
		for _, r := range p.Policy.RulesFor(cp.Name, leaf) {
			if r.MaxLength > 0 && len(sv.Value) > r.MaxLength {
				add("argument-too-long", fmt.Sprintf("%s is %d bytes, limit %d", sv.Path, len(sv.Value), r.MaxLength))
			}
			if re := r.Pattern(); re != nil && re.MatchString(sv.Value) {
				add("argument-pattern", fmt.Sprintf("%s matches the deny pattern %q", sv.Path, r.DenyPattern))
			}
			if len(r.PathRoots) > 0 {
				if why := detect.PathOutside(sv.Value, r.PathRoots); why != "" {
					add("path-escape", sv.Path+": "+why)
				}
			}
			if r.BlockPrivateURLs {
				if why := detect.PrivateURL(sv.Value); why != "" {
					add("private-url", sv.Path+": "+why)
				}
			}
		}
		if p.Policy.BlockSecretsInArgs {
			for _, f := range detect.Secrets(sv.Value) {
				add("secret-in-arguments", sv.Path+" contains a secret ("+strings.ReplaceAll(f.Rule, "-", " ")+")")
			}
		}
	}
	return rules, strings.Join(detail, "; ")
}

func (p *Proxy) allowRate(tool string, perMinute int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	cut := now.Add(-time.Minute)
	kept := p.calls[tool][:0]
	for _, t := range p.calls[tool] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= perMinute {
		p.calls[tool] = kept
		return false
	}
	p.calls[tool] = append(kept, now)
	return true
}

func leafName(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		path = path[i+1:]
	}
	if i := strings.Index(path, "["); i >= 0 {
		path = path[:i]
	}
	return path
}

func argKeys(raw json.RawMessage) []string {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func argHash(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:6])
}

func (p *Proxy) serverToClient(out io.Reader, cw, sw *lockedWriter) error {
	rd := rpc.NewReader(out)
	for {
		m, raw, err := rd.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if raw == nil && err != rpc.ErrTooLong {
				return err
			}
			p.event(audit.Event{Dir: "server>client", Decision: "drop", Rules: []string{"malformed-message"}, Detail: err.Error()})
			continue
		}
		switch {
		case m.IsRequest():
			if m.Method == "sampling/createMessage" && p.Policy.Server.BlockSampling {
				p.event(audit.Event{Dir: "server>client", Method: m.Method, Decision: "block", Rules: []string{"sampling-request"}, Detail: "the server asked the client's model to run a prompt"})
				if p.Policy.Enforcing() {
					sw.send(rpc.ErrorReply(m.ID, rpc.CodeBlocked, "mcp-sentinel: sampling is not permitted"))
					continue
				}
			}
			cw.send(m)
		case m.IsResponse():
			pe, _ := p.take(m)
			cw.send(p.inspectResponse(m, pe))
		default:
			cw.send(m)
		}
	}
}

func (p *Proxy) inspectResponse(m *rpc.Message, pe pending) *rpc.Message {
	if m.Error != nil || len(m.Result) == 0 {
		p.event(audit.Event{Dir: "server>client", Method: pe.method, Tool: pe.tool, Decision: "allow"})
		return m
	}
	if pe.method == "tools/list" {
		return p.inspectList(m)
	}
	return p.inspectResult(m, pe)
}

type toolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

func (p *Proxy) inspectList(m *rpc.Message) *rpc.Message {
	var res map[string]json.RawMessage
	if json.Unmarshal(m.Result, &res) != nil || res["tools"] == nil {
		p.event(audit.Event{Dir: "server>client", Method: "tools/list", Decision: "allow"})
		return m
	}
	var tools []json.RawMessage
	if json.Unmarshal(res["tools"], &tools) != nil {
		p.event(audit.Event{Dir: "server>client", Method: "tools/list", Decision: "drop", Rules: []string{"malformed-message"}, Detail: "tools is not a list"})
		return rpc.ErrorReply(m.ID, rpc.CodeBlocked, "mcp-sentinel: malformed tools/list")
	}
	kept := make([]json.RawMessage, 0, len(tools))
	for _, raw := range tools {
		var td toolDef
		if json.Unmarshal(raw, &td) != nil || td.Name == "" {
			p.event(audit.Event{Dir: "server>client", Method: "tools/list", Decision: "hide", Rules: []string{"malformed-tool"}})
			if !p.Policy.Enforcing() {
				kept = append(kept, raw)
			}
			continue
		}
		var fs []detect.Finding
		if p.Policy.Descriptions.Injection != "off" {
			fs = append(fs, detect.Injection(td.Description)...)
			for _, sv := range detect.Strings(td.InputSchema) {
				fs = append(fs, detect.Injection(sv.Value)...)
			}
		}
		var rules []string
		hide := false
		detail := ""
		if ok, why := p.Policy.ToolAllowed(td.Name); !ok {
			hide, rules, detail = true, append(rules, "tool-not-allowed"), why
		}
		if p.Policy.Descriptions.Pin {
			if p.Pins.Check(p.Server, td.Name, pin.Fingerprint(td.Name, td.Description, td.InputSchema)) == pin.Changed {
				fs = append(fs, detect.Finding{Rule: "definition-changed", Severity: detect.High, Sev: "high", Detail: "the tool definition differs from the one first seen (possible rug pull)"})
				hide = true
			}
		}
		if len(fs) > 0 {
			rules = append(rules, detect.Rules(fs)...)
			if detail == "" {
				detail = fs[0].Detail
			}
			if p.Policy.Descriptions.Injection == "block" && detect.Blocking(fs) {
				hide = true
			}
		}
		switch {
		case hide:
			p.event(audit.Event{Dir: "server>client", Method: "tools/list", Tool: td.Name, Decision: "hide", Rules: rules, Detail: detail})
			if !p.Policy.Enforcing() {
				kept = append(kept, raw)
			}
		case len(fs) > 0:
			p.event(audit.Event{Dir: "server>client", Method: "tools/list", Tool: td.Name, Decision: "flag", Rules: rules, Detail: detail})
			kept = append(kept, raw)
		default:
			p.event(audit.Event{Dir: "server>client", Method: "tools/list", Tool: td.Name, Decision: "allow"})
			kept = append(kept, raw)
		}
	}
	res["tools"], _ = json.Marshal(kept)
	m.Result, _ = json.Marshal(res)
	return m
}

func (p *Proxy) inspectResult(m *rpc.Message, pe pending) *rpc.Message {
	ev := audit.Event{Dir: "server>client", Method: pe.method, Tool: pe.tool, Decision: "allow"}
	if max := p.Policy.Results.MaxBytes; max > 0 && len(m.Result) > max {
		ev.Decision, ev.Rules, ev.Detail = "block", []string{"result-too-large"}, fmt.Sprintf("%d bytes, limit %d", len(m.Result), max)
		p.event(ev)
		if p.Policy.Enforcing() {
			return withheld(m, "the result was larger than the policy allows")
		}
		return m
	}
	var fs []detect.Finding
	if p.Policy.Results.Injection != "off" {
		for _, sv := range detect.Strings(m.Result) {
			fs = append(fs, detect.Injection(sv.Value)...)
		}
	}
	if p.Policy.Results.Injection == "block" && detect.Blocking(fs) {
		ev.Decision, ev.Rules, ev.Detail = "block", detect.Rules(fs), fs[0].Detail
		p.event(ev)
		if p.Policy.Enforcing() {
			return withheld(m, "the result looked like a prompt injection ("+strings.Join(detect.Rules(fs), ", ")+")")
		}
		return m
	}
	if p.Policy.Results.Redact {
		if red, hit := redactJSON(m.Result); len(hit) > 0 {
			ev.Decision, ev.Rules, ev.Detail = "redact", hit, "secret-looking values were replaced"
			if len(fs) > 0 {
				ev.Rules = append(ev.Rules, detect.Rules(fs)...)
			}
			p.event(ev)
			if p.Policy.Enforcing() {
				m.Result = red
			}
			return m
		}
	}
	if len(fs) > 0 {
		ev.Decision, ev.Rules, ev.Detail = "flag", detect.Rules(fs), fs[0].Detail
	}
	p.event(ev)
	return m
}

func withheld(m *rpc.Message, why string) *rpc.Message {
	body, _ := json.Marshal(map[string]any{"isError": true, "content": []map[string]string{{"type": "text", "text": "[mcp-sentinel] tool result withheld: " + why}}})
	return &rpc.Message{JSONRPC: "2.0", ID: m.ID, Result: body}
}

func redactJSON(raw json.RawMessage) (json.RawMessage, []string) {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return raw, nil
	}
	seen := map[string]bool{}
	var walk func(v any) any
	walk = func(v any) any {
		switch t := v.(type) {
		case string:
			r, hit := detect.Redact(t)
			for _, h := range hit {
				seen[h] = true
			}
			return r
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
		case map[string]any:
			for k := range t {
				t[k] = walk(t[k])
			}
		}
		return v
	}
	v = walk(v)
	if len(seen) == 0 {
		return raw, nil
	}
	out, _ := json.Marshal(v)
	rules := make([]string, 0, len(seen))
	for k := range seen {
		rules = append(rules, k)
	}
	sort.Strings(rules)
	return out, rules
}
