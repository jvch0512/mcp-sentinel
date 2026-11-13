// Package scan starts an MCP server, lists its tools and reports what looks dangerous, without a client.
package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/jvch0512/mcp-sentinel/internal/detect"
	"github.com/jvch0512/mcp-sentinel/internal/rpc"
)

type ToolReport struct {
	Name     string           `json:"name"`
	Findings []detect.Finding `json:"findings"`
	Blocking bool             `json:"would_block"`
}

type Report struct {
	Server string       `json:"server"`
	Tools  []ToolReport `json:"tools"`
}

// Worst returns the highest severity across all tools (0 when clean).
func (r *Report) Worst() detect.Severity {
	var w detect.Severity
	for _, t := range r.Tools {
		for _, f := range t.Findings {
			if f.Severity > w {
				w = f.Severity
			}
		}
	}
	return w
}

// Analyse checks every tool in a list of tool definitions.
func Analyse(tools []json.RawMessage) []ToolReport {
	out := make([]ToolReport, 0, len(tools))
	for _, raw := range tools {
		var td struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"inputSchema"`
		}
		if json.Unmarshal(raw, &td) != nil || td.Name == "" {
			f := detect.Finding{Rule: "malformed-tool", Severity: detect.Medium, Sev: "medium", Detail: "a tool entry without a name"}
			out = append(out, ToolReport{Name: "(unnamed)", Findings: []detect.Finding{f}})
			continue
		}
		fs := detect.Injection(td.Description)
		for _, sv := range detect.Strings(td.InputSchema) {
			fs = append(fs, detect.Injection(sv.Value)...)
		}
		out = append(out, ToolReport{Name: td.Name, Findings: fs, Blocking: detect.Blocking(fs)})
	}
	return out
}

// Fetch starts the server, performs the MCP handshake and returns every tool it lists.
func Fetch(ctx context.Context, argv []string) (string, []json.RawMessage, error) {
	if len(argv) == 0 {
		return "", nil, fmt.Errorf("no server command given")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	in, err := cmd.StdinPipe()
	if err != nil {
		return "", nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", nil, err
	}
	if err := cmd.Start(); err != nil {
		return "", nil, err
	}
	defer func() { _ = in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	rd := rpc.NewReader(out)
	send := func(m *rpc.Message) { _, _ = in.Write(rpc.Marshal(m)) }
	call := func(id int, method, params string) (*rpc.Message, error) {
		idb := json.RawMessage(fmt.Sprint(id))
		send(&rpc.Message{JSONRPC: "2.0", ID: idb, Method: method, Params: json.RawMessage(params)})
		for {
			m, _, err := rd.Next()
			if err == io.EOF {
				return nil, fmt.Errorf("the server closed its output before answering %s", method)
			}
			if err != nil {
				if m == nil {
					continue
				}
				return nil, err
			}
			if m.IsRequest() { // a server request: decline politely
				send(rpc.ErrorReply(m.ID, -32601, "not supported by the scanner"))
				continue
			}
			if m.IsResponse() && m.Key() == string(idb) {
				if m.Error != nil {
					return nil, fmt.Errorf("%s failed: %s", method, m.Error.Message)
				}
				return m, nil
			}
		}
	}
	init, err := call(1, "initialize", `{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-sentinel-scan","version":"1"}}`)
	if err != nil {
		return "", nil, err
	}
	var ir struct {
		ServerInfo struct{ Name string } `json:"serverInfo"`
	}
	_ = json.Unmarshal(init.Result, &ir)
	send(&rpc.Message{JSONRPC: "2.0", Method: "notifications/initialized"})

	var all []json.RawMessage
	cursor := ""
	for page := 0; page < 20; page++ {
		params := `{}`
		if cursor != "" {
			b, _ := json.Marshal(map[string]string{"cursor": cursor})
			params = string(b)
		}
		m, err := call(2+page, "tools/list", params)
		if err != nil {
			return ir.ServerInfo.Name, all, err
		}
		var res struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor string            `json:"nextCursor"`
		}
		if err := json.Unmarshal(m.Result, &res); err != nil {
			return ir.ServerInfo.Name, all, fmt.Errorf("tools/list result is not valid: %v", err)
		}
		all = append(all, res.Tools...)
		if res.NextCursor == "" {
			break
		}
		cursor = res.NextCursor
	}
	return ir.ServerInfo.Name, all, nil
}
