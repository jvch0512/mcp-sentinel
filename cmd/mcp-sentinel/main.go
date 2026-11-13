// mcp-sentinel is a security proxy for MCP servers.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/jvch0512/mcp-sentinel/internal/audit"
	"github.com/jvch0512/mcp-sentinel/internal/pin"
	"github.com/jvch0512/mcp-sentinel/internal/policy"
	"github.com/jvch0512/mcp-sentinel/internal/proxy"
	"github.com/jvch0512/mcp-sentinel/internal/scan"
)

const version = "1.0.0"

const usage = `mcp-sentinel ` + version + `: a security proxy for MCP servers

  mcp-sentinel proxy [-policy policy.json] [-audit audit.jsonl] [-pins pins.json] [-name server] -- COMMAND [ARGS...]
      Run COMMAND as an MCP server and filter everything between it and your client (stdio).
  mcp-sentinel scan [-json] -- COMMAND [ARGS...]
      Start a server, list its tools and report poisoned descriptions. Exit 1 on a high finding.
  mcp-sentinel report [-html out.html] audit.jsonl
      Summarise an audit log as Markdown (stdout) and, optionally, as an HTML page.
  mcp-sentinel policy
      Print the default policy as JSON.
`

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

// split separates the sentinel's flags from the server command at the first "--".
func split(args []string) (flags, cmd []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "proxy":
		return cmdProxy(args[1:], stdin, stdout, stderr)
	case "scan":
		return cmdScan(args[1:], stdout, stderr)
	case "report":
		return cmdReport(args[1:], stdout, stderr)
	case "policy":
		b, _ := json.MarshalIndent(policy.Default(), "", "  ")
		fmt.Fprintln(stdout, string(b))
		return 0
	case "version", "-v", "--version":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return 2
}

func cmdProxy(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pol := fs.String("policy", "", "policy file (default: built-in safe policy)")
	auditPath := fs.String("audit", "audit.jsonl", "audit log, JSON lines")
	pinPath := fs.String("pins", "pins.json", "tool definition fingerprints")
	name := fs.String("name", "", "name of this server in the log and pin file (default: the command)")
	flags, cmdline := split(args)
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if len(cmdline) == 0 {
		fmt.Fprintln(stderr, "proxy: give the server command after --")
		return 2
	}
	p, err := policy.Load(*pol)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	pins, err := pin.Open(*pinPath)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	var logW io.Writer = io.Discard
	if *auditPath != "" {
		f, err := os.OpenFile(*auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		defer f.Close()
		logW = f
	}
	server := *name
	if server == "" {
		server = cmdline[0]
	}
	cmd := exec.Command(cmdline[0], cmdline[1:]...)
	cmd.Stderr = stderr
	childIn, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(stderr, "error: cannot start the server:", err)
		return 1
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		_ = cmd.Process.Kill()
	}()
	px := proxy.New(p, pins, audit.NewLogger(logW), server)
	if err := px.Run(stdin, stdout, childIn, childOut); err != nil {
		fmt.Fprintln(stderr, "proxy:", err)
	}
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		return 1
	}
	return 0
}

func cmdScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	flags, cmdline := split(args)
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	name, tools, err := scan.Fetch(context.Background(), cmdline)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	rep := &scan.Report{Server: name, Tools: scan.Analyse(tools)}
	if *asJSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Fprintln(stdout, string(b))
	} else {
		fmt.Fprintf(stdout, "server %q exposes %d tools\n\n", name, len(rep.Tools))
		for _, t := range rep.Tools {
			status := "ok"
			if t.Blocking {
				status = "WOULD BLOCK"
			} else if len(t.Findings) > 0 {
				status = "review"
			}
			fmt.Fprintf(stdout, "%-14s %s\n", t.Name, status)
			for _, f := range t.Findings {
				fmt.Fprintf(stdout, "    [%s] %s: %s\n", f.Sev, f.Rule, f.Detail)
			}
		}
	}
	if rep.Worst() >= 3 {
		return 1
	}
	return 0
}

func cmdReport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	htmlOut := fs.String("html", "", "also write a self-contained HTML report to this file")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "report: give one audit log file")
		return 2
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	defer f.Close()
	sum, bad, err := audit.Summarise(f)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if bad > 0 {
		fmt.Fprintf(stderr, "note: skipped %d lines that are not audit events\n", bad)
	}
	fmt.Fprint(stdout, sum.Markdown())
	if *htmlOut != "" {
		if err := os.WriteFile(*htmlOut, []byte(sum.HTML()), 0o644); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
	}
	return 0
}
