// Package policy loads and validates the sentinel's JSON policy.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"regexp"
)

type ToolRules struct {
	Allow []string `json:"allow"` // empty means every tool is allowed unless denied
	Deny  []string `json:"deny"`
}

// ArgRule restricts the arguments of matching tools. Tool and Arg are globs ("*" matches everything).
type ArgRule struct {
	Tool             string   `json:"tool"`
	Arg              string   `json:"arg"`
	DenyPattern      string   `json:"deny_pattern,omitempty"`
	MaxLength        int      `json:"max_length,omitempty"`
	PathRoots        []string `json:"path_roots,omitempty"`
	BlockPrivateURLs bool     `json:"block_private_urls,omitempty"`
	re               *regexp.Regexp
}

// Pattern returns the compiled DenyPattern, or nil.
func (r *ArgRule) Pattern() *regexp.Regexp { return r.re }

type RateLimit struct {
	PerMinute int `json:"per_minute"` // per tool; 0 disables
}

type ResultRules struct {
	Redact    bool   `json:"redact_secrets"`
	Injection string `json:"injection"` // block, flag or off
	MaxBytes  int    `json:"max_bytes"`
}

type DescRules struct {
	Injection string `json:"injection"` // block, flag or off
	Pin       bool   `json:"pin"`
}

type ServerRules struct {
	BlockSampling bool `json:"block_sampling"`
}

type Policy struct {
	Mode               string      `json:"mode"` // enforce or monitor
	Tools              ToolRules   `json:"tools"`
	Arguments          []ArgRule   `json:"arguments"`
	BlockSecretsInArgs bool        `json:"block_secrets_in_arguments"`
	RateLimit          RateLimit   `json:"rate_limit"`
	Results            ResultRules `json:"results"`
	Descriptions       DescRules   `json:"descriptions"`
	Server             ServerRules `json:"server"`
}

// Default is a safe starting point: enforce mode, internal URLs blocked, secrets redacted, sampling refused.
func Default() *Policy {
	p := &Policy{
		Mode:               "enforce",
		Arguments:          []ArgRule{{Tool: "*", Arg: "*", MaxLength: 100000, BlockPrivateURLs: true}},
		BlockSecretsInArgs: true,
		RateLimit:          RateLimit{PerMinute: 120},
		Results:            ResultRules{Redact: true, Injection: "block", MaxBytes: 1 << 20},
		Descriptions:       DescRules{Injection: "block", Pin: true},
		Server:             ServerRules{BlockSampling: true},
	}
	_ = p.Validate()
	return p
}

// Parse reads a policy on top of the defaults. Unknown fields are an error so typos do not silently weaken it.
func Parse(data []byte) (*Policy, error) {
	p := Default()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("policy: %v", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func Load(file string) (*Policy, error) {
	if file == "" {
		return Default(), nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func oneOf(v string, ok ...string) bool {
	for _, o := range ok {
		if v == o {
			return true
		}
	}
	return false
}

func (p *Policy) Validate() error {
	if !oneOf(p.Mode, "enforce", "monitor") {
		return fmt.Errorf("policy: mode must be enforce or monitor, got %q", p.Mode)
	}
	if !oneOf(p.Results.Injection, "block", "flag", "off") {
		return fmt.Errorf("policy: results.injection must be block, flag or off")
	}
	if !oneOf(p.Descriptions.Injection, "block", "flag", "off") {
		return fmt.Errorf("policy: descriptions.injection must be block, flag or off")
	}
	if p.RateLimit.PerMinute < 0 || p.Results.MaxBytes < 0 {
		return fmt.Errorf("policy: limits cannot be negative")
	}
	for _, g := range append(append([]string{}, p.Tools.Allow...), p.Tools.Deny...) {
		if _, err := path.Match(g, "x"); err != nil {
			return fmt.Errorf("policy: bad tool glob %q", g)
		}
	}
	for i := range p.Arguments {
		r := &p.Arguments[i]
		if r.Tool == "" || r.Arg == "" {
			return fmt.Errorf("policy: arguments[%d] needs tool and arg", i)
		}
		for _, g := range []string{r.Tool, r.Arg} {
			if _, err := path.Match(g, "x"); err != nil {
				return fmt.Errorf("policy: arguments[%d]: bad glob %q", i, g)
			}
		}
		r.re = nil
		if r.DenyPattern != "" {
			re, err := regexp.Compile(r.DenyPattern)
			if err != nil {
				return fmt.Errorf("policy: arguments[%d].deny_pattern: %v", i, err)
			}
			r.re = re
		}
	}
	return nil
}

func match(globs []string, name string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(g, name); ok {
			return true
		}
	}
	return false
}

// ToolAllowed applies the allow and deny lists. Deny wins.
func (p *Policy) ToolAllowed(name string) (bool, string) {
	if match(p.Tools.Deny, name) {
		return false, "tool is on the deny list"
	}
	if len(p.Tools.Allow) > 0 && !match(p.Tools.Allow, name) {
		return false, "tool is not on the allow list"
	}
	return true, ""
}

// RulesFor returns the argument rules that apply to a tool and argument name.
func (p *Policy) RulesFor(tool, arg string) []*ArgRule {
	var out []*ArgRule
	for i := range p.Arguments {
		r := &p.Arguments[i]
		t, _ := path.Match(r.Tool, tool)
		a, _ := path.Match(r.Arg, arg)
		if t && a {
			out = append(out, r)
		}
	}
	return out
}

func (p *Policy) Enforcing() bool { return p.Mode == "enforce" }
