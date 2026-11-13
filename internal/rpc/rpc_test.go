package rpc

import (
	"io"
	"strings"
	"testing"
)

func TestReaderFramesMessages(t *testing.T) {
	in := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"result\":{}}\n"
	rd := NewReader(strings.NewReader(in))
	m, _, err := rd.Next()
	if err != nil || !m.IsRequest() || m.Key() != "1" {
		t.Fatalf("request: %+v %v", m, err)
	}
	m, _, _ = rd.Next()
	if !m.IsNotification() {
		t.Fatalf("notification: %+v", m)
	}
	m, _, _ = rd.Next()
	if !m.IsResponse() || m.Key() != `"a"` {
		t.Fatalf("response: %+v", m)
	}
	if _, _, err := rd.Next(); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestReaderRejectsBadInput(t *testing.T) {
	for name, line := range map[string]string{
		"batch":      `[{"jsonrpc":"2.0","id":1,"method":"x"}]`,
		"not json":   `hello`,
		"bad json":   `{"jsonrpc":`,
		"bad ver":    `{"jsonrpc":"1.0","id":1,"method":"x"}`,
		"top string": `"x"`,
	} {
		rd := NewReader(strings.NewReader(line + "\n"))
		m, raw, err := rd.Next()
		if err == nil || m != nil || raw == nil {
			t.Errorf("%s: want a parse error with the raw line, got %v %q %v", name, m, raw, err)
		}
	}
}

func TestReaderLimitsLineLength(t *testing.T) {
	big := `{"jsonrpc":"2.0","id":1,"method":"x","params":{"a":"` + strings.Repeat("a", MaxLine) + `"}}` + "\n"
	rd := NewReader(strings.NewReader(big + `{"jsonrpc":"2.0","id":2,"method":"ok"}` + "\n"))
	if _, _, err := rd.Next(); err != ErrTooLong {
		t.Fatalf("want ErrTooLong, got %v", err)
	}
	m, _, err := rd.Next()
	if err != nil || m.Key() != "2" {
		t.Fatalf("the reader must recover after an oversized line: %v %v", m, err)
	}
}

func TestMarshalIsOneLine(t *testing.T) {
	b := Marshal(ErrorReply([]byte(`7`), CodeBlocked, "no\nway"))
	if strings.Count(string(b), "\n") != 1 || !strings.HasSuffix(string(b), "\n") {
		t.Fatalf("not a single line: %q", b)
	}
}
