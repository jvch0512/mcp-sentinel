// Package rpc implements the newline-delimited JSON-RPC 2.0 framing used by the MCP stdio transport.
package rpc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxLine is the largest single message accepted. Longer lines are rejected, not truncated.
const MaxLine = 4 << 20

// Error codes used by the sentinel.
const (
	CodeBlocked = -32001
	CodeInvalid = -32600
)

type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Message is any JSON-RPC message: request, notification or response.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

func (m *Message) IsRequest() bool      { return m.Method != "" && len(m.ID) > 0 }
func (m *Message) IsNotification() bool { return m.Method != "" && len(m.ID) == 0 }
func (m *Message) IsResponse() bool {
	return m.Method == "" && len(m.ID) > 0 && (m.Result != nil || m.Error != nil)
}

// Key returns the id as a stable map key.
func (m *Message) Key() string { return string(bytes.TrimSpace(m.ID)) }

var ErrTooLong = errors.New("message exceeds the size limit")

// Reader reads one message per line.
type Reader struct{ r *bufio.Reader }

func NewReader(r io.Reader) *Reader { return &Reader{r: bufio.NewReaderSize(r, 64*1024)} }

// Next returns the next message and its raw line. A parse failure returns the raw line with a non-nil
// error so the caller can decide what to do with it. io.EOF ends the stream.
func (rd *Reader) Next() (*Message, []byte, error) {
	for {
		var line []byte
		for {
			chunk, isPrefix, err := rd.r.ReadLine()
			if err != nil {
				if len(line) > 0 && errors.Is(err, io.EOF) {
					break
				}
				return nil, nil, err
			}
			line = append(line, chunk...)
			if len(line) > MaxLine {
				for isPrefix { // discard the rest of the oversized line
					_, isPrefix, _ = rd.r.ReadLine()
				}
				return nil, nil, ErrTooLong
			}
			if !isPrefix {
				break
			}
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if line[0] != '{' {
			return nil, line, fmt.Errorf("not a JSON object (batches are not allowed)")
		}
		var m Message
		if err := json.Unmarshal(line, &m); err != nil {
			return nil, line, fmt.Errorf("invalid JSON: %v", err)
		}
		if m.JSONRPC != "2.0" {
			return nil, line, fmt.Errorf("jsonrpc must be \"2.0\"")
		}
		return &m, line, nil
	}
}

// Marshal encodes a message as one line.
func Marshal(m *Message) []byte {
	b, _ := json.Marshal(m)
	return append(b, '\n')
}

// ErrorReply builds an error response for a request id.
func ErrorReply(id json.RawMessage, code int, msg string) *Message {
	return &Message{JSONRPC: "2.0", ID: id, Error: &Error{Code: code, Message: msg}}
}
