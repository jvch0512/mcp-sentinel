// Package pin remembers a fingerprint of every tool definition (trust on first use) so a later change,
// the "rug pull", is noticed.
package pin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
)

type State int

const (
	New State = iota
	Same
	Changed
)

type Store struct {
	mu   sync.Mutex
	path string
	data map[string]map[string]string // server -> tool -> fingerprint
}

// Open loads the store, creating an empty one if the file does not exist. An empty path keeps pins in memory.
func Open(path string) (*Store, error) {
	s := &Store{path: path, data: map[string]map[string]string{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, errors.New("pin file is not valid JSON: " + err.Error())
	}
	return s, nil
}

// Fingerprint hashes a tool's name, description and schema in a key-order independent way.
func Fingerprint(name, description string, schema json.RawMessage) string {
	var canon any
	if len(schema) > 0 {
		_ = json.Unmarshal(schema, &canon)
	}
	b, _ := json.Marshal(map[string]any{"name": name, "description": description, "schema": canon})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Check compares a fingerprint with the stored one. A new tool is remembered. A changed tool is not overwritten:
// the first definition stays authoritative until the pin file is edited by a person.
func (s *Store) Check(server, tool, fp string) State {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.data[server]
	if m == nil {
		m = map[string]string{}
		s.data[server] = m
	}
	old, ok := m[tool]
	switch {
	case !ok:
		m[tool] = fp
		s.save()
		return New
	case old == fp:
		return Same
	}
	return Changed
}

func (s *Store) save() {
	if s.path == "" {
		return
	}
	b, _ := json.MarshalIndent(s.data, "", "  ")
	_ = os.WriteFile(s.path, append(b, '\n'), 0o600)
}
