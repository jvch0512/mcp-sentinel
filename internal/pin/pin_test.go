package pin

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestFingerprintIgnoresKeyOrderButNotContent(t *testing.T) {
	a := Fingerprint("t", "d", json.RawMessage(`{"a":1,"b":{"x":1,"y":2}}`))
	b := Fingerprint("t", "d", json.RawMessage(`{"b":{"y":2,"x":1},"a":1}`))
	if a != b {
		t.Fatal("key order must not change the fingerprint")
	}
	for name, other := range map[string]string{
		"description": Fingerprint("t", "d2", json.RawMessage(`{"a":1,"b":{"x":1,"y":2}}`)),
		"schema":      Fingerprint("t", "d", json.RawMessage(`{"a":2,"b":{"x":1,"y":2}}`)),
		"name":        Fingerprint("u", "d", json.RawMessage(`{"a":1,"b":{"x":1,"y":2}}`)),
	} {
		if other == a {
			t.Errorf("a change in %s must change the fingerprint", name)
		}
	}
}

func TestTrustOnFirstUseAndRugPull(t *testing.T) {
	s, _ := Open("")
	if s.Check("srv", "weather", "aaa") != New || s.Check("srv", "weather", "aaa") != Same {
		t.Fatal("first sight is New, then Same")
	}
	if s.Check("srv", "weather", "bbb") != Changed || s.Check("srv", "weather", "bbb") != Changed {
		t.Fatal("a changed definition stays Changed: the first one remains authoritative")
	}
	if s.Check("other", "weather", "bbb") != New {
		t.Fatal("pins are per server")
	}
}

func TestPersistence(t *testing.T) {
	f := filepath.Join(t.TempDir(), "pins.json")
	s, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	s.Check("srv", "t", "abc")
	s2, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Check("srv", "t", "abc") != Same || s2.Check("srv", "t", "zzz") != Changed {
		t.Fatal("pins must survive a restart")
	}
}
