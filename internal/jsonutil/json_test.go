package jsonutil

import (
	"errors"
	"testing"
)

func TestUnmarshalAcceptsWhitespace(t *testing.T) {
	var v map[string]any
	if err := Unmarshal([]byte("{\"a\":1}\n  "), &v); err != nil {
		t.Fatal(err)
	}
}

func TestUnmarshalRejectsSecondValue(t *testing.T) {
	var v map[string]any
	if err := Unmarshal([]byte(`{"a":1}{"b":2}`), &v); !errors.Is(err, ErrTrailing) {
		t.Fatalf("got %v", err)
	}
}

func TestUnmarshalRejectsTrailingCloser(t *testing.T) {
	var v map[string]any
	for _, raw := range []string{
		`{"a":1} }`,
		`{"a":1}]`,
		`{"keys":[]} }`,
	} {
		if err := Unmarshal([]byte(raw), &v); !errors.Is(err, ErrTrailing) {
			t.Fatalf("%q: got %v", raw, err)
		}
	}
}

func TestUnmarshalStrictUnknownField(t *testing.T) {
	var v struct {
		A int `json:"a"`
	}
	if err := UnmarshalStrict([]byte(`{"a":1,"b":2}`), &v); err == nil {
		t.Fatal("expected unknown field")
	}
}
