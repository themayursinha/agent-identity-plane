package jsonutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrTrailing is returned when input continues after one JSON value.
var ErrTrailing = errors.New("trailing json")

// Unmarshal decodes one JSON value and requires the rest of the input
// to be EOF. Extra fields on structs are ignored. Leftover tokens,
// including unmatched closers such as `}`, fail closed.
func Unmarshal(raw []byte, dest any) error {
	return decode(raw, dest, false)
}

// UnmarshalStrict is Unmarshal plus DisallowUnknownFields.
func UnmarshalStrict(raw []byte, dest any) error {
	return decode(raw, dest, true)
}

func decode(raw []byte, dest any, strict bool) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(dest); err != nil {
		return err
	}
	var extra json.RawMessage
	switch err := dec.Decode(&extra); err {
	case io.EOF:
		return nil
	case nil:
		return ErrTrailing
	default:
		return fmt.Errorf("%w: %v", ErrTrailing, err)
	}
}
