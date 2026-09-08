package token

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func decodeStrict(raw []byte, dest any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: trailing json", ErrInvalidKey)
	}
	return nil
}

func decodeJSON(raw []byte, dest any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(dest); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("%w: trailing json", ErrInvalidKey)
	}
	return nil
}
