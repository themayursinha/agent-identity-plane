package token

import (
	"errors"
	"fmt"

	"github.com/themayursinha/agent-identity-plane/internal/jsonutil"
)

func decodeStrict(raw []byte, dest any) error {
	if err := jsonutil.UnmarshalStrict(raw, dest); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return nil
}

func decodeJSON(raw []byte, dest any) error {
	if err := jsonutil.Unmarshal(raw, dest); err != nil {
		if errors.Is(err, jsonutil.ErrTrailing) {
			return fmt.Errorf("%w: trailing json", ErrInvalidKey)
		}
		return err
	}
	return nil
}
