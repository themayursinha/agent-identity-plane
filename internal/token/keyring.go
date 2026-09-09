package token

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Keyring is a rotatable set of Ed25519 STS keys. Minting always uses
// the active kid; verification JWKS includes every key in the ring so
// previously minted tokens remain valid until the old kid is removed.
type Keyring struct {
	mu        sync.RWMutex
	activeKID string
	byKID     map[string]*Signer
}

// NewKeyring builds a ring. activeKID must name one of keys.
func NewKeyring(activeKID string, keys []*KeyFile) (*Keyring, error) {
	k := &Keyring{}
	if err := k.Replace(activeKID, keys); err != nil {
		return nil, err
	}
	return k, nil
}

// Replace swaps the ring. On error the previous ring is left unchanged.
func (k *Keyring) Replace(activeKID string, keys []*KeyFile) error {
	if k == nil {
		return ErrInvalidKey
	}
	if len(keys) == 0 {
		return fmt.Errorf("%w: signing ring is empty", ErrInvalidKey)
	}
	if activeKID == "" {
		return fmt.Errorf("%w: active_kid required", ErrInvalidKey)
	}
	next := make(map[string]*Signer, len(keys))
	for _, f := range keys {
		if f == nil || f.KID == "" {
			return fmt.Errorf("%w: signing key missing kid", ErrInvalidKey)
		}
		if _, ok := next[f.KID]; ok {
			return fmt.Errorf("%w: duplicate kid %s", ErrInvalidKey, f.KID)
		}
		s, err := SignerFromKeyFile(f)
		if err != nil {
			return err
		}
		next[f.KID] = s
	}
	if _, ok := next[activeKID]; !ok {
		return fmt.Errorf("%w: active kid %q not in ring", ErrUnknownKey, activeKID)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.byKID != nil {
		if err := publicMaterialStable(jwksFrom(k.activeKID, k.byKID), jwksFrom(activeKID, next)); err != nil {
			return err
		}
		if k.activeKID != "" && activeKID != k.activeKID {
			if _, ok := k.byKID[activeKID]; !ok {
				return fmt.Errorf("%w: cannot activate unpublished kid %q", ErrUnknownKey, activeKID)
			}
		}
	}
	k.activeKID = activeKID
	k.byKID = next
	return nil
}

func (k *Keyring) HasKID(kid string) bool {
	if k == nil || kid == "" {
		return false
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	_, ok := k.byKID[kid]
	return ok
}

// AllowActivation reports whether next may replace prev. Bootstrap
// (no previous ring) may activate any kid in next. After that, a new
// active_kid must already have been published in prev's JWKS, and every
// overlapping kid must keep the same public material. A kid is a key,
// not a reusable label.
func AllowActivation(prev, next *Keyring) error {
	if next == nil || next.ActiveKID() == "" {
		return ErrInvalidKey
	}
	if prev == nil || prev.ActiveKID() == "" {
		return nil
	}
	want := next.ActiveKID()
	if want != prev.ActiveKID() && !prev.HasKID(want) {
		return fmt.Errorf("%w: cannot activate unpublished kid %q", ErrUnknownKey, want)
	}
	return publicMaterialStable(prev.JWKS(), next.JWKS())
}

func publicMaterialStable(prev, next JWKS) error {
	byNext := make(map[string]JWK, len(next.Keys))
	for _, j := range next.Keys {
		byNext[j.KID] = j
	}
	for _, j := range prev.Keys {
		n, ok := byNext[j.KID]
		if !ok {
			continue
		}
		if !j.PublicEqual(n) {
			return fmt.Errorf("%w: kid %q public material changed", ErrInvalidKey, j.KID)
		}
	}
	return nil
}

func jwksFrom(active string, by map[string]*Signer) JWKS {
	out := make([]JWK, 0, len(by))
	if s := by[active]; s != nil {
		out = append(out, s.PublicJWK())
	}
	for kid, s := range by {
		if kid == active {
			continue
		}
		out = append(out, s.PublicJWK())
	}
	return JWKS{Keys: out}
}

func (k *Keyring) ActiveKID() string {
	if k == nil {
		return ""
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.activeKID
}

func (k *Keyring) SignClaims(c Claims) (string, error) {
	if k == nil {
		return "", ErrMissingPrivateKey
	}
	k.mu.RLock()
	s := k.byKID[k.activeKID]
	k.mu.RUnlock()
	if s == nil {
		return "", ErrMissingPrivateKey
	}
	return s.SignClaims(c)
}

func (k *Keyring) JWKS() JWKS {
	if k == nil {
		return JWKS{}
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	return jwksFrom(k.activeKID, k.byKID)
}

type keyringFile struct {
	ActiveKID string    `json:"active_kid"`
	Keys      []KeyFile `json:"keys"`
}

// ParseSigningMaterial accepts a single KeyFile or a keyring document
// with active_kid and keys. Owned signing documents are strict-decoded
// (unknown fields and trailing JSON fail closed).
func ParseSigningMaterial(raw []byte) (activeKID string, keys []*KeyFile, err error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	if _, ok := probe["keys"]; ok {
		var wrap keyringFile
		if err := decodeStrict(raw, &wrap); err != nil {
			return "", nil, err
		}
		if wrap.ActiveKID == "" {
			return "", nil, fmt.Errorf("%w: active_kid required", ErrInvalidKey)
		}
		out := make([]*KeyFile, 0, len(wrap.Keys))
		for i := range wrap.Keys {
			kf := wrap.Keys[i]
			out = append(out, &kf)
		}
		return wrap.ActiveKID, out, nil
	}
	var kf KeyFile
	if err := decodeStrict(raw, &kf); err != nil {
		return "", nil, err
	}
	if kf.KID == "" {
		return "", nil, fmt.Errorf("%w: kid required", ErrInvalidKey)
	}
	return kf.KID, []*KeyFile{&kf}, nil
}

// CheckSecretFileMode fails closed if path is group- or world-accessible.
func CheckSecretFileMode(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrInvalidKey, path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: %s must not be group/world-readable (mode %o)", ErrInvalidKey, path, perm)
	}
	return nil
}

// WriteSecretFile writes b to path as a regular file mode 0600, including
// when replacing a more-permissive existing destination.
func WriteSecretFile(path string, b []byte) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: secret path required", ErrInvalidKey)
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".aip-secret-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() { _ = os.Remove(tmp) }
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// LoadSigningFile reads a 0600 key or keyring file.
func LoadSigningFile(path string) (*Keyring, error) {
	if err := CheckSecretFileMode(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	active, keys, err := ParseSigningMaterial(raw)
	if err != nil {
		return nil, err
	}
	return NewKeyring(active, keys)
}
