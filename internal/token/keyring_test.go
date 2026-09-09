package token

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKeyringRotationKeepsOldKid(t *testing.T) {
	old := mustKey(t, "sts-1")
	newer := mustKey(t, "sts-2")
	kr, err := NewKeyring("sts-1", []*KeyFile{old})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := kr.SignClaims(Claims{
		Iss: "https://sts.example.test",
		Sub: "user1",
		Aud: Audience{"next"},
		Exp: time.Now().Add(time.Minute).Unix(),
		Jti: "j1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Replace("sts-1", []*KeyFile{old, newer}); err != nil {
		t.Fatal(err)
	}
	if err := kr.Replace("sts-2", []*KeyFile{old, newer}); err != nil {
		t.Fatal(err)
	}
	if kr.ActiveKID() != "sts-2" {
		t.Fatalf("active %s", kr.ActiveKID())
	}
	if _, _, err := Verify(raw, kr.JWKS()); err != nil {
		t.Fatalf("old token should verify during overlap: %v", err)
	}
	raw2, err := kr.SignClaims(Claims{
		Iss: "https://sts.example.test",
		Sub: "user1",
		Aud: Audience{"next"},
		Exp: time.Now().Add(time.Minute).Unix(),
		Jti: "j2",
	})
	if err != nil {
		t.Fatal(err)
	}
	h, _, _, err := ParseUnverified(raw2)
	if err != nil {
		t.Fatal(err)
	}
	if h.KID != "sts-2" {
		t.Fatalf("kid %s", h.KID)
	}
	if err := kr.Replace("sts-2", []*KeyFile{newer}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(raw, kr.JWKS()); err != ErrUnknownKey && err != ErrBadSignature {
		t.Fatalf("retired kid should fail, got %v", err)
	}
}

func TestKeyringReplaceFailsClosed(t *testing.T) {
	k1 := mustKey(t, "sts-1")
	kr, err := NewKeyring("sts-1", []*KeyFile{k1})
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Replace("missing", []*KeyFile{k1}); err == nil {
		t.Fatal("expected error")
	}
	if kr.ActiveKID() != "sts-1" {
		t.Fatalf("ring mutated on failed replace: %s", kr.ActiveKID())
	}
}

func TestKeyringRejectsUnpublishedActivation(t *testing.T) {
	k1 := mustKey(t, "sts-1")
	k2 := mustKey(t, "sts-2")
	kr, err := NewKeyring("sts-1", []*KeyFile{k1})
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Replace("sts-2", []*KeyFile{k1, k2}); err == nil {
		t.Fatal("activating an unpublished kid must fail")
	}
	if kr.ActiveKID() != "sts-1" {
		t.Fatalf("active mutated: %s", kr.ActiveKID())
	}
}

func TestKeyringRejectsMutatedPublishedMaterial(t *testing.T) {
	k1 := mustKey(t, "sts-1")
	k1b := mustKey(t, "sts-1")
	kr, err := NewKeyring("sts-1", []*KeyFile{k1})
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Replace("sts-1", []*KeyFile{k1b}); err == nil {
		t.Fatal("mutating published kid material must fail")
	}
	if kr.ActiveKID() != "sts-1" {
		t.Fatalf("active mutated: %s", kr.ActiveKID())
	}
	k2 := mustKey(t, "sts-2")
	if err := kr.Replace("sts-1", []*KeyFile{k1, k2}); err != nil {
		t.Fatal(err)
	}
	k2b := mustKey(t, "sts-2")
	if err := kr.Replace("sts-2", []*KeyFile{k1, k2b}); err == nil {
		t.Fatal("activating a preloaded kid with changed bytes must fail")
	}
	next, err := NewKeyring("sts-1", []*KeyFile{k1b})
	if err != nil {
		t.Fatal(err)
	}
	if err := AllowActivation(kr, next); err == nil {
		t.Fatal("AllowActivation must require stable public material")
	}
}

func TestKeyRetirementWaitIncludesSkew(t *testing.T) {
	if KeyRetirementWait(120*time.Second) != 150*time.Second {
		t.Fatalf("got %s", KeyRetirementWait(120*time.Second))
	}
}

func TestParseSigningMaterialKeyring(t *testing.T) {
	k1 := mustKey(t, "sts-1")
	k2 := mustKey(t, "sts-2")
	doc := keyringFile{ActiveKID: "sts-2", Keys: []KeyFile{*k1, *k2}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	active, keys, err := ParseSigningMaterial(raw)
	if err != nil {
		t.Fatal(err)
	}
	if active != "sts-2" || len(keys) != 2 {
		t.Fatalf("%s %d", active, len(keys))
	}
}

func TestParseSigningMaterialSingle(t *testing.T) {
	k1 := mustKey(t, "sts-1")
	raw, err := json.Marshal(k1)
	if err != nil {
		t.Fatal(err)
	}
	active, keys, err := ParseSigningMaterial(raw)
	if err != nil {
		t.Fatal(err)
	}
	if active != "sts-1" || len(keys) != 1 {
		t.Fatalf("%s %d", active, len(keys))
	}
}

func TestCheckSecretFileMode(t *testing.T) {
	dir := t.TempDir()
	okPath := filepath.Join(dir, "ok.json")
	if err := os.WriteFile(okPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckSecretFileMode(okPath); err != nil {
		t.Fatal(err)
	}
	openPath := filepath.Join(dir, "open.json")
	if err := os.WriteFile(openPath, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckSecretFileMode(openPath); err == nil {
		t.Fatal("expected mode error")
	}
}

func TestWriteSecretFileEnforcesModeOnOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteSecretFile(path, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "new\n" {
		t.Fatalf("%q", b)
	}
}

func TestParseSigningMaterialUnknownField(t *testing.T) {
	k1 := mustKey(t, "sts-1")
	raw, err := json.Marshal(k1)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["extra"] = true
	bad, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseSigningMaterial(bad); err == nil {
		t.Fatal("unknown field must fail closed")
	}
	doc := map[string]any{"active_kid": "sts-1", "keys": []any{m}, "note": "nope"}
	badRing, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseSigningMaterial(badRing); err == nil {
		t.Fatal("unknown keyring field must fail closed")
	}
}

func TestParseSigningMaterialTrailingJSON(t *testing.T) {
	k1 := mustKey(t, "sts-1")
	raw, err := json.Marshal(k1)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, []byte(`{"kid":"x"}`)...)
	if _, _, err := ParseSigningMaterial(raw); err == nil {
		t.Fatal("trailing json must fail closed")
	}
}

func TestParseJWKSTrailingJSON(t *testing.T) {
	kf := mustKey(t, "k1")
	raw, err := kf.PublicJWKS().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseJWKS(append(append([]byte{}, raw...), []byte(`{"keys":[]}`)...)); err == nil {
		t.Fatal("trailing json must fail closed")
	}
	if _, err := ParseJWKS(append(append([]byte{}, raw...), []byte(` }`)...)); err == nil {
		t.Fatal("trailing closer must fail closed")
	}
}

func TestLoadSigningFile(t *testing.T) {
	kf := mustKey(t, "sts-1")
	raw, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sts.json")
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	kr, err := LoadSigningFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if kr.ActiveKID() != "sts-1" {
		t.Fatalf("kid %s", kr.ActiveKID())
	}
}
