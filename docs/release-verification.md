# Verifying agent-identity-plane releases

Every `v*` tag produces, via the `Release` workflow (no long-lived keys;
keyless Sigstore OIDC):

| Asset | What it proves |
|---|---|
| `checksums.txt` (+ `.sig` bundle) | Integrity of every binary; signature bound to this repo's release workflow identity |
| `sbom.spdx.json` | Machine-readable SBOM of the release binaries (covered by `checksums.txt`) |
| SLSA attestation | Build provenance, verifiable with `gh` |

Verify a download (replace `vX.Y.Z` with the release tag):

```bash
# verify only the binary you downloaded (checksums.txt lists every binary;
# the end anchor keeps similarly-named entries out; the asset keeps the tag's v)
OS=linux; ARCH=amd64; EXT=  # e.g. OS=darwin ARCH=arm64; windows needs EXT=.exe
ASSET=agent-identity-plane_vX.Y.Z_${OS}_${ARCH}${EXT}
grep " $ASSET$" checksums.txt | sha256sum -c   # Linux
grep " $ASSET$" checksums.txt | shasum -a 256 -c  # macOS
gh attestation verify checksums.txt --repo themayursinha/agent-identity-plane
cosign verify-blob --bundle checksums.txt.sig \
  --certificate-identity 'https://github.com/themayursinha/agent-identity-plane/.github/workflows/release.yml@refs/tags/vX.Y.Z' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Requires `gh` (with attestation support) and cosign v3 for the bundle format.
