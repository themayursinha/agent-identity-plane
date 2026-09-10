# Verifying agent-identity-plane releases

Every `v*` tag produces, via the `Release` workflow (no long-lived keys;
keyless Sigstore OIDC):

| Asset | What it proves |
|---|---|
| `checksums.txt` (+ `.sig` bundle) | Integrity of every binary; signature bound to this repo's release workflow identity |
| `sbom.spdx.json` | Machine-readable SBOM of the release binaries (covered by `checksums.txt`) |
| SLSA attestation | Build provenance, verifiable with `gh` |

Verify a download (replace `vX.Y.Z`):

```bash
sha256sum -c checksums.txt
gh attestation verify checksums.txt --repo themayursinha/agent-identity-plane
cosign verify-blob --bundle checksums.txt.sig \
  --certificate-identity 'https://github.com/themayursinha/agent-identity-plane/.github/workflows/release.yml@refs/tags/vX.Y.Z' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Requires `gh` (with attestation support) and cosign v3 for the bundle format.
