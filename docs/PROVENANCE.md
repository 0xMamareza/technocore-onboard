# Provenance and protocol

Technocore Onboard is an independent guided wrapper, not an official Technocore service, wallet, escrow or X publishing client.

## Pinned reference code

- Source: <https://github.com/zunmax/technocore-did-starter>
- Commit: `3cc03a6e908e8776de9fdd465c53d23d31db2e9f`
- `vendor/technocore_agent.py` is the exact Git blob, with LF line endings, unmodified.
- Source SHA-256: `1cc255ff6f4ffc12fc563f8b86a1ceb2674548a3e013b4badcdf0afee7d51ca2`
- Upstream MIT notice: `vendor/LICENSE`.

Onboard imports upstream identity creation/loading, DID derivation, normalization, message payload/signing, contribution proof creation/verification and signature verification. It does not introduce new cryptography. Its additional checks enforce canonical signatures, public URL validation, storage boundaries, exact response matching, explicit consent and uncertain-outcome recovery. Its own restricted HTTP transport is injectable for offline tests; it does not monkeypatch upstream globals.

`requirements.txt` follows the pinned upstream conditional dependencies: `cryptography==48.0.1` on Intel macOS and `cryptography==50.0.0` elsewhere. Installers accept binary wheels only; they do not silently fall back to a source build requiring Rust or compilers. Windows ARM64 uses an explicitly selected AMD64 Python runtime under Windows11 x64 emulation, because these cryptography releases have no native Windows ARM64 wheels. Native ARM testing and compatibility-runtime testing are different claims; see VERIFICATION.md for actual execution evidence.

The private uv0.13.1 archive is pinned by SHA-256 from the official Astral release metadata; selected assets and hashes are listed in `uv-assets.json` in the source repository. Managed CPython3.12 patch releases and transitive Python dependencies are resolved by uv from its managed-runtime metadata and the official PyPI index. They are not a fully hash-locked reproducible dependency tree; uv/TLS, PyPI and the upstream publishers remain part of the trust boundary.

## Protocol reference

Read-only protocol documentation checked at <https://technocore.chat/> during implementation. Writes use only `POST https://technocore.chat/r/ROOM?format=json`, never a side-effecting GET endpoint. The exact signed message bytes are UTF-8 `ROOM|NONCE|NORMALIZED_TEXT`. Verification does not trim or normalize stored text. Decimal nonce and sequence tokens retain full precision; receipt fields use strings even beyond JavaScript's safe-integer range.

Git proof payload: compact sorted UTF-8 JSON with `artifact_url`, lowercase full `commit`, and `schema: technocore-contribution-v1`. The proof document schema is `technocore-contribution-proof-v1`.

Portable envelopes follow the existing Inspector `technocore-inspector-receipt-v1` schema: message kind includes explicit `room` and one `record`; contribution kind includes one proof `record`. The exact `posted` target is selected from a server response, not a neighbouring snapshot message. Sequence and timestamp are unsigned context.

## Independent compatibility

`tests/test_wizard.py` optionally imports the actual async `inspectJson` from a sibling `technocore-proof-inspector` checkout through Node and tests both message/proof import and receipt reimport. It uses only publicly labelled disposable synthetic fixture keys, never the user's identity, and does not modify Inspector. If that separate checkout/dependencies are absent, this optional interoperability test is explicitly skipped; the Python core tests still run. See [VERIFICATION.md](VERIFICATION.md) for what was actually exercised.
