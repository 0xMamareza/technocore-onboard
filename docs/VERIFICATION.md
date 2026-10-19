# Verification evidence

## Integration and review fixes

The parent independently ran the final55-test offline suite on Windows11 x64/PowerShell5.1: OK,7 explicit network/POSIX skips. The core worker's final26-test run had no skips or warnings. The bootstrap worker ran55 tests on Ubuntu/WSL x64 (OK,12 explicit Windows/network/optional-Inspector skips), plus two actual fresh-install/reinstall integration tests each on Windows and WSL. The parent then independently reran the full55-test suite with real downloads enabled: Windows OK with5 platform skips; Ubuntu/WSL OK with10 platform/optional-Inspector skips. These runs include actual payload fresh installation and reinstall data preservation. Those checks use disposable roots and never create a user's DID or public POST.

Independent re-review of that same55-test snapshot subsequently reproduced a Windows regression: the dangerous-root test used a hardcoded path whose trailing dot was normalized away before validation. Its result depended on whether the canonical directory already existed. Re-review also exposed uncontrolled malformed-HTTP exceptions and wrong-type GitHub metadata. Those failures are retained here rather than erased by earlier green runs. The second narrow regression-first fix cycle validates raw Windows components before canonicalization with disposable test roots, normalizes HTTP protocol errors into controlled transport failures, and type-checks GitHub metadata. Its full Windows59-test suite passed with7 explicit skips; core29 tests passed without skips or warnings. Native CI and final release checks remain separate gates.

Independent review originally blocked release despite green tests. Regression-first fixes cover total slow-header deadlines, captured-byte identity-import consistency, nonfinite JSON/evidence rejection, controlled malformed-intent errors, contribution room defaults, private Windows ACL preflight/read-back, correct platform dependency pins and complete malicious archive fixtures. The review and final test results apply to the actual current files, not the earlier22-test snapshot below.

An actual read-only request through the final deadline-aware HTTPS transport resolved the exact pinned Zun public revision and parsed a200-record lobby snapshot. This is not a live posting test. Vendor source/license and conditional requirements match the pinned Git blobs byte-for-byte. Upstream binary metadata establishes Intel Mac48.0.1 universal2 wheels and the lack of native WindowsARM64 wheels for these pins; Windows11ARM deliberately uses managed x64 Python under emulation.

[Native CI](https://github.com/0xMamareza/technocore-onboard/actions/workflows/ci.yml) covers Ubuntu and Windows x64/ARM hardware plus Intel/Apple-silicon macOS, explicitly using `/bin/bash` on Macs. A workflow definition is not a passing run: inspect the exact release revision's result. Native Mac/Bash3.2 and ARM cannot be inferred from local Windows/WSL execution. The release notes carry exact CI/revision/hash handles. Full successful/uncertain POST and recovery tests are explicitly simulated; no automated check publishes a real record.

OS DNS and multiple-address connection attempts can exceed the nominal HTTP budget before returning; overdue connections are rejected immediately afterward. TLS/header/body operations use the shared remaining budget. Runtime patch downloads/transitive dependencies are not fully hash-locked; see PROVENANCE.md. Signature validity, live-source presence and authorship remain separate. Doctor is not a decryption test or full ACL audit.

To repeat all checks, use the private environment and `python -B -W error -m unittest discover -s tests -v`. Set `TC_BOOTSTRAP_INTEGRATION=1` explicitly for real dependency-download/fresh-install/reinstall checks; ordinary runs skip those. Keep platform/optional-Inspector skips visible.

## Earlier core-worker evidence (historical22-test snapshot)

This document records the **core worker's executed checks**, not a claim that publishing, every installer platform or a live contribution has been completed. Bootstrap/platform/release integration is a separate owner and gate under `SPEC.md`.

## Actual local executions

- Windows x64, Python **3.14.7**, isolated scratch test venv, **cryptography 50.0.0**: `python -m unittest discover -s tests -p test_wizard.py -v` passed **22 tests**, no skips on this host. `pip check` reported `No broken requirements found.` No global Python/dependency was modified.
- Earlier incremental runs used the existing separate Inspector Python 3.14 venv with cryptography 50.0.2, read-only; its dependency version was not changed. Final core runs use the release-pinned 50.0.0 scratch environment, not that earlier environment.
- The actual sibling Inspector async `inspectJson` accepted a synthetic message receipt and Git proof receipt and accepted their exported receipt reimports under Node. The message includes Unicode and a 19-digit nonce/sequence. Inspector source/dependencies/user identity were not modified.
- Direct `onboard.py --version` printed `1.0.0` even under a Python without cryptography installed. Different-working-directory subprocess checks cover version, non-terminal setup refusal and offline doctor with a nonexistent Unicode/space-containing data root; no identity/data directory is created in those refusal checks.
- Managed Windows directory ACL checks explicitly added an Everyone grant to a synthetic data root and synthetic encrypted key, then verified setup/reuse removes it. Symlink/junction safety is exercised locally. All identity tests use disposable clearly labelled synthetic fixtures, never the real identity.
- Separate actual **read-only** requests through the core HTTP transport resolved `https://github.com/zunmax/technocore-did-starter` to the exact published commit `3cc03a6e908e8776de9fdd465c53d23d31db2e9f` and parsed the `lobby` Technocore JSON snapshot (67,792 response bytes at that check). This is endpoint/transport evidence, not a live posting test or a durable assertion about room contents.
- Vendored source was compared byte-for-byte to `git show` of the pinned public source blob; SHA-256 is in [PROVENANCE.md](PROVENANCE.md). `git archive` initially applied the source checkout's CRLF conversion; re-extracting with `-c core.autocrlf=false` preserved the exact LF Git blob. No private upstream files were accessed.

## Vertical red/green evidence

The terminal execution history observed each main missing behavior before its implementation:

1. Setup cancellation/non-terminal slice: missing wizard assertion failed, then 1 test passed.
2. Identity create/resume/import slice: missing encrypted file failed, then 2 tests passed.
3. Git proof-before-announcement and URL validation slice: missing contribute/URL interfaces failed, then 4 tests passed.
4. Consent/pending/receipt/duplicate slice: posting was explicitly unimplemented and failed, then 5 tests passed.
5. Recover/export/unknown + offline doctor slice: missing commands failed, then 7 tests passed.
6. CLI/actual exact read-back slice: empty version and absent read-back GET assertions failed, then 8 tests passed.
7. Adversarial regression checks exposed dot-dot dangerous-root bypass and duplicate public JSON fields. Both failed before fixes, then 18 tests passed.
8. Hidden passphrase echo fallback and pre-existing broad Windows ACL regression tests failed before fixes; then 20 tests passed. Later the broad **key-file** ACL regression also failed before key permission hardening, then passed.
9. Unknown POST exit status and mismatched stored receipt regression failed before propagation/binding fixes; then 21 tests passed.
10. Unsafe GET endpoints were tested with the network opener blocked (no side-effecting live request was sent). They reached the blocked opener before transport restrictions were added, then passed. Remaining-read-deadline test failed before socket deadline enforcement, then the 22-test suite passed.

Additional safety tests exercise wrong/weak passphrases, unencrypted import rejection, public-state DID mismatch, lost-key refusal without regeneration, canonical signatures, exact non-normalized verification bytes, alias conflicts, invalid commits/private GitHub metadata, cancellation, malformed/duplicate export records, generation changes, export line/response byte caps, redirects and origin restrictions. They are controlled offline tests, not evidence of service behavior.

## Deliberately simulated / not yet established here

- All successful/uncertain POST paths and recover outcomes use injected **simulated HTTP responses**. No real DID creation, Technocore POST, X/Telegram post, GitHub write, commit or push was performed by the core worker.
- A real terminal human's passphrase entry has not been exercised; hidden prompts are unit-tested with a warning/error guard. The real non-terminal rejection is exercised in subprocesses.
- This core report does **not** establish the managed Python 3.12 installer, WSL/Linux/macOS/ARM64 installation, release archive, public one-liners, GitHub CI or published asset checks. Run/record those integration checks separately. The optional independent Inspector test is explicitly skipped if its sibling checkout is not available elsewhere.
- No formal cryptographic audit, hostile-local-process sandbox proof, complete Windows ACL audit or live-source permanence guarantee is claimed. Public-host checks are syntactic; artifact DNS and artifacts are never fetched. CPython socket reads use remaining-deadline timeouts; OS DNS resolution and connection setup remain subject to the platform's resolver/connect behavior.
- Independent review, source/payload secret scan, archive CRC/hash verification and exact public release read-back remain release gates for the parent integrator. Core test success is not itself release authorization or social-publication authorization.
