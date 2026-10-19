# Bootstrap / release audit contract

The two installers are self-contained: they never execute a neighboring `onboard.py`, require Git/Node/an existing Python, activate a system environment, or alter PATH, profiles, global execution policy, or system package managers.

- Windows: native Windows PowerShell 5.1, x64; Windows 11 ARM64 (build 22000+) uses deliberate x64 emulation, not native ARM64 dependencies. Both hosts download the AMD64 uv asset and request `cpython-3.12-windows-x86_64-none`; the private interpreter must report `sysconfig.get_platform() == "win-amd64"`. Default root: `$env:LOCALAPPDATA\TechnocoreOnboard`.
- POSIX: Bash 3.2+, macOS Intel/ARM64 or glibc Linux x64/ARM64 (including WSL). Default root: `${XDG_DATA_HOME:-$HOME/.local/share}/technocore-onboard`. Requires basic shell utilities, `tar`, `curl` or `wget`, and one of `sha256sum`, `shasum`, `openssl`. No `unzip` needed; a checksum-verified private uv bootstraps private Python for ZIP validation/extraction.
- Official uv 0.13.1 archive hashes are embedded, matching `uv-assets.json`. An old/system uv is never trusted or reused. Python 3.12 and all package/cache writes are rooted inside the private installation. The exact upstream conditional requirements select `cryptography==48.0.1` on Intel macOS and `cryptography==50.0.0` elsewhere; binary-only dependencies are installed only in `.venv`.
- Application ZIP: `https://github.com/0xMamareza/technocore-onboard/releases/download/v1.0.0/technocore-onboard.zip`. The parent release process must replace the single `__PAYLOAD_SHA256__` value in each installer after final packaging. Unstamped installers fail closed, except explicit local artifact audits below.
- An existing unmanaged root is refused, even if empty. Managed reinstalls compare all application files and refuse to overwrite a differing `app-v1.0.0`. Existing identity/state/receipt contents are not read or modified. Windows preflights ownership and explicit grants throughout the tree, refuses foreign ownership/explicit principals before writes, and replaces inherited ACLs with verified current-user/SYSTEM-only DACLs (including descendants). Locks prevent concurrent installs. Partial private runtime failures leave data untouched; follow the exact error before retrying.
- Path/reparse checks assume the local account is not maliciously changing its own private files concurrently. Do not install from an elevated shell or into a shared writable parent.

## Commands

Plan only (no installation, downloads, or key reads):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Plan
```

```bash
bash install.sh --plan
```

Interactive install: invoke the local installer without flags. It explains dependencies and asks for `yes` before downloading; after a successful install it starts `--data-dir ROOT setup`. `-Yes` / `--yes` accepts **only these dependency downloads**, never wizard choices or public posting. A real terminal is required before the interactive path performs installation. A piped Bash installer opens `/dev/tty` for download consent and passes that terminal, not the script pipe, to setup.

Noninteractive local artifact audit (still verifies the supplied SHA256):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Yes -NoRun -Root 'C:\absolute\new private root' -PayloadPath 'C:\absolute\technocore-onboard.zip' -PayloadSha256 '<64-hex SHA256>'
```

```bash
bash install.sh --yes --no-run --root '/absolute/new private root' --payload-path '/absolute/technocore-onboard.zip' --payload-sha256 '<64-hex SHA256>'
```

Artifact flags are paired and require an existing absolute file path. They are deliberately explicit test overrides, not a source-folder fallback. `-NoRun` / `--no-run` prevents all wizard execution. Neither flag is ever forwarded to setup. `-Root` / `--root` only changes the private installation location; omit it to exercise default environment-path resolution.

The resulting wrappers are always usable by explicit path:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\TechnocoreOnboard\bin\tcproof.ps1" contribute
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\TechnocoreOnboard\bin\tcproof.ps1" doctor
```

```bash
"${XDG_DATA_HOME:-$HOME/.local/share}/technocore-onboard/bin/tcproof" contribute
"${XDG_DATA_HOME:-$HOME/.local/share}/technocore-onboard/bin/tcproof" doctor
```

Wrappers use the exact private interpreter/app/root, ignore Python environment/user site injection, suppress application bytecode writes, and forward remaining arguments. A fresh installation's offline `doctor` intentionally returns **1** for missing identity/state; it does not create either.

## Local verification / CI

Bootstrap-only tests require only a test Python (not a bootstrap prerequisite):

```bash
python -m unittest discover -s tests -p test_bootstrap.py -v
```

Opt into real network downloads, fresh disposable installations, real-payload offline doctor, and idempotence tests:

```powershell
$env:TC_BOOTSTRAP_INTEGRATION='1'
python -m unittest discover -s tests -p test_bootstrap.py -v
```

```bash
TC_BOOTSTRAP_INTEGRATION=1 python -m unittest discover -s tests -p test_bootstrap.py -v
```

`python scripts/ci_install.py` runs only the real-payload fresh-install audit. It overrides default LOCALAPPDATA/XDG_DATA_HOME within its child process, diagnoses absent identity, and verifies non-TTY setup rejection. It never enters a key wizard or contacts Technocore. Simulated download failures/ZIP fixtures are explicitly separate tests. The POSIX terminal handoff test uses a synthetic input/cancellation program, not an identity wizard.

The full suite needs `requirements.txt` installed in an isolated test environment. On a developer host with a sibling Inspector repository, its optional real Inspector integration test may also require Node; neither installed Onboard nor its bootstrap depends on Node. CI configures six hardware runner variants (Windows/Linux/macOS, x64/ARM64) with read-only repository permissions. Windows uses x64 test Python on both runner architectures; Windows ARM64 therefore tests emulation, not native ARM64 cryptography. macOS installer tests and syntax/plan checks use `/bin/bash` explicitly and print its version to cover Apple Bash 3.2 rather than Homebrew Bash. Configuring a job does not mean that hardware has been tested; inspect actual run results.

## Packaging

```bash
python scripts/package_release.py --output /absolute/output/technocore-onboard.zip
```

Optional `--source /absolute/source` is for controlled release/audit fixtures. The helper only reads the specified application allowlist, checks source/output symlinks, scans known private-key/token patterns, produces deterministic ZIP metadata, checks CRC/content, and emits `.zip.sha256`. Existing artifacts are replaced only after validation. A pattern scan is not a proof that arbitrary secrets are absent; independent source review is still required. Installers, tests, keys, runtime, state and receipts are never included. This helper does not stamp installers, commit, push, publish, or upload anything.
