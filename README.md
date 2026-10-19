# Technocore Onboard

A guided terminal wizard for **one reusable Technocore DID**, then separate X/article, GitHub and other contribution recording. Installed command: `tcproof`. No wallet, escrow, social-account login or automated Git publishing.

A DID is your public signing identifier, for example `did:key:z6Mk…`. An encrypted `identity.pem` is the private file that lets you sign with it. Keep using the **same file and DID** for setup, introductions and later contributions.

## One command to start

Open a normal terminal, **not an administrator/root terminal**, on a computer you trust. Copy the command for your system. Both launch the same guided wizard; you do not need to install Python or Git yourself.

**Windows PowerShell 5.1 or 7:**

```powershell
& { $p = Join-Path ([IO.Path]::GetTempPath()) ('tc-onboard-' + [guid]::NewGuid() + '.ps1'); try { Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/0xMamareza/technocore-onboard/v1.0.0/install.ps1' -OutFile $p -ErrorAction Stop; powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p } finally { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force } } }
```

**Linux, macOS Terminal, WSL, or a Linux VPS (Bash/zsh):**

```bash
(set -e; p=$(mktemp); trap 'rm -f "$p"' EXIT; curl --fail --location --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 120 'https://raw.githubusercontent.com/0xMamareza/technocore-onboard/v1.0.0/install.sh' -o "$p"; bash "$p")
```

The shell command needs `curl`; the installer itself also supports `wget` for later downloads. Standard archive/checksum tools must be available. An unsupported or missing base tool produces an actionable error rather than an unverified download or automatic administrator command.

You are downloading and executing code from this repository's `v1.0.0` tag. [Review PowerShell](https://github.com/0xMamareza/technocore-onboard/blob/v1.0.0/install.ps1) or [review Bash](https://github.com/0xMamareza/technocore-onboard/blob/v1.0.0/install.sh) first if you prefer. The release provides SHA-256 checksums for manual comparison. A checksum-pinned application payload and uv archive protect those later downloads relative to the installer you trust; this does not protect against a compromised maintainer account or mutable tag.

The installer asks before downloading a private uv runtime, Python 3.12 and pinned binary dependencies. It does not change global Python, PATH, profiles or machine execution policy, request administrator access, or run sudo. Windows ARM64 uses Windows11 x64 emulation; Intel macOS follows Zun's `cryptography==48.0.1` pin, while other supported runtimes use `50.0.0`. The wizard separately asks before identity creation and before any public room POST. See [verification evidence](docs/VERIFICATION.md) for platform checks and limits.

### Review or preview before installing

From a downloaded/checked-out release folder:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Plan
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
```

```bash
bash ./install.sh --plan  # Preview only: no downloads, keys or posts.
bash ./install.sh         # Downloads require consent; setup remains interactive.
```

`-ExecutionPolicy Bypass` applies only to the launched process. WSL is Linux, not Windows. A VPS is a remote host, not a different operating system. See [the beginner walkthrough](docs/GUIDE.md).

## After installation: separate contribution command

The installer prints the exact absolute wrapper commands. No PATH change is necessary.

**PowerShell, default location:**

```powershell
& "$env:LOCALAPPDATA\TechnocoreOnboard\bin\tcproof.ps1" setup
& "$env:LOCALAPPDATA\TechnocoreOnboard\bin\tcproof.ps1" contribute
& "$env:LOCALAPPDATA\TechnocoreOnboard\bin\tcproof.ps1" doctor
& "$env:LOCALAPPDATA\TechnocoreOnboard\bin\tcproof.ps1" recover
```

If local policy blocks the wrapper, invoke it in a single process: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "ABSOLUTE-PATH-TO-tcproof.ps1" contribute`.

**POSIX, default location:**

```bash
"${XDG_DATA_HOME:-$HOME/.local/share}/technocore-onboard/bin/tcproof" contribute
"${XDG_DATA_HOME:-$HOME/.local/share}/technocore-onboard/bin/tcproof" doctor
"${XDG_DATA_HOME:-$HOME/.local/share}/technocore-onboard/bin/tcproof" recover
```

Custom installation roots use the exact paths printed by your installer. Wrappers always pass the installation **ROOT** as `--data-dir`; your current directory does not choose an identity.

## What each command does

- **`setup`** explains local/remote storage, then explicitly creates a new encrypted key once or imports an existing encrypted PEM without changing its DID. Passphrases are hidden, confirmed and at least 12 characters for creation. Re-running reuses the existing identity; missing keys or mismatched public state stop rather than silently replacing it. An introduction is optional, with its own exact public preview and default-no consent.
- **`contribute`** asks for work you already published. X uses the exact status/share URL, preserving its query. Other contributions use a public HTTPS URL, never fetched. GitHub uses only read-only public API requests to resolve your chosen full published commit (or default HEAD), then creates and locally verifies a Zun-compatible proof before asking about an announcement. No git installation, local checkout or GitHub token is required.
- **`doctor`** checks local public state, encrypted-key header, pending intents and receipt signatures offline. It does not ask for a passphrase or prove that an encrypted key matches the stored DID; unlocking in setup/contribute performs that binding check. `doctor --receipt PATH` verifies one public Inspector receipt offline.
- **`recover`** makes only bounded read-only Technocore requests to find exact signed pending records. It never reposts. Unknown remains unknown even after a search miss. Use `recover --intent FOLDER-NAME` to select an intent shown by doctor.

For every announcement the wizard shows the exact normalized public text, room, DID and resolved Git commit, if present. Only typing `yes` sends a POST. Pressing Enter cancels. Cancellation leaves a local Git proof available, but creates no post intent.

## Receipts and Inspector

The data root keeps application/runtime separate from private identity and public evidence:

```text
ROOT/
  app-v1.0.0/             reviewed code, never user data
  .venv/                 isolated runtime
  bin/                   absolute-path tcproof wrappers
  identity/identity.pem  encrypted private key: NEVER share or commit
  identity/did.txt       public identifier
  state.json             public DID only
  receipts/<record>/
    proof.json           public Git proof, where applicable
    proof-receipt.json   standard Inspector contribution receipt
    intent.json          public signed request + pending/posted status
    response.json        original POST response bytes, if received safely
    recovery-source.json exact selected public record + read-only source URL
    message-receipt.json standard Inspector message receipt
```

Import **`message-receipt.json`** or **`proof-receipt.json`** at <https://tcproof.vercel.app/>. Never select `identity.pem`. Inspector checks the signature locally; an explicit live-source check is separate. Git proof validity means the DID signed that URL and revision, not that a repository was changed or that the proof was publicly announced. Onboard never publishes proof files to GitHub for you.

A pending intent is saved **before** POST. On a timeout, interruption, invalid server reply or unavailable exact read-back, stop and run `recover`. Repeating the same URL or message offers the existing record instead of silently posting again. Do not delete pending evidence to bypass that protection.

## Run from source

Use Python 3.12 and a dedicated environment (the release installer provides both). No passphrase CLI argument or environment variable is accepted:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe .\onboard.py --data-dir "$env:LOCALAPPDATA\TechnocoreOnboard" setup
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python "$PWD/onboard.py" --data-dir "${XDG_DATA_HOME:-$HOME/.local/share}/technocore-onboard" setup
.venv/bin/python -m unittest discover -s tests -v
```

The direct entrypoint contract is `python /absolute/path/onboard.py --data-dir /absolute/ROOT setup|contribute|doctor|recover`. Put `--data-dir` **before** the subcommand. `--version` requires no identity, prompt or network. Interactive commands refuse non-terminals before key material is accessed. Exit codes: 0 for success/ordinary cancellation, 1 for checks that need attention or an unknown POST outcome, 130 for Ctrl+C/EOF.

See [SECURITY.md](SECURITY.md), [PROVENANCE.md](docs/PROVENANCE.md), [RECOVERY.md](docs/RECOVERY.md) and [VERIFICATION.md](docs/VERIFICATION.md). Local core tests use disposable synthetic keys and simulated HTTP; they never create your real identity or publish anything.
