#!/usr/bin/env bash
set -euo pipefail
ROOT="${XDG_DATA_HOME:-$HOME/.local/share}/technocore-onboard"
PLAN=0; YES=0; NO_RUN=0; PAYLOAD_PATH=''; PAYLOAD_SHA256=''
while (($#)); do
    case "$1" in
        --plan) PLAN=1 ;;
        --yes) YES=1 ;;
        --no-run) NO_RUN=1 ;;
        --root|--payload-path|--payload-sha256)
            [[ $# -ge 2 ]] || { printf 'Missing value for %s\n' "$1" >&2; exit 1; }
            case "$1" in --root) ROOT=$2;; --payload-path) PAYLOAD_PATH=$2;; --payload-sha256) PAYLOAD_SHA256=$2;; esac
            shift ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; exit 1 ;;
    esac
    shift
done
if ((PLAN)); then
    printf '%s\n' "Technocore Onboard 1.0.0; root: $ROOT" \
        'Download checksum-pinned private uv 0.13.1, managed Python 3.12; isolated .venv; cryptography==50.0.0 (Intel macOS: cryptography==48.0.1). No system/PATH/profile changes.' \
        'Explicit consent is required before downloads. Setup separately asks before identity creation or public posting.'
    exit 0
fi
extract_payload() {
    "$PYTHON" -I - "$1" "$2" <<'TC_ARCHIVE_PY'
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import zipfile
archive, dest = Path(sys.argv[1]), Path(sys.argv[2])
required = {'onboard.py', 'vendor/technocore_agent.py', 'vendor/LICENSE', 'requirements.txt', 'README.md', 'LICENSE', 'SECURITY.md'}
seen = set()
with zipfile.ZipFile(archive) as z:
    entries = z.infolist()
    if not entries or len(entries) > 200 or sum(e.file_size for e in entries) > 20 * 1024 * 1024:
        raise SystemExit('Unsafe payload: size or entry limit')
    for e in entries:
        name = e.orig_filename  # zipfile normalizes backslashes on Windows; validate the raw spelling
        parts = name.rstrip('/').split('/')
        if (not name or '\\' in name or any(not re.fullmatch(r'[A-Za-z0-9_.-]+', p) or p in {'.', '..'} or p.endswith('.') or re.match(r'(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)', p) for p in parts)):
            raise SystemExit('Unsafe payload path: ' + repr(name))
        if name.lower() in seen:
            raise SystemExit('Unsafe payload: case collision')
        seen.add(name.lower())
        mode = (e.external_attr >> 16) & 0xFFFF
        if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR) or bool(mode & stat.S_IFDIR) != e.is_dir() and stat.S_IFMT(mode) != 0:
            raise SystemExit('Unsafe payload: symlink or special entry')
        allowed = name in required or (len(parts) == 2 and parts[0] == 'docs' and name.endswith('.md')) or name in {'vendor/', 'docs/'}
        if not allowed or e.flag_bits & 1:
            raise SystemExit('Unexpected or encrypted payload entry: ' + repr(name))
    if not required.issubset({e.filename for e in entries if not e.is_dir()}):
        raise SystemExit('Incomplete payload')
    if z.read('requirements.txt') != (b'cryptography==50.0.0; sys_platform != "darwin" or platform_machine == "arm64"\n'
                                       b'cryptography==48.0.1; sys_platform == "darwin" and platform_machine == "x86_64"\n'):
        raise SystemExit('Unexpected dependency requirements')
    if z.testzip() is not None:
        raise SystemExit('Payload CRC failure')
    secret = re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?m:^-----BEGIN ENCRYPTED PRIVATE KEY-----)|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,}|AKIA[A-Z0-9]{16}')
    for e in entries:
        if not e.is_dir() and secret.search(z.read(e)):
            raise SystemExit('Potential secret in payload: ' + e.filename)
    if dest.exists() or dest.is_symlink():
        raise SystemExit('Extraction destination already exists')
    dest.mkdir(mode=0o700)
    for e in entries:
        target = dest.joinpath(*e.filename.rstrip('/').split('/'))
        if e.is_dir():
            target.mkdir(mode=0o700, exist_ok=True)
        else:
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with z.open(e) as src, target.open('xb') as out:
                shutil.copyfileobj(src, out)
            target.chmod(0o600)
TC_ARCHIVE_PY
}
fail() { printf '%s\n' "$*" >&2; exit 1; }
safe_path() {
    local p=$1
    while [[ -n "$p" && "$p" != / ]]; do
        [[ ! -L "$p" ]] || fail "Unsafe symlink path: $p"
        p=${p%/*}
    done
}
sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d ' ' -f 1
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d ' ' -f 1
    elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 "$1" | sed 's/^.*= //'
    else fail 'SHA256 verification unavailable. Provide sha256sum, shasum or openssl; no files will be executed.'; fi
}
# bash reading a piped installer must never consume wizard answers from the script pipe.
if (( !NO_RUN )); then
    [[ -t 1 ]] || fail 'Setup requires a real terminal; use --yes --no-run for an installation audit.'
    { exec 3<>/dev/tty; } 2>/dev/null || fail 'Setup requires a real terminal; use --yes --no-run for an installation audit.'
fi
[[ "$ROOT" == /* && "$ROOT" != *//* && "$ROOT" != / && "$ROOT" != "$HOME" && "$ROOT" != *$'\n'* && "$ROOT" != *$'\r'* && "$ROOT" != */../* && "$ROOT" != */./* && "$ROOT" != */.. && "$ROOT" != */. ]] || fail 'Unsafe install root; choose an absolute private directory.'
ROOT=${ROOT%/}
safe_path "$ROOT"
if [[ -e "$ROOT" ]]; then
    [[ -d "$ROOT" && -O "$ROOT" && ! -L "$ROOT/.bootstrap-owner" && -f "$ROOT/.bootstrap-owner" ]] || fail 'Refusing unmanaged existing root. Choose a new private directory.'
    [[ $(<"$ROOT/.bootstrap-owner") == technocore-onboard-v1 ]] || fail 'Refusing unmanaged existing root.'
fi
if [[ -n "$PAYLOAD_PATH" || -n "$PAYLOAD_SHA256" ]]; then
    [[ -n "$PAYLOAD_PATH" && -n "$PAYLOAD_SHA256" ]] || fail '--payload-path and --payload-sha256 must be supplied together.'
    [[ "$PAYLOAD_PATH" == /* && -f "$PAYLOAD_PATH" ]] || fail 'Local payload must be an explicit existing absolute file path.'
    safe_path "$PAYLOAD_PATH"
    [[ "$PAYLOAD_SHA256" =~ ^[a-fA-F0-9]{64}$ && $(sha256_file "$PAYLOAD_PATH") == "$(printf '%s' "$PAYLOAD_SHA256" | tr 'A-F' 'a-f')" ]] || fail 'Payload checksum mismatch; nothing installed.'
fi
download_verified() {
    local url=$1 dest=$2 expected=$3
    [[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || fail 'Release checksum is not finalized. Use a published release installer or explicit local audit artifact flags.'
    [[ "$url" == https://* ]] || fail 'Downloads require HTTPS.'
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 180 --retry 2 --silent --show-error --output "$dest" "$url" || fail "Download failed: $url. Check HTTPS connectivity/proxy and retry."
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only --timeout=30 --tries=3 -q -O "$dest" "$url" || fail "Download failed: $url. Check HTTPS connectivity/proxy and retry."
    else fail 'No HTTPS downloader found. Provide curl or wget and retry; no executable was downloaded.'; fi
    [[ $(sha256_file "$dest") == "$expected" ]] || fail "Download checksum mismatch: $url; refusing execution."
}
case "$(uname -s):$(uname -m)" in
    Linux:x86_64|Linux:aarch64|Linux:arm64)
        command -v getconf >/dev/null 2>&1 && getconf GNU_LIBC_VERSION >/dev/null 2>&1 || fail 'Unsupported Linux C library (glibc required; Alpine/musl is not supported).'
        case "$(uname -m)" in
            x86_64) ASSET=uv-x86_64-unknown-linux-gnu.tar.gz; UV_SHA=eadd9d27c134ab5ac1ffd4473b97a741407f3ea238288f03121fc4deddf90220 ;;
            *) ASSET=uv-aarch64-unknown-linux-gnu.tar.gz; UV_SHA=9041c73c99fdc5892cf128140beb354eca9231d502068cc36e6cb53a8e59ad14 ;;
        esac ;;
    Darwin:x86_64) ASSET=uv-x86_64-apple-darwin.tar.gz; UV_SHA=bb7b805bdcf3d0bc8c74ceb94569e6b3e8aa35bd492acdbb9d46bf46d9d4ff6b ;;
    Darwin:arm64|Darwin:aarch64) ASSET=uv-aarch64-apple-darwin.tar.gz; UV_SHA=cfe454573412ff7380d15fc7dae5997ab53ffce72fce0a78e91ddbc84001acd2 ;;
    *) fail "Unsupported OS/architecture: $(uname -s)/$(uname -m). Use native Windows install.ps1, glibc Linux or macOS x64/ARM64." ;;
esac
command -v tar >/dev/null 2>&1 || fail 'tar is required for the verified private uv archive. Provide tar and retry.'
printf '%s\n' "Technocore Onboard installs only inside: $ROOT" \
    'Downloads: checksum-pinned private uv 0.13.1 (GitHub), managed Python 3.12 (GitHub), cryptography==50.0.0 (Intel macOS: cryptography==48.0.1) and binary dependencies (PyPI).' \
    'No sudo, system Python, PATH/profile changes, identity creation or public posting by the installer.'
if ((!YES)); then
    [[ -t 1 ]] || fail 'Dependency download consent requires a terminal; audit use: --yes --no-run.'
    if ((!NO_RUN)); then :; else { exec 3<>/dev/tty; } 2>/dev/null || fail 'Dependency download consent requires a terminal.'; fi
    printf 'Allow these private dependency downloads? Type yes to continue: ' >&3
    IFS= read -r answer <&3 || fail 'No download consent received.'
    [[ "$answer" == yes ]] || { printf 'Cancelled; nothing installed.\n'; exit 0; }
fi
RELEASE_SHA='9b99c535f8b9c969cbba283568eb80409cae2576b5069a48babe37c5c6b8368a'
RELEASE_URL='https://github.com/0xMamareza/technocore-onboard/releases/download/v1.0.0/technocore-onboard.zip'
[[ -n "$PAYLOAD_PATH" || "$RELEASE_SHA" =~ ^[a-fA-F0-9]{64}$ ]] || fail 'Release checksum is not finalized. Use a published release installer or explicit local audit artifact flags.'
umask 077
mkdir -p "$ROOT"
chmod 700 "$ROOT"
if [[ ! -e "$ROOT/.bootstrap-owner" ]]; then printf 'technocore-onboard-v1\n' > "$ROOT/.bootstrap-owner"; fi
safe_path "$ROOT/.install.lock"
mkdir "$ROOT/.install.lock" 2>/dev/null || fail 'Installation lock exists. Ensure no other installer is running; remove only .install.lock after interruption.'
STAGE=''
cleanup() {
    if [[ -n "$STAGE" && -d "$STAGE" && ! -L "$STAGE" ]]; then rm -rf "$STAGE"; fi
    rmdir "$ROOT/.install.lock" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
validate_private_links() {
    local folder=$1 link target value parent steps
    [[ -d "$folder" ]] || return 0
    while IFS= read -r -d '' link; do
        target=$link; steps=0
        while [[ -L "$target" ]]; do
            steps=$((steps + 1))
            ((steps <= 40)) || fail 'Unsafe runtime symlink cycle.'
            value=$(readlink "$target") || fail 'Cannot inspect runtime symlink; readlink is required.'
            if [[ "$value" == /* ]]; then target=$value; else target="${target%/*}/$value"; fi
            parent=$(cd -P "${target%/*}" && pwd -P) || fail 'Unsafe broken runtime symlink.'
            target="$parent/${target##*/}"
            if [[ -d "$target" && ! -L "$target" ]]; then target=$(cd -P "$target" && pwd -P); fi
            [[ "$target" == "$ROOT/runtime/"* || "$target" == "$ROOT/.venv/"* ]] || fail "Unsafe runtime symlink target outside private runtime: $link"
        done
        [[ -e "$target" ]] || fail 'Unsafe broken runtime symlink.'
    done < <(find "$folder" -type l -print0)
}
for name in runtime .venv bin app-v1.0.0; do
    safe_path "$ROOT/$name"
    if [[ "$name" == runtime || "$name" == .venv ]]; then
        validate_private_links "$ROOT/$name"
    elif [[ -d "$ROOT/$name" ]] && [[ -n $(find "$ROOT/$name" -type l -print -quit) ]]; then
        fail "Unsafe managed-tree symlink: $name"
    fi
done
safe_path "$ROOT/runtime/python"
safe_path "$ROOT/runtime/cache"
safe_path "$ROOT/.venv/bin"
STAGE=$(mktemp -d "$ROOT/.stage-XXXXXXXX")
if [[ -n "$PAYLOAD_PATH" ]]; then
    cp "$PAYLOAD_PATH" "$STAGE/payload.zip"
    EXPECTED=$(printf '%s' "$PAYLOAD_SHA256" | tr 'A-F' 'a-f')
else
    download_verified "$RELEASE_URL" "$STAGE/payload.zip" "$RELEASE_SHA"
    EXPECTED=$RELEASE_SHA
fi
[[ $(sha256_file "$STAGE/payload.zip") == "$EXPECTED" ]] || fail 'Payload checksum mismatch after staging.'
download_verified "https://github.com/astral-sh/uv/releases/download/0.13.1/$ASSET" "$STAGE/uv.tar.gz" "$UV_SHA"
mkdir "$STAGE/uv"
# Only the checksum-verified official uv archive is passed to tar.
tar -xzf "$STAGE/uv.tar.gz" -C "$STAGE/uv"
UV="$STAGE/uv/${ASSET%.tar.gz}/uv"
[[ -f "$UV" && ! -L "$UV" ]] || fail 'Verified uv archive did not contain the expected executable.'
[[ $("$UV" --version) == 'uv 0.13.1'* ]] || fail 'Unexpected private uv version.'
export UV_PYTHON_INSTALL_DIR="$ROOT/runtime/python"
export UV_CACHE_DIR="$ROOT/runtime/cache"
export UV_PYTHON_PREFERENCE=only-managed UV_PYTHON_DOWNLOADS=automatic UV_NO_CONFIG=1 UV_NO_PROGRESS=1 UV_SYSTEM_CERTS=true
PYTHON="$ROOT/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
    [[ ! -e "$ROOT/.venv" ]] || fail 'Incomplete .venv exists; move only that directory aside and retry. Identity/data are unaffected.'
    "$UV" venv --python 3.12 "$ROOT/.venv" || fail 'Private Python/venv setup failed; check download connectivity.'
fi
"$PYTHON" -I -c 'import sys; assert sys.version_info[:2] == (3,12) and sys.prefix != sys.base_prefix' || fail 'Private venv is not isolated Python 3.12.'
extract_payload "$STAGE/payload.zip" "$STAGE/app"
APP="$ROOT/app-v1.0.0"
if [[ -e "$APP" ]]; then
    "$PYTHON" -I - "$STAGE/app" "$APP" <<'TC_COMPARE_PY'
from pathlib import Path
import hashlib
import sys
def tree(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).digest() for p in Path(root).rglob('*') if p.is_file()}
if tree(sys.argv[1]) != tree(sys.argv[2]):
    raise SystemExit('Existing versioned app differs; refusing to overwrite it.')
TC_COMPARE_PY
fi
"$UV" pip install --python "$PYTHON" --index-url https://pypi.org/simple --only-binary :all: -r "$STAGE/app/requirements.txt" || fail 'Private dependency installation failed; no wizard started.'
"$PYTHON" -I -c 'import cryptography, sys, platform; expected = "48.0.1" if sys.platform == "darwin" and platform.machine() == "x86_64" else "50.0.0"; assert cryptography.__version__ == expected' || fail 'cryptography version verification failed.'
if [[ ! -e "$APP" ]]; then mv "$STAGE/app" "$APP"; fi
mkdir -p "$ROOT/bin"
safe_path "$ROOT/bin/tcproof"
{
    printf '#!/usr/bin/env bash\n# Private runtime; no activation or PATH changes.\n'
    printf 'exec %q -B -E -s %q --data-dir %q "$@"\n' "$PYTHON" "$APP/onboard.py" "$ROOT"
} > "$STAGE/tcproof"
chmod 700 "$STAGE/tcproof"
mv -f "$STAGE/tcproof" "$ROOT/bin/tcproof"
printf 'Installed. No identity or public post was created.\nContribute: %q contribute\nDoctor: %q doctor\n' "$ROOT/bin/tcproof" "$ROOT/bin/tcproof"
if ((!NO_RUN)); then
    cleanup
    trap - EXIT
    # Restore the controlling terminal, not the exhausted curl|bash script stream.
    exec "$PYTHON" -B -E -s "$APP/onboard.py" --data-dir "$ROOT" setup <&3
fi
