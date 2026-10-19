#!/usr/bin/env python3
"""Build only the allowlisted application payload; never include identities or environments."""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import re
import stat
import tempfile
import zipfile

REQUIRED = {'onboard.py', 'vendor/technocore_agent.py', 'vendor/LICENSE', 'requirements.txt', 'README.md', 'LICENSE', 'SECURITY.md'}
SECRET = re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?m:^-----BEGIN ENCRYPTED PRIVATE KEY-----)|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,}|AKIA[A-Z0-9]{16}')


def assert_plain_path(path: Path) -> None:
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, 'is_junction') and part.is_junction()):
            raise ValueError('Source/output symlink or junction is refused: ' + str(part))


def package(source: Path, output: Path) -> str:
    source, output = source.absolute(), output.absolute()
    assert_plain_path(source)
    assert_plain_path(output)
    names = set(REQUIRED)
    docs = source / 'docs'
    assert_plain_path(docs)
    if docs.exists():
        for path in docs.iterdir():
            if path.suffix == '.md':
                if not re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_.-]*\.md', path.name) or re.match(r'(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])\.', path.name):
                    raise ValueError('Unsafe documentation filename')
                names.add('docs/' + path.name)
    if len(names) > 200:
        raise ValueError('Payload entry limit')
    files = {}
    for name in sorted(names):
        path = source / name
        assert_plain_path(path)
        if not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
            raise ValueError('Missing or special payload source: ' + name)
        if path.stat().st_size > 20 * 1024 * 1024:
            raise ValueError('Payload file size limit')
        data = path.read_bytes()
        if SECRET.search(data):
            raise ValueError('Potential secret in release source: ' + name)
        files[name] = data
    if sum(map(len, files.values())) > 20 * 1024 * 1024:
        raise ValueError('Payload size limit')
    if files['requirements.txt'] != (b'cryptography==50.0.0; sys_platform != "darwin" or platform_machine == "arm64"\n'
                                      b'cryptography==48.0.1; sys_platform == "darwin" and platform_machine == "x86_64"\n'):
        raise ValueError('Unexpected dependency pin')
    output.parent.mkdir(parents=True, exist_ok=True)
    # Same-directory staging makes replacement atomic, and leaves a prior artifact intact on scan failure.
    with tempfile.TemporaryDirectory(prefix='.package-', dir=output.parent) as temp:
        stage = Path(temp) / 'payload.zip'
        with zipfile.ZipFile(stage, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for name, data in files.items():
                entry = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | 0o644) << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(entry, data, compresslevel=9)
        with zipfile.ZipFile(stage) as z:
            if z.testzip() is not None or set(z.namelist()) != names:
                raise ValueError('Payload CRC/content validation failed')
            for name in names:
                if z.read(name) != files[name]:
                    raise ValueError('Payload content differs from source')
        digest = hashlib.sha256(stage.read_bytes()).hexdigest()
        stage.replace(output)
        sidecar = output.with_suffix(output.suffix + '.sha256')
        assert_plain_path(sidecar)
        staged_hash = Path(temp) / 'sha256'
        staged_hash.write_text(digest + '  ' + output.name + '\n', encoding='ascii')
        staged_hash.replace(sidecar)
    return digest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        digest = package(args.source, args.output)
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        parser.exit(1, str(exc) + '\n')
    print(digest + '  ' + str(args.output))
    print('CRC/content and allowlist scan passed. Review source independently; pattern scanning cannot prove absence of all secrets.')


if __name__ == '__main__':
    main()
