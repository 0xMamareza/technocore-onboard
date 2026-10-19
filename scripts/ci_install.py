#!/usr/bin/env python3
"""Consent-authorized CI audit: private downloads, real payload, no wizard/identity/post."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
from package_release import package


def run(command, expected=0):
    p = subprocess.run([str(arg) for arg in command], stdin=subprocess.DEVNULL, capture_output=True, text=True, errors='replace', timeout=600)
    print(p.stdout, end='')
    print(p.stderr, end='', file=sys.stderr)
    if p.returncode != expected:
        raise RuntimeError('Unexpected command exit code: ' + str(p.returncode))
    return p.stdout + p.stderr


def main():
    repo = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="tc real payload ' ") as temp:
        temp = Path(temp)
        archive = temp / 'technocore-onboard.zip'
        digest = package(repo, archive)
        # Exercise default LOCALAPPDATA/XDG_DATA_HOME resolution, including spaces, not --root.
        if os.name == 'nt':
            os.environ['LOCALAPPDATA'] = str(temp / 'Local App Data')
            root = Path(os.environ['LOCALAPPDATA']) / 'TechnocoreOnboard'
            shell = shutil.which('powershell.exe')
            if not shell:
                raise RuntimeError('Native Windows PowerShell 5.1 required')
            run([shell, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', repo / 'install.ps1', '-Yes', '-NoRun', '-PayloadPath', archive, '-PayloadSha256', digest])
            wrapper = [shell, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', root / 'bin/tcproof.ps1']
        else:
            os.environ['XDG_DATA_HOME'] = str(temp / 'XDG Data Home')
            root = Path(os.environ['XDG_DATA_HOME']) / 'technocore-onboard'
            bash = '/bin/bash' if sys.platform == 'darwin' else 'bash'
            run([bash, repo / 'install.sh', '--yes', '--no-run', '--payload-path', archive, '--payload-sha256', digest])
            wrapper = [root / 'bin/tcproof']
        assert '1.0.0' in run(wrapper + ['--version'])
        # A fresh install correctly diagnoses missing identity/state with nonzero status.
        output = run(wrapper + ['doctor'], expected=1)
        assert 'identity missing' in output.lower()
        assert not (root / 'identity').exists()
        assert not (root / 'state.json').exists()
        assert not (root / 'receipts').exists()
        assert not (root / '.install.lock').exists()
        # Real CLI must reject non-TTY setup before any keys/state can be created.
        output = run(wrapper + ['setup'], expected=1)
        assert 'terminal' in output.lower()
        assert not (root / 'identity').exists()
        assert not (root / 'state.json').exists()
        print('real payload install + offline doctor passed; no identity, receipt or state created')


if __name__ == '__main__':
    main()
