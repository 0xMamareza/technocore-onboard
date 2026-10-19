"""Local installer regression tests; no identity creation or public writes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

REPO = Path(__file__).resolve().parents[1]
PS = (shutil.which('powershell.exe') or shutil.which('pwsh')) if os.name == 'nt' else None
BASH = ('/bin/bash' if sys.platform == 'darwin' else shutil.which('bash')) if os.name != 'nt' else None
REQUIREMENTS = ('cryptography==50.0.0; sys_platform != "darwin" or platform_machine == "arm64"\n'
                'cryptography==48.0.1; sys_platform == "darwin" and platform_machine == "x86_64"\n')
CRYPTO_VERSION = '48.0.1' if sys.platform == 'darwin' and __import__('platform').machine() == 'x86_64' else '50.0.0'


class BootstrapPlans(unittest.TestCase):
    @unittest.skipUnless(PS, 'native Windows runtime selection')
    def test_windows_arm_deliberately_selects_x64_runtime(self):
        text = (REPO / 'install.ps1').read_text(encoding='utf-8')
        selection = '$arch = $env:' + text.split('$arch = $env:', 1)[1].split('Write-Output "Technocore Onboard installs only inside:', 1)[0]
        p = subprocess.run([PS, '-NoProfile', '-Command', "$ErrorActionPreference='Stop'; $env:PROCESSOR_ARCHITEW6432='ARM64'; " + selection + '; Write-Output $asset; Write-Output $PythonRequest'], capture_output=True, text=True, errors='replace')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('uv-x86_64-pc-windows-msvc.zip', p.stdout)
        self.assertIn('cpython-3.12-windows-x86_64-none', p.stdout)
        self.assertIn('emulation', p.stdout.lower())

    @unittest.skipUnless(PS, 'native Windows host policy checks')
    def test_windows_unsupported_host_fails_before_installation(self):
        text = (REPO / 'install.ps1').read_text(encoding='utf-8')
        selection = '$arch = $env:' + text.split('$arch = $env:', 1)[1].split('Write-Output "Technocore Onboard installs only inside:', 1)[0]
        for arch, build in [('x86', '26200'), ('ARM64', '19045')]:
            with self.subTest(arch=arch, simulated_build=build):
                # Policy simulation, not evidence of execution on ARM hardware.
                code = selection.replace('[Environment]::OSVersion.Version.Build', build)
                p = subprocess.run([PS, '-NoProfile', '-Command', "$ErrorActionPreference='Stop'; $env:PROCESSOR_ARCHITEW6432='" + arch + "'; " + code], capture_output=True, text=True, errors='replace')
                self.assertNotEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertIn('Unsupported Windows', p.stdout + p.stderr)

    def test_installers_use_exact_platform_requirements_and_validate_runtime(self):
        self.assertEqual((REPO / 'requirements.txt').read_bytes(), REQUIREMENTS.encode())
        sh = (REPO / 'install.sh').read_text()
        ps = (REPO / 'install.ps1').read_text()
        self.assertIn('--only-binary :all: -r "$STAGE/app/requirements.txt"', sh)
        self.assertIn('"48.0.1"', sh)
        self.assertIn('--only-binary :all: -r (Join-Path $stagedApp', ps)
        self.assertIn('--python $PythonRequest', ps)
        self.assertIn('sysconfig.get_platform()', ps)
        self.assertIn('win-amd64', ps)

    def test_posix_plan_needs_no_download_or_root(self):
        if not BASH:
            self.skipTest('native POSIX bash required (run this test in WSL)')
        with tempfile.TemporaryDirectory(prefix='tc plan ') as temp:
            root = Path(temp) / 'not created'
            p = subprocess.run([BASH, str(REPO / 'install.sh'), '--plan', '--root', str(root)], capture_output=True, text=True, errors='replace')
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn('cryptography==50.0.0', p.stdout)
            self.assertIn(str(root), p.stdout)
            self.assertFalse(root.exists())

    @unittest.skipUnless(PS, 'PowerShell unavailable')
    def test_powershell_plan_needs_no_download_or_root(self):
        with tempfile.TemporaryDirectory(prefix='tc plan ') as temp:
            root = Path(temp) / 'not created'
            p = subprocess.run([PS, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(REPO / 'install.ps1'), '-Plan', '-Root', str(root)], capture_output=True, text=True, errors='replace')
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn('cryptography==50.0.0', p.stdout)
            self.assertIn(str(root), p.stdout)
            self.assertFalse(root.exists())


def posix_archive_code():
    text = (REPO / 'install.sh').read_text(encoding='utf-8')
    return text.split("<<'TC_ARCHIVE_PY'\n", 1)[1].split('\nTC_ARCHIVE_PY', 1)[0]


VALID_ENTRIES = [('onboard.py', 'safe'), ('requirements.txt', REQUIREMENTS), ('vendor/technocore_agent.py', 'safe'), ('vendor/LICENSE', 'license'), ('README.md', 'readme'), ('LICENSE', 'license'), ('SECURITY.md', 'security')]


class ArchiveBoundaries(unittest.TestCase):
    def check_archive(self, entries, good=False, failure=None):
        with tempfile.TemporaryDirectory(prefix='tc archive ') as temp:
            archive = Path(temp) / 'payload.zip'
            dest = Path(temp) / 'stage'
            with zipfile.ZipFile(archive, 'w') as z:
                for name, value in entries:
                    if isinstance(name, str):
                        entry = zipfile.ZipInfo('placeholder')
                        entry.filename = name  # preserve malicious separators even on Windows
                        name = entry
                    z.writestr(name, value)
            commands = [[sys.executable, '-I', '-c', posix_archive_code(), str(archive), str(dest)]]
            if PS:
                text = (REPO / 'install.ps1').read_text(encoding='utf-8')
                code = text.split('# BEGIN SAFE ARCHIVE\n', 1)[1].split('# END SAFE ARCHIVE', 1)[0]
                quote = lambda s: "'" + str(s).replace("'", "''") + "'"
                commands.append([PS, '-NoProfile', '-Command', "$ErrorActionPreference='Stop'; " + code + '; Expand-SafePayload ' + quote(archive) + ' ' + quote(dest)])
            for command in commands:
                if dest.exists():
                    shutil.rmtree(dest)
                proc = subprocess.run(command, capture_output=True, text=True, errors='replace')
                if good:
                    self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    self.assertEqual((dest / 'onboard.py').read_text(), 'safe')
                else:
                    self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    self.assertIsNotNone(failure, 'negative tests must assert the specific validation failure')
                    self.assertIn(failure.lower(), (proc.stdout + proc.stderr).lower())
                    self.assertFalse(dest.exists(), 'validation must finish before any extraction')

    def test_archive_valid_payload(self):
        self.check_archive(VALID_ENTRIES, good=True)

    def test_archive_rejects_unsafe_entries(self):
        for name in ['../escape', '/escape', 'C:/escape', 'vendor\\escape', 'vendor/../escape', 'docs/CON.md', 'docs/ads:stream.md', 'docs/trailing .md/evil', 'docs/./evil.md', 'docs//evil.md', 'docs/trailing.md.', 'docs/NUL.md']:
            with self.subTest(name=name):
                self.check_archive(VALID_ENTRIES + [(name, 'bad')], failure='Unsafe payload path')
        for name in ['identity/key.pem', 'vendor/evil.py', '.env', 'state.json']:
            with self.subTest(name=name):
                self.check_archive(VALID_ENTRIES + [(name, 'bad')], failure='Unexpected')

    def test_archive_rejects_symlinks(self):
        for mode in [0o120777, 0o010600, 0o020600]:
            with self.subTest(mode=oct(mode)):
                link = zipfile.ZipInfo('docs/link.md')
                link.create_system = 3
                link.external_attr = mode << 16
                self.check_archive(VALID_ENTRIES + [(link, '../../escape')], failure='symlink or special entry')

    def test_archive_rejects_case_collisions(self):
        self.check_archive(VALID_ENTRIES + [('readme.md', 'bad')], failure='case collision')
        self.check_archive(VALID_ENTRIES + [('docs/guide.md', 'safe'), ('docs/GUIDE.md', 'bad')], failure='case collision')

    def test_archive_rejects_secret_inside_allowed_file(self):
        for secret in ['-----BEGIN PRIVATE KEY-----\nsynthetic\n', '-----BEGIN ENCRYPTED PRIVATE KEY-----\nsynthetic\n', 'ghp_' + 'A' * 36]:
            with self.subTest(secret_type=secret[:30]):
                self.check_archive(VALID_ENTRIES + [('docs/leak.md', secret)], failure='secret')

    def test_archive_rejects_modified_dependency_markers(self):
        for requirements in ['cryptography==50.0.0\n', REQUIREMENTS.replace('48.0.1', '50.0.0'), REQUIREMENTS.replace('\n', '\r\n'), '\ufeff' + REQUIREMENTS]:
            entries = [(name, requirements if name == 'requirements.txt' else value) for name, value in VALID_ENTRIES]
            self.check_archive(entries, failure='Unexpected dependency requirements')


def _piped_installer_pty(script, env, timeout=15):
    """Run only in a fresh helper: forkpty must not inherit the test runner's state."""
    import errno
    import select
    import signal
    import time

    reader, writer = os.pipe()
    pid, master = os.forkpty()
    if pid == 0:
        try:
            os.close(writer)
            os.tcsetpgrp(0, os.getpgrp())
            tty = os.open('/dev/tty', os.O_RDWR)
            assert os.tcgetpgrp(tty) == os.getpgrp()
            os.close(tty)
            os.write(1, b'FIXTURE_SLAVE:' + os.ttyname(0).encode() + b'\n')
            os.dup2(reader, 0)
            os.close(reader)
            os.execve(BASH, [BASH, '-s'], env)
        finally:
            os._exit(127)

    # The outer watchdog can clean up this exact disposable group if needed.
    print(pid, file=sys.stderr, flush=True)
    os.close(reader)
    slave = None
    status = None
    output = b''
    cancel_sent = False
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.05)[0]:
                try:
                    chunk = os.read(master, 4096)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    chunk = b''
                output += chunk
                if slave is None and b'FIXTURE_SLAVE:' in output and b'\n' in output:
                    name = output.split(b'FIXTURE_SLAVE:', 1)[1].split(b'\n', 1)[0].rstrip(b'\r')
                    # Deliberately hold the slave: completion cannot rely on EOF.
                    slave = os.open(os.fsdecode(name), os.O_RDWR | os.O_NOCTTY)
                    os.write(writer, script.encode())
                    os.close(writer)
                    writer = None
                if not cancel_sent and any(line.rstrip(b'\r') == b'SYNTHETIC_READY'
                                           for line in output.split(b'\n')[:-1]):
                    os.write(master, b'cancel\n')
                    cancel_sent = True
            reaped, child_status = os.waitpid(pid, os.WNOHANG)
            if reaped:
                status = child_status
                # The slave is still held, so drain only currently available data.
                while time.monotonic() < deadline and select.select([master], [], [], 0)[0]:
                    output += os.read(master, 4096)
                return {'returncode': os.waitstatus_to_exitcode(status),
                        'output': output.decode(errors='replace'), 'cancel_sent': cancel_sent}
        raise TimeoutError('PTY fixture deadline exceeded: ' + output.decode(errors='replace'))
    finally:
        # Native macOS hung reaping a killed child while these PTYs were open.
        for fd in (writer, slave, master):
            if fd is not None:
                os.close(fd)
        if status is None:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            cleanup_deadline = time.monotonic() + 2
            while time.monotonic() < cleanup_deadline:
                if os.waitpid(pid, os.WNOHANG)[0]:
                    break
                time.sleep(0.01)
            else:
                raise TimeoutError('PTY fixture child was not reaped within cleanup deadline')


def _run_piped_installer_pty(script, env, timeout=15):
    # A fresh interpreter avoids fork-unsafe native state from earlier tests on macOS.
    entry = ('import importlib.util,json,sys; '
             'spec=importlib.util.spec_from_file_location("pty_fixture",sys.argv[1]); '
             'module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); '
             'request=json.load(sys.stdin); '
             'print(json.dumps(module._piped_installer_pty(**request)))')
    p = subprocess.Popen([sys.executable, '-I', '-c', entry, str(Path(__file__).resolve())],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)
    try:
        stdout, stderr = p.communicate(json.dumps({'script': script, 'env': env, 'timeout': timeout}),
                                       timeout=timeout + 5)
        return subprocess.CompletedProcess(p.args, p.returncode, stdout, stderr)
    except subprocess.TimeoutExpired as exc:
        import signal
        # forkpty creates a separate session; kill only its reported disposable group.
        child_pid = (exc.stderr or b'').splitlines()[:1]
        if child_pid and child_pid[0].isdigit():
            try:
                os.killpg(int(child_pid[0]), signal.SIGKILL)
            except ProcessLookupError:
                pass
        raise
    finally:
        if p.poll() is None:
            p.kill()
            p.communicate(timeout=2)


class InstallerBoundaries(unittest.TestCase):
    def commands(self, root, payload=None, digest=None, consent=True, no_run=True):
        if PS:
            args = [PS, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(REPO / 'install.ps1'), '-Root', str(root)]
            if consent: args += ['-Yes']
            if no_run: args += ['-NoRun']
            if payload: args += ['-PayloadPath', str(payload), '-PayloadSha256', digest]
            yield args
        if BASH:
            args = [BASH, str(REPO / 'install.sh'), '--root', str(root)]
            if consent: args += ['--yes']
            if no_run: args += ['--no-run']
            if payload: args += ['--payload-path', str(payload), '--payload-sha256', digest]
            yield args

    def test_bad_checksum_fails_without_installing(self):
        with tempfile.TemporaryDirectory(prefix='tc sha ') as temp:
            root = Path(temp) / 'private root'
            archive = Path(temp) / 'payload.zip'
            archive.write_bytes(b'not a real payload')
            for cmd in self.commands(root, archive, '0' * 64):
                p = subprocess.run(cmd, capture_output=True, text=True, errors='replace', timeout=30)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('checksum', (p.stdout + p.stderr).lower())
                self.assertFalse(root.exists())

    def test_nonterminal_cannot_start_wizard(self):
        with tempfile.TemporaryDirectory(prefix='tc tty ') as temp:
            root = Path(temp) / 'private root'
            for cmd in self.commands(root, no_run=False):
                p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, errors='replace', timeout=20)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('terminal', (p.stdout + p.stderr).lower())
                self.assertFalse(root.exists())

    @unittest.skipUnless(BASH, 'native POSIX controlling-terminal test')
    def test_piped_installer_hands_wizard_the_real_terminal(self):
        with tempfile.TemporaryDirectory(prefix='tc tty handoff ') as temp:
            app = Path(temp) / 'app'
            app.mkdir()
            (app / 'onboard.py').write_text(
                "import os, sys, termios, time\n"
                "assert sys.stdin.isatty() and sys.stdout.isatty()\n"
                "assert os.tcgetpgrp(sys.stdin.fileno()) == os.getpgrp()\n"
                # Simulate terminal initialization discarding prematurely typed input.
                "time.sleep(0.1)\ntermios.tcflush(sys.stdin, termios.TCIFLUSH)\n"
                "print('SYNTHETIC_READY', flush=True)\n"
                "assert input() == 'cancel'\nprint('SYNTHETIC_CANCELLED', flush=True)\n")
            text = (REPO / 'install.sh').read_text(encoding='utf-8')
            acquisition = text.split('# bash reading a piped installer', 1)[1].split('[[ "$ROOT"', 1)[0]
            acquisition = acquisition[acquisition.index('\n'):]
            handoff = 'if ((!NO_RUN)); then\n    cleanup\n' + text.split('if ((!NO_RUN)); then\n    cleanup\n', 1)[1]
            script = ('set -euo pipefail\nNO_RUN=0\n'
                      'fail(){ printf "%s\\n" "$*" >&2; exit 1; }\ncleanup(){ :; }\n'
                      '[[ ! -t 0 ]] || fail "installer stdin must be a pipe"\n') + acquisition + handoff
            env = dict(os.environ, PYTHON=sys.executable, APP=str(app), ROOT=str(Path(temp) / 'no data'))
            p = _run_piped_installer_pty(script, env)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            result = json.loads(p.stdout)
            self.assertEqual(result['returncode'], 0, result['output'])
            self.assertTrue(result['cancel_sent'], result['output'])
            self.assertIn('SYNTHETIC_CANCELLED', result['output'])
            self.assertFalse((Path(temp) / 'no data').exists())

    def test_dangerous_roots_are_refused(self):
        values = ['C:\\'] if PS else ['/', '//', '/tmp/../']
        for value in values:
            for cmd in self.commands(value):
                p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, errors='replace', timeout=20)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('unsafe', (p.stdout + p.stderr).lower())

    @unittest.skipUnless(PS, 'native Windows raw root validation')
    def test_windows_raw_root_components_are_refused_before_canonicalization(self):
        with tempfile.TemporaryDirectory(prefix='tc raw root ') as temp:
            archive = Path(temp) / 'local.zip'
            archive.write_bytes(b'invalid local archive prevents all network downloads')
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            paths = ['not-created./child', 'not-created /child', 'not-created/child.', 'not-created/child ',
                     'not-created/./child', 'not-created/../child', 'CON/child', 'prn.txt/child',
                     'AUX/child', 'nul.txt/child', 'COM1/child', 'lpt9.log/child']
            for separator in ['/', '\\']:
                for path in paths:
                    with self.subTest(separator=separator, path=path):
                        raw = temp.replace('\\', separator) + separator + path.replace('/', separator)
                        quoted = "'" + raw.replace("'", "''") + "'"
                        canonical = subprocess.run([PS, '-NoProfile', '-Command', '[IO.Path]::GetFullPath(' + quoted + ')'], capture_output=True, text=True, errors='replace', timeout=20)
                        self.assertEqual(canonical.returncode, 0, canonical.stdout + canonical.stderr)
                        command = next(self.commands(raw, archive, digest))
                        p = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, errors='replace', timeout=20)
                        self.assertFalse(Path(raw).exists(), 'raw install root must not be created')
                        self.assertFalse(Path(canonical.stdout.strip()).exists(), 'canonical install root must not be created')
                        self.assertEqual(list(Path(temp).iterdir()), [archive], 'no raw or canonical parent may be created')
                        self.assertNotEqual(p.returncode, 0, p.stdout + p.stderr)
                        self.assertIn('Unsafe Windows root path component.', p.stdout + p.stderr)

    def test_dependency_download_consent_is_not_implicit(self):
        with tempfile.TemporaryDirectory(prefix='tc consent ') as temp:
            root = Path(temp) / 'private root'
            for cmd in self.commands(root, consent=False):
                p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, errors='replace', timeout=20)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('consent', (p.stdout + p.stderr).lower())
                self.assertFalse(root.exists())

    @unittest.skipUnless(BASH, 'native POSIX test')
    def test_unsupported_platform_stops_before_writing(self):
        with tempfile.TemporaryDirectory(prefix='tc unsupported ') as temp:
            root = Path(temp) / 'private root'
            tools = Path(temp) / 'tools'
            tools.mkdir()
            uname = tools / 'uname'
            uname.write_text('#!/bin/sh\necho FreeBSD\n')
            uname.chmod(0o700)
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'])
            p = subprocess.run([BASH, str(REPO / 'install.sh'), '--yes', '--no-run', '--root', str(root)], env=env, capture_output=True, text=True, errors='replace', timeout=20)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn('unsupported', (p.stdout + p.stderr).lower())
            self.assertFalse(root.exists())

    @unittest.skipUnless(BASH, 'native POSIX test')
    def test_download_failure_and_checksum_mismatch_never_execute(self):
        with tempfile.TemporaryDirectory(prefix='tc network ') as temp:
            tools = Path(temp) / 'tools'
            tools.mkdir()
            archive = Path(temp) / 'local.zip'
            archive.write_bytes(b'checksum-approved audit fixture, never executable')
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'])
            for name, script, message in [('offline', '#!/bin/sh\nexit 22\n', 'download failed'), ('corrupt', '#!/bin/sh\nwhile [ "$1" != --output ]; do shift; done\nshift\nprintf corrupt > "$1"\n', 'checksum mismatch')]:
                curl = tools / 'curl'
                curl.write_text(script)
                curl.chmod(0o700)
                root = Path(temp) / name
                cmd = [BASH, str(REPO / 'install.sh'), '--yes', '--no-run', '--root', str(root), '--payload-path', str(archive), '--payload-sha256', digest]
                p = subprocess.run(cmd, env=env, capture_output=True, text=True, errors='replace', timeout=20)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn(message, (p.stdout + p.stderr).lower())
                self.assertFalse((root / '.venv').exists())
                self.assertFalse((root / 'app-v1.0.0').exists())
                self.assertFalse((root / '.install.lock').exists())

    @unittest.skipUnless(BASH, 'native POSIX test')
    def test_nested_runtime_symlink_is_rejected_before_download(self):
        with tempfile.TemporaryDirectory(prefix='tc links ') as temp:
            root = Path(temp) / 'private root'
            (root / 'runtime').mkdir(parents=True)
            (root / '.bootstrap-owner').write_text('technocore-onboard-v1\n')
            outside = Path(temp) / 'outside'
            outside.mkdir()
            (root / 'runtime/cache').mkdir()
            (root / 'runtime/cache/alias').symlink_to(root / '..', target_is_directory=True)
            archive = Path(temp) / 'payload.zip'
            archive.write_bytes(b'local fixture')
            tools = Path(temp) / 'tools'
            tools.mkdir()
            curl = tools / 'curl'
            curl.write_text('#!/bin/sh\nexit 22\n')
            curl.chmod(0o700)
            cmd = [BASH, str(REPO / 'install.sh'), '--yes', '--no-run', '--root', str(root), '--payload-path', str(archive), '--payload-sha256', hashlib.sha256(archive.read_bytes()).hexdigest()]
            p = subprocess.run(cmd, env=dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH']), capture_output=True, text=True, errors='replace', timeout=20)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn('symlink', (p.stdout + p.stderr).lower())
            self.assertEqual(list(outside.iterdir()), [])

    @unittest.skipUnless(PS, 'native Windows test')
    def test_windows_download_failures_are_bounded_and_fail_closed(self):
        code = (REPO / 'install.ps1').read_text().split('function Download-Verified', 1)[1].split('function Assert-ManagedTree', 1)[0]
        code = 'function Download-Verified' + code
        with tempfile.TemporaryDirectory(prefix='tc win download ') as temp:
            dest = str(Path(temp) / 'untrusted.zip').replace("'", "''")
            for body, message in [("throw 'SIMULATED transport failure'", 'Download failed'), ("[IO.File]::WriteAllText($OutFile, 'SIMULATED corrupt archive')", 'checksum mismatch')]:
                stub = "function Invoke-WebRequest { [CmdletBinding()] param([switch]$UseBasicParsing,[string]$Uri,[string]$OutFile,[int]$TimeoutSec); " + body + ' }; '
                p = subprocess.run([PS, '-NoProfile', '-Command', "$ErrorActionPreference='Stop'; " + stub + code + "; Download-Verified 'https://example.invalid/simulation' '" + dest + "' '" + '0' * 64 + "'"], capture_output=True, text=True, errors='replace', timeout=20)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn(message.lower(), (p.stdout + p.stderr).lower())

    @unittest.skipUnless(PS, 'native Windows junction test')
    def test_windows_external_runtime_junction_is_refused(self):
        with tempfile.TemporaryDirectory(prefix='tc junction ') as temp:
            root = Path(temp) / 'root'
            (root / 'runtime').mkdir(parents=True)
            (root / '.bootstrap-owner').write_text('technocore-onboard-v1\n')
            outside = Path(temp) / 'outside'
            outside.mkdir()
            link = root / 'runtime/python'
            p = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(link), str(outside)], capture_output=True, text=True, errors='replace')
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            try:
                archive = Path(temp) / 'local.zip'
                archive.write_bytes(b'audit fixture')
                cmd = next(self.commands(root, archive, hashlib.sha256(archive.read_bytes()).hexdigest()))
                p = subprocess.run(cmd, capture_output=True, text=True, errors='replace', timeout=20)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('outside private runtime', (p.stdout + p.stderr).lower())
                self.assertEqual(list(outside.iterdir()), [])
            finally:
                os.rmdir(link)

    @unittest.skipUnless(PS, 'real Windows DACL regression')
    def test_windows_unsafe_explicit_acl_is_refused_before_modification(self):
        with tempfile.TemporaryDirectory(prefix='tc acl ') as temp:
            for target_name in ['', 'identity', 'state.json']:
                with self.subTest(target=target_name):
                    root = Path(temp) / ('root' + str(len(list(Path(temp).iterdir()))))
                    root.mkdir()
                    (root / '.bootstrap-owner').write_text('technocore-onboard-v1\n')
                    (root / 'identity').mkdir()
                    sentinel = root / 'state.json'
                    sentinel.write_bytes(b'synthetic state sentinel')
                    target = root / target_name if target_name else root
                    p = subprocess.run(['icacls.exe', str(target), '/grant', '*S-1-1-0:F'], capture_output=True, text=True)
                    self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                    archive = Path(temp) / 'audit.zip'
                    archive.write_bytes(b'checksum-approved but invalid payload')
                    command = next(self.commands(root, archive, hashlib.sha256(archive.read_bytes()).hexdigest()))
                    p = subprocess.run(command, capture_output=True, text=True, errors='replace', timeout=30)
                    self.assertNotEqual(p.returncode, 0)
                    self.assertIn('unsafe private dacl', (p.stdout + p.stderr).lower())
                    self.assertEqual(sentinel.read_bytes(), b'synthetic state sentinel')
                    self.assertEqual({x.name for x in root.iterdir()}, {'.bootstrap-owner', 'identity', 'state.json'})

    @unittest.skipUnless(PS, 'real Windows private DACL verification')
    def test_windows_inherited_acl_is_replaced_and_owner_verified(self):
        with tempfile.TemporaryDirectory(prefix='tc inherited acl ') as temp:
            p = subprocess.run(['icacls.exe', temp, '/grant', '*S-1-1-0:(OI)(CI)F'], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            root = Path(temp) / 'root'
            (root / 'identity').mkdir(parents=True)
            sentinel = root / 'identity/fixture.pem'
            sentinel.write_bytes(b'synthetic non-key content')
            code = (REPO / 'install.ps1').read_text().split('# BEGIN PRIVATE ACL\n', 1)[1].split('# END PRIVATE ACL', 1)[0]
            quoted = "'" + str(root).replace("'", "''") + "'"
            verify = "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; foreach($item in @((Get-Item -LiteralPath $root)) + @(Get-ChildItem -LiteralPath $root -Recurse -Force)) { $acl=Get-Acl -LiteralPath $item.FullName; if(!$acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid) { throw 'Owner/protection mismatch' }; $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])); if($rules.Count -ne 2) { throw 'Rule count' }; foreach($rule in $rules) { if($rule.IdentityReference.Value -notin @($sid,'S-1-5-18') -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne 'FullControl') { throw 'Foreign ACL' } } }; Write-Output 'PRIVATE_ACL_VERIFIED'"
            p = subprocess.run([PS, '-NoProfile', '-Command', "$ErrorActionPreference='Stop'; " + code + '; $root=' + quoted + '; Set-PrivateTree $root; Set-PrivateTree $root; ' + verify], capture_output=True, text=True, errors='replace', timeout=30)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn('PRIVATE_ACL_VERIFIED', p.stdout)
            self.assertEqual(sentinel.read_bytes(), b'synthetic non-key content')

    @unittest.skipUnless(PS, 'real Windows private-tree junction regression')
    def test_windows_private_acl_refuses_unvalidated_junction(self):
        with tempfile.TemporaryDirectory(prefix='tc acl junction ') as temp:
            root, outside = Path(temp) / 'root', Path(temp) / 'outside'
            root.mkdir(); outside.mkdir()
            link = root / 'unexpected'
            p = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(link), str(outside)], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            try:
                code = (REPO / 'install.ps1').read_text().split('# BEGIN PRIVATE ACL\n', 1)[1].split('# END PRIVATE ACL', 1)[0]
                quote = "'" + str(root).replace("'", "''") + "'"
                p = subprocess.run([PS, '-NoProfile', '-Command', "$ErrorActionPreference='Stop'; " + code + '; Set-PrivateTree ' + quote], capture_output=True, text=True, errors='replace', timeout=30)
                self.assertNotEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertIn('reparse', (p.stdout + p.stderr).lower())
                self.assertEqual(list(outside.iterdir()), [])
            finally:
                os.rmdir(link)

    def test_existing_unmanaged_root_is_not_modified(self):
        with tempfile.TemporaryDirectory(prefix='tc existing ') as temp:
            root = Path(temp) / 'existing root'
            root.mkdir()
            sentinel = root / 'keep.txt'
            sentinel.write_bytes(b'do not touch')
            for cmd in self.commands(root):
                p = subprocess.run(cmd, capture_output=True, text=True, errors='replace', timeout=20)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('unmanaged', (p.stdout + p.stderr).lower())
                self.assertEqual(sentinel.read_bytes(), b'do not touch')
                self.assertEqual(list(root.iterdir()), [sentinel])


@unittest.skipUnless(PS, 'native Windows image-mapping cleanup regression')
class WindowsStageCleanup(unittest.TestCase):
    def check_cleanup(self, release, primary_error=False):
        import ctypes
        from ctypes import wintypes as w
        import time

        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
        kernel.CreateFileW.restype = w.HANDLE
        kernel.CreateFileMappingW.argtypes = [w.HANDLE, w.LPVOID, w.DWORD, w.DWORD, w.DWORD, w.LPCWSTR]
        kernel.CreateFileMappingW.restype = w.HANDLE
        kernel.MapViewOfFile.argtypes = [w.HANDLE, w.DWORD, w.DWORD, w.DWORD, ctypes.c_size_t]
        kernel.MapViewOfFile.restype = w.LPVOID
        kernel.UnmapViewOfFile.argtypes = [w.LPCVOID]
        kernel.CloseHandle.argtypes = [w.HANDLE]
        with tempfile.TemporaryDirectory(prefix='tc mapped cleanup ') as temp:
            root = Path(temp)
            stage = root / '.stage-fixture'
            (stage / 'uv').mkdir(parents=True)
            exe = stage / 'uv/uv.exe'
            # Map a disposable real PE image; no uv download or execution is needed.
            shutil.copyfile(Path(sys.base_prefix) / 'python.exe', exe)
            sentinel = root / 'identity-sentinel'
            sentinel.write_bytes(b'unrelated data must survive')
            lock_path, ready = root / '.install.lock', root / 'cleanup-ready'
            quote = lambda value: "'" + str(value).replace("'", "''") + "'"
            text = (REPO / 'install.ps1').read_text(encoding='utf-8')
            # Keep the production catch/finally intact; substitute only the download/setup body.
            lifecycle = text.split('$oldTls = ', 1)[1].split('\nif (!$NoRun)', 1)[0]
            lifecycle = '$oldTls = ' + lifecycle
            body_start = lifecycle.index('\ntry {\n') + len('\ntry {\n')
            doctor = lifecycle.index('    Write-Output "Doctor:')
            body_end = lifecycle.index('\n', doctor)
            body = ('    $lock = [IO.File]::Open($lockPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)\n'
                    '    try { [IO.File]::Delete(' + quote(exe) + "); throw 'Image was not contended' }\n"
                    "    catch [UnauthorizedAccessException] { Write-Output 'IMAGE_DELETE_DENIED' }\n"
                    '    [IO.File]::WriteAllText(' + quote(ready) + ", 'ready')\n")
            if primary_error:
                body += "    throw 'PRIMARY_SETUP_FAILURE'\n"
            lifecycle = lifecycle[:body_start] + body + lifecycle[body_end:]
            code = ("$ErrorActionPreference='Stop'; $oldEnv=@{}; $lock=$null; $stage=" + quote(stage)
                    + '; $lockPath=' + quote(lock_path)
                    + '\ntry {\n' + lifecycle + "\n} catch { Write-Output ('CAUGHT_ERROR=' + $_.Exception.Message); exit 23 }\n")
            script = root / 'cleanup.ps1'
            script.write_text(code, encoding='utf-8-sig')
            file = section = view = None
            proc = None
            try:
                file = kernel.CreateFileW(str(exe), 0x80000000, 7, None, 3, 0, None)
                self.assertNotEqual(file, ctypes.c_void_p(-1).value, ctypes.get_last_error())
                section = kernel.CreateFileMappingW(file, None, 0x1000000 | 2, 0, 0, None)  # SEC_IMAGE | PAGE_READONLY
                self.assertTrue(section, ctypes.get_last_error())
                view = kernel.MapViewOfFile(section, 4, 0, 0, 0)
                self.assertTrue(view, ctypes.get_last_error())
                kernel.CloseHandle(file); file = None
                kernel.CloseHandle(section); section = None
                started = time.monotonic()
                proc = subprocess.Popen([PS, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(script)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='replace')
                deadline = started + 15
                while not ready.exists() and proc.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                if release and ready.exists():
                    time.sleep(0.5)
                    self.assertTrue(kernel.UnmapViewOfFile(view), ctypes.get_last_error())
                    view = None
                stdout, stderr = proc.communicate(timeout=15)
                elapsed = time.monotonic() - started
                output = stdout + stderr
                self.assertIn('IMAGE_DELETE_DENIED', output, output)
                self.assertTrue(ready.exists(), output)
                self.assertEqual(sentinel.read_bytes(), b'unrelated data must survive')
                self.assertLess(elapsed, 12, output)
                self.assertFalse(lock_path.exists(), output)
                if release:
                    self.assertEqual(proc.returncode, 0, output)
                    self.assertFalse(stage.exists(), output)
                else:
                    self.assertNotEqual(proc.returncode, 0, output)
                    self.assertTrue(exe.exists(), output)
                    self.assertIn('Access', output, output)
                if primary_error:
                    self.assertIn('CAUGHT_ERROR=PRIMARY_SETUP_FAILURE', output, output)
                    self.assertIn('WARNING:', output, 'secondary cleanup failure must remain visible')
            finally:
                if proc is not None and proc.poll() is None:
                    proc.kill(); proc.communicate(timeout=10)
                if view: kernel.UnmapViewOfFile(view)
                if section: kernel.CloseHandle(section)
                if file and file != ctypes.c_void_p(-1).value: kernel.CloseHandle(file)

    def test_transient_image_mapping_retries_then_removes_stage_and_lock(self):
        self.check_cleanup(release=True)

    def test_persistent_image_mapping_fails_bounded_but_removes_lock(self):
        self.check_cleanup(release=False)

    def test_primary_setup_error_survives_persistent_cleanup_failure(self):
        self.check_cleanup(release=False, primary_error=True)


@unittest.skipUnless(os.environ.get('TC_BOOTSTRAP_INTEGRATION') == '1', 'opt-in network downloads: TC_BOOTSTRAP_INTEGRATION=1')
class FreshInstall(unittest.TestCase):
    def test_real_payload_fresh_install_doctor(self):
        p = subprocess.run([sys.executable, str(REPO / 'scripts/ci_install.py')], stdin=subprocess.DEVNULL, capture_output=True, text=True, errors='replace', timeout=600)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('real payload install + offline doctor passed', p.stdout)

    def test_fresh_install_wrapper_and_rerun_preserve_data(self):
        with tempfile.TemporaryDirectory(prefix="tc install space ' unicode-é ") as temp:
            root = Path(temp) / 'private root'
            archive = Path(temp) / 'audit payload.zip'
            app = "import json,sys,cryptography; from vendor import technocore_agent; assert 'setup' not in sys.argv; print(json.dumps({'argv':sys.argv[1:],'crypto':cryptography.__version__}))\n"
            entries = {'onboard.py': app, 'vendor/technocore_agent.py': '# synthetic audit fixture\n', 'vendor/LICENSE': 'synthetic fixture', 'requirements.txt': REQUIREMENTS, 'README.md': 'synthetic fixture', 'LICENSE': 'synthetic fixture', 'SECURITY.md': 'synthetic fixture'}
            with zipfile.ZipFile(archive, 'w') as z:
                for name, data in entries.items(): z.writestr(name, data)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            commands = list(InstallerBoundaries().commands(root, archive, digest))
            self.assertTrue(commands, 'native installer shell unavailable')
            for command in commands:
                p = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, errors='replace', timeout=600)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                if PS:
                    wrapper = [PS, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(root / 'bin/tcproof.ps1'), 'doctor']
                else:
                    wrapper = [str(root / 'bin/tcproof'), 'doctor']
                p = subprocess.run(wrapper, capture_output=True, text=True, errors='replace', timeout=30)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                result = json.loads(p.stdout)
                self.assertEqual(result['argv'], ['--data-dir', str(root), 'doctor'])
                self.assertEqual(result['crypto'], CRYPTO_VERSION)
                self.assertFalse((root / 'identity').exists())
                sentinel = root / 'state.json'
                sentinel.write_bytes(b'{"synthetic_sentinel":true}')
                p = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, errors='replace', timeout=600)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertEqual(sentinel.read_bytes(), b'{"synthetic_sentinel":true}')


class WorkflowContract(unittest.TestCase):
    def test_runner_temp_is_only_resolved_in_step_context(self):
        text = (REPO / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        job_config, steps = text.split('    steps:', 1)
        self.assertNotIn('${{ runner.', job_config)
        self.assertIn('TMPDIR: ${{ runner.temp }}', steps)

    def test_ci_covers_native_architectures_and_no_public_actions(self):
        path = REPO / '.github/workflows/ci.yml'
        self.assertTrue(path.is_file(), 'cross-platform workflow is missing')
        text = path.read_text(encoding='utf-8')
        for label in ['windows-2025', 'windows-11-arm', 'ubuntu-24.04', 'ubuntu-24.04-arm', 'macos-15-intel', 'macos-15']:
            self.assertIn(label, text)
        self.assertIn("architecture: ${{ runner.os == 'Windows' && 'x64' || '' }}", text)
        self.assertIn('shell: /bin/bash {0}', text)
        self.assertIn('/bin/bash --version', text)
        self.assertIn('/bin/bash -n install.sh', text)
        self.assertIn('TC_BOOTSTRAP_INTEGRATION', text)
        self.assertIn('unittest discover', text)
        self.assertNotIn('contents: write', text)
        self.assertNotIn('pull_request_target', text)


class ReleasePackaging(unittest.TestCase):
    def test_package_is_allowlisted_reproducible_and_scanned(self):
        with tempfile.TemporaryDirectory(prefix='tc package ') as temp:
            source = Path(temp) / 'source'
            (source / 'vendor').mkdir(parents=True)
            (source / 'docs').mkdir()
            files = {'onboard.py': "# safe\nMARKER = b'-----BEGIN ENCRYPTED PRIVATE KEY-----'\n", 'requirements.txt': REQUIREMENTS, 'README.md': 'readme', 'LICENSE': 'license', 'SECURITY.md': 'security', 'vendor/technocore_agent.py': '# safe vendor\n', 'vendor/LICENSE': 'license', 'docs/usage.md': '# usage'}
            for name, data in files.items(): (source / name).write_bytes(data.encode('utf-8'))
            (source / 'identity.pem').write_bytes(b'not to be packaged or read')
            output = Path(temp) / 'technocore-onboard.zip'
            cmd = [sys.executable, str(REPO / 'scripts/package_release.py'), '--source', str(source), '--output', str(output)]
            p = subprocess.run(cmd, capture_output=True, text=True, errors='replace')
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            first = output.read_bytes()
            with zipfile.ZipFile(output) as z:
                self.assertEqual(set(z.namelist()), set(files))
                self.assertIsNone(z.testzip())
            p = subprocess.run(cmd, capture_output=True, text=True, errors='replace')
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertEqual(output.read_bytes(), first)
            self.assertIn(hashlib.sha256(first).hexdigest(), output.with_suffix('.zip.sha256').read_text())
            (source / 'onboard.py').write_text('-----BEGIN PRIVATE KEY-----')
            p = subprocess.run(cmd, capture_output=True, text=True, errors='replace')
            self.assertNotEqual(p.returncode, 0)
            self.assertIn('secret', (p.stdout + p.stderr).lower())
            self.assertEqual(output.read_bytes(), first, 'failed scan must not replace a valid artifact')


if __name__ == '__main__':
    unittest.main()
