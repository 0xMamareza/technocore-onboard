#!/usr/bin/env python3
"""Technocore Onboard: local identity and consent-gated public contributions."""
from __future__ import annotations

import argparse
import base64
import contextlib
import warnings
import getpass
import os
import json
import math
import secrets
import subprocess
import tempfile
import ipaddress
import io
import http.client
import re
import time
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlsplit, quote
from urllib.request import Request, build_opener, HTTPRedirectHandler, HTTPSHandler
try:
    from vendor import technocore_agent as zun
except ModuleNotFoundError:
    zun = None  # --version and --help still work before the isolated dependency install.
from pathlib import Path
import platform
import sys

VERSION = '1.0.0'


class SafetyError(ValueError):
    """A local or remote input is unsafe or cannot be verified."""


class TerminalUI:
    def require_terminal(self):
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise SafetyError('Open an interactive terminal; piped/unattended key prompts are refused.')

    def ask(self, prompt):
        return input(prompt)

    def secret(self, prompt):
        self.require_terminal()
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error', getpass.GetPassWarning)
                return getpass.getpass(prompt)
        except getpass.GetPassWarning:
            raise SafetyError('Hidden passphrase entry is unavailable; use a real local terminal. Echo fallback is refused.') from None

    def say(self, text):
        print(text)

    def yes(self, prompt):
        return self.ask(prompt + ' [yes/NO]: ').strip().lower() == 'yes'


class ScriptUI(TerminalUI):
    """Explicit offline test adapter; never selected by the CLI."""
    def __init__(self, answers, secrets=(), terminal=True):
        self.answers = iter(answers)
        self.secrets = iter(secrets)
        self.terminal = terminal
        self.output = []

    def require_terminal(self):
        if not self.terminal:
            raise SafetyError('Interactive terminal required')

    def ask(self, prompt):
        self.output.append(prompt)
        return next(self.answers)

    def secret(self, prompt):
        self.require_terminal()
        self.output.append(prompt)
        return next(self.secrets)

    def say(self, text):
        self.output.append(str(text))


def check_path(path):
    path = Path(path).expanduser().absolute()
    for item in (path, *path.parents):
        if item.is_symlink() or (hasattr(item, 'is_junction') and item.is_junction()):
            raise SafetyError('Symlink/junction paths are refused')
    return Path(os.path.abspath(path))


def private_permissions(path, *, directory=False):
    check_path(path)
    if os.name == 'nt':
        import csv
        result = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'], capture_output=True, text=True, check=True)
        sid = next(csv.reader(result.stdout.splitlines()))[1]
        subprocess.run(['icacls', str(path), '/reset'], capture_output=True, check=True)
        grant = f'*{sid}:' + ('(OI)(CI)F' if directory else 'F')
        subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r', grant], capture_output=True, check=True)
    else:
        path.chmod(0o700 if directory else 0o600)


def private_directory(path):
    check_path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_permissions(path, directory=True)


def atomic_write(path, data, *, replace=True):
    check_path(path)
    raw = data if isinstance(data, bytes) else data.encode('utf-8')
    descriptor, name = tempfile.mkstemp(prefix='.stage-', dir=path.parent)
    staged = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        staged.chmod(0o600)
        if replace:
            os.replace(staged, path)
        else:
            os.link(staged, path)  # Publish atomically, refusing an existing identity.
    finally:
        staged.unlink(missing_ok=True)


def read_json(path):
    check_path(path)
    if path.stat().st_size > 256 * 1024:
        raise SafetyError('Local JSON exceeds safety limit')
    return decode_json(path.read_bytes())


def write_json(path, value, *, replace=True):
    public_tree(value)
    atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + '\n', replace=replace)


def public_url(value, kind='other'):
    if not isinstance(value, str) or len(value) > 2048 or any(c.isspace() or unicodedata.category(c) in zun.INVISIBLE_CATEGORIES for c in value):
        raise SafetyError('Use the exact public HTTPS URL without whitespace or control characters')
    try:
        parsed = urlsplit(value)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        raise SafetyError('Malformed URL') from None
    if parsed.scheme != 'https' or not host or parsed.username is not None or parsed.password is not None or parsed.fragment or port not in (None, 443):
        raise SafetyError('URL must be public HTTPS without credentials, fragment or a nonstandard port')
    if not host.isascii() or '%' in host or '\\' in value or host.endswith('.'):
        raise SafetyError('Use a public ASCII hostname (punycode is supported)')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if '.' not in host or host.endswith(('.local', '.localhost', '.internal', '.lan', '.home', '.test', '.invalid')) or not re.fullmatch(r'[a-zA-Z0-9.-]+', host) or host.rsplit('.', 1)[-1].isdigit():
            raise SafetyError('Local/private or malformed hosts cannot be shared')
    else:
        if not address.is_global:
            raise SafetyError('Local/private IP addresses cannot be shared')
    if kind == 'x' and (host not in ('x.com', 'www.x.com', 'twitter.com', 'www.twitter.com') or not re.fullmatch(r'/[A-Za-z0-9_]{1,15}/status/[0-9]{1,25}/?', parsed.path)):
        raise SafetyError('Paste a published x.com or twitter.com /name/status/ID URL (articles may use the sharing post URL)')
    if kind == 'github' and (host != 'github.com' or parsed.query or not re.fullmatch(r'/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}/?', parsed.path) or parsed.path.rstrip('/').rsplit('/', 1)[-1] in ('.', '..')):
        raise SafetyError('Use https://github.com/OWNER/REPO; publish the project first')
    return value


@dataclass
class Response:
    body: bytes
    headers: dict = field(default_factory=dict)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SafetyError('HTTP redirects are refused; check the exact public repository URL')


def remaining_time(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('HTTP deadline exceeded')
    return remaining


class DeadlineReader(io.RawIOBase):
    """Refresh the budget for every raw read, including header/chunk lines."""
    def __init__(self, stream, sock, deadline):
        self.stream, self._sock, self.deadline = stream, sock, deadline

    def readable(self):
        return True

    def readinto(self, target):
        self._sock.settimeout(remaining_time(self.deadline))
        chunk = self.stream.read1(len(target))
        target[:len(chunk)] = chunk
        return len(chunk)

    def close(self):
        try:
            self.stream.close()
        finally:
            super().close()


class DeadlineHTTPSHandler(HTTPSHandler):
    def __init__(self, deadline):
        super().__init__()
        self.deadline = deadline

    def https_open(self, req):
        deadline = self.deadline

        class BoundedResponse(http.client.HTTPResponse):
            def __init__(self, sock, *args, **kwargs):
                super().__init__(sock, *args, **kwargs)
                self.fp = io.BufferedReader(DeadlineReader(self.fp, sock, deadline))

        class BoundedConnection(http.client.HTTPSConnection):
            response_class = BoundedResponse

            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                create_connection = self._create_connection

                def connect_socket(address, timeout, source_address):
                    # OS DNS/address attempts may outlast the budget; reject on return.
                    sock = create_connection(address, remaining_time(deadline), source_address)
                    try:
                        sock.settimeout(remaining_time(deadline))
                    except BaseException:
                        sock.close()
                        raise
                    return sock
                self._create_connection = connect_socket

            def connect(self):
                http.client.HTTPConnection.connect(self)
                self.sock.settimeout(remaining_time(deadline))
                self.sock = self._context.wrap_socket(self.sock, server_hostname=self._tunnel_host or self.host)

            def send(self, data):
                if self.sock is None:
                    self.connect()
                self.sock.settimeout(remaining_time(deadline))
                super().send(data)

        return self.do_open(BoundedConnection, req, context=self._context)


def http_request(method, url, body=None, *, cap=2 * 1024 * 1024, timeout=15):
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname not in ('technocore.chat', 'api.github.com') or parsed.username is not None or parsed.port is not None:
        raise SafetyError('Network access is restricted to the Technocore and GitHub APIs')
    room_path = r'/r/[a-z0-9][a-z0-9_-]{0,47}'
    if method not in ('GET', 'POST') or parsed.fragment:
        raise SafetyError('Disallowed HTTP operation')
    if method == 'POST':
        if parsed.hostname != 'technocore.chat' or not re.fullmatch(room_path, parsed.path) or parsed.query != 'format=json':
            raise SafetyError('Disallowed POST endpoint')
    elif body is not None:
        raise SafetyError('Read-only requests cannot include a body')
    elif parsed.hostname == 'technocore.chat':
        if not ((re.fullmatch(room_path, parsed.path) and parsed.query == 'limit=200&format=json') or (re.fullmatch(room_path + '/export', parsed.path) and not parsed.query)):
            raise SafetyError('Disallowed read endpoint; side-effecting GET lanes are never used')
    elif not re.fullmatch(r'/repos/[A-Za-z0-9-]+/[A-Za-z0-9_.-]+(?:/commits/[A-Za-z0-9_.%~-]+)?', parsed.path) or parsed.query:
        raise SafetyError('Disallowed GitHub read endpoint')
    request = Request(url, data=body, method=method, headers={'Accept': 'application/json', 'Content-Type': 'application/json; charset=utf-8', 'User-Agent': 'technocore-onboard/' + VERSION})
    deadline = time.monotonic() + timeout
    with build_opener(NoRedirect(), DeadlineHTTPSHandler(deadline)).open(request, timeout=timeout) as response:
        chunks, size = [], 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Read deadline exceeded')
            # CPython HTTPResponse exposes the underlying TLS socket here. Fail closed on an unsupported transport.
            sock = getattr(getattr(getattr(response, 'fp', None), 'raw', None), '_sock', None)
            if sock is None:
                if response.isclosed():
                    break
                raise SafetyError('Cannot enforce a bounded HTTP read on this runtime')
            sock.settimeout(remaining)
            chunk = response.read1(min(65536, cap + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > cap:
                raise SafetyError('HTTP response exceeds safety limit')
            chunks.append(chunk)
        return Response(b''.join(chunks), dict(response.headers))


def decode_json(raw):
    def finite_float(token):
        value = float(token)
        if not math.isfinite(value):
            raise SafetyError('Nonfinite JSON number')
        return value

    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise SafetyError('Duplicate JSON field')
            result[name] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_float=finite_float, parse_constant=lambda _: (_ for _ in ()).throw(SafetyError('Invalid JSON constant')))
    except (ValueError, UnicodeError):
        raise SafetyError('Malformed JSON response') from None
    if not isinstance(value, dict):
        raise SafetyError('Expected a JSON object')
    return value


def public_tree(value, depth=0):
    if depth > 32:
        raise SafetyError('Public JSON nesting exceeds safety limit')
    if isinstance(value, float) and not math.isfinite(value):
        raise SafetyError('Nonfinite JSON number')
    if isinstance(value, str) and re.search(r'-----BEGIN [^-]*(?:PRIVATE KEY|SECRET)', value, re.I):
        raise SafetyError('Private key/secret material is refused in public data')
    if isinstance(value, dict):
        for name, child in value.items():
            if re.search(r'(?:private[ _-]?key|secret|seed|mnemonic|password|passphrase|(?:access|refresh)[ _-]?token|api[ _-]?key|authorization)', name, re.I):
                raise SafetyError('Secret-bearing public fields are refused')
            public_tree(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            public_tree(child, depth + 1)


def verify_signature(did, signature, payload):
    if not isinstance(signature, str) or not re.fullmatch(r'[A-Za-z0-9_-]{86}', signature):
        raise SafetyError('Malformed signature')
    if base64.urlsafe_b64encode(base64.urlsafe_b64decode(signature + '==')).decode().rstrip('=') != signature:
        raise SafetyError('Noncanonical signature')
    zun.verify_bytes(did, signature, payload)


def message_receipt(room, record):
    zun.validate_name(room)
    public_tree(record)
    if not isinstance(record, dict) or any(k in record for k in ('message', 'messages', 'posted', 'schema')):
        raise SafetyError('Ambiguous message record')
    if record.get('room', room) != room:
        raise SafetyError('Room context mismatch')
    did, signature = record.get('did', record.get('from')), record.get('sig', record.get('signature'))
    if ('did' in record and 'from' in record and record['did'] != record['from']) or ('sig' in record and 'signature' in record and record['sig'] != record['signature']):
        raise SafetyError('Conflicting DID/signature aliases')
    nonce, text = record.get('nonce'), record.get('text')
    if isinstance(nonce, bool) or not isinstance(nonce, (str, int)):
        raise SafetyError('Invalid nonce')
    nonce = zun.validate_nonce(nonce)
    if not isinstance(text, str) or len(text) > 4096:
        raise SafetyError('Invalid message text')
    verify_signature(did, signature, f'{room}|{nonce}|{text}'.encode('utf-8'))
    result = {'from': did, 'sig': signature, 'nonce': nonce, 'text': text}
    if 'seq' in record:
        seq = record['seq']
        if isinstance(seq, bool) or not isinstance(seq, (str, int)) or not re.fullmatch(r'[1-9][0-9]{0,18}', str(seq)):
            raise SafetyError('Invalid sequence')
        result['seq'] = str(seq)
    if 'ts' in record:
        if not isinstance(record['ts'], str):
            raise SafetyError('Invalid timestamp')
        result['ts'] = record['ts']
    return {'schema': 'technocore-inspector-receipt-v1', 'kind': 'message', 'room': room, 'record': result}


def verify_receipt(receipt):
    public_tree(receipt)
    if not isinstance(receipt, dict) or receipt.get('schema') != 'technocore-inspector-receipt-v1':
        raise SafetyError('Unsupported public receipt')
    if receipt.get('kind') == 'message':
        return message_receipt(receipt.get('room'), receipt.get('record'))
    if receipt.get('kind') == 'contribution' and isinstance(receipt.get('record'), dict):
        proof = receipt['record']
        zun.verify_contribution_proof(proof)
        verify_signature(proof['did'], proof['signature'], zun.contribution_payload(proof['artifact_url'], proof['commit']))
        return receipt
    raise SafetyError('Unsupported receipt kind')


@contextlib.contextmanager
def posting_lock(root):
    path = check_path(root / '.posting.lock')
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise SafetyError('Another post may be in progress. Run recover. If a process crashed, check it has stopped before removing .posting.lock; never retry an uncertain POST.') from None
    try:
        os.close(descriptor)
        yield
    finally:
        path.unlink()


class Wizard:
    def __init__(self, root, *, ui=None, transport=None):
        self.root = check_path(root)
        dangerous = {Path(self.root.anchor), Path.home().absolute(), Path.home().parent.absolute()}
        if os.name == 'nt':
            system_dirs = [Path(os.environ.get('SystemRoot', 'C:/Windows')), Path(os.environ.get('ProgramFiles', 'C:/Program Files')), Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)'))]
        else:
            system_dirs = [Path(p) for p in ('/etc', '/usr', '/bin', '/sbin', '/lib', '/boot', '/dev', '/proc', '/sys')]
        if self.root in dangerous or any(self.root == p or p in self.root.parents for p in system_dirs) or 'system32' in {p.lower() for p in self.root.parts}:
            raise SafetyError('Choose a dedicated data directory, not a home, filesystem or system root')
        self.ui = ui or TerminalUI()
        self.transport = transport
        self.key_path = self.root / 'identity' / 'identity.pem'
        self.state_path = self.root / 'state.json'

    def prepare(self):
        private_directory(self.root)
        private_directory(self.root / 'identity')
        private_directory(self.root / 'receipts')

    def load_key(self):
        self.ui.require_terminal()
        check_path(self.key_path)
        if not self.key_path.exists():
            raise SafetyError('No identity here. Run setup; do not create another DID to fix a path error.')
        if self.key_path.stat().st_size > 65536 or not self.key_path.read_bytes().startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'):
            raise SafetyError('Only encrypted PKCS8 PEM identities are accepted')
        private_permissions(self.key_path)
        key = zun.load_identity(self.key_path, password_prompt=self.ui.secret)
        did = zun.did_from_private_key(key)
        if self.state_path.exists() and read_json(self.state_path).get('did') != did:
            raise SafetyError('Stored public DID differs from the key; restore the matching identity, never regenerate automatically.')
        return key

    def save_identity_state(self, key):
        did = zun.did_from_private_key(key)
        write_json(self.state_path, {'schema': 'technocore-onboard-state-v1', 'did': did})
        atomic_write(self.root / 'identity' / 'did.txt', did + '\n')
        self.ui.say('Your public DID: ' + did)
        self.ui.say('Back up identity/identity.pem (encrypted) privately. Keep its passphrase separately. Public receipts contain no private key. Losing either means losing this DID; setup will never replace it automatically.')

    def setup(self):
        self.ui.require_terminal()
        self.ui.say(f'This is {platform.system()}; shell: {os.environ.get("SHELL") or os.environ.get("COMSPEC", "terminal")}.')
        self.ui.say('Your encrypted identity stays on this host. On a remote/VPS host its administrator can access files and memory. Prefer a trusted local computer.')
        location = self.ui.ask('Host: local computer or remote/VPS? [local/remote/cancel]: ').strip().lower()
        if location not in ('local', 'remote'):
            self.ui.say('Cancelled; no identity created.')
            return
        if self.key_path.exists():
            self.prepare()
            key = self.load_key()
            self.save_identity_state(key)
            self.ui.say('Existing identity reused; no new key was created.')
            return self.introduction(key)
        if self.state_path.exists():
            raise SafetyError('Public state exists but identity is missing. Restore the encrypted backup into identity/identity.pem; no new key will be created.')
        choice = self.ui.ask('Identity: reuse an encrypted PEM, create once, or cancel? [reuse/create/CANCEL]: ').strip().lower()
        if choice not in ('reuse', 'create'):
            self.ui.say('Cancelled; no identity created.')
            return
        if choice == 'create':
            if not self.ui.yes('Create one encrypted identity on this host?'):
                self.ui.say('Cancelled; no identity created.')
                return
            first = self.ui.secret('New passphrase (12+ characters; hidden): ')
            second = self.ui.secret('Confirm passphrase (hidden): ')
            if first != second or len(first) < 12:
                raise SafetyError('Passphrases must match and contain at least 12 characters')
            self.prepare()
            zun.create_identity(self.key_path, first)
            key = zun.load_identity(self.key_path, first.encode('utf-8'), allow_prompt=False)
            del first, second
        else:
            source = check_path(self.ui.ask('Absolute path to existing encrypted identity.pem (never paste its contents): '))
            if source.stat().st_size > 65536:
                raise SafetyError('Identity file exceeds safety limit')
            encrypted = source.read_bytes()
            if not encrypted.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'):
                raise SafetyError('Only encrypted PKCS8 PEM identities are accepted')
            self.prepare()
            with tempfile.TemporaryDirectory(prefix='.import-', dir=self.key_path.parent) as temporary:
                staged = Path(temporary) / 'identity.pem'
                private_directory(staged.parent)
                atomic_write(staged, encrypted, replace=False)
                key = zun.load_identity(staged, password_prompt=self.ui.secret)
                atomic_write(self.key_path, encrypted, replace=False)
        self.save_identity_state(key)
        return self.introduction(key)

    def introduction(self, key):
        self.ui.say('Setup is complete. An introduction is separate and optional: it publishes your DID and the text to a world-readable room; never include secrets.')
        if not self.ui.yes('Prepare an optional public introduction?'):
            return
        text = zun.normalize_message(self.ui.ask('Introduction text (public): '))
        public_tree(text)
        room = zun.validate_name(self.ui.ask('Public Technocore room [lobby]: ').strip() or 'lobby')
        return self.announce(key, room, text, None, None)

    def request(self, method, url, body=None, *, cap=2 * 1024 * 1024, timeout=15):
        try:
            response = (self.transport or http_request)(method, url, body, cap=cap, timeout=timeout)
        except http.client.HTTPException as error:
            raise OSError('HTTP transport failed: ' + type(error).__name__) from error
        if len(response.body) > cap:
            raise SafetyError('HTTP response exceeds safety limit')
        return response

    def github_revision(self, url, chosen):
        public_url(url, 'github')
        if chosen and not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', chosen):
            raise SafetyError('Choose a complete lowercase 40/64-hex published commit, or leave blank for default HEAD')
        repo = urlsplit(url).path.strip('/')
        base = 'https://api.github.com/repos/' + repo
        metadata = decode_json(self.request('GET', base).body)
        full_name = metadata.get('full_name')
        if metadata.get('private') is not False or metadata.get('visibility', 'public') != 'public' or not isinstance(full_name, str) or full_name.lower() != repo.lower():
            raise SafetyError('GitHub did not confirm this exact public repository')
        branch = metadata.get('default_branch')
        if not chosen and (not isinstance(branch, str) or not branch):
            raise SafetyError('Repository has no published default branch')
        revision = decode_json(self.request('GET', base + '/commits/' + quote(chosen or branch, safe='')).body).get('sha')
        if not isinstance(revision, str) or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', revision) or (chosen and revision != chosen):
            raise SafetyError('GitHub did not resolve the chosen exact published revision')
        return revision

    def contribute(self):
        self.ui.require_terminal()
        self.ui.say('Publish your work yourself first. This wizard records its public URL; it never posts to X or creates/commits/pushes a Git repository. GitHub lookup is read-only. Artifact URLs are never fetched.')
        kind = self.ui.ask('Contribution: X post/article, GitHub project, other, or cancel? [x/github/other/CANCEL]: ').strip().lower()
        if kind not in ('x', 'github', 'other'):
            self.ui.say('Cancelled; no POST sent.')
            return
        url = public_url(self.ui.ask('Exact published public URL (queries are preserved): '), kind)
        commit = None
        if kind == 'github':
            commit = self.github_revision(url, self.ui.ask('Exact published full commit, or Enter for default HEAD: '))
        description = zun.normalize_message(self.ui.ask('Describe honestly what you contributed (public; no secrets): '))
        room = zun.validate_name(self.ui.ask('Public Technocore room [technocore]: ').strip() or 'technocore')
        text = zun.normalize_message(f'{kind}: {description} | {url}' + (f' | commit {commit}' if commit else ''))
        key = self.load_key()
        self.prepare()
        folder = self.root / 'receipts' / ('contribution-' + secrets.token_hex(12))
        private_directory(folder)
        if commit:
            proof = zun.create_contribution_proof(key, url, commit)
            zun.verify_contribution_proof(proof)
            write_json(folder / 'proof.json', proof, replace=False)
            write_json(folder / 'proof-receipt.json', {'schema': 'technocore-inspector-receipt-v1', 'kind': 'contribution', 'record': proof}, replace=False)
            self.ui.say('Local Git proof verified and saved at ' + str(folder / 'proof.json') + '. You may publish this public proof separately; no repository change was made.')
        return self.announce(key, room, text, url, folder, commit)

    def intent_paths(self):
        directory = self.root / 'receipts'
        check_path(directory)
        if not directory.exists():
            return []
        entries = list(directory.iterdir())
        if len(entries) > 10000:
            raise SafetyError('Too many receipt folders; archive old public receipts before continuing')
        result = []
        for folder in entries:
            check_path(folder)
            if folder.is_dir():
                path = check_path(folder / 'intent.json')
                if path.exists():
                    result.append(path)
        return sorted(result)

    def existing_record(self, did, room, text, artifact):
        intents = [(path, self.read_intent(path)) for path in self.intent_paths()]
        for path, intent in intents:
            request = intent['request']
            if request.get('did') == did and ((artifact is not None and intent.get('artifact_url') == artifact) or (intent.get('room') == room and request.get('text') == text)):
                return path
        return None

    def announce(self, key, room, text, artifact, folder, commit=None):
        public_tree(text)
        did = zun.did_from_private_key(key)
        existing = self.existing_record(did, room, text, artifact)
        if existing:
            self.ui.say('Existing record: ' + str(existing.parent) + '. Reuse its receipt; run recover if pending. No POST sent.')
            return
        self.ui.say('Exact public preview:\nRoom: ' + room + '\nDID: ' + did + '\nText: ' + text + ('\nCommit: ' + commit if commit else ''))
        if not self.ui.yes('Send this exact signed announcement to the public room?'):
            self.ui.say('No POST sent. Local proof (if any) remains available.')
            return
        with posting_lock(self.root):
            existing = self.existing_record(did, room, text, artifact)
            if existing:
                self.ui.say('Existing record: ' + str(existing.parent) + '; no POST sent.')
                return
            if folder is None:
                folder = self.root / 'receipts' / ('introduction-' + secrets.token_hex(12))
                private_directory(folder)
            nonce = zun.next_nonce()
            normalized, payload = zun.message_payload(room, nonce, text)
            if normalized != text:
                raise SafetyError('Preview changed; refusing to sign a different message')
            request = {'did': did, 'nonce': nonce, 'text': text, 'sig': zun.sign_bytes(key, payload)}
            verify_signature(did, request['sig'], payload)
            intent = {'schema': 'technocore-onboard-intent-v1', 'status': 'pending', 'room': room, 'artifact_url': artifact, 'request': request}
            write_json(folder / 'intent.json', intent, replace=False)
            try:
                response = self.request('POST', 'https://technocore.chat/r/' + room + '?format=json', json.dumps(request, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
                result = decode_json(response.body)
                public_tree(result)
                atomic_write(folder / 'response.json', response.body, replace=False)
                if result.get('room') != room or not isinstance(result.get('posted'), dict) or any(k in result for k in ('message', 'text', 'from', 'did', 'nonce', 'sig', 'signature', 'seq')):
                    raise SafetyError('Missing or ambiguous posted response')
                receipt = message_receipt(room, result['posted'])
                self.match_intent(intent, receipt)
                if 'seq' not in receipt['record']:
                    raise SafetyError('Server did not return a sequence')
                found = self.find_record(intent)
                if found is None:
                    raise SafetyError('POST response signed correctly, but exact read-back is unavailable')
                confirmed, evidence = found
                if confirmed['record'] != receipt['record']:
                    raise SafetyError('Read-back differs from POST response')
                write_json(folder / 'recovery-source.json', evidence)
                self.complete(folder, intent, receipt)
            except (OSError, ValueError, RuntimeError) as error:
                self.ui.say('Outcome UNKNOWN; intent saved at ' + str(folder / 'intent.json') + '. Do not retry. Run recover (read-only). Reason: ' + zun.terminal_safe_detail(type(error).__name__))
                return 1

    def match_intent(self, intent, receipt):
        if receipt['room'] != intent['room']:
            raise SafetyError('Room differs from pending intent')
        record, request = receipt['record'], intent['request']
        if any(record[a] != request[b] for a, b in (('from', 'did'), ('sig', 'sig'), ('nonce', 'nonce'), ('text', 'text'))):
            raise SafetyError('Server record differs from exact DID/nonce/text/signature intent')

    def complete(self, folder, intent, receipt):
        verify_receipt(receipt)
        write_json(folder / 'message-receipt.json', receipt)
        intent = dict(intent, status='posted')
        write_json(folder / 'intent.json', intent)
        self.ui.say('Verified signed record saved: ' + str(folder / 'message-receipt.json') + '. Import this public file at https://tcproof.vercel.app/. Sequence/timestamp are unsigned; signature verification is not live-source confirmation.')

    def read_intent(self, path):
        try:
            return self.validate_intent(read_json(path))
        except (OSError, ValueError, RuntimeError) as error:
            raise SafetyError('Invalid stored intent in ' + path.parent.name + '; preserve this folder and resolve it before posting or recovery.') from error

    def validate_intent(self, intent):
        public_tree(intent)
        if not isinstance(intent, dict) or intent.get('schema') != 'technocore-onboard-intent-v1' or intent.get('status') not in ('pending', 'posted') or not isinstance(intent.get('request'), dict):
            raise SafetyError('Invalid pending intent')
        request = intent['request']
        receipt = message_receipt(intent.get('room'), {'from': request.get('did'), 'sig': request.get('sig'), 'nonce': request.get('nonce'), 'text': request.get('text')})
        self.match_intent(intent, receipt)
        return intent

    def find_record(self, intent):
        self.validate_intent(intent)
        room = intent['room']
        deadline = time.monotonic() + 15
        url = 'https://technocore.chat/r/' + room
        snapshot_response = self.request('GET', url + '?limit=200&format=json', timeout=15)
        snapshot = decode_json(snapshot_response.body)
        if snapshot.get('room') != room or not isinstance(snapshot.get('messages'), list) or any(k in snapshot for k in ('message', 'posted', 'text', 'from', 'did', 'nonce', 'sig', 'signature', 'seq')):
            raise SafetyError('Invalid or ambiguous room snapshot')
        records = snapshot['messages']
        source_url = url + '?limit=200&format=json'
        def matches(records):
            found = []
            for record in records:
                if not isinstance(record, dict) or any(k in record for k in ('message', 'messages', 'posted')) or record.get('room', room) != room:
                    raise SafetyError('Malformed source record')
                request = intent['request']
                if (record.get('did', record.get('from')) == request['did'] and str(record.get('nonce')) == request['nonce']):
                    receipt = message_receipt(room, record)
                    self.match_intent(intent, receipt)
                    if 'seq' not in receipt['record']:
                        raise SafetyError('Found record lacks a sequence')
                    found.append((receipt, record))
            if len(found) > 1:
                raise SafetyError('Multiple matching records; source is ambiguous')
            return found
        found = matches(records)
        if not found:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Recovery deadline exceeded')
            source_url = url + '/export'
            exported = self.request('GET', source_url, cap=12 * 1024 * 1024, timeout=remaining)
            headers = {k.lower(): v for k, v in exported.headers.items()}
            if 'generation' in snapshot and 'x-room-generation' in headers and str(snapshot['generation']) != headers['x-room-generation']:
                raise SafetyError('Room generation changed between snapshot and export')
            records = []
            for line in exported.body.splitlines():
                if len(line) > 256 * 1024:
                    raise SafetyError('Export line exceeds safety limit')
                if line.strip():
                    records.append(decode_json(line))
            found = matches(records)  # Consume and validate the entire bounded export before selecting.
        if not found:
            return None
        receipt, raw_record = found[0]
        return receipt, {'url': source_url, 'record': raw_record}

    def recover(self, selected=None):
        paths = self.intent_paths()
        if selected is not None:
            if not re.fullmatch(r'(?:contribution|introduction)-[a-f0-9]{24}', selected):
                raise SafetyError('Use the receipt folder name shown by doctor, not a path')
            paths = [p for p in paths if p.parent.name == selected]
            if not paths:
                raise SafetyError('Selected intent does not exist')
        intents = [(path, self.read_intent(path)) for path in paths]
        pending = [(path, intent) for path, intent in intents if intent['status'] == 'pending']
        if len(pending) > 5:
            raise SafetyError('More than five pending intents; use recover --intent FOLDER to select one')
        unknown = 0
        for path, intent in pending:
            try:
                found = self.find_record(intent)
                if found is None:
                    unknown += 1
                    self.ui.say('UNKNOWN: exact record not found in retained bounded snapshot/export. This is not proof it was never posted. Intent retained; no repost: ' + path.parent.name)
                    continue
                receipt, evidence = found
                write_json(path.parent / 'recovery-source.json', evidence)
                self.complete(path.parent, intent, receipt)
            except (OSError, ValueError, RuntimeError) as error:
                unknown += 1
                self.ui.say('UNKNOWN: recovery unavailable or source rejected (' + type(error).__name__ + '). Pending intent retained; no repost: ' + path.parent.name)
        if not pending:
            self.ui.say('No pending intents. No network requests or posts made.')
        return 1 if unknown else 0

    def doctor(self):
        self.ui.say('Technocore Onboard ' + VERSION + ' | offline doctor | data: ' + str(self.root))
        errors = []
        if not self.root.exists():
            self.ui.say('No installation data here. Run setup, or use the original --data-dir. No files were created.')
            return 1
        try:
            check_path(self.key_path)
            if not self.key_path.exists():
                errors.append('Encrypted identity missing: restore your backup; never regenerate to fix a path error.')
            else:
                with self.key_path.open('rb') as key_file:
                    if not key_file.read(64).startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'):
                        errors.append('Identity is not encrypted PKCS8 PEM.')
                if os.name != 'nt' and self.key_path.stat().st_mode & 0o077:
                    errors.append('Identity permissions are not private; chmod 600 identity/identity.pem.')
            if not self.state_path.exists():
                errors.append('Public state missing: run setup to reuse the existing encrypted identity.')
            else:
                state = read_json(self.state_path)
                public_tree(state)
                zun.public_key_from_did(state.get('did'))
                self.ui.say('Stored public DID: ' + state['did'] + ' (key not decrypted; binding is checked when you unlock setup/contribute).')
                did_path = self.root / 'identity' / 'did.txt'
                check_path(did_path)
                if not did_path.exists() or did_path.read_text(encoding='utf-8').strip() != state['did']:
                    errors.append('Public did.txt missing or mismatched; run setup to unlock and repair it.')
            valid, pending = 0, 0
            for path in self.intent_paths():
                intent = self.read_intent(path)
                if intent['status'] == 'pending':
                    pending += 1
                    self.ui.say('Pending: ' + path.parent.name + ' — run recover; never blindly repost.')
                elif not (path.parent / 'message-receipt.json').exists():
                    errors.append('Posted intent missing its receipt: ' + path.parent.name)
                else:
                    self.match_intent(intent, verify_receipt(read_json(path.parent / 'message-receipt.json')))
                if self.state_path.exists() and intent['request']['did'] != state['did']:
                    errors.append('Intent belongs to a different DID: ' + path.parent.name)
            directory = self.root / 'receipts'
            if directory.exists():
                for folder in directory.iterdir():
                    check_path(folder)
                    if folder.is_dir():
                        for name in ('message-receipt.json', 'proof-receipt.json'):
                            path = check_path(folder / name)
                            if path.exists():
                                verify_receipt(read_json(path))
                                valid += 1
            self.ui.say(f'Locally verified receipts: {valid}; pending intents: {pending}. No network requested; identity not decrypted.')
            if pending:
                errors.append('Resolve pending outcomes with recover (read-only).')
            if (self.root / '.posting.lock').exists():
                errors.append('Posting lock exists; another process may be active. Recover first; remove only after checking the process has stopped.')
        except (OSError, ValueError, RuntimeError) as error:
            detail = error if isinstance(error, SafetyError) else type(error).__name__
            errors.append('Local validation failed: ' + zun.terminal_safe_detail(detail) + '. Preserve your encrypted identity and inspect the affected public files.')
        for error in errors:
            self.ui.say('CHECK: ' + error)
        return 1 if errors else 0


def default_data_dir():
    if os.name == 'nt':
        return Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData' / 'Local')) / 'TechnocoreOnboard'
    return Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local' / 'share')) / 'technocore-onboard'


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='backslashreplace')
    parser = argparse.ArgumentParser(prog='tcproof', description='Local encrypted Technocore identity; separately preview and consent to public contributions.')
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('--data-dir', type=Path, default=default_data_dir(), help='Installation ROOT, not app-v1.0.0; wrappers supply this automatically')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('setup', help='Create once or reuse the SAME encrypted identity interactively')
    commands.add_parser('contribute', help='Record a published X/GitHub/other URL; public POST requires explicit yes')
    doctor = commands.add_parser('doctor', help='Offline local checks; never decrypts keys or contacts the network')
    doctor.add_argument('--receipt', type=Path, help='Verify one public Inspector receipt offline (never supply a PEM)')
    recover = commands.add_parser('recover', help='Read-only snapshot/export recovery for uncertain POSTs; never reposts')
    recover.add_argument('--intent', help='Select a receipt folder name shown by doctor')
    args = parser.parse_args(argv)
    if zun is None:
        print('error: dependency missing; run the verified installer or install requirements.txt inside an isolated Python 3.12 environment.', file=sys.stderr)
        return 1
    try:
        wizard = Wizard(args.data_dir)
        if args.command == 'doctor' and args.receipt:
            result = verify_receipt(read_json(args.receipt))
            print('Valid local ' + result['kind'] + ' signature. No network requested; this does not establish live-source presence.')
            return 0
        if args.command == 'recover':
            return wizard.recover(args.intent)
        return getattr(wizard, args.command)() or 0
    except (EOFError, KeyboardInterrupt):
        print('Cancelled. Existing identity and pending intents are preserved; use recover after an interrupted POST.', file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print('error: ' + zun.terminal_safe_detail(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
