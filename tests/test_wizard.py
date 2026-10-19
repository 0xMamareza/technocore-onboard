"""Offline tests. All generated identities are disposable synthetic fixtures."""
import contextlib
import io
import json
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

_scratch = Path.home() / 'AppData' / 'Local' / 'hermes' / 'cache' / 'scratch'
tempfile.tempdir = str(_scratch) if os.name == 'nt' and _scratch.is_dir() else tempfile.gettempdir()

try:
    import onboard as app
except ImportError:
    app = None


class WizardTests(unittest.TestCase):
    def test_setup_cancel_and_nonterminal_never_create_identity(self):
        self.assertIsNotNone(app, 'wizard implementation is missing')
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
            root = Path(tmp) / 'data'
            ui = app.ScriptUI(['local', 'cancel'])
            wizard = app.Wizard(root, ui=ui)
            wizard.setup()
            self.assertFalse((root / 'identity' / 'identity.pem').exists())
            with self.assertRaises(app.SafetyError):
                app.Wizard(root, ui=app.ScriptUI([], terminal=False)).setup()
            self.assertFalse((root / 'identity' / 'identity.pem').exists())
    def test_identity_create_resume_and_import_never_replace(self):
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
            root = Path(tmp) / "data spaces ' آزمایش"
            passphrase = 'SYNTHETIC disposable fixture passphrase'
            ui = app.ScriptUI(['local', 'create', 'yes', ''], [passphrase, passphrase])
            app.Wizard(root, ui=ui).setup()
            key = root / 'identity' / 'identity.pem'
            original = key.read_bytes()
            self.assertIn(b'ENCRYPTED PRIVATE KEY', original)
            state = json.loads((root / 'state.json').read_text())
            self.assertTrue(state['did'].startswith('did:key:z6Mk'))
            ui2 = app.ScriptUI(['local', ''], [passphrase])
            app.Wizard(root, ui=ui2).setup()
            self.assertEqual(key.read_bytes(), original)
            self.assertEqual(json.loads((root / 'state.json').read_text())['did'], state['did'])
            public = (root / 'state.json').read_text() + (root / 'identity' / 'did.txt').read_text() + str(ui.output)
            self.assertNotIn(passphrase, public)
            self.assertNotIn('BEGIN ENCRYPTED', public)
            imported = Path(tmp) / 'imported'
            app.Wizard(imported, ui=app.ScriptUI(['local', 'reuse', str(key), ''], [passphrase])).setup()
            self.assertEqual((imported / 'identity' / 'identity.pem').read_bytes(), original)
            self.assertEqual(json.loads((imported / 'state.json').read_text())['did'], state['did'])
    def test_import_validates_captured_bytes_when_source_changes_before_load(self):
        from unittest.mock import patch
        from vendor import technocore_agent as zun
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
            source, replacement = Path(tmp) / 'source.pem', Path(tmp) / 'replacement.pem'
            password = 'SYNTHETIC disposable passphrase'
            did_a = zun.create_identity(source, password)
            zun.create_identity(replacement, password)
            captured, changed = source.read_bytes(), replacement.read_bytes()
            root, loaded_paths = Path(tmp) / 'data', []
            load_identity = zun.load_identity
            def replace_source_before_load(path, *args, **kwargs):
                source.write_bytes(changed)
                loaded_paths.append(path)
                return load_identity(path, *args, **kwargs)
            with patch.object(zun, 'load_identity', side_effect=replace_source_before_load):
                app.Wizard(root, ui=app.ScriptUI(['local', 'reuse', str(source), ''], [password])).setup()
            installed = root / 'identity' / 'identity.pem'
            self.assertEqual(installed.read_bytes(), captured)
            self.assertEqual(app.read_json(root / 'state.json')['did'], did_a)
            self.assertEqual(zun.did_from_private_key(load_identity(installed, password.encode(), allow_prompt=False)), did_a)
            self.assertNotEqual(loaded_paths[0], source, 'Never reopen the changing import source')
            self.assertFalse(loaded_paths[0].exists(), 'Private import staging must be cleaned up')

    def test_contribution_cancel_saves_verified_github_proof_without_post(self):
        from vendor import technocore_agent as zun
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
            root = Path(tmp) / 'data'
            password = 'SYNTHETIC disposable passphrase'
            app.Wizard(root, ui=app.ScriptUI(['local', 'create', 'yes', ''], [password, password])).setup()
            commit = 'a' * 40
            calls = []
            def simulated(method, url, body=None, **limits):
                calls.append((method, url, body))
                if url.endswith('/commits/main'):
                    return app.Response(json.dumps({'sha': commit}).encode())
                return app.Response(json.dumps({'private': False, 'visibility': 'public', 'full_name': 'example/project', 'default_branch': 'main'}).encode())
            ui = app.ScriptUI(['github', 'https://github.com/example/project', '', 'A useful public tool', '', ''], [password])
            app.Wizard(root, ui=ui, transport=simulated).contribute()
            self.assertTrue(all(call[0] == 'GET' for call in calls))
            proof_path = next((root / 'receipts').glob('*/proof.json'))
            proof = json.loads(proof_path.read_text())
            zun.verify_contribution_proof(proof)
            self.assertEqual(proof['did'], json.loads((root / 'state.json').read_text())['did'])
            self.assertEqual(proof['commit'], commit)
            self.assertTrue((proof_path.parent / 'proof-receipt.json').exists())
            self.assertFalse((proof_path.parent / 'intent.json').exists())
            self.assertIn('No POST sent', '\n'.join(ui.output))

    def test_url_validation_preserves_exact_x_query_and_rejects_private(self):
        self.assertEqual(app.public_url('https://x.com/example/status/1234567890123456789?s=20', 'x'), 'https://x.com/example/status/1234567890123456789?s=20')
        for url in ['http://example.com/a', 'https://user:pass@example.com/a', 'https://127.0.0.1/a', 'https://[::1]/a', 'https://10.0.0.1/a', 'https://localhost/a', 'https://private.local/a', 'https://example.com/\nsecret', 'https://example.com/a#fragment']:
            with self.subTest(url=url), self.assertRaises(app.SafetyError):
                app.public_url(url)
        for url in ['https://x.com/name', 'https://twitter.com/name/status/notdecimal', 'https://x.com.evil.test/name/status/123', 'https://github.com/owner/repo/tree/main']:
            with self.subTest(url=url), self.assertRaises(app.SafetyError):
                app.public_url(url, 'github' if 'github' in url else 'x')
    def test_post_consent_pending_receipt_signature_and_duplicate_guard(self):
        from vendor import technocore_agent as zun
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
            root = Path(tmp) / 'data'
            password = 'SYNTHETIC disposable passphrase'
            app.Wizard(root, ui=app.ScriptUI(['local', 'create', 'yes', ''], [password, password])).setup()
            calls = []
            last_posted = []
            def simulated(method, url, body=None, **limits):
                calls.append(method)
                if method == 'GET':
                    return app.Response(json.dumps({'room': 'lobby', 'messages': last_posted}).encode())
                self.assertEqual(method, 'POST')
                request = json.loads(body)
                intent = next((root / 'receipts').glob('*/intent.json'))
                self.assertEqual(json.loads(intent.read_text())['status'], 'pending')
                zun.verify_bytes(request['did'], request['sig'], f"lobby|{request['nonce']}|{request['text']}".encode())
                posted = {'from': request['did'], 'nonce': int(request['nonce']), 'sig': request['sig'], 'text': request['text'], 'seq': 9999999999999999999, 'ts': '2026-01-01T00:00:00Z'}
                last_posted.append(posted)
                return app.Response(json.dumps({'room': 'lobby', 'count': 1, 'last_seq': posted['seq'], 'posted': posted, 'messages': [posted]}).encode())
            answers = ['x', 'https://x.com/example/status/123?s=20', 'Public synthetic example', 'lobby', 'yes']
            with patch.object(zun, 'next_nonce', return_value='9999999999999999998'):
                app.Wizard(root, ui=app.ScriptUI(answers, [password]), transport=simulated).contribute()
            receipt = next((root / 'receipts').glob('*/message-receipt.json'))
            app.verify_receipt(json.loads(receipt.read_text()))
            self.assertEqual(json.loads(receipt.read_text())['record']['nonce'], '9999999999999999998')
            self.assertEqual(json.loads(receipt.read_text())['record']['seq'], '9999999999999999999')
            self.assertTrue((receipt.parent / 'response.json').exists())
            ui = app.ScriptUI(answers, [password])
            app.Wizard(root, ui=ui, transport=simulated).contribute()
            self.assertEqual(calls, ['POST', 'GET'])
            self.assertIn('Existing record', '\n'.join(ui.output))
    def test_timeout_recover_export_exact_match_and_unknown_never_repost(self):
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
            root = Path(tmp) / 'data'
            password = 'SYNTHETIC disposable passphrase'
            app.Wizard(root, ui=app.ScriptUI(['local', 'create', 'yes', ''], [password, password])).setup()
            captured = []
            def timeout(method, url, body=None, **limits):
                captured.append(json.loads(body))
                raise TimeoutError('SIMULATED uncertain write')
            ui = app.ScriptUI(['other', 'https://example.com/work', 'Synthetic article', 'lobby', 'yes'], [password])
            app.Wizard(root, ui=ui, transport=timeout).contribute()
            path = next((root / 'receipts').glob('*/intent.json'))
            self.assertEqual(json.loads(path.read_text())['status'], 'pending')
            self.assertIn('UNKNOWN', '\n'.join(ui.output))
            calls = []
            def absent(method, url, body=None, **limits):
                calls.append((method, url))
                return app.Response(b'' if url.endswith('/export') else b'{"room":"lobby","messages":[],"generation":1}', {'X-Room-Generation': '1'})
            reader = app.Wizard(root, ui=app.ScriptUI([]), transport=absent)
            self.assertEqual(reader.recover(), 1)
            self.assertEqual(json.loads(path.read_text())['status'], 'pending')
            self.assertEqual(len(calls), 2)
            self.assertTrue(all(x[0] == 'GET' for x in calls))
            request = captured[0]
            record = {'from': request['did'], 'sig': request['sig'], 'nonce': int(request['nonce']), 'text': request['text'], 'seq': 9007199254740993, 'metadata': {'finite': [1e100, -0.25]}}
            def found(method, url, body=None, **limits):
                self.assertEqual(method, 'GET')
                return app.Response((json.dumps(record) + '\n').encode() if url.endswith('/export') else b'{"room":"lobby","messages":[],"generation":1}', {'X-Room-Generation': '1'})
            reader.transport = found
            self.assertEqual(reader.recover(), 0)
            self.assertEqual(json.loads(path.read_text())['status'], 'posted')
            app.verify_receipt(json.loads((path.parent / 'message-receipt.json').read_text()))
            evidence_path = path.parent / 'recovery-source.json'
            evidence = app.read_json(evidence_path)
            self.assertEqual(evidence['record'], record)
            self.assertEqual(app.decode_json(evidence_path.read_bytes()), evidence)
            self.assertEqual(len(captured), 1)

    def test_http_protocol_failures_preserve_pending_and_exit_without_reposting(self):
        import http.client
        from unittest.mock import patch
        from vendor import technocore_agent as zun
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.from_private_bytes(bytes([8]) * 32)
        wires = ((b'not-http\r\n\r\n', http.client.BadStatusLine),
                 (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nnot-hex\r\n', http.client.IncompleteRead))
        for wire, expected in wires:
            # Observe the real stdlib parser's exception, rather than inventing its type.
            class SyntheticSocket:
                def makefile(self, *args):
                    return io.BytesIO(wire)
            with http.client.HTTPResponse(SyntheticSocket()) as response:
                try:
                    response.begin()
                    response.read()
                except expected as error:
                    observed = error
                else:
                    self.fail('Malformed HTTP fixture did not fail')
            for stage in ('post', 'readback', 'snapshot', 'export'):
                with self.subTest(error=expected.__name__, stage=stage), tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
                    root, calls = Path(tmp) / 'data', []
                    ui = app.ScriptUI(['yes'])
                    def simulated(method, url, body=None, **limits):
                        calls.append((method, url))
                        if method == 'POST':
                            path = next((root / 'receipts').glob('*/intent.json'))
                            self.assertEqual(app.read_json(path)['status'], 'pending')
                            if stage == 'post':
                                raise observed
                            request = json.loads(body)
                            return app.Response(json.dumps({'room': 'lobby', 'posted': dict(request, seq=1)}).encode())
                        if stage == 'export' and not url.endswith('/export'):
                            return app.Response(b'{"room":"lobby","messages":[]}')
                        raise observed
                    wizard = app.Wizard(root, ui=ui, transport=simulated)
                    wizard.prepare()
                    if stage in ('snapshot', 'export'):
                        folder = root / 'receipts' / ('introduction-' + '8' * 24)
                        folder.mkdir()
                        request = {'did': zun.did_from_private_key(key), 'nonce': '1', 'text': 'SYNTHETIC protocol failure'}
                        request['sig'] = zun.sign_bytes(key, b'lobby|1|SYNTHETIC protocol failure')
                        app.write_json(folder / 'intent.json', {'schema': 'technocore-onboard-intent-v1', 'status': 'pending', 'room': 'lobby', 'request': request})
                        before = (folder / 'intent.json').read_bytes()
                        command = 'recover'
                    else:
                        command = 'contribute'
                    with patch('onboard.Wizard', return_value=wizard), patch.object(wizard, 'contribute', side_effect=lambda: wizard.announce(key, 'lobby', 'SYNTHETIC protocol failure', None, None)):
                        self.assertEqual(app.main(['--data-dir', str(root), command]), 1)
                    path = next((root / 'receipts').glob('*/intent.json'))
                    intent = wizard.read_intent(path)
                    self.assertEqual(intent['status'], 'pending')
                    if command == 'recover':
                        self.assertEqual(path.read_bytes(), before)
                    self.assertFalse((path.parent / 'message-receipt.json').exists())
                    output = '\n'.join(ui.output)
                    self.assertIn('UNKNOWN', output)
                    self.assertIn('Do not retry' if command == 'contribute' else 'no repost', output)
                    self.assertEqual([method for method, _ in calls], {'post': ['POST'], 'readback': ['POST', 'GET'], 'snapshot': ['GET'], 'export': ['GET', 'GET']}[stage])
                    before_calls, before_intent = list(calls), path.read_bytes()
                    wizard.announce(key, 'lobby', 'SYNTHETIC protocol failure', None, None)
                    self.assertEqual(calls, before_calls, 'A pending intent must prevent a second POST')
                    self.assertEqual(path.read_bytes(), before_intent)

    def test_cli_controls_http_protocol_failure_before_posting(self):
        import http.client
        from unittest.mock import patch
        for error in (http.client.BadStatusLine('malformed'), http.client.IncompleteRead(b'')):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
                root, calls, stderr = Path(tmp) / 'data', [], io.StringIO()
                def simulated(method, url, body=None, **limits):
                    calls.append(method)
                    raise error
                wizard = app.Wizard(root, ui=app.ScriptUI(['github', 'https://github.com/example/project', '']), transport=simulated)
                with patch('onboard.Wizard', return_value=wizard), contextlib.redirect_stderr(stderr):
                    self.assertEqual(app.main(['--data-dir', str(root), 'contribute']), 1)
                self.assertIn('error:', stderr.getvalue())
                self.assertNotIn('Traceback', stderr.getvalue())
                self.assertEqual(calls, ['GET'])
                self.assertFalse(root.exists())

    def test_doctor_offline_reports_missing_and_valid_receipts_without_secret_prompt(self):
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
            root = Path(tmp) / 'data'
            ui = app.ScriptUI([], terminal=False)
            self.assertEqual(app.Wizard(root, ui=ui).doctor(), 1)
            self.assertFalse(root.exists())
            password = 'SYNTHETIC disposable passphrase'
            app.Wizard(root, ui=app.ScriptUI(['local', 'create', 'yes', ''], [password, password])).setup()
            ui = app.ScriptUI([], terminal=False)
            self.assertEqual(app.Wizard(root, ui=ui).doctor(), 0)
            self.assertIn('not decrypted', '\n'.join(ui.output))
    def test_cli_version_and_nonterminal_setup_are_cwd_independent(self):
        import os
        import subprocess
        import sys
        script = Path(app.__file__).absolute()
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
            root = Path(tmp) / 'Unicode space-آزمایش'
            version = subprocess.run([sys.executable, str(script), '--version'], cwd=tmp, capture_output=True, text=True)
            self.assertEqual(version.returncode, 0)
            self.assertEqual(version.stdout.strip(), '1.0.0')
            result = subprocess.run([sys.executable, str(script), '--data-dir', str(root), 'setup'], cwd=tmp, input='', capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('interactive terminal', result.stderr.lower())
            self.assertFalse(root.exists())
            result = subprocess.run([sys.executable, str(script), '--data-dir', str(root), 'doctor'], cwd=tmp, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('No installation data', result.stdout)
            self.assertFalse(root.exists())
    def test_filesystem_safety_rejects_roots_dotdot_and_symlinks(self):
        roots = [Path.home(), Path(Path.home().anchor), Path.home() / 'data' / '..']
        if os.name == 'nt':
            roots += [Path(os.environ.get('SystemRoot', 'C:/Windows')), Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'not-created']
        else:
            roots += [Path('/etc'), Path('/usr/local/SYNTHETIC-not-created')]
        for root in roots:
            with self.subTest(root=str(root)), self.assertRaises(app.SafetyError):
                app.Wizard(root)
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
            source, target = Path(tmp) / 'source', Path(tmp) / 'target'
            target.mkdir()
            try:
                source.symlink_to(target, target_is_directory=True)
            except OSError:
                if os.name == 'nt':
                    subprocess.run(['cmd', '/c', 'mklink', '/J', str(source), str(target)], check=True, capture_output=True)
                else:
                    raise
            with self.assertRaises(app.SafetyError):
                app.Wizard(source)
            self.assertFalse((target / 'identity').exists())

    def test_weak_passphrase_and_missing_identity_never_regenerate(self):
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
            root = Path(tmp) / 'data'
            with self.assertRaises(app.SafetyError):
                app.Wizard(root, ui=app.ScriptUI(['local', 'create', 'yes'], ['short', 'short'])).setup()
            self.assertFalse(root.exists())
            password = 'SYNTHETIC disposable passphrase'
            app.Wizard(root, ui=app.ScriptUI(['local', 'create', 'yes', ''], [password, password])).setup()
            key = root / 'identity' / 'identity.pem'
            original = key.read_bytes()
            state = (root / 'state.json').read_bytes()
            with self.assertRaises(ValueError):
                app.Wizard(root, ui=app.ScriptUI(['local'], ['SYNTHETIC wrong passphrase'])).setup()
            self.assertEqual(key.read_bytes(), original)
            key.unlink()
            with self.assertRaises(app.SafetyError):
                app.Wizard(root, ui=app.ScriptUI(['local', 'create', 'yes'], [password, password])).setup()
            self.assertFalse(key.exists())
            self.assertEqual((root / 'state.json').read_bytes(), state)

    def test_unencrypted_import_and_changed_public_did_are_refused(self):
        from vendor import technocore_agent as zun
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
            source = Path(tmp) / 'SYNTHETIC-unencrypted.pem'
            source.write_bytes(Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            root = Path(tmp) / 'data'
            with self.assertRaises(app.SafetyError):
                app.Wizard(root, ui=app.ScriptUI(['local', 'reuse', str(source)])).setup()
            self.assertFalse(root.exists())
            password = 'SYNTHETIC disposable passphrase'
            app.Wizard(root, ui=app.ScriptUI(['local', 'create', 'yes', ''], [password, password])).setup()
            old_key = (root / 'identity' / 'identity.pem').read_bytes()
            state = json.loads((root / 'state.json').read_text())
            state['did'] = zun.did_from_private_key(Ed25519PrivateKey.from_private_bytes(bytes([2]) * 32))
            app.write_json(root / 'state.json', state)
            with self.assertRaises(app.SafetyError):
                app.Wizard(root, ui=app.ScriptUI(['local'], [password])).setup()
            self.assertEqual((root / 'identity' / 'identity.pem').read_bytes(), old_key)

    def test_github_commit_validation_and_public_metadata_fail_closed(self):
        calls = []
        def simulated(method, url, body=None, **limits):
            calls.append(url)
            return app.Response(b'{"private":true,"full_name":"example/project"}')
        wizard = app.Wizard(Path(tempfile.gettempdir()) / 'SYNTHETIC-no-writes', transport=simulated)
        for chosen in ['main', '1234', 'A' * 40, 'g' * 40, 'a' * 39]:
            with self.subTest(chosen=chosen), self.assertRaises(app.SafetyError):
                wizard.github_revision('https://github.com/example/project', chosen)
        self.assertEqual(calls, [])
        with self.assertRaises(app.SafetyError):
            wizard.github_revision('https://github.com/example/project', '')
        def mismatched(method, url, body=None, **limits):
            return app.Response(json.dumps({'sha': 'b' * 40} if '/commits/' in url else {'private': False, 'full_name': 'example/project', 'default_branch': 'main'}).encode())
        wizard.transport = mismatched
        with self.assertRaises(app.SafetyError):
            wizard.github_revision('https://github.com/example/project', 'a' * 40)

    def test_github_full_name_wrong_types_are_rejected_before_revision_lookup(self):
        from unittest.mock import patch
        for full_name in (None, [], 123, {}, True):
            with self.subTest(full_name=full_name), tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
                root, calls, stderr = Path(tmp) / 'data', [], io.StringIO()
                def simulated(method, url, body=None, **limits):
                    calls.append((method, url))
                    return app.Response(json.dumps({'private': False, 'full_name': full_name, 'default_branch': 'main'}).encode())
                wizard = app.Wizard(root, ui=app.ScriptUI(['github', 'https://github.com/example/project', '']), transport=simulated)
                with self.assertRaisesRegex(app.SafetyError, 'exact public repository'):
                    wizard.github_revision('https://github.com/example/project', '')
                calls.clear()
                with patch('onboard.Wizard', return_value=wizard), contextlib.redirect_stderr(stderr):
                    self.assertEqual(app.main(['--data-dir', str(root), 'contribute']), 1)
                self.assertIn('exact public repository', stderr.getvalue())
                self.assertNotIn('Traceback', stderr.getvalue())
                self.assertEqual(calls, [('GET', 'https://api.github.com/repos/example/project')])
                self.assertFalse(root.exists())

    def test_public_json_rejects_duplicate_fields_and_secret_markers(self):
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
            path = Path(tmp) / 'bad.json'
            path.write_text('{"did":"first","did":"second"}')
            with self.assertRaises(app.SafetyError):
                app.read_json(path)
            with self.assertRaises(app.SafetyError):
                app.write_json(Path(tmp) / 'public.json', {'text': '-----BEGIN PRIVATE KEY-----'})
            self.assertFalse((Path(tmp) / 'public.json').exists())

    def test_nonfinite_json_numbers_never_decode_or_persist(self):
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
            path = Path(tmp) / 'evidence.json'
            for token in ('1e100000', '-1e100000', 'NaN', 'Infinity', '-Infinity'):
                with self.subTest(token=token), self.assertRaises(app.SafetyError):
                    app.decode_json(('{"metadata":[{"value":' + token + '}]}').encode())
            for value in (float('inf'), -float('inf'), float('nan')):
                tree = {'metadata': [{'value': value}]}
                with self.subTest(value=value), self.assertRaises(app.SafetyError):
                    app.public_tree(tree)
                with self.subTest(write=value), self.assertRaises(ValueError):
                    app.write_json(path, tree)
                self.assertFalse(path.exists(), 'Nonfinite JSON must not be written')

    def test_stored_intents_fail_closed_with_folder_identifying_errors(self):
        from vendor import technocore_agent as zun
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
        request = {'did': zun.did_from_private_key(key), 'nonce': '1', 'text': 'SYNTHETIC intent'}
        request['sig'] = zun.sign_bytes(key, b'lobby|1|SYNTHETIC intent')
        valid = {'schema': 'technocore-onboard-intent-v1', 'status': 'pending', 'room': 'lobby', 'request': request}
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
            root = Path(tmp) / 'data'
            def forbidden(*args, **kwargs):
                self.fail('Malformed local intents must prevent network requests')
            ui = app.ScriptUI([], terminal=False)
            wizard = app.Wizard(root, ui=ui, transport=forbidden)
            wizard.prepare()
            bad_folder = root / 'receipts' / ('introduction-' + 'f' * 24)
            bad_folder.mkdir()
            path = bad_folder / 'intent.json'
            corruptions = ({'request': None}, {'request': []}, {'request': 'not an object'},
                           {'status': 'broken'}, {'schema': 'unsupported'}, {'request': dict(request, sig='A' * 86)})
            for change in corruptions:
                path.write_text(json.dumps(dict(valid, **change)), encoding='utf-8')
                before = path.read_bytes()
                for command in (lambda: wizard.existing_record(request['did'], 'lobby', request['text'], None), wizard.recover):
                    with self.subTest(change=change, command=command):
                        try:
                            command()
                        except Exception as error:
                            self.assertIsInstance(error, app.SafetyError)
                            self.assertIn(bad_folder.name, str(error))
                        else:
                            self.fail('Malformed stored intent was silently accepted')
                with self.subTest(doctor=change):
                    ui.output.clear()
                    self.assertEqual(wizard.doctor(), 1)
                    self.assertIn(bad_folder.name, '\n'.join(ui.output))
                self.assertEqual(path.read_bytes(), before)
            # A matching earlier intent must not hide a later corrupt one.
            good_folder = root / 'receipts' / ('introduction-' + '0' * 24)
            good_folder.mkdir()
            app.write_json(good_folder / 'intent.json', valid)
            with self.assertRaisesRegex(app.SafetyError, bad_folder.name):
                wizard.existing_record(request['did'], 'lobby', request['text'], None)

    def test_cancel_menu_and_intro_preview_default_no_never_post(self):
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
            root = Path(tmp) / 'data'
            app.Wizard(root, ui=app.ScriptUI([''])).contribute()
            self.assertFalse(root.exists())
            password = 'SYNTHETIC disposable passphrase'
            ui = app.ScriptUI(['remote', 'create', 'yes', 'yes', '  Hello\nworld!  ', '', ''], [password, password])
            def forbidden(*args, **kwargs):
                self.fail('No network allowed after cancellation')
            app.Wizard(root, ui=ui, transport=forbidden).setup()
            self.assertIn('Text: Hello world!', '\n'.join(ui.output))
            self.assertIn('Room: lobby', '\n'.join(ui.output))
            self.assertEqual(list((root / 'receipts').glob('*/intent.json')), [])
            contribution_ui = app.ScriptUI(['other', 'https://example.com/work', 'SYNTHETIC public tool', '', ''], [password])
            app.Wizard(root, ui=contribution_ui, transport=forbidden).contribute()
            self.assertIn('Public Technocore room [technocore]: ', contribution_ui.output)
            self.assertIn('Room: technocore', '\n'.join(contribution_ui.output))
            self.assertEqual(list((root / 'receipts').glob('*/intent.json')), [])

    def test_receipt_exact_bytes_tamper_alias_and_noncanonical_signature(self):
        from vendor import technocore_agent as zun
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.from_private_bytes(bytes([3]) * 32)  # Public SYNTHETIC key.
        did = zun.did_from_private_key(key)
        text = 'Unicode: فارسی e\u0301 😀  '
        sig = zun.sign_bytes(key, f'lobby|9007199254740993|{text}'.encode())
        record = {'from': did, 'text': text, 'nonce': 9007199254740993, 'sig': sig, 'seq': 9007199254740994}
        receipt = app.message_receipt('lobby', record)
        self.assertEqual(app.verify_receipt(json.loads(json.dumps(receipt)))['record']['text'], text)
        for change in ({'text': text.rstrip()}, {'signature': 'A' * 86}, {'did': 'wrong'}, {'message': {}}, {'nonce': True}, {'nonce': 1.5}, {'seq': 0}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                app.message_receipt('lobby', dict(record, **change))
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
        noncanonical = sig[:-1] + alphabet[alphabet.index(sig[-1]) + 1]
        with self.assertRaises(app.SafetyError):
            app.message_receipt('lobby', dict(record, sig=noncanonical))

    def test_recovery_rejects_duplicates_generation_mismatch_and_malformed_export(self):
        from vendor import technocore_agent as zun
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.from_private_bytes(bytes([4]) * 32)
        request = {'did': zun.did_from_private_key(key), 'nonce': '9007199254740993', 'text': 'Synthetic recovery fixture'}
        request['sig'] = zun.sign_bytes(key, f"lobby|{request['nonce']}|{request['text']}".encode())
        intent = {'schema': 'technocore-onboard-intent-v1', 'status': 'pending', 'room': 'lobby', 'request': request}
        record = dict(request, seq=123)
        line = json.dumps(record).encode() + b'\n'
        for exported, generation in [(line + line, '1'), (line + b'not-json\n', '1'), (line, '2'), (line + json.dumps({'posted': record}).encode(), '1'), (line + b' ' * (256 * 1024 + 1), '1')]:
            calls = []
            def simulated(method, url, body=None, **limits):
                calls.append((method, url))
                return app.Response(exported if url.endswith('/export') else b'{"room":"lobby","messages":[],"generation":1}', {'X-Room-Generation': generation})
            wizard = app.Wizard(Path(tempfile.gettempdir()) / 'SYNTHETIC-no-writes', transport=simulated)
            with self.subTest(generation=generation, size=len(exported)), self.assertRaises(ValueError):
                wizard.find_record(intent)
            self.assertLessEqual(len(calls), 2)
            self.assertTrue(all(x[0] == 'GET' for x in calls))

    def test_transport_origin_redirect_and_response_limits(self):
        for url in ['https://example.com/r/lobby', 'http://technocore.chat/r/lobby', 'https://user@technocore.chat/r/lobby', 'https://technocore.chat:444/r/lobby']:
            with self.subTest(url=url), self.assertRaises(app.SafetyError):
                app.http_request('GET', url)
        from unittest.mock import patch
        for url in ['https://technocore.chat/r/lobby/say/name/danger', 'https://technocore.chat/kv/example/key/set/value', 'https://technocore.chat/r/lobby?unexpected=1']:
            with self.subTest(url=url), patch('onboard.build_opener', side_effect=AssertionError('Unsafe endpoint reached network')), self.assertRaises(app.SafetyError):
                app.http_request('GET', url)
        with self.assertRaises(app.SafetyError):
            app.http_request('POST', 'https://api.github.com/repos/example/project', b'{}')
        with self.assertRaises(app.SafetyError):
            app.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://example.com')
        wizard = app.Wizard(Path(tempfile.gettempdir()) / 'SYNTHETIC-no-writes', transport=lambda *a, **kw: app.Response(b'12345'))
        with self.assertRaises(app.SafetyError):
            wizard.request('GET', 'https://technocore.chat/r/lobby', cap=4)

    def test_actual_inspector_async_receipt_reimport_with_synthetic_vectors(self):
        from vendor import technocore_agent as zun
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        inspector = Path(__file__).resolve().parents[2] / 'technocore-proof-inspector'
        core = inspector / 'src' / 'core' / 'index.js'
        import shutil
        if not core.exists() or not shutil.which('node'):
            self.skipTest('Independent Inspector sibling and Node required (optional local interoperability check)')
        key = Ed25519PrivateKey.from_private_bytes(bytes([5]) * 32)
        text = 'SYNTHETIC compatibility: فارسی 😀'
        record = {'from': zun.did_from_private_key(key), 'nonce': 9999999999999999998, 'text': text, 'sig': zun.sign_bytes(key, f'lobby|9999999999999999998|{text}'.encode()), 'seq': 9999999999999999999}
        proof = zun.create_contribution_proof(key, 'https://github.com/example/project', 'a' * 40)
        receipts = [app.message_receipt('lobby', record), {'schema': 'technocore-inspector-receipt-v1', 'kind': 'contribution', 'record': proof}]
        js = 'import {inspectJson} from ' + json.dumps(core.as_uri()) + '; let raw=""; for await (const chunk of process.stdin) raw+=chunk; for(const r of JSON.parse(raw)){const first=await inspectJson(JSON.stringify(r));if(first.signatureStatus!=="valid")throw Error("invalid"); const second=await inspectJson(JSON.stringify(first.receipt));if(second.signatureStatus!=="valid")throw Error("reimport invalid");} console.log("2 synthetic receipts: valid import and reimport");'
        result = subprocess.run(['node', '--input-type=module', '-e', js], cwd=inspector, input=json.dumps(receipts), text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('2 synthetic receipts', result.stdout)
    def test_hidden_prompt_refuses_getpass_echo_fallback(self):
        from unittest.mock import patch
        import getpass
        import warnings
        def echo_fallback(prompt):
            warnings.warn('cannot hide input', getpass.GetPassWarning)
            self.fail('An echo fallback must never be reached')
        with patch('onboard.sys.stdin.isatty', return_value=True), patch('onboard.sys.stdout.isatty', return_value=True), patch('onboard.getpass.getpass', side_effect=echo_fallback):
            with self.assertRaises((app.SafetyError, getpass.GetPassWarning)):
                app.TerminalUI().secret('Hidden: ')

    def test_windows_managed_identity_acl_excludes_inherited_or_extra_grants(self):
        if os.name != 'nt':
            self.skipTest('Windows DACL check')
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
            root = Path(tmp) / 'data'
            root.mkdir()
            subprocess.run(['icacls', str(root), '/grant', '*S-1-1-0:(OI)(CI)F'], check=True, capture_output=True)
            password = 'SYNTHETIC disposable passphrase'
            app.Wizard(root, ui=app.ScriptUI(['local', 'create', 'yes', ''], [password, password])).setup()
            acl = subprocess.run(['icacls', str(root)], text=True, capture_output=True, check=True).stdout
            self.assertNotIn('Everyone:', acl)
            self.assertNotIn('(I)', acl)
            key_path = root / 'identity' / 'identity.pem'
            subprocess.run(['icacls', str(key_path), '/grant', '*S-1-1-0:F'], check=True, capture_output=True)
            app.Wizard(root, ui=app.ScriptUI(['local', ''], [password])).setup()
            key_acl = subprocess.run(['icacls', str(key_path)], text=True, capture_output=True, check=True).stdout
            self.assertNotIn('Everyone:', key_acl)
    def test_uncertain_post_returns_nonzero_and_doctor_matches_intent(self):
        from vendor import technocore_agent as zun
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-') as tmp:
            root = Path(tmp) / 'data'
            password = 'SYNTHETIC disposable passphrase'
            app.Wizard(root, ui=app.ScriptUI(['local', 'create', 'yes', ''], [password, password])).setup()
            def timeout(*args, **kwargs):
                raise TimeoutError('SIMULATED')
            result = app.Wizard(root, ui=app.ScriptUI(['other', 'https://example.com/work', 'Synthetic example', '', 'yes'], [password]), transport=timeout).contribute()
            self.assertEqual(result, 1)
            path = next((root / 'receipts').glob('*/intent.json'))
            intent = json.loads(path.read_text())
            key = Ed25519PrivateKey.from_private_bytes(bytes([6]) * 32)
            record = {'from': zun.did_from_private_key(key), 'nonce': '1', 'text': 'OTHER SYNTHETIC record', 'sig': zun.sign_bytes(key, b'lobby|1|OTHER SYNTHETIC record'), 'seq': '1'}
            app.write_json(path.parent / 'message-receipt.json', app.message_receipt('lobby', record))
            intent['status'] = 'posted'
            app.write_json(path, intent)
            self.assertEqual(app.Wizard(root, ui=app.ScriptUI([], terminal=False)).doctor(), 1)
    def test_http_deadline_covers_slow_response_headers(self):
        import datetime
        import socket
        import ssl
        import threading
        import time
        import urllib.error
        import urllib.request
        from unittest.mock import patch
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        with tempfile.TemporaryDirectory(prefix='onboard-SYNTHETIC-TLS-') as tmp:
            key = ec.generate_private_key(ec.SECP256R1())
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'technocore.chat')])
            now = datetime.datetime.now(datetime.timezone.utc)
            certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                           .public_key(key.public_key()).serial_number(1)
                           .not_valid_before(now - datetime.timedelta(minutes=1))
                           .not_valid_after(now + datetime.timedelta(minutes=5))
                           .add_extension(x509.SubjectAlternativeName([x509.DNSName('technocore.chat')]), critical=False)
                           .sign(key, hashes.SHA256()))
            cert_path, key_path = Path(tmp) / 'cert.pem', Path(tmp) / 'SYNTHETIC-server.pem'
            cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_tls.load_cert_chain(cert_path, key_path)
            client_tls = ssl.create_default_context(cafile=str(cert_path))
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(3)
            address = listener.getsockname()
            stopped, errors = threading.Event(), []
            tls_established, headers_started = threading.Event(), threading.Event()
            self.assertTrue(client_tls.check_hostname)
            self.assertEqual(client_tls.verify_mode, ssl.CERT_REQUIRED)
            def serve():
                try:
                    peer, _ = listener.accept()
                    peer.settimeout(3)
                    with server_tls.wrap_socket(peer, server_side=True) as stream:
                        tls_established.set()
                        request = stream.recv(8192)
                        if not request.startswith(b'GET /r/lobby?limit=200&format=json HTTP/1.1\r\n'):
                            raise AssertionError('Expected the read-only request over verified TLS')
                        stream.sendall(b'HTTP/1.1 200 OK\r\nX-Slow: ')
                        headers_started.set()
                        for _ in range(30):
                            if stopped.wait(.04):
                                return
                            stream.sendall(b'x')
                        stream.sendall(b'\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}')
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass  # The deadline intentionally closes this disposable connection.
                except Exception as error:
                    errors.append(error)
            worker = threading.Thread(target=serve)
            worker.start()
            create_connection = socket.create_connection
            connections = []
            def local_connection(target, *args, **kwargs):
                connections.append(target)
                return create_connection(address, *args, **kwargs)
            handler_init = urllib.request.HTTPSHandler.__init__
            def trusted_handler_init(handler, *args, **kwargs):
                # Avoid loading then discarding system trust inside the timed request.
                handler_init(handler, *args, context=client_tls, **kwargs)
            def trusted_opener(*handlers):
                return urllib.request.build_opener(urllib.request.ProxyHandler({}), *handlers)
            started = time.monotonic()
            try:
                with patch.object(urllib.request.HTTPSHandler, '__init__', trusted_handler_init), patch('onboard.build_opener', side_effect=trusted_opener), patch('socket.create_connection', side_effect=local_connection):
                    with self.assertRaises((TimeoutError, urllib.error.URLError)):
                        app.http_request('GET', 'https://technocore.chat/r/lobby?limit=200&format=json', timeout=.25)
                self.assertLess(time.monotonic() - started, .8, 'Slow headers exceeded the total HTTP deadline')
                self.assertEqual(len(connections), 1, 'Never retry a timed-out request')
                self.assertTrue(tls_established.is_set(), 'Verified TLS handshake never completed')
                self.assertTrue(headers_started.is_set(), 'Slow response headers never started')
            finally:
                stopped.set()
                listener.close()
                worker.join(timeout=4)
            self.assertFalse(worker.is_alive(), 'Disposable test server did not stop')
            self.assertEqual(errors, [])

    def test_http_deadline_exhausted_during_handler_init_never_connects(self):
        import socket
        import urllib.error
        import urllib.request
        from unittest.mock import patch
        clock = [0.0]
        deadline_handler = app.DeadlineHTTPSHandler
        def slow_handler_init(deadline):
            handler = deadline_handler(deadline)
            clock[0] = .26  # Deterministic setup cost exhausts the .25-second budget.
            return handler
        def direct_opener(*handlers):
            return urllib.request.build_opener(urllib.request.ProxyHandler({}), *handlers)
        with patch('onboard.time.monotonic', side_effect=lambda: clock[0]), patch('onboard.DeadlineHTTPSHandler', side_effect=slow_handler_init), patch('onboard.build_opener', side_effect=direct_opener), patch.object(socket, 'create_connection', side_effect=OSError('SYNTHETIC forbidden socket attempt')) as connect:
            with self.assertRaises(urllib.error.URLError) as error:
                app.http_request('GET', 'https://technocore.chat/r/lobby?limit=200&format=json', timeout=.25)
        connect.assert_not_called()
        self.assertIsInstance(error.exception.reason, TimeoutError)
        self.assertEqual(str(error.exception.reason), 'HTTP deadline exceeded')

    def test_http_stream_enforces_cap_and_remaining_deadline(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        budgets = []
        class SimulatedStream:
            headers = {}
            fp = SimpleNamespace(raw=SimpleNamespace(_sock=SimpleNamespace(settimeout=budgets.append)))
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read1(self, count):
                return b'12345'[:count]
        opener = SimpleNamespace(open=lambda *a, **kw: SimulatedStream())
        with patch('onboard.build_opener', return_value=opener), patch('onboard.time.monotonic', side_effect=[0, 1, 2]):
            with self.assertRaises(app.SafetyError):
                app.http_request('GET', 'https://technocore.chat/r/lobby?limit=200&format=json', cap=4, timeout=15)
        self.assertEqual(budgets, [14])
        budgets.clear()
        with patch('onboard.build_opener', return_value=opener), patch('onboard.time.monotonic', side_effect=[0, 16]):
            with self.assertRaises(TimeoutError):
                app.http_request('GET', 'https://technocore.chat/r/lobby?limit=200&format=json')
        self.assertEqual(budgets, [])


if __name__ == '__main__':
    unittest.main()
