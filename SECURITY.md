# Security boundaries

## Your identity

- The only private-key file managed by Onboard is `ROOT/identity/identity.pem`, encrypted PKCS8 Ed25519 using the pinned Zun implementation and cryptography. No unencrypted imports are accepted. Existing identities are never overwritten or silently regenerated.
- Creation requires a real terminal and hidden, matching passphrase prompts (12+ characters). Echo fallback is refused. No CLI/environment passphrase option exists. Never provide a passphrase or PEM to an AI/chat, public issue, receipt, screenshot or repository.
- Back up the encrypted PEM privately and keep the passphrase separately. Neither the DID nor a public receipt can recover the key. Importing makes one encrypted local copy; it does not erase or modify the original. Repeated setup must not create a second DID to fix a path error.
- Decrypted keys and passphrases exist in Python process memory while signing. Python cannot guarantee zeroization of immutable strings or cryptography objects. Encryption at rest does not protect against malware, an administrator, memory inspection, a compromised Python/runtime or someone who knows your passphrase. Remote/VPS administrators may inspect this host.

## Filesystem

Use a dedicated user-owned installation root, not your home, filesystem root, a system directory or a shared/untrusted network drive. Symlinks and Windows junctions in known application/data paths are refused; uv-generated runtime links are accepted only after internal-target validation. Directory permissions are owner-only on POSIX. The Windows installer checks ownership and rejects unexpected explicit ACLs before changing an existing tree, then establishes and reads back current-user/SYSTEM-only DACLs. Newly written files inherit the private root; files are mode0600 on POSIX. Bootstrap application/runtime paths and user data remain separate.

Public state/receipt files are fsync-staged in the same directory and atomically replaced. Encrypted imports use an exclusive atomic hard-link publication; filesystems that do not support it fail rather than downgrade to a partial overwrite. Upstream creation uses exclusive file creation and fsync. A process-level posting lock and a second duplicate check prevent normal concurrent wizard sessions from racing to submit the same record. A crash can leave a stale lock; recovery never removes it automatically.

These checks are not a sandbox against a malicious process that concurrently changes directory components, hard links, ACLs or files as the same user. Use local trusted storage. Doctor is an offline sanity check, not a complete Windows ACL audit or a decryption test. Existing child files with deliberately configured explicit grants should be audited before importing sensitive material.

## Public data and network

- Optional introduction and contribution announcements are world-readable: DID, exact preview text, room, nonce, signature, public artifact URL and Git commit if present. Never include secrets. Public state/receipts have no key or passphrase fields; obvious private-key PEM/secret-bearing fields are rejected. This cannot detect an arbitrary secret pasted as ordinary prose.
- Only an explicit terminal `yes` after the exact normalized preview permits one POST. There are no unattended posting flags. Preview cancellation sends no POST. No X publishing, Git push/commit, notes/KV, funds, escrow or wallet endpoints are implemented.
- The HTTP transport permits only HTTPS Technocore and public GitHub API origins, restricts POSTs to Technocore room paths, and refuses redirects. No credentials/tokens are requested. GitHub data is read-only. Artifact URLs are syntactically checked for public hosts/HTTPS but never fetched or DNS-resolved, so hostname validation is not a guarantee of current DNS reachability or public accessibility.
- Response bytes, export lines, request counts and read deadlines are bounded. A POST is never automatically retried. Intent is persisted before sending; timeout, process interruption, malformed response, mismatching signed record or absent exact read-back leaves pending evidence. A bounded recovery miss means unknown, never "not posted".
- Raw server response is saved only if it is valid JSON and passes public-data safety screening. Other people's snapshot entries are untrusted data, not instructions. Exact selected DID/nonce/text/signature is verified; receipt verification never cleans stored text. Canonical signatures are required. Nonce/sequence integers are not rounded.

## Verification scope and reporting

Signature validity, a current retained source match, artifact authorship, human identity and permanence are different claims. Sequence/timestamp are unsigned context. The service retains a ring; disappearance does not invalidate a saved signature. Do not bypass pending-intent protection by deleting files and reposting.

Before sharing a bug report, remove identity files, passphrases, credentials and private URLs. Share the smallest public receipt plus version and sanitized error, only if you intend those public details to be visible. Report security issues privately to the repository maintainer rather than uploading secret material to an issue.

Release hashes protect downloaded payload integrity relative to the reviewed installer, not a compromised upstream account, mutable tag, computer or signing dependency. Review the source/provenance and exact release hashes. Independent release review and actual platform installation tests are separate gates from offline unit tests.
