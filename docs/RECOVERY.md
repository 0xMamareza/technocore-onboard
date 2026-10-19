# Recovery without duplicate posts

## Uncertain POST

A connection can time out after the server accepted a message. A crash or invalid response can also leave the outcome uncertain. Onboard persists `intent.json` before sending and never silently retries.

1. Keep the entire receipt folder. Do not delete its intent, copy it into a new data directory to bypass the guard, change nonce to force resubmission, or run a Zun `say` command merely to obtain another output file.
2. Run your installed absolute wrapper with `doctor` to list pending folder names.
3. Run `recover`. It is read-only against the service and does not unlock or read a private key. If there are more than five pending records, select one with `recover --intent contribution-...` using the exact folder name.
4. Recovery reads one explicit-room JSON snapshot (2 MiB cap), then only if absent one `/r/ROOM/export` JSONL response (12 MiB cap, 256 KiB per line). The two requests share a 15-second search deadline. It consumes the bounded export before selecting a record, checks a visible generation stamp if supplied, and rejects ambiguous duplicates/malformed source containers.
5. A match must have the exact DID, nonce, text and canonical signature. The signature is verified again; source sequence must be present. A match creates `message-receipt.json`, records the exact selected record and source URL in `recovery-source.json`, and marks the intent posted.
6. If absent, too large, unavailable or invalid, it remains **unknown/pending**. Retention, room reset or read timing can explain an absent record. Nothing automatically clears/reposts it.

A received original POST response is saved as `response.json` when it can safely be retained. If no response arrived, recovery does not invent one; `recovery-source.json` is separately labelled read-only evidence rather than a synthetic POST response.

## Interrupted process / stale lock

`.posting.lock` prevents ordinary simultaneous submissions. A killed process may leave it behind. Run recovery first, then check that the old wizard process has stopped before manually removing this lock file. Removing a lock is **not** permission to remove pending intent or retry its POST. Do not kill unrelated Python processes.

## Missing identity or public state

- Wrong folder: use the original installer-printed wrapper/data root. Do not initialize a new DID from a different working directory.
- Missing `identity.pem`: restore the encrypted backup to `ROOT/identity/identity.pem`; keep the original passphrase separate and enter it only locally when prompted. Setup refuses to create over existing public state.
- Missing `state.json` or `did.txt`, but encrypted key remains: run setup; it unlocks/reuses the same key and recreates only public state after confirming any existing DID matches.
- DID mismatch: preserve all files and restore the matching encrypted backup/public state. The wizard refuses to silently switch identity.
- Lost passphrase/key: a DID or public receipt cannot recover the private key. There is no service reset or wallet fallback in this tool.

For a manual public receipt check, use `doctor --receipt ABSOLUTE-PATH.json` or Inspector. Never supply an identity PEM to a public verifier or send it to a maintainer/chat.
