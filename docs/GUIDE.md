# Beginner walkthrough

## 1. Choose a trusted host

An operating system (Windows, Linux, macOS) is different from a hosting choice. The wizard detects the system, then asks whether you are on a local computer or a remote/VPS host. On a remote machine the host administrator can access your files and memory. Prefer a trusted local computer unless you intentionally accept that exposure.

The installer downloads a private runtime only after consent. A plan preview installs nothing. Run the exact commands in the README from the folder holding the reviewed installer. Its printed wrapper paths work from any folder, so you do not need to activate an environment every time.

## 2. Set up once, without changing an existing DID

Choose **reuse** if you already have an encrypted Zun `identity.pem`. Enter its absolute file path in your terminal, not the PEM contents. Enter the existing passphrase only in the hidden local prompt. Onboard copies the encrypted file into its private identity directory, preserving the DID, and leaves your source file untouched.

Choose **create** only if you genuinely need your first identity. Confirm creation and enter a strong passphrase twice. Twelve characters is a minimum, not a recommended limit. Nothing is sent to a service just because a key was created.

Write down the displayed public DID. Back up the encrypted `identity.pem` to private storage; back up the passphrase separately. `identity/did.txt` is public but cannot recover the private key. Re-running setup reuses the key. If a key is missing or the stored DID conflicts, stop and restore the matching backup; do not generate another identity to repair a directory mistake.

Setup offers an optional introduction. Decline if you do not want a public record yet. If you prepare one, you still see the exact normalized text, DID and room before a separate final `yes`. Pressing Enter never means publish. Normalization replaces control/invisible characters and line breaks with spaces; ordinary Unicode is preserved, not NFC/NFD-normalized.

## 3. Publish your work separately

Onboard records work; it does not create or publish that work for you.

- **X post/article:** publish the post yourself, then copy its exact `/name/status/ID` share URL. Queries such as `?s=20` are retained. For an X article, use the published sharing post URL; direct article editor URLs are not status records.
- **GitHub project:** create/publish the repository and push the implementation yourself first. Paste `https://github.com/OWNER/REPO`. Choose a complete lowercase published 40/64-hex commit, or press Enter to resolve the current default-branch HEAD through the read-only GitHub API. Short hashes/branch names typed as a commit are rejected rather than guessed. No git program or local checkout is required here.
- **Other public contribution:** publish an article, documentation, translation or tool yourself, then paste its public HTTPS URL. Do not submit a local/VPS address, credential-bearing URL or private link. Onboard never fetches that artifact.

Give an honest public description. Choose a public room (default `technocore`) where the contribution is relevant. The optional setup introduction defaults to `lobby` instead. Your same encrypted identity is unlocked locally. For GitHub, a public local proof is generated and verified before any announcement: it binds the DID to the URL and exact commit. You can import/share the proof file separately; its existence does not mean it was uploaded anywhere.

## 4. Review, then decide

Read the complete public preview. It includes the normalized message, room, DID and any commit. Check links, description and identity before answering. Only `yes` submits a single signed Technocore POST. Any other response cancels; a locally generated Git proof remains available.

The wizard signs using pinned upstream functions, saves pending intent before POST, verifies the returned `posted` record, then reads back the exact same signed record. On success it saves a standard Inspector receipt and the original safe JSON response. It never publishes to X or Telegram.

## 5. Verify and save the public evidence

Open <https://tcproof.vercel.app/>, import `message-receipt.json` or `proof-receipt.json` from the printed record folder, and check that the displayed DID, exact nonce/text and commit match. Export the receipt and reimport it to check portability. Only request a live-source check if you want a separate read-only service confirmation. Never import your PEM file.

`tcproof doctor` runs local checks offline. `tcproof doctor --receipt ABSOLUTE-PUBLIC-RECEIPT.json` verifies one receipt offline. A signature stays checkable even if the service later drops the room record. It authenticates the signed claim; it does not turn the claim into proof of artifact authorship.

## 6. If a result is uncertain

Do not run the contribution again to obtain missing output. Keep the pending folder and use `tcproof recover`. That command only reads the room snapshot and, when necessary, one bounded retained export. It requires no passphrase and never reposts. A miss remains **unknown**, because a room is not permanent storage. More detail: [RECOVERY.md](RECOVERY.md).

Preparing or publishing an X/Telegram project announcement is a separate later action. A signed Technocore contribution record, a public Git proof file and a social announcement are different artifacts; creating one does not create the others.
