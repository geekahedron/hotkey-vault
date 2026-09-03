# Hotkey Vault

AutoHotkey v2 helper for injecting short secrets and passphrases with a hotkey plus a 4-digit PIN.

This is a **convenience layer**, not a replacement for Bitwarden, Enpass, or another real password manager. Keep the canonical secrets there. Use this when you want raw keystrokes (SSH prompts, awkward login fields, etc.).

**Status:** early public draft. Portable session-unlock first. Optional Windows DPAPI storage is planned as an add-on, not the default.

## Why this exists

- Type a 4-digit PIN after a hotkey, get the snippet sent as keystrokes.
- Vault file is a separate `snippets.ini` next to the script or compiled exe.
- Master passphrase is entered once per session and is **not** written to disk.
- The INI only stores a verifier hash, per-entry salts, ciphertext, and metadata.

## Requirements

- Windows
- [AutoHotkey v2](https://www.autohotkey.com/)

Compiled `.exe` builds are optional. A compiled script still contains recoverable source; do not treat an exe as encryption.

## Quick start (demo)

1. Clone this repo and place `PassVault.ahk` in the same folder.
2. Copy `snippets.ini.example` to `snippets.ini`.
3. Run `PassVault.ahk`.
4. When asked for the master passphrase, type **`demo`**.
5. Focus Notepad (or any text field).
6. Press **Ctrl+Alt+Shift+1**, then type **`1234`**.
7. The word **`password`** should appear.

After that, open **Manage Snippets** from the tray or `Ctrl+Alt+Shift+0` and replace the demo with real entries. Use a strong master passphrase of your own for anything that matters — `demo` is only for first-run testing.

## Security model

| Item | Stored? |
| --- | --- |
| Master passphrase | Session memory only |
| Master verifier | Yes, SHA-256 in `[Master] Verifier` |
| 4-digit PIN | Never stored |
| Per-entry salt | Yes, next to ciphertext |
| Password / snippet | Ciphertext only |

A stolen INI is not enough by itself. An attacker still needs the master passphrase. The 4-digit PIN is a second factor for each snippet, not the only secret.

**Limits**

- Current crypto is a keyed SHA-256 keystream XOR behind `VaultCrypto_*` functions. It is meant to be swapped for AES later.
- This does not protect you if someone already has your unlocked Windows session.
- Copying `snippets.ini` to another machine works only if you also know the master passphrase.
- Compiling to `.exe` does not hide the algorithm or make the vault stronger.
- The shipped demo uses master=`demo` and PIN=`1234`. Treat that as public test data.

## Config format

See `snippets.ini.example` for a working sample section named `[sample]`.

## Project layout

```
PassVault.ahk              ; runnable entry point
snippets.ini.example       ; demo vault (safe to publish)
LICENSE
README.md
```

Later splits: `Lib/Crypto.ahk`, `Lib/Config.ahk`, `Lib/Gui.ahk`, optional `Lib/Dpapi.ahk`.

## Compile (optional)

Ahk2Exe packs the interpreter with the script. It is not a real compiler and it is not obfuscation.

```text
Ahk2Exe.exe /in PassVault.ahk /base "C:\\Program Files\\AutoHotkey\\v2\\AutoHotkey64.exe" /out dist\\PassVault.exe
```

Keep `snippets.ini` beside the exe. Do not FileInstall a real vault into the exe.

## Roadmap

- [x] Portable session master passphrase
- [x] INI-backed snippets and hotkeys
- [x] Manager GUI
- [x] Published demo snippet
- [ ] Split library files
- [ ] Optional DPAPI-wrapped master key for single-machine convenience
- [ ] AES-GCM behind the existing `VaultCrypto_*` API
- [ ] GitHub Actions compile of a demo exe (no secrets)

## License

MIT
