# Spec: Aegis Clip Guard (Standalone Windows Cleaner)

Aegis Clip Guard (`aegis-clipguard.exe`) is a **standalone, air-gapped Windows 10/11 desktop utility**. It helps users find and clean up residual copies of their **own** wallet recovery data that Windows retains in places people forget about ("ghost copies"): Windows clipboard history (`Win+V`), Windows 11 Notepad's unsaved tab cache (`TabState\*.bin`), Sticky Notes (`plum.sqlite`), and local files on their PC.

It is strictly local and isolated:
- **Zero network code** (`System.Net.*`, sockets, HTTP clients, and URL launching are forbidden and verified by CI)
- **Zero browser bridge** (no Chrome/Edge/Brave Native Messaging, no `stdin`/`stdout` IPC)
- **Zero Windows Registry edits** (no installer, no background service, no startup entries)
- **Results are always masked** (`ab...xy (12 words)` or `5K...9x`); raw secrets are never written to disk or stdout

## Modes
- **GUI mode (default, no arguments):** Double-clicking `aegis-clipguard.exe` opens a clean, dark-themed Windows Forms window (`MainForm.cs`) with:
  - **Ghost Copy Quick Scan** (Windows `Win+V` Clipboard History + Windows 11 Notepad unsaved tabs + Sticky Notes)
  - ** Targeted Cleanup** (`Remove Flagged History`, `Clear All Clipboard History`, `Clear Unsaved Notepad Tabs`, `Open Clipboard Settings`)
  - **Live Notepad Tab Watcher** toggle (`FileSystemWatcher` on `TabState`)
  - **Local Folder Sweep** (`Quick Scan` of common user folders or `Choose Folder...`, optional offline Windows OCR for `.png`/`.jpg`, `Send to Recycle Bin` / `Permanently Delete` / `Open Containing Folder`)
- **CLI mode:**
  - `--ghost-scan`: runs a local scan of Clipboard History, Notepad `TabState`, and Sticky Notes and prints a masked summary
  - `--selftest`: runs built-in Ed25519 and BIP-39 detector self-checks
  - `--help`: prints CLI usage

## Tech constraints
- C# 5 on .NET Framework 4.8, compiled with the compiler built into Windows: `%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe`.
- C# 5 syntax only: no `$""` interpolation, no `?.`, no `nameof`, no expression-bodied members.
- WinRT APIs: reference `.winmd` files from `%WINDIR%\System32\WinMetadata\` plus `System.Runtime.dll`, `System.Runtime.WindowsRuntime.dll`, and `System.Runtime.InteropServices.WindowsRuntime.dll` from the Framework folder. Clipboard and OCR calls run on STA/MTA helpers as appropriate.
- Zip (`.docx`/`.xlsx`): `System.IO.Compression` + `System.IO.Compression.FileSystem`.
- Recycle Bin: `Microsoft.VisualBasic.FileIO.FileSystem.DeleteFile(..., RecycleOption.SendToRecycleBin)`.
- **Forbidden:** `System.Net.*`, sockets, `WebClient`, `HttpClient`, `Microsoft.Win32.Registry`, `RegCreateKey` / `RegSetValue`, `Process.Start` of URLs. Verified by `tools/check-no-network.ps1` and `scripts/verify-security.ps1`.
- Every source file starts with a header comment (`PURPOSE` / `ACCESS` / `NEVER`). Sensitive API calls are tagged `// AEGIS-PERMISSION:` and safety invariants `// AEGIS-SECURITY:`.

## Layout
```
clipguard-helper/
  build.bat            -> bin\aegis-clipguard.exe (embeds shared-fixtures/bip39-english.txt)
  src/Program.cs       STA entry point: launches MainForm GUI when no args, or CLI flags
  src/Ui/MainForm.cs   Dark-themed standalone WinForms desktop UI
  src/Crypto/          Ed25519PublicKey.cs, Base58.cs, Bip39.cs (SHA-256 checksum)
  src/Detection/       SecretDetector.cs (parity with extension/src/shared/detectors/secret-detector.ts)
  src/Sources/         ClipboardHistory, NotepadTabs, StickyNotes, FileSweep, FileActions, OcrEngineWrapper
  tests/               run-tests.bat + Ed25519Tests + ClipGuardTests + QaStressTests
  tools/check-no-network.ps1
```

## Detection parity
Matches the TypeScript detector across `shared-fixtures/detector-corpus.jsonl` and `shared-fixtures/ed25519-vectors.txt`:
- 64-byte Solana secret keys verified via mathematical Ed25519 scalar-base multiplication (`seed -> pubkey`); 32-byte public addresses and 64-byte random/signature values are never flagged
- Base58 (72–90 chars to support leading zero bytes), JSON byte array (`[n, n, ...]`), and 128-hex formats
- BIP-39 12/15/18/21/24-word recovery phrases with SHA-256 checksum verification plus candidate warning rule
- Per-process HMAC `DedupKey` prevents multi-seed signature collisions while keeping `Preview` strictly masked
- Overlapping 5,000-char window step (`Step = 45000` on `50000`-char chunks) catches secrets straddling chunk boundaries

## Sources & filesystem hardening
- **Clipboard history:** `Clipboard.GetHistoryItemsAsync` (text items only), `DeleteItemFromHistory`, `ClearHistory`; reports `ClipboardHistoryDisabled` cleanly without changing user settings.
- **Notepad tabs (Windows 11):** `%LOCALAPPDATA%\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState\*.bin`; extracts UTF-16LE runs, sanitizes tab labels so BIP-39 words (even numbered like `1.abandon`) never leak, refuses deletion while `Notepad.exe` is open, and supports live `FileSystemWatcher` alerts.
- **Sticky Notes:** Read-only scan of `plum.sqlite`, `plum.sqlite-wal`, and `plum.sqlite-shm` using `FileShare.ReadWrite`.
- **File sweep:**
  - Skips NTFS directory junctions and symlink reparse points (`IO_REPARSE_TAG_MOUNT_POINT` / `IO_REPARSE_TAG_SYMLINK`) while allowing OneDrive/cloud root folders (`IO_REPARSE_TAG_CLOUD*`), and tracks `(VolumeSerialNumber, FileIndex)` to prevent directory cycles.
  - Skips cloud-only placeholders (`Offline 0x1000`, `RecallOnOpen 0x40000`, `RecallOnDataAccess 0x400000`) so cloud files are never hydrated/downloaded.
  - Redacts any secret appearing inside a file name via `DisplayPath`, and verifies `!ReparsePoint` before Recycle Bin or permanent delete actions.
