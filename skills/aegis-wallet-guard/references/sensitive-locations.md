# Sensitive Key Locations & OS Leak Map

This guide documents where private keys, seed phrases, and wallet recovery data silently leak on modern desktop operating systems and developer environments.

---

## 1. Windows Operating System Caches

### A. Windows 11 Notepad TabState Cache
- **Location**:
  ```text
  %LOCALAPPDATA%\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState
  ```
- **File Names**: `{guid}.bin`, `{guid}.0.bin`, `{guid}.1.bin`, `{guid}.2.bin`
- **Internal Structure**:
  - Magic header: `0x4E 0x50 0x00` (`NP\0`)
  - Status byte: `0x00` (unsaved / modified), `0x01` (saved file)
  - Content payload: UTF-16LE text runs (often starting at byte offset 5, an odd parity alignment).
  - Incremental diffs: Windows writes keystrokes and pastes into `.0.bin`, `.1.bin` sibling files.
- **Remediation**:
  - Verify if `notepad.exe` is running before attempting file deletion (Windows holds a file handle).
  - Open with `FileShare.ReadWrite | FileShare.Delete` for non-blocking read.
  - Delete all siblings belonging to `{guid}` simultaneously to prevent Windows from restoring the tab on the next launch.

### B. Windows Clipboard History (`Win+V`)
- **API**: `Windows.ApplicationModel.DataTransfer.Clipboard`
- **Storage**: Windows internal SQLite / WinRT app service database.
- **Cloud Roaming**: If `Clipboard.IsRoamingEnabled()` is `true`, items sync to Microsoft Azure cloud infrastructure and propagate to other Windows machines logged into the same Microsoft account.
- **Remediation**:
  - Individual items can be removed via `Clipboard.DeleteItemFromHistory(item)`.
  - The entire history can be purged via `Clipboard.ClearHistory()`.

### C. Microsoft Sticky Notes
- **Location**:
  ```text
  %LOCALAPPDATA%\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState
  ```
- **Files**: `plum.sqlite`, `plum.sqlite-wal`, `plum.sqlite-shm`
- **Behavior**:
  - Notes are stored in SQLite text columns encoded in UTF-8.
  - Deleting a note inside the Sticky Notes UI removes the record from the active index, but raw note text remains in unallocated `plum.sqlite-wal` pages until the next checkpoint/vacuum.

### D. Windows Recycle Bin
- **Location**: `C:\$Recycle.Bin\<User-SID>`
- **Behavior**: Files deleted in Windows Explorer are renamed to `$R<id>.<ext>` with metadata in `$I<id>.<ext>`. Plaintext `.env` or `.txt` files containing keys can still be scanned and recovered until the Recycle Bin is permanently emptied.

---

## 2. Developer & Workspace Artifacts

When scanning repositories or build directories:
1. **Environment Files**: `.env`, `.env.local`, `.env.production`, `.env.backup`, `.env.stage`.
2. **Keypair JSONs**: `id.json`, `deploy-keypair.json`, `phantom.json`, `solana-keypair.json`.
3. **Shell History**:
   - PowerShell: `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
   - Bash/Zsh: `~/.bash_history`, `~/.zsh_history` (often contains `solana airdrop` or CLI key commands).
4. **Editor Scratchpads**:
   - VS Code / Cursor: `%APPDATA%\Code\User\History\` and unsaved editor buffers.
5. **Git Diffs & Commit History**:
   - Accidental commits containing keys pushed and then reverted still exist in Git history unless purged with `git filter-repo`.

