# Browser Permissions & Windows APIs Explained

Aegis Browser Guard and Aegis Clip Guard are **completely separate tools with zero connection between them**. Below is every browser permission requested by the extension and every Windows API used by the standalone cleaner.

---

## 1. Chrome Manifest V3 Permissions (`extension/static/manifest.template.json`)

Notice what is **NOT** here: **no `nativeMessaging`**, no `declarativeNetRequest`, no `history`, no `management`, no `tabs` browsing spyware, no `cookies`, and no `webRequest` interception.

| Permission | Why Aegis Needs It | What Aegis Never Does With It |
| :--- | :--- | :--- |
| `clipboardRead` | Allows the local offscreen poller to check whether a newly copied value is a Solana secret key or BIP-39 recovery phrase so Aegis can start the 30-second auto-clear countdown. | Never stores, logs, or transmits clipboard text. Only a random session-salted HMAC fingerprint is held in memory. |
| `clipboardWrite` | Overwrites the clipboard with `[Aegis: cleared]` when the countdown finishes — and only if the clipboard still contains that exact secret. | Never overwrites something new you copied while the timer was counting down. |
| `offscreen` | Manifest V3 service workers go to sleep after ~30 seconds and have no DOM clipboard access. The offscreen document keeps the 1-second clipboard check and countdown timer alive reliably. | Rejects messages from content scripts; never loads remote resources. |
| `notifications` | Shows desktop countdown alerts with **Clear now** and **+30s** action buttons. | Never includes secret words or private keys in notification text. |
| `storage` | Saves your 4 local on/off toggles, trusted paste origins, and recent public addresses (max 300) in `chrome.storage.local`. | Never uses `chrome.storage.sync` (nothing syncs to Google accounts) and never stores secrets. |
| `alarms` | Supports MV3 background timer lifecycle in the service worker. | Never wakes up to phone home. |
| `scripting` | Injects `content.js` and `inpage.js` into tabs that were already open before Aegis was installed or reloaded so you are protected immediately without refreshing every tab. | Only injects Aegis's own packaged `content.js` and `inpage.js`; never executes dynamic or remote code. |
| `<all_urls>` (host access) | Injects `inpage.js` (to pause wallet signature calls before Phantom/Solflare/Backpack opens) and `content.js` (to block accidental secret-key pastes on any phishing URL, even brand-new domains). | Never scrapes page text, passwords, cookies, or browsing activity. Browsers never inject content scripts into other extensions (`chrome-extension://`), so Aegis never touches your wallet extension's own UI. |

---

## 2. Standalone Clip Guard Windows APIs (`clipguard-helper/src/`)

Notice what is **NOT** in `aegis-clipguard.exe`: **zero `System.Net` / socket APIs**, **zero Windows Registry APIs**, and **zero browser IPC**.

| Windows / .NET API | Where Used | Why It Is Needed |
| :--- | :--- | :--- |
| `Windows.ApplicationModel.DataTransfer.Clipboard` | `ClipboardHistory.cs` | Reads text items in `Win+V` Clipboard History to find forgotten keys/seeds and calls `DeleteItemFromHistory` on only the flagged items (or `ClearHistory` on request). |
| `FileStream` (`FileShare.ReadWrite`) on `TabState\*.bin` & `plum.sqlite*` | `NotepadTabs.cs`, `StickyNotes.cs` | Scans Windows 11 Notepad's unsaved tab cache and Sticky Notes database without locking those apps, and deletes flagged `.bin` files when Notepad is closed. |
| `FileSystemWatcher` | `NotepadTabs.cs` | Opt-in live watch on Notepad's `TabState` folder while the Clip Guard window is open so you are alerted if Windows auto-saves a pasted secret to disk. |
| `Process.GetProcessesByName("Notepad")` | `NotepadTabs.cs` | Checks whether `Notepad.exe` is currently open before deleting `TabState\*.bin` files to prevent corrupting an active Notepad session. |
| `Windows.Media.Ocr.OcrEngine` | `FileSweep.cs` | Optional 100% offline Windows OCR when you explicitly check "Include Offline Screenshot OCR" during a local file sweep. |
| `Microsoft.VisualBasic.FileIO.FileSystem.DeleteFile` | `FileActions.cs` | Moves a flagged local file to the Windows Recycle Bin when you click **Move to Recycle Bin**. |
| `System.Windows.Forms` | `MainForm.cs` | Renders the standalone local desktop UI using the framework built into Windows. |
