# Installing Aegis Wallet Shield

Aegis provides **two completely standalone, unconnected open-source tools** from the same repository. Use either one by itself, or both:

| Download | What Is Inside | Connections & Footprint |
| :--- | :--- | :--- |
| **`Aegis-BrowserGuard.zip`** | Chrome / Brave / Edge extension (`extension/` folder — **no `.exe` file**) | Zero backend servers · Zero `nativeMessaging` · Optional Solana RPC only |
| **`Aegis-ClipGuard-Windows.zip`** | Standalone Windows Ghost Copy & Clipboard Cleaner (`aegis-clipguard.exe`) | **100% Air-Gapped**: Zero network code · Zero browser connection · Zero registry edits · Zero install |

---

## ⚠️ Upfront Note on Unsigned Open-Source Software (Windows SmartScreen)

We do **not** buy a corporate EV code-signing certificate. Every line of Aegis is open source, non-minified, and reproducible on your own machine.

- **`Aegis-BrowserGuard.zip` (Browser Extension)**: contains **no `.exe`**, so Windows SmartScreen never appears.
- **`Aegis-ClipGuard-Windows.zip` (`aegis-clipguard.exe`)**: because the `.exe` is unsigned, Windows SmartScreen may show *"Windows protected your PC"* the first time you double-click it:
  1. Verify the SHA-256 hash or compile `clipguard-helper\build.bat` yourself in 2 seconds (see [VERIFY.md](VERIFY.md) and [BUILD.md](BUILD.md) — Windows already ships with the C# compiler, so zero downloads are required).
  2. Click **More info** → **Run anyway**.
- **Expected heuristic antivirus alerts**: Clip Guard calls Windows' official `Clipboard.GetHistoryItemsAsync()` API so you can find and delete accidentally copied keys from your `Win+V` history. Unlike browser-connected helpers, Clip Guard makes **zero Windows Registry edits** and runs **zero background daemons**, which minimizes false flags — and if you prefer zero `.exe` files at all, simply use **Browser Guard** alone and disable `Win+V` in Windows Settings (`ms-settings:clipboard`).

---

## Tool 1 — Install Aegis Browser Guard (Extension)

1. Download and unzip `Aegis-BrowserGuard.zip` (or build locally with `build.bat` to produce `extension\dist\extension`).
2. Open Chrome, Brave, or Edge and go to:
   - Chrome: `chrome://extensions`
   - Brave: `brave://extensions`
   - Edge: `edge://extensions`
3. Toggle **Developer mode** ON in the top-right corner.
4. Click **Load unpacked** and select the `extension` folder.
5. Pin the **Aegis** shield icon to your browser toolbar.

**Zero Setup Required**: There are no settings screens, API keys, or manual inputs to fill out. Live Solana Mainnet transaction simulation (`https://api.mainnet-beta.solana.com` with automatic failover to `https://solana.publicnode.com`), sign-in checks, 30-second clipboard auto-clear, paste protection, and address-swap alerts all work automatically the moment Aegis is loaded.

---

## Tool 2 — Run Aegis Clip Guard (Standalone Windows Cleaner)

1. Download and unzip `Aegis-ClipGuard-Windows.zip` anywhere on your Windows 10/11 PC (or compile `clipguard-helper\build.bat` into `clipguard-helper\bin\aegis-clipguard.exe`).
2. **Double-click `aegis-clipguard.exe`** — no installation, no admin prompt, and no browser connection required.
3. Click **Scan All Ghost Copies** to check:
   - **Windows 11 Notepad unsaved tabs** (`TabState\*.bin`)
   - **Windows Clipboard History (`Win+V`)**
   - **Microsoft Sticky Notes** (`plum.sqlite`)
   - **Quick User Folders** (Desktop, Documents, Downloads, Screenshots, Recycle Bin, OneDrive/Dropbox/Drive local folders)
4. Review masked findings (`7xKp…9Qm4` or `"12 words, starts with a…"`) and use the cleanup buttons to remove flagged `Win+V` items, delete unsaved Notepad `.bin` caches (while Notepad is closed), or move plaintext key files to the Recycle Bin.
5. *(Optional CLI mode)* Run `aegis-clipguard.exe --ghost-scan` or `aegis-clipguard.exe --selftest` from PowerShell / Command Prompt.

---

## Uninstalling Cleanly

- **Browser Extension**: Click **Remove** on **Aegis** in `chrome://extensions` (deletes all local extension storage).
- **Clip Guard Windows Cleaner**: Simply delete `aegis-clipguard.exe`. Because it is 100% portable and writes zero registry keys or AppData files, nothing is left behind.
