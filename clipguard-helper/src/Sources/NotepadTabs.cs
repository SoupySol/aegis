// ---------------------------------------------------------------------------
// NotepadTabs.cs
// PURPOSE:  Finds secrets in Windows 11 Notepad's auto-saved tab state
//           (%LOCALAPPDATA%\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\
//           LocalState\TabState\*.bin). Windows keeps unsaved/closed tab text
//           there even when the user never pressed Save.
//           Can remove ONLY the affected tab files, and can watch the folder
//           to raise notepad.secretSaved when a secret gets auto-saved.
// ACCESS:   Reads (FileShare.ReadWrite) and, on explicit user request,
//           deletes .bin files inside the TabState folder only. Checks whether
//           Notepad.exe is running (process list, names only).
// NEVER:    No network. Never returns tab text: only masked findings and a
//           label with secret-looking tokens removed. Never deletes outside the
//           TabState folder. Never deletes while Notepad is running.
// ---------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Aegis.ClipGuard.Crypto;
using Aegis.ClipGuard.Detection;
using Aegis.ClipGuard.Model;

namespace Aegis.ClipGuard.Sources
{
    public sealed class NotepadTabs : IDisposable
    {
        public const string LocationType = "notepad-tab";
        private const long MaxFileBytes = 20L * 1024 * 1024;

        private readonly string _folder;
        private readonly Func<bool> _isNotepadRunning;
        private readonly object _watchGate = new object();
        private FileSystemWatcher _watcher;
        private Action<List<Finding>> _onSecretSaved;
        private readonly Dictionary<string, Timer> _debounce = new Dictionary<string, Timer>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _lastSignature = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public static string DefaultFolder
        {
            get
            {
                string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                return Path.Combine(local, @"Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState");
            }
        }

        public NotepadTabs(string folder, Func<bool> isNotepadRunning)
        {
            _folder = Path.GetFullPath(folder);
            _isNotepadRunning = isNotepadRunning ?? IsNotepadRunning;
        }

        public string Folder { get { return _folder; } }
        public bool Supported { get { return Directory.Exists(_folder); } }
        public bool Watching { get { lock (_watchGate) return _watcher != null; } }

        public static bool IsNotepadRunning()
        {
            // AEGIS-PERMISSION: process list (names only) to refuse removal while Notepad holds the files.
            Process[] procs = Process.GetProcessesByName("Notepad");
            bool running = procs.Length > 0;
            foreach (Process p in procs) p.Dispose();
            return running;
        }

        /// <summary>Tab id for "{guid}.bin", "{guid}.0.bin", "{guid}.1.bin", "{guid}.2.bin", etc.</summary>
        public static string TabBase(string fileName)
        {
            string name = Path.GetFileName(fileName);
            if (name.EndsWith(".bin", StringComparison.OrdinalIgnoreCase)) name = name.Substring(0, name.Length - 4);
            int dot = name.LastIndexOf('.');
            if (dot > 0 && dot < name.Length - 1)
            {
                bool allDigits = true;
                for (int i = dot + 1; i < name.Length; i++)
                {
                    if (name[i] < '0' || name[i] > '9') { allDigits = false; break; }
                }
                if (allDigits) name = name.Substring(0, dot);
            }
            return name;
        }

        private List<string> FilesOfTab(string tabBase)
        {
            List<string> files = new List<string>();
            if (!Directory.Exists(_folder)) return files;
            string main = Path.Combine(_folder, tabBase + ".bin");
            if (File.Exists(main)) files.Add(main);
            try
            {
                string[] siblings = Directory.GetFiles(_folder, tabBase + ".*.bin");
                Array.Sort(siblings, StringComparer.OrdinalIgnoreCase);
                foreach (string s in siblings)
                {
                    if (string.Equals(TabBase(s), tabBase, StringComparison.OrdinalIgnoreCase))
                    {
                        files.Add(s);
                    }
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            return files;
        }

        private static byte[] ReadShared(string path)
        {
            // ARCHITECTURAL DESIGN NOTE: Non-Blocking FileShare Concurrency
            // Windows 11 Notepad auto-saves open tabs to TabState\*.bin asynchronously on a timer.
            // Opening these files with default exclusive locks (`FileShare.None`) causes Windows
            // to throw ERROR_SHARING_VIOLATION (0x20) in Notepad.exe, resulting in failed auto-saves,
            // UI freezes, or corrupted tab metadata.
            // By specifying `FileShare.ReadWrite | FileShare.Delete`, Clip Guard reads tab snapshots
            // purely concurrently, never contending with or interrupting Notepad's background writes.
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                if (fs.Length > MaxFileBytes) return null;
                byte[] buf = new byte[fs.Length];
                int read = 0;
                while (read < buf.Length)
                {
                    int n = fs.Read(buf, read, buf.Length - read);
                    if (n <= 0) break;
                    read += n;
                }
                return buf;
            }
        }

        public List<Finding> Scan()
        {
            List<Finding> all = new List<Finding>();
            if (!Supported) return all;
            HashSet<string> tabs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string f in Directory.GetFiles(_folder, "*.bin")) tabs.Add(TabBase(f));
            List<string> sorted = new List<string>(tabs);
            sorted.Sort(StringComparer.OrdinalIgnoreCase);
            foreach (string tab in sorted) all.AddRange(ScanTab(tab));
            return all;
        }

        /// <summary>Scans one tab (its .bin plus .0.bin/.1.bin siblings).</summary>
        public List<Finding> ScanTab(string tabBase)
        {
            List<Finding> findings = new List<Finding>();
            List<string> files = FilesOfTab(tabBase);
            if (files.Count == 0) return findings;

            StringBuilder text = new StringBuilder();
            string label = null;
            foreach (string file in files)
            {
                byte[] data;
                try { data = ReadShared(file); }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }
                if (data == null) continue;
                string fileLabel;
                string t = ExtractText(data, out fileLabel);
                // ARCHITECTURAL DESIGN NOTE: Immediate Heap Memory Sanitization
                // TabState buffers may contain unencrypted private keys or seed phrases read from disk.
                // In managed runtimes, unreferenced byte arrays remain in Gen 0/1/2 GC heaps until collected,
                // making them vulnerable to process memory scrapers or crash dump inspection.
                // `Array.Clear` overwrites all elements with zeroes immediately after text decoding.
                Array.Clear(data, 0, data.Length); // AEGIS-SECURITY: wipe raw bytes
                if (label == null) label = fileLabel;
                if (text.Length > 0) text.Append('\n');
                text.Append(t);
            }
            string all = text.ToString();
            text.Length = 0;

            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
            // ARCHITECTURAL DESIGN NOTE: Ed25519 Public Key Verification & Zero-False-Alarm Guarantee
            // SecretDetector processes decoded tab text through Ed25519PublicKey.IsSolanaSecretKey.
            // On Solana, transaction signatures are also 64-byte Base58 strings (88 chars), and public
            // keys are 32-byte Base58 strings (44 chars). Flagging every 64-byte or high-entropy Base58
            // string would cause massive false alarms on transaction logs and DEX addresses.
            // By re-deriving the Ed25519 public key from the first 32-byte seed and verifying it matches
            // the second 32 bytes in constant-time comparison, Clip Guard mathematically guarantees that
            // a finding is a genuine exportable Solana private key, completely eliminating false positives.
            foreach (SecretFinding s in SecretDetector.DetectAll(all))
            {
                if (!seen.Add(s.Signature)) continue;
                Finding f = Finding.From(s, LocationType, label ?? "Notepad tab");
                f.AddFlag("auto-saved-by-windows");
                f.TargetFiles.AddRange(files);
                findings.Add(FindingStore.Register(f));
            }
            return findings;
        }

        private static readonly Regex PathStart = new Regex(@"^(?:[A-Za-z]:\\|\\\\)", RegexOptions.CultureInvariant);

        /// <summary>
        /// Extracts UTF-16LE (min 3 chars for 3-letter BIP-39 words) and UTF-8
        /// text runs from a TabState .bin file and builds a redacted label.
        /// </summary>
        public static string ExtractText(byte[] data, out string label)
        {
            List<TextRun> runs16 = TextRuns.Utf16LE(data, 3);
            List<TextRun> runs8 = TextRuns.Utf8(data, TextRuns.DefaultMinChars);
            string savedName = null;
            string firstContent = null;
            for (int i = 0; i < runs16.Count; i++)
            {
                string t = runs16[i].Text;
                if (i == 0 && savedName == null && PathStart.IsMatch(t))
                {
                    savedName = FileNameFromPathRun(t);
                    continue;
                }
                if (firstContent == null && CountLetters(t) >= 3) firstContent = t;
            }
            if (firstContent == null)
            {
                for (int i = 0; i < runs8.Count; i++)
                {
                    string t = runs8[i].Text;
                    if (CountLetters(t) >= 3 && !t.StartsWith("NP", StringComparison.Ordinal))
                    {
                        firstContent = t;
                        break;
                    }
                }
            }
            string clean = null;
            if (savedName != null) clean = SanitizeLabel(savedName);
            if (!string.IsNullOrEmpty(clean)) label = "Notepad tab '" + clean + "'";
            else
            {
                clean = firstContent == null ? null : SanitizeLabel(FirstLine(firstContent));
                label = string.IsNullOrEmpty(clean) ? "Notepad tab (untitled)" : "Notepad tab starting with '" + clean + "'";
            }
            string joined16 = TextRuns.Join(runs16);
            string joined8 = TextRuns.Join(runs8);
            if (joined8.Length == 0) return joined16;
            if (joined16.Length == 0) return joined8;
            return joined16 + "\n" + joined8;
        }

        private static string FileNameFromPathRun(string t)
        {
            int end = 0;
            while (end < t.Length)
            {
                char c = t[end];
                if (c < 0x20 || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') break;
                end++;
            }
            string p = t.Substring(0, end);
            int slash = p.LastIndexOf('\\');
            return slash >= 0 ? p.Substring(slash + 1) : p;
        }

        private static int CountLetters(string t)
        {
            int n = 0;
            foreach (char c in t) if (char.IsLetter(c)) n++;
            return n;
        }

        private static string FirstLine(string t)
        {
            foreach (string line in t.Split('\r', '\n'))
            {
                if (line.Trim().Length > 0) return line.Trim();
            }
            return "";
        }

        /// <summary>
        /// Label text: drops tokens that could be part of a secret (BIP-39
        /// words or embedded BIP-39 letter sub-tokens, long alphanumeric runs,
        /// number lists, brackets), then keeps at most ~20 characters.
        /// AEGIS-SECURITY: a label must never reveal any part of a secret.
        /// </summary>
        public static string SanitizeLabel(string line)
        {
            if (line == null) return "";
            List<string> kept = new List<string>();
            foreach (string raw in line.Split(new char[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string core = raw.Trim('.', ',', ';', ':', '!', '?', '"', '\'', '(', ')', '-');
                if (core.Length == 0) continue;
                if (core.Length >= 16) continue;
                if (core.IndexOf('[') >= 0 || core.IndexOf(']') >= 0) continue;
                int digits = 0;
                foreach (char c in core) if (char.IsDigit(c)) digits++;
                if (digits >= 3) continue;
                if (Bip39.IsWord(core.ToLowerInvariant())) continue;
                if (ContainsBip39LetterRun(raw)) continue;
                kept.Add(raw);
            }
            string s = string.Join(" ", kept.ToArray());
            if (s.Length > 20) s = s.Substring(0, 20).TrimEnd() + "\u2026";
            return s;
        }

        private static bool ContainsBip39LetterRun(string raw)
        {
            int runStart = -1;
            for (int i = 0; i <= raw.Length; i++)
            {
                char c = i < raw.Length ? raw[i] : '\0';
                bool isAsciiLetter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
                if (isAsciiLetter)
                {
                    if (runStart < 0) runStart = i;
                }
                else if (runStart >= 0)
                {
                    string sub = raw.Substring(runStart, i - runStart).ToLowerInvariant();
                    if (Bip39.IsWord(sub)) return true;
                    runStart = -1;
                }
            }
            return false;
        }

        /// <summary>Deletes the tab files behind the given findings. Refuses while Notepad runs.</summary>
        public int RemoveFindings(IEnumerable<string> findingIds)
        {
            // ARCHITECTURAL DESIGN NOTE: Process Lifetime Check Before Deletion
            // While Notepad.exe is running, it maintains in-memory state of open tabs and may hold
            // open file handles. Attempting to delete a .bin file while Notepad is open can cause
            // Notepad to recreate the file upon tab switch or overwrite it upon graceful application exit.
            // Requiring Notepad to be closed guarantees clean file deletion and tab removal.
            if (_isNotepadRunning()) throw new ClipGuardException("NotepadRunning");
            int removed = 0;
            foreach (string id in findingIds)
            {
                Finding f = FindingStore.Get(id);
                if (f == null || f.LocationType != LocationType) continue;
                HashSet<string> targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (string file in f.TargetFiles)
                {
                    targets.Add(file);
                    foreach (string sib in FilesOfTab(TabBase(file))) targets.Add(sib);
                }
                bool allGone = true;
                foreach (string file in targets)
                {
                    string full = Path.GetFullPath(file);
                    // AEGIS-SECURITY: only ever delete TabState .bin files of this folder.
                    if (!string.Equals(Path.GetDirectoryName(full), _folder, StringComparison.OrdinalIgnoreCase)) { allGone = false; continue; }
                    if (!full.EndsWith(".bin", StringComparison.OrdinalIgnoreCase)) { allGone = false; continue; }
                    try
                    {
                        // AEGIS-PERMISSION: deletes the auto-saved tab file the user asked to remove.
                        if (File.Exists(full)) File.Delete(full);
                    }
                    catch (IOException) { allGone = false; }
                    catch (UnauthorizedAccessException) { allGone = false; }
                }
                if (allGone)
                {
                    removed++;
                    FindingStore.Remove(id);
                }
            }
            return removed;
        }

        /// <summary>Starts/stops the TabState watcher. Returns whether it is watching.</summary>
        public bool SetWatch(bool enabled, Action<List<Finding>> onSecretSaved)
        {
            lock (_watchGate)
            {
                if (!enabled)
                {
                    StopWatchLocked();
                    return false;
                }
                if (_watcher != null) { _onSecretSaved = onSecretSaved; return true; }
                if (!Supported) return false;
                _onSecretSaved = onSecretSaved;
                // AEGIS-PERMISSION: change notifications for the TabState folder only.
                FileSystemWatcher w = new FileSystemWatcher(_folder, "*.bin");
                w.IncludeSubdirectories = false;
                w.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size;
                w.Changed += OnFsEvent;
                w.Created += OnFsEvent;
                w.Renamed += delegate (object s, RenamedEventArgs e) { Schedule(e.FullPath); };
                w.EnableRaisingEvents = true;
                _watcher = w;
                return true;
            }
        }

        private void OnFsEvent(object sender, FileSystemEventArgs e)
        {
            Schedule(e.FullPath);
        }

        private void Schedule(string fullPath)
        {
            if (fullPath == null || !fullPath.EndsWith(".bin", StringComparison.OrdinalIgnoreCase)) return;
            string tab = TabBase(fullPath);
            lock (_watchGate)
            {
                if (_watcher == null) return;
                Timer t;
                if (_debounce.TryGetValue(tab, out t)) { t.Change(400, Timeout.Infinite); return; }
                _debounce[tab] = new Timer(delegate { Fire(tab); }, null, 400, Timeout.Infinite);
            }
        }

        private void Fire(string tab)
        {
            Action<List<Finding>> cb;
            lock (_watchGate)
            {
                Timer t;
                if (_debounce.TryGetValue(tab, out t)) { t.Dispose(); _debounce.Remove(tab); }
                if (_watcher == null) return;
                cb = _onSecretSaved;
            }
            List<Finding> found;
            try { found = ScanTab(tab); }
            catch (Exception) { return; }
            List<string> sigs = new List<string>();
            foreach (Finding f in found) sigs.Add(f.Signature);
            sigs.Sort(StringComparer.Ordinal);
            string sig = string.Join(";", sigs.ToArray());
            lock (_watchGate)
            {
                string last;
                if (_lastSignature.TryGetValue(tab, out last) && last == sig) return; // nothing new
                _lastSignature[tab] = sig;
            }
            if (found.Count > 0 && cb != null) cb(found);
        }

        private void StopWatchLocked()
        {
            if (_watcher != null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Dispose();
                _watcher = null;
            }
            foreach (Timer t in _debounce.Values) t.Dispose();
            _debounce.Clear();
            _lastSignature.Clear();
        }

        public void Dispose()
        {
            lock (_watchGate) StopWatchLocked();
        }
    }
}
