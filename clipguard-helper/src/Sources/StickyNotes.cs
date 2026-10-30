// ---------------------------------------------------------------------------
// StickyNotes.cs
// PURPOSE:  Finds secrets in Microsoft Sticky Notes' local database by scanning
//           the raw bytes of plum.sqlite, plum.sqlite-wal and plum.sqlite-shm
//           for UTF-8 text runs. Raw bytes also cover deleted notes that SQLite
//           has not overwritten yet ("ghost copies").
// ACCESS:   Read-only (FileShare.ReadWrite) access to those three files in
//           %LOCALAPPDATA%\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState.
// NEVER:    No network. Never writes or deletes anything. Never returns note
//           text: only masked findings.
// ---------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.IO;
using Aegis.ClipGuard.Detection;
using Aegis.ClipGuard.Model;

namespace Aegis.ClipGuard.Sources
{
    public sealed class StickyNotes
    {
        public const string LocationType = "sticky-notes";
        private static readonly string[] FileNames = { "plum.sqlite", "plum.sqlite-wal", "plum.sqlite-shm" };
        private const long MaxFileBytes = 256L * 1024 * 1024;

        private readonly string _folder;

        public static string DefaultFolder
        {
            get
            {
                string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                return Path.Combine(local, @"Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState");
            }
        }

        public StickyNotes(string folder)
        {
            _folder = Path.GetFullPath(folder);
        }

        public bool Supported
        {
            get { return Directory.Exists(_folder) && File.Exists(Path.Combine(_folder, FileNames[0])); }
        }

        public List<Finding> Scan()
        {
            List<Finding> findings = new List<Finding>();
            if (!Supported) return findings;
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (string name in FileNames)
            {
                string path = Path.Combine(_folder, name);
                if (!File.Exists(path)) continue;
                string text;
                try { text = ExtractText(path); }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }
                if (text == null) continue;
                foreach (SecretFinding s in SecretDetector.DetectAll(text))
                {
                    if (!seen.Add(s.Signature)) continue; // same note in db + wal -> one finding
                    Finding f = Finding.From(s, LocationType, "Sticky Notes (" + name + ")");
                    f.AddFlag("auto-saved-by-windows");
                    findings.Add(FindingStore.Register(f));
                }
            }
            return findings;
        }

        /// <summary>UTF-8 text runs of one file, joined by newlines (detector input only).</summary>
        public static string ExtractText(string path)
        {
            byte[] data;
            // AEGIS-PERMISSION: read-only, shared; Sticky Notes keeps the db open.
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                if (fs.Length > MaxFileBytes) return null;
                data = new byte[fs.Length];
                int read = 0;
                while (read < data.Length)
                {
                    int n = fs.Read(data, read, data.Length - read);
                    if (n <= 0) break;
                    read += n;
                }
            }
            string text = TextRuns.Join(TextRuns.Utf8(data, TextRuns.DefaultMinChars));
            Array.Clear(data, 0, data.Length); // AEGIS-SECURITY: wipe raw bytes
            return text;
        }
    }
}
