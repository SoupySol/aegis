// ---------------------------------------------------------------------------
// Finding.cs
// PURPOSE:  Represents a masked secret finding plus a per-session in-memory
//           store that maps opaque findingIds to where the finding lives (local
//           file path, Notepad tab files, clipboard history item id) so user
//           cleanup actions can target only that item.
// ACCESS:   In-memory only.
// NEVER:    Never stores or serializes secret material: only the masked form
//           (shortened public key / "12 words, starts with a…") and redacted
//           DisplayPath when a filename itself contains a secret. Nothing is
//           persisted; the store dies with the process. No network.
// ---------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Aegis.ClipGuard.Detection;

namespace Aegis.ClipGuard.Model
{
    public sealed class Finding
    {
        private string _path;
        private string _displayPath;

        public string FindingId;
        public string Kind;
        public string Format;
        public string Masked;
        public int WordCount;
        public string LocationType;   // clipboard-history | notepad-tab | sticky-notes | file | recycle-bin
        public int Line;              // files only, 0 = unknown
        public string Label;
        public List<string> Flags = new List<string>();

        // Session-only action targets & deduplication key (never serialized).
        public string ClipboardItemId;
        public List<string> TargetFiles = new List<string>();
        public string DedupKey;

        /// <summary>
        /// Internal local file path kept in memory for Open Folder / Recycle / Delete.
        /// Setting Path automatically computes the redacted DisplayPath.
        /// </summary>
        public string Path
        {
            get { return _path; }
            set
            {
                _path = value;
                _displayPath = BuildDisplayPath(value);
            }
        }

        /// <summary>
        /// Safe path for UI, CLI, and JSON output. Redacts the filename segment to
        /// "&lt;redacted-secret-filename&gt;&lt;ext&gt;" if the filename contains a secret.
        /// </summary>
        public string DisplayPath
        {
            get { return _displayPath; }
        }

        public string Signature
        {
            get
            {
                string key = !string.IsNullOrEmpty(DedupKey) ? DedupKey : Masked;
                return Kind + "|" + Format + "|" + key;
            }
        }

        public static string BuildDisplayPath(string fullPath)
        {
            if (string.IsNullOrEmpty(fullPath)) return fullPath;

            string dir;
            string fileName;
            try
            {
                dir = System.IO.Path.GetDirectoryName(fullPath);
                fileName = System.IO.Path.GetFileName(fullPath);
            }
            catch (Exception)
            {
                if (SecretDetector.Detect(fullPath).Findings.Count > 0)
                {
                    return "<redacted-secret-filename>";
                }
                return fullPath;
            }

            // AEGIS-SECURITY: redact directory segments if a folder name itself embeds a secret.
            string safeDir = dir;
            if (!string.IsNullOrEmpty(dir) && SecretDetector.Detect(dir).Findings.Count > 0)
            {
                string[] parts = dir.Split('\\', '/');
                for (int i = 0; i < parts.Length; i++)
                {
                    if (!string.IsNullOrEmpty(parts[i]) && SecretDetector.Detect(parts[i]).Findings.Count > 0)
                    {
                        parts[i] = "<redacted-secret-dir>";
                    }
                }
                safeDir = string.Join("\\", parts);
            }

            // AEGIS-SECURITY: redact filename segment if the filename embeds a secret key or seed phrase.
            string safeFile = fileName;
            if (!string.IsNullOrEmpty(fileName) && SecretDetector.Detect(fileName).Findings.Count > 0)
            {
                string ext = "";
                try { ext = System.IO.Path.GetExtension(fileName) ?? ""; }
                catch (Exception) { ext = ""; }
                if (!string.IsNullOrEmpty(ext) && SecretDetector.Detect(ext).Findings.Count > 0)
                {
                    ext = "";
                }
                safeFile = "<redacted-secret-filename>" + ext;
            }

            if (string.IsNullOrEmpty(safeDir)) return safeFile;
            if (string.IsNullOrEmpty(safeFile)) return safeDir;
            return safeDir.TrimEnd('\\', '/') + "\\" + safeFile;
        }

        public static Finding From(SecretFinding s, string locationType, string label)
        {
            Finding f = new Finding();
            f.Kind = s.Kind;
            f.Format = s.Format;
            f.Masked = s.Masked;
            f.WordCount = s.WordCount;
            f.DedupKey = s.DedupKey;
            f.LocationType = locationType;
            f.Label = label;
            return f;
        }

        public void AddFlag(string flag)
        {
            if (!Flags.Contains(flag)) Flags.Add(flag);
        }

        public Dictionary<string, object> ToJson()
        {
            Dictionary<string, object> d = new Dictionary<string, object>();
            d["findingId"] = FindingId;
            d["kind"] = Kind;
            d["format"] = Format;
            d["masked"] = Masked;
            if (WordCount > 0) d["wordCount"] = WordCount;
            Dictionary<string, object> loc = new Dictionary<string, object>();
            loc["type"] = LocationType;
            if (DisplayPath != null) loc["path"] = DisplayPath;
            if (Line > 0) loc["line"] = Line;
            if (Label != null) loc["label"] = Label;
            d["location"] = loc;
            d["flags"] = new List<string>(Flags);
            return d;
        }

        public static List<object> ToJsonList(IEnumerable<Finding> findings)
        {
            List<object> list = new List<object>();
            foreach (Finding f in findings) list.Add(f.ToJson());
            return list;
        }
    }

    /// <summary>Session-scoped registry of findings (findingId -> action target).</summary>
    public static class FindingStore
    {
        private static readonly object Gate = new object();
        private static readonly Dictionary<string, Finding> Items = new Dictionary<string, Finding>(StringComparer.Ordinal);
        private const int MaxItems = 200000;

        public static Finding Register(Finding f)
        {
            byte[] id = new byte[12];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(id);
            string hex = BitConverter.ToString(id).Replace("-", "").ToLowerInvariant();
            f.FindingId = "f" + hex;
            lock (Gate)
            {
                if (Items.Count >= MaxItems) Items.Clear(); // bounded memory; old ids simply expire
                Items[f.FindingId] = f;
            }
            return f;
        }

        public static Finding Get(string findingId)
        {
            if (findingId == null) return null;
            lock (Gate)
            {
                Finding f;
                return Items.TryGetValue(findingId, out f) ? f : null;
            }
        }

        public static void Remove(string findingId)
        {
            if (findingId == null) return;
            lock (Gate) Items.Remove(findingId);
        }
    }
}
