// ---------------------------------------------------------------------------
// GhostScan.cs
// PURPOSE:  Coordinates a standalone offline "Ghost Copy Scan" across Win+V
//           Clipboard History, Windows 11 Notepad auto-saved TabState, Sticky
//           Notes SQLite/WAL pages, and local user folders for both CLI mode
//           and the standalone Windows desktop UI.
// ACCESS:   Delegates read-only scanning to ClipboardHistory, NotepadTabs,
//           StickyNotes, and FileSweep according to caller-selected scope.
//           In isolated custom-directory mode, touches ONLY the specified
//           directory (never real user folders or Windows app state).
// NEVER:    No network. No Registry access. Never logs, persists, or prints
//           unmasked secret material or unredacted secret filenames.
// ---------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using Aegis.ClipGuard.Model;

namespace Aegis.ClipGuard.Sources
{
    public sealed class GhostScanOptions
    {
        public bool Isolated;
        public bool SkipHistory;
        public string NotepadFolder;
        public string StickyNotesFolder;
        public bool SkipFileSweep;
        public string SweepScope = "quick";
        public List<string> CustomPaths = new List<string>();
        public bool Ocr;
    }

    public sealed class GhostScanReport
    {
        public string HistoryStatus = "Skipped";
        public int HistoryItemCount;
        public List<Finding> HistoryFindings = new List<Finding>();

        public bool NotepadSupported;
        public bool NotepadRunning;
        public List<Finding> NotepadFindings = new List<Finding>();

        public bool StickyNotesSupported;
        public List<Finding> StickyNotesFindings = new List<Finding>();

        public int FilesScanned;
        public int SkippedCloudOnly;
        public long SweepDurationMs;
        public bool Cancelled;
        public List<Finding> FileFindings = new List<Finding>();

        public List<Finding> AllFindings = new List<Finding>();
        public long TotalDurationMs;
    }

    public static class GhostScan
    {
        public static GhostScanReport Run(
            GhostScanOptions options,
            Action<string> onStatus,
            CancellationToken cancelToken)
        {
            if (options == null) options = new GhostScanOptions();
            Stopwatch totalClock = Stopwatch.StartNew();
            GhostScanReport report = new GhostScanReport();

            bool skipHistory = options.Isolated || options.SkipHistory;
            if (!skipHistory && !cancelToken.IsCancellationRequested)
            {
                Notify(onStatus, "Scanning Win+V Clipboard History...");
                try
                {
                    HistoryScanResult hr = ClipboardHistory.Scan();
                    report.HistoryStatus = hr.Status;
                    report.HistoryItemCount = hr.ItemCount;
                    report.HistoryFindings.AddRange(hr.Findings);
                    report.AllFindings.AddRange(hr.Findings);
                }
                catch (ClipGuardException ex)
                {
                    report.HistoryStatus = ex.Code;
                }
                catch (Exception)
                {
                    report.HistoryStatus = "ClipboardError";
                }
            }

            if (!cancelToken.IsCancellationRequested)
            {
                string npFolder = ResolveNotepadFolder(options);
                if (!string.IsNullOrEmpty(npFolder))
                {
                    Notify(onStatus, "Scanning Windows 11 Notepad unsaved TabState...");
                    Func<bool> runningCheck = options.Isolated
                        ? (Func<bool>)delegate () { return false; }
                        : null;
                    using (NotepadTabs np = new NotepadTabs(npFolder, runningCheck))
                    {
                        List<Finding> nf = np.Scan();
                        report.NotepadSupported = np.Supported;
                        report.NotepadRunning = options.Isolated ? false : NotepadTabs.IsNotepadRunning();
                        report.NotepadFindings.AddRange(nf);
                        report.AllFindings.AddRange(nf);
                    }
                }
            }

            if (!cancelToken.IsCancellationRequested)
            {
                string snFolder = ResolveStickyNotesFolder(options);
                if (!string.IsNullOrEmpty(snFolder))
                {
                    Notify(onStatus, "Scanning Microsoft Sticky Notes local database...");
                    StickyNotes sn = new StickyNotes(snFolder);
                    List<Finding> sf = sn.Scan();
                    report.StickyNotesSupported = sn.Supported;
                    report.StickyNotesFindings.AddRange(sf);
                    report.AllFindings.AddRange(sf);
                }
            }

            if (!options.SkipFileSweep && !cancelToken.IsCancellationRequested)
            {
                Notify(onStatus, "Scanning local folders for exposed secret keys & seed phrases...");
                SweepOptions sweepOpts = new SweepOptions();
                sweepOpts.Scope = (options.CustomPaths.Count > 0 || options.Isolated)
                    ? "custom"
                    : (string.IsNullOrEmpty(options.SweepScope) ? "quick" : options.SweepScope);
                sweepOpts.Paths.AddRange(options.CustomPaths);
                sweepOpts.Ocr = options.Ocr;

                SweepResult sw = FileSweep.Run(
                    sweepOpts,
                    delegate (SweepProgress p)
                    {
                        string dirHint = ShortenDirectory(p.CurrentDir, 56);
                        Notify(onStatus,
                            "Scanning local files: " + p.FilesScanned + " checked (" +
                            (report.AllFindings.Count + p.FindingsSoFar) + " findings) — " + dirHint);
                    },
                    cancelToken);

                report.FilesScanned = sw.FilesScanned;
                report.SkippedCloudOnly = sw.SkippedCloudOnly;
                report.SweepDurationMs = sw.DurationMs;
                report.FileFindings.AddRange(sw.Findings);
                report.AllFindings.AddRange(sw.Findings);
            }

            totalClock.Stop();
            report.Cancelled = cancelToken.IsCancellationRequested;
            report.TotalDurationMs = totalClock.ElapsedMilliseconds;
            return report;
        }

        private static string ResolveNotepadFolder(GhostScanOptions options)
        {
            if (!string.IsNullOrEmpty(options.NotepadFolder)) return options.NotepadFolder;
            if (options.Isolated)
            {
                if (options.CustomPaths != null && options.CustomPaths.Count == 1 && !string.IsNullOrEmpty(options.CustomPaths[0]))
                {
                    string candidate = Path.Combine(options.CustomPaths[0], "TabState");
                    if (Directory.Exists(candidate)) return candidate;
                }
                return null;
            }
            return NotepadTabs.DefaultFolder;
        }

        private static string ResolveStickyNotesFolder(GhostScanOptions options)
        {
            if (!string.IsNullOrEmpty(options.StickyNotesFolder)) return options.StickyNotesFolder;
            if (options.Isolated)
            {
                if (options.CustomPaths != null && options.CustomPaths.Count == 1 && !string.IsNullOrEmpty(options.CustomPaths[0]))
                {
                    string candidate = Path.Combine(options.CustomPaths[0], "StickyNotes");
                    if (Directory.Exists(candidate)) return candidate;
                }
                return null;
            }
            return StickyNotes.DefaultFolder;
        }

        private static void Notify(Action<string> onStatus, string message)
        {
            if (onStatus == null) return;
            try { onStatus(message); }
            catch (Exception) { }
        }

        private static string ShortenDirectory(string path, int maxChars)
        {
            if (string.IsNullOrEmpty(path)) return "";
            string safe = Finding.BuildDisplayPath(path);
            if (safe.Length <= maxChars) return safe;
            return "\u2026" + safe.Substring(safe.Length - (maxChars - 1));
        }

        public static string FormatCliSummary(GhostScanReport report, string version)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Aegis Clip Guard v" + version + " — Standalone Offline Ghost Copy Scan");
            sb.AppendLine("Trust Guarantee: 100% Offline | 0 Network Code | 0 Browser IPC | 0 Registry Edits");
            sb.AppendLine("------------------------------------------------------------------------");
            sb.AppendLine("  Win+V Clipboard History : " + report.HistoryStatus +
                " (" + report.HistoryItemCount + " items, " + report.HistoryFindings.Count + " findings)");
            sb.AppendLine("  Windows 11 Notepad Tabs : " + (report.NotepadSupported ? "Scanned" : "Not present") +
                " (" + report.NotepadFindings.Count + " findings)");
            sb.AppendLine("  Microsoft Sticky Notes  : " + (report.StickyNotesSupported ? "Scanned" : "Not present") +
                " (" + report.StickyNotesFindings.Count + " findings)");
            sb.AppendLine("  Local File Sweep        : " + report.FilesScanned + " files scanned, " +
                report.SkippedCloudOnly + " cloud-only skipped (" + report.FileFindings.Count + " findings)");
            sb.AppendLine("------------------------------------------------------------------------");
            sb.AppendLine("Total Findings: " + report.AllFindings.Count + " (" + report.TotalDurationMs + " ms)");

            for (int i = 0; i < report.AllFindings.Count; i++)
            {
                Finding f = report.AllFindings[i];
                // AEGIS-SECURITY: emit only Masked preview and redacted DisplayPath / sanitized Label.
                string where = !string.IsNullOrEmpty(f.DisplayPath)
                    ? (f.Line > 0 ? (f.DisplayPath + ":" + f.Line) : f.DisplayPath)
                    : (f.Label ?? f.LocationType);
                string flags = f.Flags.Count > 0 ? (" [" + string.Join(", ", f.Flags.ToArray()) + "]") : "";
                sb.AppendLine("  [" + (i + 1) + "] " + f.LocationType + " | " +
                    f.Kind + " (" + f.Format + ") | " + f.Masked + " | " + where + flags);
            }
            return sb.ToString();
        }
    }
}
