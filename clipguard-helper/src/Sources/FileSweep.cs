// ---------------------------------------------------------------------------
// FileSweep.cs
// PURPOSE:  Scans local user folders (or caller-specified paths) for forgotten
//           copies of the user's own Solana secret keys and seed phrases in
//           text files, .docx/.xlsx documents, and (when opted in) local
//           screenshots via Windows offline OCR.
// ACCESS:   Read-only (FileShare.ReadWrite) access to eligible local files
//           under the chosen scope. Inspects FileAttributes and Win32 reparse
//           tags / file IDs before opening so cloud-only placeholders and NTFS
//           junction/symlink loops are skipped safely.
// NEVER:    No network. No Registry access. Never hydrates cloud-only
//           placeholder files. Never modifies or deletes files during a sweep.
//           Never returns file contents: only masked findings, DisplayPath,
//           and line numbers.
// ---------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Aegis.ClipGuard.Detection;
using Aegis.ClipGuard.Model;
using Windows.Graphics.Imaging;
using Windows.Media.Ocr;
using Windows.Storage.Streams;

namespace Aegis.ClipGuard.Sources
{
    public sealed class SweepOptions
    {
        public string Scope = "quick"; // quick | custom | full
        public List<string> Paths = new List<string>();
        public bool Ocr;
        public Func<FileInfo, FileAttributes> AttributeReader;
    }

    public sealed class SweepProgress
    {
        public string SweepId;
        public int FilesScanned;
        public string CurrentDir;
        public int FindingsSoFar;

        public Dictionary<string, object> ToJson()
        {
            Dictionary<string, object> d = new Dictionary<string, object>();
            d["sweepId"] = SweepId;
            d["filesScanned"] = FilesScanned;
            d["currentDir"] = CurrentDir ?? "";
            d["findingsSoFar"] = FindingsSoFar;
            return d;
        }
    }

    public sealed class SweepResult
    {
        public string SweepId;
        public List<Finding> Findings = new List<Finding>();
        public int FilesScanned;
        public int SkippedCloudOnly;
        public long DurationMs;
        public bool Cancelled;

        public Dictionary<string, object> ToDoneJson()
        {
            Dictionary<string, object> d = new Dictionary<string, object>();
            d["sweepId"] = SweepId;
            d["findings"] = Finding.ToJsonList(Findings);
            d["skippedCloudOnly"] = SkippedCloudOnly;
            d["durationMs"] = DurationMs;
            return d;
        }
    }

    public static class FileSweep
    {
        public const long MaxFileBytes = 20L * 1024 * 1024;
        private const long MaxZipEntryBytes = 25L * 1024 * 1024;
        private const long MaxZipTotalBytes = 50L * 1024 * 1024;
        private const int BinaryProbeBytes = 4096;
        private const int MaxDirectoryDepth = 64;
        private const int MaxFindingsPerSweep = 2000;
        private const long ProgressIntervalMs = 250;
        private const int WinRtTimeoutMs = 15000;

        // Cloud placeholder attributes: skip BEFORE opening so Windows never hydrates them.
        public const int AttrOffline = 0x1000;
        public const int AttrRecallOnOpen = 0x40000;
        public const int AttrRecallOnDataAccess = 0x400000;
        public const int CloudOnlyMask = AttrOffline | AttrRecallOnOpen | AttrRecallOnDataAccess;

        // Win32 reparse tag & file identity constants for NTFS junction/symlink loop prevention.
        private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);
        private static readonly Guid FolderIdDownloads = new Guid("374DE290-123F-4565-9164-39C4925E467B");
        private const uint KF_FLAG_DONT_VERIFY = 0x00004000;
        private const uint FILE_READ_ATTRIBUTES = 0x0080;
        private const uint FILE_SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FSCTL_GET_REPARSE_POINT = 0x000900A8;
        private const int MaxReparseBufferBytes = 16384;
        public const uint IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003;
        public const uint IO_REPARSE_TAG_SYMLINK = 0xA000000C;

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint dwFileAttributes;
            public FILETIME ftCreationTime;
            public FILETIME ftLastAccessTime;
            public FILETIME ftLastWriteTime;
            public uint dwVolumeSerialNumber;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint nNumberOfLinks;
            public uint nFileIndexHigh;
            public uint nFileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WIN32_FIND_DATAW
        {
            public uint dwFileAttributes;
            public FILETIME ftCreationTime;
            public FILETIME ftLastAccessTime;
            public FILETIME ftLastWriteTime;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint dwReserved0;
            public uint dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
            public string cAlternateFileName;
        }

        private struct FileIdKey : IEquatable<FileIdKey>
        {
            public uint VolumeSerial;
            public uint IndexHigh;
            public uint IndexLow;

            public bool Equals(FileIdKey other)
            {
                return VolumeSerial == other.VolumeSerial &&
                       IndexHigh == other.IndexHigh &&
                       IndexLow == other.IndexLow;
            }

            public override bool Equals(object obj)
            {
                return obj is FileIdKey && Equals((FileIdKey)obj);
            }

            public override int GetHashCode()
            {
                unchecked
                {
                    int h = (int)VolumeSerial;
                    h = (h * 397) ^ (int)IndexHigh;
                    h = (h * 397) ^ (int)IndexLow;
                    return h;
                }
            }
        }

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            [Out] byte[] lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            IntPtr hFile,
            out BY_HANDLE_FILE_INFORMATION lpFileInformation);

        [DllImport("kernel32.dll", EntryPoint = "FindFirstFileW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr FindFirstFileW(
            string lpFileName,
            out WIN32_FIND_DATAW lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindClose(IntPtr hFindFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("shell32.dll")]
        private static extern int SHGetKnownFolderPath(
            [MarshalAs(UnmanagedType.LPStruct)] Guid rfid,
            uint dwFlags,
            IntPtr hToken,
            out IntPtr ppszPath);

        private static readonly HashSet<string> TextExtensions = BuildSet(new string[]
        {
            ".txt", ".md", ".json", ".env", ".csv", ".log", ".ini",
            ".yaml", ".yml", ".toml", ".js", ".ts", ".py", ".sol",
            ".rs", ".cfg", ".conf", ".xml", ".html",
            ".bak", ".old", ".tmp", ".key", ".seed", ".secret", ".wallet",
            ".ps1", ".bat", ".cmd", ".sh", ".rtf"
        });

        private static readonly HashSet<string> SkippedDirNames = BuildSet(new string[]
        {
            "node_modules", ".git", "AppData", "Windows",
            "Program Files", "Program Files (x86)",
            "$WinREAgent", "System Volume Information"
        });

        private static readonly object ActiveGate = new object();
        private static readonly Dictionary<string, CancellationTokenSource> ActiveSweeps =
            new Dictionary<string, CancellationTokenSource>(StringComparer.Ordinal);
        private static int _sweepCounter;

        private enum CandidateKind
        {
            None = 0,
            Text = 1,
            Docx = 2,
            Xlsx = 3,
            ImageOcr = 4
        }

        private sealed class WalkContext
        {
            public SweepOptions Options;
            public SweepResult Result;
            public Action<SweepProgress> OnProgress;
            public CancellationToken Token;
            public Stopwatch Clock;
            public long LastProgressMs;
            public List<string> CloudRoots;
            public HashSet<string> VisitedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> VisitedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            public HashSet<FileIdKey> VisitedDirIds = new HashSet<FileIdKey>();
            public HashSet<FileIdKey> VisitedFileIds = new HashSet<FileIdKey>();
            public OcrEngine Ocr;
            public bool OcrInitialized;
        }

        private static HashSet<string> BuildSet(string[] items)
        {
            return new HashSet<string>(items, StringComparer.OrdinalIgnoreCase);
        }

        public static bool IsCloudOnlyAttributes(FileAttributes attrs)
        {
            return (((int)attrs) & CloudOnlyMask) != 0;
        }

        public static bool IsOcrAvailable()
        {
            try
            {
                // AEGIS-PERMISSION: checks availability of built-in Windows offline OCR.
                return OcrEngine.TryCreateFromUserProfileLanguages() != null;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static string NextSweepId()
        {
            int n = Interlocked.Increment(ref _sweepCounter);
            return "s" + DateTime.UtcNow.Ticks.ToString("x") + "-" + n.ToString(CultureInfo.InvariantCulture);
        }

        public static string StartBackground(
            SweepOptions options,
            Action<SweepProgress> onProgress,
            Action<SweepResult> onDone)
        {
            ValidateScope(options);
            string sweepId = NextSweepId();
            CancellationTokenSource cts = new CancellationTokenSource();
            lock (ActiveGate)
            {
                ActiveSweeps[sweepId] = cts;
            }

            Thread worker = new Thread(delegate ()
            {
                SweepResult res = null;
                try
                {
                    res = RunInternal(sweepId, options, onProgress, cts.Token);
                }
                catch (Exception)
                {
                    res = new SweepResult();
                    res.SweepId = sweepId;
                    res.Cancelled = cts.IsCancellationRequested;
                }
                finally
                {
                    lock (ActiveGate)
                    {
                        ActiveSweeps.Remove(sweepId);
                    }
                    cts.Dispose();
                    if (onDone != null && res != null)
                    {
                        try { onDone(res); }
                        catch (Exception) { }
                    }
                }
            });
            worker.IsBackground = true;
            worker.Name = "AegisFileSweep-" + sweepId;
            worker.Start();
            return sweepId;
        }

        public static bool Cancel(string sweepId)
        {
            if (string.IsNullOrEmpty(sweepId)) return false;
            lock (ActiveGate)
            {
                CancellationTokenSource cts;
                if (ActiveSweeps.TryGetValue(sweepId, out cts))
                {
                    cts.Cancel();
                    return true;
                }
            }
            return false;
        }

        public static void CancelAll()
        {
            lock (ActiveGate)
            {
                foreach (CancellationTokenSource cts in ActiveSweeps.Values)
                {
                    try { cts.Cancel(); }
                    catch (Exception) { }
                }
            }
        }

        public static SweepResult Run(
            SweepOptions options,
            Action<SweepProgress> onProgress,
            CancellationToken cancelToken)
        {
            ValidateScope(options);
            return RunInternal(NextSweepId(), options, onProgress, cancelToken);
        }

        private static void ValidateScope(SweepOptions options)
        {
            if (options == null) throw new ClipGuardException("InvalidArgs");
            string s = string.IsNullOrEmpty(options.Scope) ? "quick" : options.Scope;
            if (s != "quick" && s != "custom" && s != "profile" && s != "full")
            {
                throw new ClipGuardException("InvalidScope");
            }
            options.Scope = s;
        }

        private static SweepResult RunInternal(
            string sweepId,
            SweepOptions options,
            Action<SweepProgress> onProgress,
            CancellationToken token)
        {
            Stopwatch sw = Stopwatch.StartNew();
            SweepResult result = new SweepResult();
            result.SweepId = sweepId;

            WalkContext ctx = new WalkContext();
            ctx.Options = options;
            ctx.Result = result;
            ctx.OnProgress = onProgress;
            ctx.Token = token;
            ctx.Clock = sw;
            ctx.LastProgressMs = 0;
            ctx.CloudRoots = DetectLocalCloudFolders();

            List<string> roots = ResolveRoots(options, ctx.CloudRoots);
            foreach (string rawRoot in roots)
            {
                if (token.IsCancellationRequested || result.Findings.Count >= MaxFindingsPerSweep) break;
                if (string.IsNullOrEmpty(rawRoot)) continue;

                string fullRoot;
                try { fullRoot = Path.GetFullPath(rawRoot); }
                catch (Exception) { continue; }

                if (File.Exists(fullRoot))
                {
                    ScanCandidateFile(ctx, new FileInfo(fullRoot));
                }
                else if (Directory.Exists(fullRoot))
                {
                    WalkDirectory(ctx, fullRoot, 0);
                }
            }

            sw.Stop();
            result.Cancelled = token.IsCancellationRequested;
            result.DurationMs = sw.ElapsedMilliseconds;
            return result;
        }

        private static List<string> ResolveRoots(SweepOptions options, List<string> cloudRoots)
        {
            List<string> roots = new List<string>();

            // Explicit paths override default roots (used by custom scope and isolated tests).
            if (options.Paths != null && options.Paths.Count > 0)
            {
                foreach (string p in options.Paths)
                {
                    if (!string.IsNullOrEmpty(p)) roots.Add(p);
                }
                return roots;
            }

            if (options.Scope == "custom")
            {
                return roots;
            }

            if (options.Scope == "profile")
            {
                AddIfPresent(roots, SafeSpecialFolder(Environment.SpecialFolder.UserProfile));
                foreach (string rb in GetUserRecycleBinFolders()) AddIfPresent(roots, rb);
                foreach (string cf in cloudRoots) AddIfPresent(roots, cf);
                return roots;
            }

            if (options.Scope == "full")
            {
                try
                {
                    // AEGIS-PERMISSION: enumerates local fixed drives for a user-requested full PC sweep.
                    foreach (DriveInfo d in DriveInfo.GetDrives())
                    {
                        if (d.DriveType == DriveType.Fixed && d.IsReady)
                        {
                            roots.Add(d.RootDirectory.FullName);
                        }
                    }
                }
                catch (Exception) { }
                return roots;
            }

            // "quick" scope: Desktop, Documents, Downloads, Pictures, user's Recycle Bin, local cloud folders.
            AddIfPresent(roots, SafeSpecialFolder(Environment.SpecialFolder.DesktopDirectory));
            AddIfPresent(roots, SafeSpecialFolder(Environment.SpecialFolder.MyDocuments));
            AddIfPresent(roots, GetDownloadsFolder());
            AddIfPresent(roots, SafeSpecialFolder(Environment.SpecialFolder.MyPictures));

            foreach (string rb in GetUserRecycleBinFolders()) AddIfPresent(roots, rb);
            foreach (string cf in cloudRoots) AddIfPresent(roots, cf);

            return roots;
        }

        private static void AddIfPresent(List<string> list, string dir)
        {
            if (string.IsNullOrEmpty(dir)) return;
            try
            {
                string full = Path.GetFullPath(dir);
                if (!Directory.Exists(full)) return;
                foreach (string existing in list)
                {
                    if (string.Equals(existing, full, StringComparison.OrdinalIgnoreCase)) return;
                }
                list.Add(full);
            }
            catch (Exception) { }
        }

        private static string SafeSpecialFolder(Environment.SpecialFolder sf)
        {
            try { return Environment.GetFolderPath(sf); }
            catch (Exception) { return null; }
        }

        private static string GetDownloadsFolder()
        {
            IntPtr pathPtr = IntPtr.Zero;
            try
            {
                // AEGIS-PERMISSION: queries Shell Known Folder path for Downloads without touching registry keys.
                int hr = SHGetKnownFolderPath(FolderIdDownloads, KF_FLAG_DONT_VERIFY, IntPtr.Zero, out pathPtr);
                if (hr == 0 && pathPtr != IntPtr.Zero)
                {
                    string known = Marshal.PtrToStringUni(pathPtr);
                    if (!string.IsNullOrEmpty(known) && Directory.Exists(known)) return known;
                }
            }
            catch (Exception) { }
            finally
            {
                if (pathPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(pathPtr);
            }

            string profile = SafeSpecialFolder(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(profile))
            {
                string fallback = Path.Combine(profile, "Downloads");
                if (Directory.Exists(fallback)) return fallback;
            }
            return null;
        }

        private static List<string> GetUserRecycleBinFolders()
        {
            List<string> bins = new List<string>();
            string sid = null;
            try
            {
                WindowsIdentity id = WindowsIdentity.GetCurrent();
                if (id != null && id.User != null) sid = id.User.Value;
            }
            catch (Exception) { }
            if (string.IsNullOrEmpty(sid)) return bins;

            try
            {
                foreach (DriveInfo d in DriveInfo.GetDrives())
                {
                    if (d.DriveType != DriveType.Fixed || !d.IsReady) continue;
                    string candidate = Path.Combine(Path.Combine(d.RootDirectory.FullName, "$Recycle.Bin"), sid);
                    if (Directory.Exists(candidate)) bins.Add(candidate);
                }
            }
            catch (Exception) { }
            return bins;
        }

        public static List<string> DetectLocalCloudFolders()
        {
            List<string> folders = new List<string>();
            string[] envVars = new string[] { "OneDrive", "OneDriveConsumer", "OneDriveCommercial" };
            foreach (string ev in envVars)
            {
                string val = Environment.GetEnvironmentVariable(ev);
                AddIfPresent(folders, val);
            }

            string profile = SafeSpecialFolder(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(profile) && Directory.Exists(profile))
            {
                AddIfPresent(folders, Path.Combine(profile, "OneDrive"));
                AddIfPresent(folders, Path.Combine(profile, "Dropbox"));
                AddIfPresent(folders, Path.Combine(profile, "Google Drive"));
                AddIfPresent(folders, Path.Combine(profile, "My Drive"));

                try
                {
                    foreach (string sub in Directory.GetDirectories(profile))
                    {
                        string name = Path.GetFileName(sub);
                        if (name.StartsWith("OneDrive - ", StringComparison.OrdinalIgnoreCase) ||
                            name.StartsWith("Dropbox (", StringComparison.OrdinalIgnoreCase) ||
                            name.StartsWith("Google Drive", StringComparison.OrdinalIgnoreCase))
                        {
                            AddIfPresent(folders, sub);
                        }
                    }
                }
                catch (Exception) { }
            }
            return folders;
        }

        private static void WalkDirectory(WalkContext ctx, string dirPath, int depth)
        {
            if (ctx.Token.IsCancellationRequested) return;
            if (depth > MaxDirectoryDepth) return;
            if (ctx.Result.Findings.Count >= MaxFindingsPerSweep) return;

            string normalized = dirPath.TrimEnd('\\', '/');
            if (!ctx.VisitedDirs.Add(normalized)) return;

            // AEGIS-SECURITY: track physical directory (VolumeSerialNumber, FileIndex) to prevent NTFS cycle loops.
            FileIdKey dirId;
            if (TryGetFileId(normalized, true, out dirId) && !ctx.VisitedDirIds.Add(dirId)) return;

            MaybeReportProgress(ctx, dirPath);

            DirectoryInfo di;
            try { di = new DirectoryInfo(dirPath); }
            catch (Exception) { return; }

            FileInfo[] files = null;
            try
            {
                // AEGIS-PERMISSION: lists directory metadata (WIN32_FIND_DATA) without opening files.
                files = di.GetFiles();
            }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }
            catch (Exception) { return; }

            for (int i = 0; i < files.Length; i++)
            {
                if (ctx.Token.IsCancellationRequested || ctx.Result.Findings.Count >= MaxFindingsPerSweep) return;
                ScanCandidateFile(ctx, files[i]);
                MaybeReportProgress(ctx, dirPath);
            }

            DirectoryInfo[] subDirs = null;
            try { subDirs = di.GetDirectories(); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }
            catch (Exception) { return; }

            for (int i = 0; i < subDirs.Length; i++)
            {
                if (ctx.Token.IsCancellationRequested || ctx.Result.Findings.Count >= MaxFindingsPerSweep) return;
                DirectoryInfo sub = subDirs[i];
                if (ShouldSkipSubdirectory(sub)) continue;
                WalkDirectory(ctx, sub.FullName, depth + 1);
            }
        }

        private static bool ShouldSkipSubdirectory(DirectoryInfo sub)
        {
            string name = sub.Name;
            if (string.IsNullOrEmpty(name)) return true;
            if (SkippedDirNames.Contains(name)) return true;

            FileAttributes attrs;
            try { attrs = sub.Attributes; }
            catch (Exception) { return true; }

            // AEGIS-SECURITY: skip NTFS junctions (0xA0000003) and symlinks (0xA000000C)
            // while still entering OneDrive cloud directories (0x9000*).
            if ((attrs & FileAttributes.ReparsePoint) != 0)
            {
                if (IsJunctionOrSymlinkReparsePoint(sub.FullName, true)) return true;
            }
            return false;
        }

        public static bool TryGetReparseTag(string path, bool isDirectory, out uint reparseTag)
        {
            reparseTag = 0;
            if (string.IsNullOrEmpty(path)) return false;

            uint flags = FILE_FLAG_OPEN_REPARSE_POINT | (isDirectory ? FILE_FLAG_BACKUP_SEMANTICS : 0u);
            // AEGIS-PERMISSION: metadata-only (0 desired access) handle to inspect NTFS reparse tag without following link.
            IntPtr handle = CreateFileW(path, 0, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero);
            if (handle != IntPtr.Zero && handle != InvalidHandleValue)
            {
                try
                {
                    byte[] buf = new byte[MaxReparseBufferBytes];
                    uint bytesReturned;
                    if (DeviceIoControl(
                        handle,
                        FSCTL_GET_REPARSE_POINT,
                        IntPtr.Zero,
                        0,
                        buf,
                        (uint)buf.Length,
                        out bytesReturned,
                        IntPtr.Zero) && bytesReturned >= 4)
                    {
                        reparseTag = BitConverter.ToUInt32(buf, 0);
                        return true;
                    }
                }
                catch (Exception) { }
                finally
                {
                    CloseHandle(handle);
                }
            }

            // Fallback: inspect WIN32_FIND_DATAW.dwReserved0 from parent directory entry.
            try
            {
                string trimmed = path.TrimEnd('\\', '/');
                WIN32_FIND_DATAW findData;
                IntPtr findHandle = FindFirstFileW(trimmed, out findData);
                if (findHandle != IntPtr.Zero && findHandle != InvalidHandleValue)
                {
                    try
                    {
                        if ((findData.dwFileAttributes & (uint)FileAttributes.ReparsePoint) != 0)
                        {
                            reparseTag = findData.dwReserved0;
                            return true;
                        }
                    }
                    finally
                    {
                        FindClose(findHandle);
                    }
                }
            }
            catch (Exception) { }
            return false;
        }

        private static bool IsJunctionOrSymlinkReparsePoint(string path, bool isDirectory)
        {
            uint tag;
            if (!TryGetReparseTag(path, isDirectory, out tag))
            {
                // Unreadable reparse point: skip safely rather than risking traversal loops.
                return true;
            }
            return tag == IO_REPARSE_TAG_MOUNT_POINT || tag == IO_REPARSE_TAG_SYMLINK;
        }

        private static bool TryGetFileId(string path, bool isDirectory, out FileIdKey key)
        {
            key = new FileIdKey();
            if (string.IsNullOrEmpty(path)) return false;

            uint flags = isDirectory ? FILE_FLAG_BACKUP_SEMANTICS : 0u;
            // AEGIS-PERMISSION: metadata-only handle to query (VolumeSerialNumber, FileIndex) for cycle/hardlink deduplication.
            IntPtr handle = CreateFileW(path, 0, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero);
            if (handle != IntPtr.Zero && handle != InvalidHandleValue)
            {
                try
                {
                    BY_HANDLE_FILE_INFORMATION info;
                    if (GetFileInformationByHandle(handle, out info) &&
                        (info.dwVolumeSerialNumber != 0 || info.nFileIndexHigh != 0 || info.nFileIndexLow != 0))
                    {
                        key.VolumeSerial = info.dwVolumeSerialNumber;
                        key.IndexHigh = info.nFileIndexHigh;
                        key.IndexLow = info.nFileIndexLow;
                        return true;
                    }
                }
                catch (Exception) { }
                finally
                {
                    CloseHandle(handle);
                }
            }

            handle = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero);
            if (handle != IntPtr.Zero && handle != InvalidHandleValue)
            {
                try
                {
                    BY_HANDLE_FILE_INFORMATION info;
                    if (GetFileInformationByHandle(handle, out info) &&
                        (info.dwVolumeSerialNumber != 0 || info.nFileIndexHigh != 0 || info.nFileIndexLow != 0))
                    {
                        key.VolumeSerial = info.dwVolumeSerialNumber;
                        key.IndexHigh = info.nFileIndexHigh;
                        key.IndexLow = info.nFileIndexLow;
                        return true;
                    }
                }
                catch (Exception) { }
                finally
                {
                    CloseHandle(handle);
                }
            }

            return false;
        }

        private static void MaybeReportProgress(WalkContext ctx, string currentDir)
        {
            if (ctx.OnProgress == null) return;
            long now = ctx.Clock.ElapsedMilliseconds;
            if (now - ctx.LastProgressMs < ProgressIntervalMs) return;
            ctx.LastProgressMs = now;

            SweepProgress p = new SweepProgress();
            p.SweepId = ctx.Result.SweepId;
            p.FilesScanned = ctx.Result.FilesScanned;
            p.CurrentDir = currentDir;
            p.FindingsSoFar = ctx.Result.Findings.Count;
            try { ctx.OnProgress(p); }
            catch (Exception) { }
        }

        private static CandidateKind ClassifyFile(string fileName, bool ocrEnabled)
        {
            if (string.IsNullOrEmpty(fileName)) return CandidateKind.None;

            if (fileName.Equals(".env", StringComparison.OrdinalIgnoreCase) ||
                fileName.StartsWith(".env.", StringComparison.OrdinalIgnoreCase) ||
                fileName.StartsWith(".env-", StringComparison.OrdinalIgnoreCase) ||
                fileName.StartsWith(".env_", StringComparison.OrdinalIgnoreCase))
            {
                return CandidateKind.Text;
            }

            string ext = Path.GetExtension(fileName);
            if (string.IsNullOrEmpty(ext)) return CandidateKind.None;

            if (TextExtensions.Contains(ext)) return CandidateKind.Text;
            if (ext.Equals(".docx", StringComparison.OrdinalIgnoreCase)) return CandidateKind.Docx;
            if (ext.Equals(".xlsx", StringComparison.OrdinalIgnoreCase)) return CandidateKind.Xlsx;

            if (ocrEnabled && (
                ext.Equals(".png", StringComparison.OrdinalIgnoreCase) ||
                ext.Equals(".jpg", StringComparison.OrdinalIgnoreCase) ||
                ext.Equals(".jpeg", StringComparison.OrdinalIgnoreCase)))
            {
                return CandidateKind.ImageOcr;
            }

            return CandidateKind.None;
        }

        private static void ScanCandidateFile(WalkContext ctx, FileInfo fi)
        {
            CandidateKind kind = ClassifyFile(fi.Name, ctx.Options.Ocr);
            if (kind == CandidateKind.None) return;

            string fullPath;
            try { fullPath = fi.FullName; }
            catch (Exception) { return; }

            if (!ctx.VisitedFiles.Add(fullPath)) return;

            // AEGIS-SECURITY: check cloud placeholder attributes BEFORE opening the file
            // so Windows Files On-Demand / cloud providers never hydrate or download it.
            FileAttributes attrs;
            try
            {
                attrs = ctx.Options.AttributeReader != null
                    ? ctx.Options.AttributeReader(fi)
                    : fi.Attributes;
            }
            catch (Exception) { return; }

            if (IsCloudOnlyAttributes(attrs))
            {
                ctx.Result.SkippedCloudOnly++;
                return;
            }

            if ((attrs & FileAttributes.ReparsePoint) != 0 && IsJunctionOrSymlinkReparsePoint(fullPath, false))
            {
                return;
            }

            long length;
            try { length = fi.Length; }
            catch (Exception) { return; }
            if (length <= 0 || length > MaxFileBytes) return;

            FileIdKey fileId;
            if (TryGetFileId(fullPath, false, out fileId) && !ctx.VisitedFileIds.Add(fileId))
            {
                return;
            }

            ctx.Result.FilesScanned++;

            string extracted = null;
            bool hasLineNumbers = false;
            try
            {
                if (kind == CandidateKind.Text)
                {
                    extracted = ReadTextIfNotBinary(fullPath);
                    hasLineNumbers = true;
                }
                else if (kind == CandidateKind.Docx)
                {
                    extracted = ReadOfficeZipText(fullPath, true);
                }
                else if (kind == CandidateKind.Xlsx)
                {
                    extracted = ReadOfficeZipText(fullPath, false);
                }
                else if (kind == CandidateKind.ImageOcr)
                {
                    extracted = ReadImageOcrText(ctx, fullPath);
                }

                if (string.IsNullOrEmpty(extracted)) return;

                List<SecretFinding> found = SecretDetector.DetectAll(extracted);
                if (found.Count == 0) return;

                bool inRecycleBin = IsRecycleBinPath(fullPath);
                bool cloudSynced = IsCloudSyncedPath(fullPath, ctx.CloudRoots);
                string locType = inRecycleBin ? "recycle-bin" : "file";
                string safeLabel = BuildSafeFileLabel(fullPath);

                HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (SecretFinding s in found)
                {
                    if (ctx.Result.Findings.Count >= MaxFindingsPerSweep) break;
                    if (!seen.Add(s.Signature)) continue;

                    Finding f = Finding.From(s, locType, safeLabel);
                    f.Path = fullPath;
                    f.TargetFiles.Add(fullPath);
                    if (hasLineNumbers) f.Line = TextRuns.LineAt(extracted, s.Index);
                    if (inRecycleBin) f.AddFlag("recycle-bin");
                    if (cloudSynced) f.AddFlag("cloud-synced");
                    ctx.Result.Findings.Add(FindingStore.Register(f));
                }
            }
            catch (Exception)
            {
                // Unreadable, locked, or malformed files are skipped gracefully.
            }
            finally
            {
                extracted = null; // AEGIS-SECURITY: drop extracted file text immediately after detection
            }
        }

        private static string BuildSafeFileLabel(string fullPath)
        {
            string name = Path.GetFileName(fullPath);
            if (string.IsNullOrEmpty(name)) return "Local file";
            // AEGIS-SECURITY: ensure even an unusual filename cannot echo secret material in label.
            if (SecretDetector.Detect(name).Findings.Count > 0)
            {
                return "Local file (" + Path.GetExtension(name) + ")";
            }
            return name;
        }

        public static bool IsRecycleBinPath(string fullPath)
        {
            if (string.IsNullOrEmpty(fullPath)) return false;
            string[] parts = fullPath.Split('\\', '/');
            for (int i = 0; i < parts.Length; i++)
            {
                if (parts[i].Equals("$Recycle.Bin", StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        public static bool IsCloudSyncedPath(string fullPath, List<string> cloudRoots)
        {
            if (string.IsNullOrEmpty(fullPath)) return false;

            if (cloudRoots != null)
            {
                for (int i = 0; i < cloudRoots.Count; i++)
                {
                    string root = cloudRoots[i];
                    if (string.IsNullOrEmpty(root)) continue;
                    string prefix = root.TrimEnd('\\', '/') + "\\";
                    if (fullPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(fullPath, root.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }

            string[] parts = fullPath.Split('\\', '/');
            for (int i = 0; i < parts.Length; i++)
            {
                string seg = parts[i];
                if (seg.Equals("OneDrive", StringComparison.OrdinalIgnoreCase) ||
                    seg.StartsWith("OneDrive - ", StringComparison.OrdinalIgnoreCase) ||
                    seg.StartsWith("OneDrive-", StringComparison.OrdinalIgnoreCase) ||
                    seg.Equals("Dropbox", StringComparison.OrdinalIgnoreCase) ||
                    seg.StartsWith("Dropbox (", StringComparison.OrdinalIgnoreCase) ||
                    seg.Equals("Google Drive", StringComparison.OrdinalIgnoreCase) ||
                    seg.Equals("My Drive", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        private static string ReadTextIfNotBinary(string fullPath)
        {
            // AEGIS-PERMISSION: read-only shared file open to scan text for the user's secrets.
            using (FileStream fs = new FileStream(
                fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                long len = fs.Length;
                if (len <= 0 || len > MaxFileBytes) return null;
                byte[] buf = new byte[len];
                try
                {
                    int total = 0;
                    while (total < buf.Length)
                    {
                        int n = fs.Read(buf, total, buf.Length - total);
                        if (n <= 0) break;
                        total += n;
                    }

                    // Binary skip rule: NUL byte in the first 4 KB.
                    int check = Math.Min(BinaryProbeBytes, total);
                    for (int i = 0; i < check; i++)
                    {
                        if (buf[i] == 0) return null;
                    }

                    int offset = 0;
                    if (total >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF) offset = 3;
                    return Encoding.UTF8.GetString(buf, offset, total - offset);
                }
                finally
                {
                    Array.Clear(buf, 0, buf.Length); // AEGIS-SECURITY: wipe raw file bytes
                }
            }
        }

        private static string ReadOfficeZipText(string fullPath, bool isDocx)
        {
            // AEGIS-PERMISSION: opens local .docx/.xlsx zip archive read-only to extract XML text.
            using (FileStream fs = new FileStream(
                fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                if (fs.Length <= 0 || fs.Length > MaxFileBytes) return null;
                using (ZipArchive zip = new ZipArchive(fs, ZipArchiveMode.Read))
                {
                    StringBuilder combined = new StringBuilder();
                    long totalExtracted = 0;

                    foreach (ZipArchiveEntry entry in zip.Entries)
                    {
                        string entryPath = entry.FullName.Replace('\\', '/').TrimStart('/');
                        if (!IsTargetOfficeXml(entryPath, isDocx)) continue;

                        // AEGIS-SECURITY: guard against compressed XML expansion bombs.
                        if (entry.Length > MaxZipEntryBytes) continue;
                        if (totalExtracted + entry.Length > MaxZipTotalBytes) break;

                        string xml = ReadZipEntryUtf8(entry, (int)MaxZipEntryBytes);
                        if (string.IsNullOrEmpty(xml)) continue;
                        totalExtracted += xml.Length;

                        string plain = StripXmlTags(xml);
                        xml = null;
                        if (!string.IsNullOrEmpty(plain))
                        {
                            if (combined.Length > 0) combined.Append('\n');
                            combined.Append(plain);
                        }
                    }
                    return combined.ToString();
                }
            }
        }

        private static bool IsTargetOfficeXml(string entryPath, bool isDocx)
        {
            if (isDocx)
            {
                return entryPath.Equals("word/document.xml", StringComparison.OrdinalIgnoreCase) ||
                       (entryPath.StartsWith("word/header", StringComparison.OrdinalIgnoreCase) &&
                        entryPath.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)) ||
                       (entryPath.StartsWith("word/footer", StringComparison.OrdinalIgnoreCase) &&
                        entryPath.EndsWith(".xml", StringComparison.OrdinalIgnoreCase));
            }

            if (entryPath.Equals("xl/sharedStrings.xml", StringComparison.OrdinalIgnoreCase)) return true;
            if (entryPath.StartsWith("xl/worksheets/", StringComparison.OrdinalIgnoreCase) &&
                entryPath.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            return false;
        }

        private static string ReadZipEntryUtf8(ZipArchiveEntry entry, int maxBytes)
        {
            using (Stream s = entry.Open())
            using (MemoryStream ms = new MemoryStream())
            {
                byte[] chunk = new byte[8192];
                int total = 0;
                try
                {
                    while (true)
                    {
                        int n = s.Read(chunk, 0, chunk.Length);
                        if (n <= 0) break;
                        total += n;
                        if (total > maxBytes) return null;
                        ms.Write(chunk, 0, n);
                    }
                    byte[] raw = ms.ToArray();
                    try
                    {
                        int offset = 0;
                        if (raw.Length >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF) offset = 3;
                        return Encoding.UTF8.GetString(raw, offset, raw.Length - offset);
                    }
                    finally
                    {
                        Array.Clear(raw, 0, raw.Length); // AEGIS-SECURITY: wipe extracted XML bytes
                    }
                }
                finally
                {
                    Array.Clear(chunk, 0, chunk.Length);
                }
            }
        }

        public static string StripXmlTags(string xml)
        {
            if (string.IsNullOrEmpty(xml)) return "";
            StringBuilder sb = new StringBuilder(xml.Length / 2);
            int i = 0;
            while (i < xml.Length)
            {
                char c = xml[i];
                if (c == '<')
                {
                    int close = xml.IndexOf('>', i + 1);
                    if (close < 0) break;
                    string tag = ExtractXmlLocalTagName(xml, i + 1, close);
                    if (IsBlockOrSeparatorTag(tag)) sb.Append('\n');
                    i = close + 1;
                }
                else if (c == '&')
                {
                    int semi = xml.IndexOf(';', i + 1);
                    if (semi > i && semi - i <= 12)
                    {
                        string ent = xml.Substring(i + 1, semi - i - 1);
                        sb.Append(DecodeXmlEntity(ent));
                        i = semi + 1;
                    }
                    else
                    {
                        sb.Append(c);
                        i++;
                    }
                }
                else
                {
                    sb.Append(c);
                    i++;
                }
            }
            return sb.ToString();
        }

        private static string ExtractXmlLocalTagName(string xml, int start, int end)
        {
            int p = start;
            while (p < end && (xml[p] == '/' || xml[p] == ' ' || xml[p] == '\t' || xml[p] == '\r' || xml[p] == '\n')) p++;
            int nameStart = p;
            while (p < end)
            {
                char c = xml[p];
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '/') break;
                if (c == ':') nameStart = p + 1;
                p++;
            }
            return p > nameStart ? xml.Substring(nameStart, p - nameStart) : "";
        }

        private static bool IsBlockOrSeparatorTag(string localName)
        {
            if (string.IsNullOrEmpty(localName)) return false;
            return localName.Equals("p", StringComparison.OrdinalIgnoreCase) ||
                   localName.Equals("br", StringComparison.OrdinalIgnoreCase) ||
                   localName.Equals("cr", StringComparison.OrdinalIgnoreCase) ||
                   localName.Equals("tab", StringComparison.OrdinalIgnoreCase) ||
                   localName.Equals("tc", StringComparison.OrdinalIgnoreCase) ||
                   localName.Equals("tr", StringComparison.OrdinalIgnoreCase) ||
                   localName.Equals("si", StringComparison.OrdinalIgnoreCase) ||
                   localName.Equals("c", StringComparison.OrdinalIgnoreCase) ||
                   localName.Equals("row", StringComparison.OrdinalIgnoreCase) ||
                   localName.Equals("v", StringComparison.OrdinalIgnoreCase) ||
                   localName.Equals("div", StringComparison.OrdinalIgnoreCase) ||
                   localName.Equals("li", StringComparison.OrdinalIgnoreCase);
        }

        private static string DecodeXmlEntity(string entity)
        {
            if (entity == "amp") return "&";
            if (entity == "lt") return "<";
            if (entity == "gt") return ">";
            if (entity == "quot") return "\"";
            if (entity == "apos") return "'";
            if (entity.Length > 1 && entity[0] == '#')
            {
                int code;
                bool ok = (entity.Length > 2 && (entity[1] == 'x' || entity[1] == 'X'))
                    ? int.TryParse(entity.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out code)
                    : int.TryParse(entity.Substring(1), NumberStyles.Integer, CultureInfo.InvariantCulture, out code);
                if (ok && code > 0 && code <= 0x10FFFF && (code < 0xD800 || code > 0xDFFF))
                {
                    return char.ConvertFromUtf32(code);
                }
            }
            return "&" + entity + ";";
        }

        private static Task<T> AsTask<T>(Windows.Foundation.IAsyncOperation<T> op)
        {
            TaskCompletionSource<T> tcs = new TaskCompletionSource<T>();
            op.Completed = delegate (Windows.Foundation.IAsyncOperation<T> o, Windows.Foundation.AsyncStatus status)
            {
                if (status == Windows.Foundation.AsyncStatus.Completed) tcs.TrySetResult(o.GetResults());
                else if (status == Windows.Foundation.AsyncStatus.Error) tcs.TrySetException(o.ErrorCode);
                else tcs.TrySetCanceled();
            };
            return tcs.Task;
        }

        private static T AwaitWinRt<T>(Windows.Foundation.IAsyncOperation<T> op)
        {
            Task<T> task = AsTask(op);
            if (!task.Wait(WinRtTimeoutMs)) throw new TimeoutException();
            return task.Result;
        }

        private static string ReadImageOcrText(WalkContext ctx, string fullPath)
        {
            if (!ctx.OcrInitialized)
            {
                ctx.OcrInitialized = true;
                try
                {
                    // AEGIS-PERMISSION: uses built-in Windows offline OCR; never sends images off-device.
                    ctx.Ocr = OcrEngine.TryCreateFromUserProfileLanguages();
                }
                catch (Exception)
                {
                    ctx.Ocr = null;
                }
            }
            if (ctx.Ocr == null) return null;

            try
            {
                FileInfo fi = new FileInfo(fullPath);
                if (!fi.Exists || fi.Length <= 0 || fi.Length > MaxFileBytes) return null;

                // AEGIS-PERMISSION: opens local image read-only via WinRT StorageFile for offline OCR.
                Windows.Storage.StorageFile sf = AwaitWinRt(Windows.Storage.StorageFile.GetFileFromPathAsync(fullPath));
                IRandomAccessStream ras = AwaitWinRt(sf.OpenAsync(Windows.Storage.FileAccessMode.Read));
                try
                {
                    BitmapDecoder decoder = AwaitWinRt(BitmapDecoder.CreateAsync(ras));
                    if (decoder.PixelWidth == 0 || decoder.PixelHeight == 0) return null;
                    if (decoder.PixelWidth > OcrEngine.MaxImageDimension ||
                        decoder.PixelHeight > OcrEngine.MaxImageDimension)
                    {
                        return null;
                    }

                    SoftwareBitmap bmp = AwaitWinRt(decoder.GetSoftwareBitmapAsync(
                        BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied));
                    try
                    {
                        OcrResult ocr = AwaitWinRt(ctx.Ocr.RecognizeAsync(bmp));
                        if (ocr == null) return null;
                        StringBuilder sb = new StringBuilder();
                        if (ocr.Lines != null)
                        {
                            foreach (OcrLine line in ocr.Lines)
                            {
                                if (sb.Length > 0) sb.Append('\n');
                                sb.Append(line.Text);
                            }
                        }
                        return sb.Length > 0 ? sb.ToString() : ocr.Text;
                    }
                    finally
                    {
                        IDisposable dispBmp = bmp as IDisposable;
                        if (dispBmp != null) dispBmp.Dispose();
                    }
                }
                finally
                {
                    IDisposable dispRas = ras as IDisposable;
                    if (dispRas != null) dispRas.Dispose();
                }
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
