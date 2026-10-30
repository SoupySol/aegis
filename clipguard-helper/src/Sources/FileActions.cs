// ---------------------------------------------------------------------------
// FileActions.cs
// PURPOSE:  Performs user-requested local cleanup actions ("open-location",
//           "recycle", "delete") on a specific file finding previously
//           registered in FindingStore during this Clip Guard session.
// ACCESS:   Launches Windows Explorer (/select) with UseShellExecute=false,
//           sends a file to the Windows Recycle Bin, or deletes a local file
//           for findings whose location type is "file" or "recycle-bin".
// NEVER:    No network. Never acts on arbitrary paths not in FindingStore.
//           Never deletes or recycles reparse points (symlinks/junctions).
//           Never executes files or opens URLs. Never touches directories.
// ---------------------------------------------------------------------------
using System;
using System.Diagnostics;
using System.IO;
using Aegis.ClipGuard.Model;
using Microsoft.VisualBasic.FileIO;

namespace Aegis.ClipGuard.Sources
{
    public static class FileActions
    {
        public static void Execute(string findingId, string action)
        {
            if (string.IsNullOrEmpty(findingId)) throw new ClipGuardException("InvalidFindingId");
            if (string.IsNullOrEmpty(action)) throw new ClipGuardException("InvalidAction");

            Finding f = FindingStore.Get(findingId);
            if (f == null) throw new ClipGuardException("FindingNotFound");

            // AEGIS-SECURITY: only act on session-registered file or recycle-bin findings.
            if (f.LocationType != "file" && f.LocationType != "recycle-bin")
            {
                throw new ClipGuardException("InvalidFindingLocation");
            }

            string fullPath = ValidateLocalFilePath(f.Path);
            if (action == "recycle" || action == "delete")
            {
                EnsureSafeRegularFileTarget(fullPath);
            }
            if (!File.Exists(fullPath)) throw new ClipGuardException("FileNotFound");

            if (action == "open-location")
            {
                OpenInExplorer(fullPath);
                return;
            }

            if (action == "recycle")
            {
                // AEGIS-PERMISSION: sends only the selected finding file to the Windows Recycle Bin.
                FileSystem.DeleteFile(fullPath, UIOption.OnlyErrorDialogs, RecycleOption.SendToRecycleBin);
                FindingStore.Remove(findingId);
                return;
            }

            if (action == "delete")
            {
                // AEGIS-PERMISSION: permanently deletes only the selected finding file on explicit user request.
                File.Delete(fullPath);
                FindingStore.Remove(findingId);
                return;
            }

            throw new ClipGuardException("InvalidAction");
        }

        private static void EnsureSafeRegularFileTarget(string fullPath)
        {
            FileAttributes attrs;
            try
            {
                attrs = File.GetAttributes(fullPath);
            }
            catch (FileNotFoundException)
            {
                throw new ClipGuardException("FileNotFound");
            }
            catch (DirectoryNotFoundException)
            {
                throw new ClipGuardException("FileNotFound");
            }
            catch (Exception)
            {
                throw new ClipGuardException("AccessDenied");
            }

            // AEGIS-SECURITY: refuse reparse points or directories so a TOCTOU symlink swap cannot delete an unintended target.
            if ((attrs & FileAttributes.ReparsePoint) != 0 || (attrs & FileAttributes.Directory) != 0)
            {
                throw new ClipGuardException("UnsafeReparseTarget");
            }
        }

        public static string ValidateLocalFilePath(string rawPath)
        {
            if (string.IsNullOrEmpty(rawPath)) throw new ClipGuardException("InvalidPath");

            // AEGIS-SECURITY: reject URI schemes, UNC/device prefixes, quotes, and control characters.
            if (rawPath.IndexOf("://", StringComparison.Ordinal) >= 0) throw new ClipGuardException("InvalidPath");
            if (rawPath.StartsWith(@"\\", StringComparison.Ordinal) || rawPath.StartsWith("//", StringComparison.Ordinal))
            {
                throw new ClipGuardException("InvalidPath");
            }
            for (int i = 0; i < rawPath.Length; i++)
            {
                char c = rawPath[i];
                if (c < 0x20 || c == '"') throw new ClipGuardException("InvalidPath");
            }

            // AEGIS-SECURITY: require an explicit drive-rooted path BEFORE calling Path.GetFullPath
            // so relative or drive-relative paths are never resolved against Environment.CurrentDirectory.
            bool rooted;
            try
            {
                rooted = Path.IsPathRooted(rawPath);
            }
            catch (Exception)
            {
                throw new ClipGuardException("InvalidPath");
            }
            if (!rooted) throw new ClipGuardException("InvalidPath");
            if (rawPath.Length < 4 || !char.IsLetter(rawPath[0]) || rawPath[1] != ':' || (rawPath[2] != '\\' && rawPath[2] != '/'))
            {
                throw new ClipGuardException("InvalidPath");
            }

            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(rawPath);
            }
            catch (Exception)
            {
                throw new ClipGuardException("InvalidPath");
            }

            if (!Path.IsPathRooted(fullPath)) throw new ClipGuardException("InvalidPath");
            if (fullPath.Length < 4 || !char.IsLetter(fullPath[0]) || fullPath[1] != ':' || fullPath[2] != '\\')
            {
                throw new ClipGuardException("InvalidPath");
            }
            return fullPath;
        }

        private static void OpenInExplorer(string fullPath)
        {
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string explorerPath = Path.Combine(winDir, "explorer.exe");
            if (!File.Exists(explorerPath)) throw new ClipGuardException("ExplorerNotFound");

            // AEGIS-SECURITY: UseShellExecute=false + explicit explorer.exe path prevents URL/verb execution.
            // AEGIS-PERMISSION: highlights the local file in File Explorer so the user can inspect it.
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = explorerPath;
            psi.Arguments = "/select,\"" + fullPath + "\"";
            psi.UseShellExecute = false;
            using (Process p = Process.Start(psi))
            {
            }
        }
    }
}
