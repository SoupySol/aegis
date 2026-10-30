// ---------------------------------------------------------------------------
// ClipboardHistory.cs
// PURPOSE:  Finds secrets in the Windows clipboard history (Win+V) and removes
//           ONLY the affected items (or clears the history on request).
// ACCESS:   Windows.ApplicationModel.DataTransfer.Clipboard (WinRT):
//           IsHistoryEnabled, IsRoamingEnabled, GetHistoryItemsAsync (text
//           items only), DeleteItemFromHistory, ClearHistory. All calls run on
//           a dedicated STA thread, as the clipboard requires.
// NEVER:    No network. Never changes the clipboard-history setting. Never
//           reads non-text items. Never returns clipboard text: only masked
//           findings. Text is dropped right after detection.
// ---------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Aegis.ClipGuard.Detection;
using Aegis.ClipGuard.Model;
using Windows.ApplicationModel.DataTransfer;

namespace Aegis.ClipGuard.Sources
{
    public sealed class HistoryScanResult
    {
        public string Status;   // Success | ClipboardHistoryDisabled | AccessDenied
        public int ItemCount;
        public List<Finding> Findings = new List<Finding>();
    }

    public static class ClipboardHistory
    {
        public const string LocationType = "clipboard-history";
        private const int TimeoutMs = 15000;

        /// <summary>Runs f on a fresh STA thread and returns its result (rethrows its exception).</summary>
        public static T RunSta<T>(Func<T> f)
        {
            T result = default(T);
            Exception error = null;
            Thread t = new Thread(delegate ()
            {
                try { result = f(); }
                catch (Exception ex) { error = ex; }
            });
            t.IsBackground = true;
            t.SetApartmentState(ApartmentState.STA); // AEGIS-PERMISSION: clipboard APIs need STA
            t.Start();
            t.Join();
            if (error != null)
            {
                if (error is ClipGuardException) throw error;
                throw new ClipGuardException("ClipboardError: " + error.GetType().Name);
            }
            return result;
        }

        // Bridges WinRT IAsyncOperation<T> to Task<T> (see spikes/spike5-csharp-builtin).
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

        private static T Await<T>(Windows.Foundation.IAsyncOperation<T> op)
        {
            Task<T> task = AsTask(op);
            if (!task.Wait(TimeoutMs)) throw new ClipGuardException("ClipboardTimeout");
            return task.Result;
        }

        public static bool IsHistoryEnabled()
        {
            return RunSta(delegate ()
            {
                try { return Clipboard.IsHistoryEnabled(); } // AEGIS-PERMISSION: read setting only
                catch (Exception) { return false; }
            });
        }

        public static bool IsRoamingEnabled()
        {
            return RunSta(delegate ()
            {
                try { return Clipboard.IsRoamingEnabled(); } // AEGIS-PERMISSION: read setting only
                catch (Exception) { return false; }
            });
        }

        private static string StatusName(ClipboardHistoryItemsResultStatus s)
        {
            if (s == ClipboardHistoryItemsResultStatus.Success) return "Success";
            if (s == ClipboardHistoryItemsResultStatus.ClipboardHistoryDisabled) return "ClipboardHistoryDisabled";
            return "AccessDenied";
        }

        public static HistoryScanResult Scan()
        {
            bool roaming = IsRoamingEnabled();
            return RunSta(delegate ()
            {
                HistoryScanResult r = new HistoryScanResult();
                // AEGIS-PERMISSION: reads clipboard history items (text only) to look for the user's secrets.
                ClipboardHistoryItemsResult items = Await(Clipboard.GetHistoryItemsAsync());
                r.Status = StatusName(items.Status);
                if (items.Status != ClipboardHistoryItemsResultStatus.Success) return r;
                r.ItemCount = items.Items.Count;
                int n = 0;
                foreach (ClipboardHistoryItem item in items.Items)
                {
                    n++;
                    if (!item.Content.Contains(StandardDataFormats.Text)) continue;
                    string text = Await(item.Content.GetTextAsync());
                    List<SecretFinding> found = SecretDetector.DetectAll(text);
                    text = null; // AEGIS-SECURITY: drop the clipboard text immediately
                    HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
                    foreach (SecretFinding s in found)
                    {
                        if (!seen.Add(s.Signature)) continue;
                        string when = item.Timestamp.ToLocalTime().ToString("MMM d, HH:mm");
                        Finding f = Finding.From(s, LocationType, "Win+V item #" + n + " (copied " + when + ")");
                        f.AddFlag("auto-saved-by-windows");
                        if (roaming) f.AddFlag("cloud-synced");
                        f.ClipboardItemId = item.Id;
                        r.Findings.Add(FindingStore.Register(f));
                    }
                }
                return r;
            });
        }

        private static int DeleteWhere(Func<ClipboardHistoryItem, bool> match)
        {
            return RunSta(delegate ()
            {
                ClipboardHistoryItemsResult items = Await(Clipboard.GetHistoryItemsAsync());
                if (items.Status == ClipboardHistoryItemsResultStatus.ClipboardHistoryDisabled) throw new ClipGuardException("ClipboardHistoryDisabled");
                if (items.Status != ClipboardHistoryItemsResultStatus.Success) throw new ClipGuardException("AccessDenied");
                List<ClipboardHistoryItem> targets = new List<ClipboardHistoryItem>();
                foreach (ClipboardHistoryItem item in items.Items) if (match(item)) targets.Add(item);
                int deleted = 0;
                // AEGIS-PERMISSION: removes only the Win+V items the user chose.
                foreach (ClipboardHistoryItem item in targets) if (Clipboard.DeleteItemFromHistory(item)) deleted++;
                return deleted;
            });
        }

        public static int DeleteFindings(IEnumerable<string> findingIds)
        {
            HashSet<string> itemIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (string id in findingIds)
            {
                Finding f = FindingStore.Get(id);
                if (f != null && f.LocationType == LocationType && f.ClipboardItemId != null) itemIds.Add(f.ClipboardItemId);
            }
            if (itemIds.Count == 0) return 0;
            int deleted = DeleteWhere(delegate (ClipboardHistoryItem item) { return itemIds.Contains(item.Id); });
            foreach (string id in findingIds)
            {
                Finding f = FindingStore.Get(id);
                if (f != null && f.LocationType == LocationType) FindingStore.Remove(id);
            }
            return deleted;
        }

        /// <summary>
        /// Fingerprints supported cross-process: "solana-secret-key:&lt;publicKeyShort&gt;"
        /// (public, non-sensitive). Other fingerprints are ignored (see PROTOCOL note).
        /// </summary>
        public static int DeleteMatching(IEnumerable<string> fingerprints)
        {
            HashSet<string> wanted = new HashSet<string>(StringComparer.Ordinal);
            foreach (string fp in fingerprints)
            {
                if (fp != null && fp.StartsWith(SecretDetector.KindSecretKey + ":")) wanted.Add(fp.Substring(SecretDetector.KindSecretKey.Length + 1));
            }
            if (wanted.Count == 0) return 0;
            return DeleteWhere(delegate (ClipboardHistoryItem item)
            {
                if (!item.Content.Contains(StandardDataFormats.Text)) return false;
                string text = Await(item.Content.GetTextAsync());
                bool hit = false;
                foreach (SecretFinding s in SecretDetector.DetectAll(text))
                {
                    if (s.Kind == SecretDetector.KindSecretKey && wanted.Contains(s.PublicKeyShort)) { hit = true; break; }
                }
                text = null; // AEGIS-SECURITY: drop the clipboard text immediately
                return hit;
            });
        }

        public static bool Clear()
        {
            return RunSta(delegate ()
            {
                // AEGIS-PERMISSION: clears Win+V history on explicit user request.
                return Clipboard.ClearHistory();
            });
        }
    }
}
