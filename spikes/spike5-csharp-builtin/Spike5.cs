// ---------------------------------------------------------------------------
// AEGIS PHASE 0 - SPIKE 5: Clip Guard in C#, built with the compiler that
// ships inside Windows (csc.exe, .NET Framework 4.8). No downloads needed.
//
// PURPOSE:  Prove the built-in compiler can produce an exe that reaches the
//           Windows APIs Clip Guard needs:
//             1. Clipboard history (Win+V)   Windows.ApplicationModel.DataTransfer
//             2. Offline OCR                 Windows.Media.Ocr
// ACCESS:   Clipboard history METADATA (status, item count, formats) and OCR
//           engine availability.
// NEVER:    Does not read, print, store or send clipboard CONTENT. No network.
//
// NOTE:     The built-in compiler supports C# 5, so this code avoids newer
//           syntax (no $"" strings, no ?. operator).
// ---------------------------------------------------------------------------
using System;
using System.Threading.Tasks;
using Windows.ApplicationModel.DataTransfer;
using Windows.Media.Ocr;

internal static class Spike5
{
    [STAThread] // the Windows clipboard APIs require a single-threaded apartment
    private static int Main()
    {
        try
        {
            Run().GetAwaiter().GetResult();
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine("ERROR: " + ex.GetType().Name + ": " + ex.Message);
            return 1;
        }
    }

    // The built-in compiler can't use the SDK's WinRT await helpers (they expect
    // the unified Windows.winmd, which only ships with the Windows SDK), so we
    // bridge WinRT async operations to Tasks ourselves. WinRT guarantees the
    // Completed handler fires even if the operation already finished.
    private static Task<T> AsTask<T>(Windows.Foundation.IAsyncOperation<T> op)
    {
        var tcs = new TaskCompletionSource<T>();
        op.Completed = (o, status) =>
        {
            if (status == Windows.Foundation.AsyncStatus.Completed) tcs.TrySetResult(o.GetResults());
            else if (status == Windows.Foundation.AsyncStatus.Error) tcs.TrySetException(o.ErrorCode);
            else tcs.TrySetCanceled();
        };
        return tcs.Task;
    }

    private static async Task Run()
    {
        // 1. Clipboard history
        Console.WriteLine("IsHistoryEnabled: " + Clipboard.IsHistoryEnabled());
        Console.WriteLine("IsRoamingEnabled: " + Clipboard.IsRoamingEnabled());
        ClipboardHistoryItemsResult result = await AsTask(Clipboard.GetHistoryItemsAsync());
        Console.WriteLine("GetHistoryItemsAsync status: " + result.Status);
        if (result.Status == ClipboardHistoryItemsResultStatus.Success)
        {
            Console.WriteLine("History item count: " + result.Items.Count);
            // AEGIS-SECURITY: formats only, never content.
            int i = 0;
            foreach (ClipboardHistoryItem item in result.Items)
            {
                Console.WriteLine("  item " + i + ": hasText=" + item.Content.Contains(StandardDataFormats.Text));
                i++;
            }
        }

        // 2. Offline OCR engine (used later to scan screenshots locally)
        OcrEngine engine = OcrEngine.TryCreateFromUserProfileLanguages();
        Console.WriteLine("Offline OCR engine available: " + (engine != null));
        if (engine != null) Console.WriteLine("OCR language: " + engine.RecognizerLanguage.LanguageTag);
    }
}
