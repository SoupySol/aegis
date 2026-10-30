// ---------------------------------------------------------------------------
// ClipGuardException.cs
// PURPOSE:  Error with a stable error code (e.g. "NotepadRunning",
//           "ClipboardHistoryDisabled", "UnsafeReparseTarget") surfaced cleanly
//           to the standalone desktop UI and CLI.
// ACCESS:   None.
// NEVER:    Messages never include secret material. No network.
// ---------------------------------------------------------------------------
using System;

namespace Aegis.ClipGuard.Model
{
    public sealed class ClipGuardException : Exception
    {
        public readonly string Code;

        public ClipGuardException(string code) : base(code)
        {
            Code = code;
        }
    }
}
