// ---------------------------------------------------------------------------
// TextRuns.cs
// PURPOSE:  Pulls human-readable text out of raw bytes without a full file
//           format parser: UTF-16LE runs (Notepad TabState .bin files) and
//           UTF-8 runs (Sticky Notes plum.sqlite / -wal / -shm pages).
//           Also maps a character offset to a 1-based line number.
// ACCESS:   Pure functions over byte arrays handed in by the callers.
// NEVER:    No network. Never logs or returns extracted text outside the
//           process; callers only pass it to the detector, then drop it.
// ---------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.ClipGuard.Sources
{
    public sealed class TextRun
    {
        public int ByteOffset;
        public string Text;
    }

    public static class TextRuns
    {
        public const int DefaultMinChars = 4;

        private static bool IsTextChar16(int c)
        {
            if (c == '\t' || c == '\r' || c == '\n') return true;
            if (c >= 0x20 && c <= 0x7E) return true;
            if (c >= 0xA0 && c <= 0x52F) return true;   // Latin-1, Latin ext, IPA, Greek, Cyrillic
            if (c >= 0x2000 && c <= 0x206F) return true; // general punctuation (smart quotes, …)
            if (c == 0x20AC) return true;
            return false;
        }

        /// <summary>UTF-16LE text runs at both byte alignments, ordered by byte offset.</summary>
        public static List<TextRun> Utf16LE(byte[] data, int minChars)
        {
            List<TextRun> runs = new List<TextRun>();
            if (data == null) return runs;
            StringBuilder sb = new StringBuilder();
            for (int parity = 0; parity < 2; parity++)
            {
                int runStart = -1;
                for (int i = parity; ; i += 2)
                {
                    bool ok = false;
                    int c = 0;
                    if (i + 1 < data.Length)
                    {
                        c = data[i] | (data[i + 1] << 8);
                        ok = IsTextChar16(c);
                    }
                    if (ok)
                    {
                        if (runStart < 0) runStart = i;
                        sb.Append((char)c);
                    }
                    else
                    {
                        if (runStart >= 0 && sb.Length >= minChars)
                        {
                            TextRun r = new TextRun();
                            r.ByteOffset = runStart;
                            r.Text = sb.ToString();
                            runs.Add(r);
                        }
                        sb.Length = 0;
                        runStart = -1;
                    }
                    if (i + 1 >= data.Length) break;
                }
            }
            runs.Sort(delegate (TextRun a, TextRun b) { return a.ByteOffset.CompareTo(b.ByteOffset); });
            return runs;
        }

        /// <summary>UTF-8 text runs (printable ASCII + valid multi-byte sequences).</summary>
        public static List<TextRun> Utf8(byte[] data, int minChars)
        {
            List<TextRun> runs = new List<TextRun>();
            if (data == null) return runs;
            StringBuilder sb = new StringBuilder();
            int runStart = -1;
            int i = 0;
            while (i <= data.Length)
            {
                int consumed = 0;
                int cp = -1;
                if (i < data.Length)
                {
                    byte b = data[i];
                    if (b == 0x09 || b == 0x0A || b == 0x0D || (b >= 0x20 && b <= 0x7E)) { cp = b; consumed = 1; }
                    else if (b >= 0xC2 && b <= 0xF4)
                    {
                        int need = b >= 0xF0 ? 3 : (b >= 0xE0 ? 2 : 1);
                        if (i + need < data.Length)
                        {
                            int v = b & (need == 1 ? 0x1F : (need == 2 ? 0x0F : 0x07));
                            bool valid = true;
                            for (int k = 1; k <= need; k++)
                            {
                                byte cb = data[i + k];
                                if ((cb & 0xC0) != 0x80) { valid = false; break; }
                                v = (v << 6) | (cb & 0x3F);
                            }
                            if (valid && ((need == 2 && v < 0x800) || (need == 3 && (v < 0x10000 || v > 0x10FFFF)) || (v >= 0xD800 && v <= 0xDFFF))) valid = false;
                            if (valid) { cp = v; consumed = need + 1; }
                        }
                    }
                }
                if (cp >= 0)
                {
                    if (runStart < 0) runStart = i;
                    if (cp > 0xFFFF)
                    {
                        cp -= 0x10000;
                        sb.Append((char)(0xD800 + (cp >> 10)));
                        sb.Append((char)(0xDC00 + (cp & 0x3FF)));
                    }
                    else sb.Append((char)cp);
                    i += consumed;
                }
                else
                {
                    if (runStart >= 0 && sb.Length >= minChars)
                    {
                        TextRun r = new TextRun();
                        r.ByteOffset = runStart;
                        r.Text = sb.ToString();
                        runs.Add(r);
                    }
                    sb.Length = 0;
                    runStart = -1;
                    i++;
                }
            }
            return runs;
        }

        /// <summary>Joins runs with newlines (newline = word separator for the detector).</summary>
        public static string Join(List<TextRun> runs)
        {
            StringBuilder sb = new StringBuilder();
            foreach (TextRun r in runs)
            {
                if (sb.Length > 0) sb.Append('\n');
                sb.Append(r.Text);
            }
            return sb.ToString();
        }

        /// <summary>1-based line number of a char offset (\r\n, \n and lone \r each end a line).</summary>
        public static int LineAt(string text, int index)
        {
            int line = 1;
            int end = Math.Min(index, text.Length);
            for (int i = 0; i < end; i++)
            {
                char c = text[i];
                if (c == '\n') line++;
                else if (c == '\r' && (i + 1 >= text.Length || text[i + 1] != '\n')) line++;
            }
            return line;
        }
    }
}
