// ---------------------------------------------------------------------------
// SecretDetector.cs
// PURPOSE:  Detects Solana secret keys and BIP-39 seed phrases inside text.
//           Line-for-line port of extension/src/shared/detectors/
//           secret-detector.ts (same regexes, same order, same rules), checked
//           against shared-fixtures/detector-corpus.jsonl in tests/.
// ACCESS:   Pure functions. Receives a string, returns a verdict.
// NEVER:    No network. No storage. No logging.
//           The result NEVER contains the secret: only kind, format, word
//           count, the shortened PUBLIC key, a character offset (for line
//           numbers) and, for seeds, the first letter of the first word (the
//           protocol's "starts with a..." mask).
//           Seed phrases are NEVER converted into addresses or keys.
//
// FALSE POSITIVES (same as the extension):
//   - 32-byte values (addresses, token mints) are never flagged.
//   - 64-byte values are flagged only when the second half is the ed25519
//     public key of the first half (signatures and random data fail this).
//   - Seeds need 12/15/18/21/24 consecutive BIP-39 words with a valid
//     checksum; a bad-checksum run is "possible" only if it is ~the whole input.
// ---------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Aegis.ClipGuard.Crypto;

namespace Aegis.ClipGuard.Detection
{
    public sealed class SecretFinding
    {
        public string Kind;            // solana-secret-key | seed-phrase | possible-seed-phrase
        public string Format;          // base58 | json-array | hex | mnemonic
        public int WordCount;          // seeds only (0 otherwise)
        public string PublicKeyShort;  // secret keys only, e.g. "7xKp…9Qm4" (public, not sensitive)
        public int Index;              // char offset of the match in the scanned text
        public char FirstLetter;       // seeds only: first letter of the first word
        public string DedupKey;        // seeds only: session-only HMAC tag for deduplication (never serialized)

        /// <summary>Masked, display-safe description.</summary>
        public string Masked
        {
            get
            {
                if (Kind == SecretDetector.KindSecretKey) return PublicKeyShort;
                return WordCount + " words, starts with " + FirstLetter + "\u2026";
            }
        }

        /// <summary>Non-secret session signature used to de-duplicate findings.</summary>
        public string Signature
        {
            get
            {
                if (!string.IsNullOrEmpty(DedupKey))
                {
                    return Kind + "|" + Format + "|" + DedupKey;
                }
                return Kind + "|" + Format + "|" + Masked;
            }
        }
    }

    public sealed class DetectionResult
    {
        public List<SecretFinding> Findings = new List<SecretFinding>();
        public bool Truncated;
    }

    public static class SecretDetector
    {
        public const string KindSecretKey = "solana-secret-key";
        public const string KindSeed = "seed-phrase";
        public const string KindPossibleSeed = "possible-seed-phrase";
        public const int DefaultMaxLength = 50000;

        private static readonly int[] ValidMnemonicSizes = { 24, 21, 18, 15, 12 };
        private static readonly byte[] SessionHmacKey = CreateSessionHmacKey();

        // JavaScript's \s (ECMAScript WhiteSpace + LineTerminator), spelled out so
        // .NET matches exactly the same characters as the reference detector.
        private const string JsWs = @"[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]";
        private const string B58 = "1-9A-HJ-NP-Za-km-z";

        private static readonly Regex Base58Run = new Regex(
            "(?<![" + B58 + "])[" + B58 + "]{72,90}(?![" + B58 + "])", RegexOptions.CultureInvariant);

        private static byte[] CreateSessionHmacKey()
        {
            byte[] key = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            return key;
        }
        private static readonly Regex JsonArray64 = new Regex(
            @"\[" + JsWs + "*(?:[0-9]{1,3}" + JsWs + "*," + JsWs + "*){63}[0-9]{1,3}" + JsWs + @"*\]",
            RegexOptions.CultureInvariant);
        private static readonly Regex Hex128 = new Regex(
            "(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{128})(?![0-9a-fA-F])", RegexOptions.CultureInvariant);

        /// <summary>first 4 + "…" + last 4 of the base58 public key.</summary>
        public static string ShortKey(byte[] pubkey)
        {
            string s = Base58.Encode(pubkey);
            return s.Substring(0, 4) + "\u2026" + s.Substring(s.Length - 4);
        }

        /// <summary>Returns the public key if bytes is a genuine Solana secret key, else null.</summary>
        public static byte[] VerifySolanaSecretKey(byte[] bytes)
        {
            if (bytes == null || bytes.Length != 64) return null;
            try
            {
                byte[] pub;
                return Ed25519PublicKey.IsSolanaSecretKey(bytes, out pub) ? pub : null;
            }
            catch
            {
                return null;
            }
        }

        private static void DetectSecretKeys(string text, List<SecretFinding> output)
        {
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);

            foreach (Match m in Base58Run.Matches(text))
            {
                byte[] bytes = Base58.Decode(m.Value);
                if (bytes == null) continue;
                byte[] pub = VerifySolanaSecretKey(bytes);
                Array.Clear(bytes, 0, bytes.Length); // AEGIS-SECURITY: wipe decoded secret
                if (pub != null) Push(output, seen, pub, "base58", m.Index);
            }

            foreach (Match m in JsonArray64.Matches(text))
            {
                string inner = m.Value.Substring(1, m.Value.Length - 2);
                string[] parts = inner.Split(',');
                if (parts.Length != 64) continue;
                byte[] bytes = new byte[64];
                bool okay = true;
                for (int i = 0; i < 64; i++)
                {
                    string digits = ExtractDigits(parts[i]);
                    int n;
                    if (digits == null || !int.TryParse(digits, out n) || n < 0 || n > 255) { okay = false; break; }
                    bytes[i] = (byte)n;
                }
                byte[] pub = okay ? VerifySolanaSecretKey(bytes) : null;
                Array.Clear(bytes, 0, bytes.Length); // AEGIS-SECURITY: wipe decoded secret
                if (pub != null) Push(output, seen, pub, "json-array", m.Index);
            }

            foreach (Match m in Hex128.Matches(text))
            {
                string hexStr = m.Groups[1].Value;
                if (hexStr.Length != 128) continue;
                byte[] bytes = new byte[64];
                for (int i = 0; i < 64; i++) bytes[i] = (byte)((HexVal(hexStr[2 * i]) << 4) | HexVal(hexStr[2 * i + 1]));
                byte[] pub = VerifySolanaSecretKey(bytes);
                Array.Clear(bytes, 0, bytes.Length); // AEGIS-SECURITY: wipe decoded secret
                if (pub != null) Push(output, seen, pub, "hex", m.Index);
            }
        }

        // The regex guarantees each part is JS-whitespace + 1-3 ASCII digits + JS-whitespace.
        private static string ExtractDigits(string part)
        {
            int s = 0, e = part.Length;
            while (s < e && (part[s] < '0' || part[s] > '9')) s++;
            while (e > s && (part[e - 1] < '0' || part[e - 1] > '9')) e--;
            if (s >= e) return null;
            for (int i = s; i < e; i++) if (part[i] < '0' || part[i] > '9') return null;
            return part.Substring(s, e - s);
        }

        private static int HexVal(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return c - 'A' + 10;
        }

        private static void Push(List<SecretFinding> output, HashSet<string> seen, byte[] pub, string format, int index)
        {
            string shortKey = ShortKey(pub);
            string id = format + ":" + shortKey;
            if (!seen.Add(id)) return;
            SecretFinding f = new SecretFinding();
            f.Kind = KindSecretKey;
            f.Format = format;
            f.PublicKeyShort = shortKey;
            f.Index = index;
            output.Add(f);
        }

        /// <summary>
        /// Same as JS text.toLowerCase().match(/[a-z]+/g): the only non-ASCII
        /// characters whose lowercase contains ASCII letters are U+212A (Kelvin
        /// sign, becomes "k") and U+0130 (becomes "i" + combining dot, which ends
        /// the token). Every other character is a separator.
        /// </summary>
        private static void TokenizeWords(string text, List<string> words, List<int> starts)
        {
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            int tokenStart = -1;
            for (int i = 0; i <= text.Length; i++)
            {
                char c = i < text.Length ? text[i] : '\0';
                char lower = '\0';
                bool endsAfter = false;
                if (c >= 'a' && c <= 'z') lower = c;
                else if (c >= 'A' && c <= 'Z') lower = (char)(c + 32);
                else if (c == '\u212A') lower = 'k';
                else if (c == '\u0130') { lower = 'i'; endsAfter = true; }

                if (lower != '\0')
                {
                    if (tokenStart < 0) tokenStart = i;
                    sb.Append(lower);
                    if (!endsAfter) continue;
                }
                if (tokenStart >= 0)
                {
                    words.Add(sb.ToString());
                    starts.Add(tokenStart);
                    sb.Length = 0;
                    tokenStart = -1;
                }
            }
            sb.Length = 0;
        }

        private static void DetectSeedPhrases(string text, List<SecretFinding> output)
        {
            List<string> words = new List<string>();
            List<int> starts = new List<int>();
            TokenizeWords(text, words, starts);
            try
            {
                if (words.Count < 12) return;

                List<int[]> runs = new List<int[]>();
                int start = -1;
                for (int i = 0; i <= words.Count; i++)
                {
                    bool isWord = i < words.Count && Bip39.IsWord(words[i]);
                    if (isWord && start == -1) start = i;
                    if (!isWord && start != -1)
                    {
                        if (i - start >= 12) runs.Add(new int[] { start, i });
                        start = -1;
                    }
                }

                foreach (int[] run in runs)
                {
                    int runStart = run[0], runEnd = run[1];
                    int i = runStart;
                    bool foundInRun = false;
                    while (i + 12 <= runEnd)
                    {
                        int matched = 0;
                        foreach (int size in ValidMnemonicSizes)
                        {
                            if (i + size > runEnd) continue;
                            if (Bip39.IsValidMnemonic(words, i, size)) { matched = size; break; }
                        }
                        if (matched > 0)
                        {
                            string dedupKey = ComputeSeedDedupKey(words, i, matched);
                            output.Add(SeedFinding(KindSeed, matched, words[i][0], starts[i], dedupKey));
                            foundInRun = true;
                            i += matched;
                        }
                        else
                        {
                            i += 1;
                        }
                    }

                    int runLength = runEnd - runStart;
                    bool coversInput = runLength >= words.Count - 1;
                    if (!foundInRun && coversInput && Array.IndexOf(ValidMnemonicSizes, runLength) >= 0)
                    {
                        string dedupKey = ComputeSeedDedupKey(words, runStart, runLength);
                        output.Add(SeedFinding(KindPossibleSeed, runLength, words[runStart][0], starts[runStart], dedupKey));
                    }
                }
            }
            finally
            {
                words.Clear(); // AEGIS-SECURITY: drop references to the words promptly
            }
        }

        private static string ComputeSeedDedupKey(IList<string> words, int start, int count)
        {
            int totalBytes = 0;
            for (int i = 0; i < count; i++)
            {
                if (i > 0) totalBytes++;
                totalBytes += Encoding.UTF8.GetByteCount(words[start + i]);
            }
            byte[] utf8 = new byte[totalBytes];
            try
            {
                int pos = 0;
                for (int i = 0; i < count; i++)
                {
                    if (i > 0) utf8[pos++] = (byte)' ';
                    string w = words[start + i];
                    pos += Encoding.UTF8.GetBytes(w, 0, w.Length, utf8, pos);
                }
                using (HMACSHA256 hmac = new HMACSHA256(SessionHmacKey))
                {
                    byte[] mac = hmac.ComputeHash(utf8);
                    try
                    {
                        return BitConverter.ToString(mac).Replace("-", "").ToLowerInvariant();
                    }
                    finally
                    {
                        Array.Clear(mac, 0, mac.Length); // AEGIS-SECURITY: wipe raw HMAC digest bytes
                    }
                }
            }
            finally
            {
                Array.Clear(utf8, 0, utf8.Length); // AEGIS-SECURITY: wipe temporary UTF-8 phrase bytes immediately
            }
        }

        private static SecretFinding SeedFinding(string kind, int wordCount, char firstLetter, int index, string dedupKey)
        {
            SecretFinding f = new SecretFinding();
            f.Kind = kind;
            f.Format = "mnemonic";
            f.WordCount = wordCount;
            f.FirstLetter = firstLetter;
            f.Index = index;
            f.DedupKey = dedupKey;
            return f;
        }

        /// <summary>Scans text (first maxLength chars) for Solana secret keys and BIP-39 seed phrases.</summary>
        public static DetectionResult Detect(string input, int maxLength)
        {
            if (input == null) input = "";
            DetectionResult r = new DetectionResult();
            r.Truncated = input.Length > maxLength;
            string text = r.Truncated ? input.Substring(0, maxLength) : input;
            DetectSecretKeys(text, r.Findings);
            DetectSeedPhrases(text, r.Findings);
            return r;
        }

        public static DetectionResult Detect(string input)
        {
            return Detect(input, DefaultMaxLength);
        }

        /// <summary>
        /// Scans text of any length: overlapping 50,000-char windows, each run
        /// through Detect(). A finding that starts inside a window's overlap tail
        /// is left to the next window, which contains it completely.
        /// Index values are absolute offsets into text.
        /// </summary>
        public static List<SecretFinding> DetectAll(string text)
        {
            const int Window = DefaultMaxLength;
            const int Step = 45000; // 5,000-char overlap > 4,096 max multi-line JSON array length
            List<SecretFinding> all = new List<SecretFinding>();
            if (text == null) return all;
            HashSet<string> keySeen = new HashSet<string>(StringComparer.Ordinal);
            for (int off = 0; ; off += Step)
            {
                int len = Math.Min(Window, text.Length - off);
                bool last = off + len >= text.Length;
                string part = off == 0 && last ? text : text.Substring(off, len);
                foreach (SecretFinding f in Detect(part, Window).Findings)
                {
                    if (!last && f.Index >= Step) continue;
                    f.Index += off;
                    if (f.Kind == KindSecretKey && !keySeen.Add(f.Format + ":" + f.PublicKeyShort)) continue;
                    all.Add(f);
                }
                if (last) break;
            }
            return all;
        }
    }
}
