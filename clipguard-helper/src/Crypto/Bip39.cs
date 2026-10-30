// ---------------------------------------------------------------------------
// Bip39.cs
// PURPOSE:  BIP-39 English wordlist + mnemonic checksum validation (SHA-256),
//           equivalent to @scure/bip39 validateMnemonic(phrase, english).
// ACCESS:   Reads the wordlist embedded in this exe as a resource
//           (shared-fixtures/bip39-english.txt). No other I/O.
// NEVER:    No network. Never derives keys or addresses from a phrase.
//           Never logs words. Scratch buffers are wiped.
// ---------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.ClipGuard.Crypto
{
    public static class Bip39
    {
        public const string ResourceName = "Aegis.ClipGuard.bip39-english.txt";
        private static readonly object Gate = new object();
        private static string[] _words;
        private static Dictionary<string, int> _index;

        public static string[] Words { get { EnsureLoaded(); return _words; } }

        private static void EnsureLoaded()
        {
            if (_index != null) return;
            lock (Gate)
            {
                if (_index != null) return;
                List<string> list = new List<string>(2048);
                Stream s = typeof(Bip39).Assembly.GetManifestResourceStream(ResourceName);
                if (s == null) throw new InvalidOperationException("BIP-39 wordlist resource missing");
                using (StreamReader r = new StreamReader(s, Encoding.UTF8))
                {
                    string line;
                    while ((line = r.ReadLine()) != null)
                    {
                        line = line.Trim();
                        if (line.Length > 0) list.Add(line);
                    }
                }
                if (list.Count != 2048) throw new InvalidOperationException("BIP-39 wordlist must have 2048 words");
                Dictionary<string, int> idx = new Dictionary<string, int>(2048, StringComparer.Ordinal);
                for (int i = 0; i < list.Count; i++) idx[list[i]] = i;
                _words = list.ToArray();
                _index = idx;
            }
        }

        public static bool IsWord(string w)
        {
            EnsureLoaded();
            return _index.ContainsKey(w);
        }

        /// <summary>
        /// True when words[start..start+count) is a valid BIP-39 English mnemonic
        /// (length 12/15/18/21/24, all words known, checksum correct).
        /// </summary>
        public static bool IsValidMnemonic(IList<string> words, int start, int count)
        {
            EnsureLoaded();
            if (count != 12 && count != 15 && count != 18 && count != 21 && count != 24) return false;
            if (start < 0 || start + count > words.Count) return false;

            int totalBits = count * 11;
            int csBits = totalBits / 33;
            int entBits = totalBits - csBits;
            byte[] bits = new byte[(totalBits + 7) / 8];
            try
            {
                int bitPos = 0;
                for (int i = 0; i < count; i++)
                {
                    int v;
                    if (!_index.TryGetValue(words[start + i], out v)) return false;
                    for (int b = 10; b >= 0; b--)
                    {
                        if (((v >> b) & 1) == 1) bits[bitPos >> 3] |= (byte)(0x80 >> (bitPos & 7));
                        bitPos++;
                    }
                }
                byte[] entropy = new byte[entBits / 8];
                Array.Copy(bits, entropy, entropy.Length);
                byte[] hash;
                using (SHA256 sha = SHA256.Create()) hash = sha.ComputeHash(entropy);
                Array.Clear(entropy, 0, entropy.Length); // AEGIS-SECURITY: wipe entropy
                bool ok = true;
                for (int i = 0; i < csBits; i++)
                {
                    int p = entBits + i;
                    int actual = (bits[p >> 3] >> (7 - (p & 7))) & 1;
                    int expected = (hash[i >> 3] >> (7 - (i & 7))) & 1;
                    if (actual != expected) { ok = false; break; }
                }
                Array.Clear(hash, 0, hash.Length);
                return ok;
            }
            finally
            {
                Array.Clear(bits, 0, bits.Length); // AEGIS-SECURITY: wipe bit buffer
            }
        }
    }
}
