// ---------------------------------------------------------------------------
// Base58.cs
// PURPOSE:  Base58 (Bitcoin/Solana alphabet) encode/decode, matching
//           @scure/base `base58` used by the extension (leading '1' <-> 0x00).
// ACCESS:   Pure functions. No I/O.
// NEVER:    No network. No storage. No logging of inputs.
// ---------------------------------------------------------------------------
using System;
using System.Collections.Generic;

namespace Aegis.ClipGuard.Crypto
{
    public static class Base58
    {
        public const string Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        private static readonly int[] Index = BuildIndex();

        private static int[] BuildIndex()
        {
            int[] idx = new int[128];
            for (int i = 0; i < idx.Length; i++) idx[i] = -1;
            for (int i = 0; i < Alphabet.Length; i++) idx[Alphabet[i]] = i;
            return idx;
        }

        /// <summary>Decodes base58; returns null for invalid characters.</summary>
        public static byte[] Decode(string s)
        {
            if (s == null) return null;
            if (s.Length == 0) return new byte[0];
            int zeros = 0;
            while (zeros < s.Length && s[zeros] == '1') zeros++;

            // Big-endian base256 accumulator (size bound: log(58)/log(256) ~ 0.733).
            byte[] b256 = new byte[s.Length * 733 / 1000 + 1];
            int length = 0;
            for (int i = zeros; i < s.Length; i++)
            {
                char c = s[i];
                int carry = c < 128 ? Index[c] : -1;
                if (carry < 0) { Array.Clear(b256, 0, b256.Length); return null; }
                int k = 0;
                for (int j = b256.Length - 1; (carry != 0 || k < length) && j >= 0; j--, k++)
                {
                    carry += 58 * b256[j];
                    b256[j] = (byte)(carry % 256);
                    carry /= 256;
                }
                length = k;
            }
            int start = b256.Length - length;
            while (start < b256.Length && b256[start] == 0) start++;
            byte[] result = new byte[zeros + (b256.Length - start)];
            Array.Copy(b256, start, result, zeros, b256.Length - start);
            Array.Clear(b256, 0, b256.Length); // AEGIS-SECURITY: wipe scratch buffer
            return result;
        }

        public static string Encode(byte[] data)
        {
            if (data == null || data.Length == 0) return "";
            int zeros = 0;
            while (zeros < data.Length && data[zeros] == 0) zeros++;
            byte[] b58 = new byte[data.Length * 138 / 100 + 1];
            int length = 0;
            for (int i = zeros; i < data.Length; i++)
            {
                int carry = data[i];
                int k = 0;
                for (int j = b58.Length - 1; (carry != 0 || k < length) && j >= 0; j--, k++)
                {
                    carry += 256 * b58[j];
                    b58[j] = (byte)(carry % 58);
                    carry /= 58;
                }
                length = k;
            }
            int start = b58.Length - length;
            while (start < b58.Length && b58[start] == 0) start++;
            char[] chars = new char[zeros + (b58.Length - start)];
            for (int i = 0; i < zeros; i++) chars[i] = '1';
            for (int i = start; i < b58.Length; i++) chars[zeros + i - start] = Alphabet[b58[i]];
            Array.Clear(b58, 0, b58.Length);
            return new string(chars);
        }
    }
}
