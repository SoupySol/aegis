// ---------------------------------------------------------------------------
// Ed25519PublicKey.cs
// PURPOSE:  Derives an ed25519 public key from a 32-byte seed (RFC 8032 §5.1.5).
//           Clip Guard uses this ONLY to confirm that a 64-byte value is a real
//           Solana secret key ([seed][public key]) and not a transaction
//           signature or random data. Same check as the browser extension.
// ACCESS:   Pure math (System.Numerics.BigInteger + SHA-512). No I/O.
// NEVER:    No network. No storage. Callers wipe the seed after use.
//
// WHY HAND-WRITTEN: .NET Framework 4.8 (built into Windows) has no ed25519.
// This implementation is verified against RFC 8032 test vectors and against
// @noble/curves (the library used by the extension) in tests/.
// Not constant-time; it never signs anything, it only re-derives a public key
// for local comparison.
// ---------------------------------------------------------------------------
using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Aegis.ClipGuard.Crypto
{
    public static class Ed25519PublicKey
    {
        private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
        private static readonly BigInteger D = Mod(-121665 * Inv(121666));
        private static readonly BigInteger D2 = Mod(2 * D);
        private static readonly BigInteger Bx = BigInteger.Parse("15112221349535400772501151409588531511454012693041857206046113283949847762202");
        private static readonly BigInteger By = BigInteger.Parse("46316835694926478169428394003475163141307993866256225615783033603165251855960");

        private struct Point
        {
            public BigInteger X, Y, Z, T; // extended homogeneous coordinates
        }

        private static BigInteger Mod(BigInteger v)
        {
            BigInteger r = v % P;
            return r.Sign < 0 ? r + P : r;
        }

        private static BigInteger Inv(BigInteger v)
        {
            return BigInteger.ModPow(Mod(v), P - 2, P);
        }

        // RFC 8032 §5.1.4 addition (complete for ed25519, also valid for doubling)
        private static Point Add(Point p, Point q)
        {
            BigInteger a = Mod((p.Y - p.X) * (q.Y - q.X));
            BigInteger b = Mod((p.Y + p.X) * (q.Y + q.X));
            BigInteger c = Mod(p.T * D2 * q.T);
            BigInteger d = Mod(p.Z * 2 * q.Z);
            BigInteger e = b - a, f = d - c, g = d + c, h = b + a;
            Point r;
            r.X = Mod(e * f);
            r.Y = Mod(g * h);
            r.T = Mod(e * h);
            r.Z = Mod(f * g);
            return r;
        }

        private static Point ScalarMultBase(BigInteger s)
        {
            Point result;
            result.X = BigInteger.Zero; result.Y = BigInteger.One; result.Z = BigInteger.One; result.T = BigInteger.Zero;
            Point addend;
            addend.X = Bx; addend.Y = By; addend.Z = BigInteger.One; addend.T = Mod(Bx * By);
            while (s.Sign > 0)
            {
                if (!s.IsEven) result = Add(result, addend);
                addend = Add(addend, addend);
                s >>= 1;
            }
            return result;
        }

        /// <summary>Returns the 32-byte public key for a 32-byte seed.</summary>
        public static byte[] FromSeed(byte[] seed)
        {
            if (seed == null || seed.Length != 32) throw new ArgumentException("seed must be 32 bytes");
            byte[] h;
            using (SHA512 sha = SHA512.Create()) h = sha.ComputeHash(seed);

            // Clamp (RFC 8032 §5.1.5 step 2), then read as a little-endian integer.
            byte[] scalarBytes = new byte[33]; // extra 0 byte keeps BigInteger positive
            Array.Copy(h, scalarBytes, 32);
            scalarBytes[0] &= 248;
            scalarBytes[31] &= 127;
            scalarBytes[31] |= 64;
            BigInteger s = new BigInteger(scalarBytes);
            Array.Clear(h, 0, h.Length);          // AEGIS-SECURITY: wipe derived material
            Array.Clear(scalarBytes, 0, scalarBytes.Length);

            Point pt = ScalarMultBase(s);
            BigInteger zInv = Inv(pt.Z);
            BigInteger x = Mod(pt.X * zInv);
            BigInteger y = Mod(pt.Y * zInv);

            byte[] yBytes = y.ToByteArray(); // little-endian, may be shorter or have a sign byte
            byte[] output = new byte[32];
            Array.Copy(yBytes, output, Math.Min(32, yBytes.Length));
            if (!x.IsEven) output[31] |= 0x80;
            return output;
        }

        /// <summary>
        /// True when bytes is a genuine Solana secret key: 64 bytes where the
        /// last 32 equal the public key derived from the first 32.
        /// </summary>
        public static bool IsSolanaSecretKey(byte[] bytes, out byte[] publicKey)
        {
            publicKey = null;
            if (bytes == null || bytes.Length != 64) return false;
            byte[] seed = new byte[32];
            Array.Copy(bytes, seed, 32);
            try
            {
                byte[] derived = FromSeed(seed);
                int diff = 0;
                for (int i = 0; i < 32; i++) diff |= derived[i] ^ bytes[32 + i];
                if (diff != 0) return false;
                publicKey = derived;
                return true;
            }
            finally
            {
                Array.Clear(seed, 0, seed.Length); // AEGIS-SECURITY: wipe the seed copy
            }
        }
    }
}

