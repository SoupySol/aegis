// ---------------------------------------------------------------------------
// Program.cs
// PURPOSE:  Entry point for the standalone, air-gapped Aegis Clip Guard
//           Windows desktop cleanup utility and CLI.
// ACCESS:   With no arguments, detaches the console window and launches the
//           local dark-themed WinForms desktop UI (MainForm). With CLI flags,
//           runs synchronous self-tests (--selftest) or an offline Ghost Copy
//           Scan (--ghost-scan [--custom-dir <path>]).
// NEVER:    No network. No browser Native Messaging IPC. No Windows Registry
//           reads or writes. Never prints unmasked secret material.
// ---------------------------------------------------------------------------
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using Aegis.ClipGuard.Crypto;
using Aegis.ClipGuard.Detection;
using Aegis.ClipGuard.Model;
using Aegis.ClipGuard.Sources;
using Aegis.ClipGuard.Ui;

namespace Aegis.ClipGuard
{
    public static class Program
    {
        public const string Version = "0.2.0";

        // AEGIS-PERMISSION: detach console window when launched as desktop GUI
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeConsole();

        // AEGIS-PERMISSION: opt into crisp per-display DPI rendering for the desktop GUI
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetProcessDPIAware();

        [STAThread]
        public static int Main(string[] args)
        {
            if (args != null && args.Length > 0)
            {
                return RunCli(args);
            }

            try
            {
                // AEGIS-PERMISSION: detach console window when launched as desktop GUI
                FreeConsole();
            }
            catch (Exception) { }

            try
            {
                SetProcessDPIAware();
            }
            catch (Exception) { }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            using (MainForm form = new MainForm())
            {
                Application.Run(form);
            }
            return 0;
        }

        public static int RunCli(string[] args)
        {
            try
            {
                Console.OutputEncoding = System.Text.Encoding.UTF8;
            }
            catch (Exception) { }

            if (args == null || args.Length == 0)
            {
                PrintUsage(Console.Out);
                return 0;
            }

            bool wantHelp = false;
            bool wantSelfTest = false;
            bool wantGhostScan = false;
            bool wantOcr = false;
            string customDir = null;

            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                if (a == "--help" || a == "-h")
                {
                    wantHelp = true;
                }
                else if (a == "--selftest")
                {
                    wantSelfTest = true;
                }
                else if (a == "--ghost-scan")
                {
                    wantGhostScan = true;
                }
                else if (a == "--ocr")
                {
                    wantOcr = true;
                }
                else if (a == "--custom-dir")
                {
                    if (i + 1 >= args.Length || string.IsNullOrEmpty(args[i + 1]))
                    {
                        Console.Error.WriteLine("Error: --custom-dir requires a directory path.");
                        PrintUsage(Console.Error);
                        return 1;
                    }
                    customDir = args[++i];
                }
                else
                {
                    Console.Error.WriteLine("Unknown flag: " + a);
                    PrintUsage(Console.Error);
                    return 1;
                }
            }

            int modes = (wantHelp ? 1 : 0) + (wantSelfTest ? 1 : 0) + (wantGhostScan ? 1 : 0);
            if (modes != 1)
            {
                Console.Error.WriteLine("Error: specify exactly one CLI command (--ghost-scan, --selftest, or --help).");
                PrintUsage(Console.Error);
                return 1;
            }

            if (!wantGhostScan && (customDir != null || wantOcr))
            {
                Console.Error.WriteLine("Error: --custom-dir and --ocr are only valid with --ghost-scan.");
                PrintUsage(Console.Error);
                return 1;
            }

            if (wantHelp)
            {
                PrintUsage(Console.Out);
                return 0;
            }

            if (wantSelfTest)
            {
                return RunSelfTest();
            }

            try
            {
                GhostScanOptions opts = new GhostScanOptions();
                opts.Ocr = wantOcr;
                if (customDir != null)
                {
                    string fullCustom = Path.GetFullPath(customDir);
                    if (!Directory.Exists(fullCustom))
                    {
                        Console.Error.WriteLine("Error: custom directory does not exist: " + Finding.BuildDisplayPath(fullCustom));
                        return 1;
                    }
                    // AEGIS-SECURITY: isolated custom-dir scan touches ONLY the specified directory.
                    opts.Isolated = true;
                    opts.SkipHistory = true;
                    opts.SweepScope = "custom";
                    opts.CustomPaths.Add(fullCustom);
                }

                GhostScanReport report = GhostScan.Run(opts, null, CancellationToken.None);
                Console.Write(GhostScan.FormatCliSummary(report, Version));
                return 0;
            }
            catch (ClipGuardException ex)
            {
                Console.Error.WriteLine("Clip Guard error: " + ex.Code);
                return 1;
            }
            catch (Exception ex)
            {
                // AEGIS-SECURITY: print exception type name only, never raw messages.
                Console.Error.WriteLine("CLI error: " + ex.GetType().Name);
                return 1;
            }
        }

        private static void PrintUsage(TextWriter writer)
        {
            writer.WriteLine("Aegis Clip Guard v" + Version + " — Standalone Local Secret & Ghost Copy Cleaner");
            writer.WriteLine("100% Offline | 0 Network Code | 0 Browser Connection | 0 Registry Edits");
            writer.WriteLine();
            writer.WriteLine("Usage:");
            writer.WriteLine("  aegis-clipguard.exe");
            writer.WriteLine("      Launches the standalone dark-themed Windows desktop cleanup app.");
            writer.WriteLine();
            writer.WriteLine("  aegis-clipguard.exe --ghost-scan [--custom-dir <path>] [--ocr]");
            writer.WriteLine("      Runs an offline Ghost Copy Scan and prints a masked summary.");
            writer.WriteLine("      When --custom-dir <path> is supplied, scans ONLY that folder in");
            writer.WriteLine("      isolated mode (never touches Win+V, real Notepad, or user folders).");
            writer.WriteLine();
            writer.WriteLine("  aegis-clipguard.exe --selftest");
            writer.WriteLine("      Runs built-in cryptographic, detector, and privacy redaction self-checks.");
            writer.WriteLine();
            writer.WriteLine("  aegis-clipguard.exe --help | -h");
            writer.WriteLine("      Displays this usage help.");
        }

        public static int RunSelfTest()
        {
            // 1. Verify embedded 2048-word BIP-39 wordlist
            if (Bip39.Words.Length != 2048)
            {
                Console.Error.WriteLine("Self-test failed: BIP-39 wordlist count != 2048");
                return 1;
            }

            // 2. Verify Base58 round-trip
            byte[] sample = new byte[] { 0, 0, 1, 2, 3, 254, 255 };
            byte[] decoded = Base58.Decode(Base58.Encode(sample));
            if (decoded == null || decoded.Length != sample.Length)
            {
                Console.Error.WriteLine("Self-test failed: Base58 round-trip length mismatch");
                return 1;
            }
            for (int i = 0; i < sample.Length; i++)
            {
                if (decoded[i] != sample[i])
                {
                    Console.Error.WriteLine("Self-test failed: Base58 round-trip byte mismatch");
                    return 1;
                }
            }

            // 3. Verify Ed25519 + Solana secret key detection + masking (including leading-zero <84-char base58)
            byte[] seed = new byte[32];
            for (int i = 16; i < 32; i++) seed[i] = (byte)(i + 1); // 16 leading zero bytes -> ~78-char Base58
            byte[] pub = Ed25519PublicKey.FromSeed(seed);
            byte[] fullKey = new byte[64];
            Array.Copy(seed, 0, fullKey, 0, 32);
            Array.Copy(pub, 0, fullKey, 32, 32);
            string b58Secret = Base58.Encode(fullKey);
            Array.Clear(seed, 0, seed.Length);
            Array.Clear(fullKey, 0, fullKey.Length);

            DetectionResult keyRes = SecretDetector.Detect("PRIVATE_KEY=" + b58Secret);
            if (keyRes.Findings.Count != 1 ||
                keyRes.Findings[0].Kind != SecretDetector.KindSecretKey ||
                keyRes.Findings[0].Format != "base58" ||
                keyRes.Findings[0].Masked.IndexOf(b58Secret, StringComparison.Ordinal) >= 0)
            {
                Console.Error.WriteLine("Self-test failed: Solana secret key detection/masking check");
                return 1;
            }

            // 4. Verify 32-byte public address is NOT flagged
            string pubAddr = Base58.Encode(pub);
            if (SecretDetector.Detect(pubAddr).Findings.Count != 0)
            {
                Console.Error.WriteLine("Self-test failed: 32-byte public address false positive");
                return 1;
            }

            // 5. Verify BIP-39 mnemonic checksum detection, masking, and non-colliding Signature
            string mnemonic1 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            string mnemonic2 = "absurd abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon asthma";
            DetectionResult seedRes1 = SecretDetector.Detect(mnemonic1);
            DetectionResult seedRes2 = SecretDetector.Detect(mnemonic2);
            if (seedRes1.Findings.Count != 1 ||
                seedRes1.Findings[0].Kind != SecretDetector.KindSeed ||
                seedRes1.Findings[0].WordCount != 12 ||
                seedRes1.Findings[0].Masked.IndexOf("abandon", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Console.Error.WriteLine("Self-test failed: BIP-39 mnemonic detection/masking check");
                return 1;
            }
            if (seedRes2.Findings.Count != 1 ||
                seedRes2.Findings[0].Kind != SecretDetector.KindSeed ||
                seedRes1.Findings[0].Signature == seedRes2.Findings[0].Signature)
            {
                Console.Error.WriteLine("Self-test failed: distinct 'a...' mnemonics collided on Signature");
                return 1;
            }

            // 6. Verify DisplayPath redaction when filename contains a secret
            Finding f = Finding.From(keyRes.Findings[0], "file", "Local file (.txt)");
            f.Path = @"C:\Temp\leak_" + b58Secret + ".txt";
            if (f.DisplayPath == null ||
                f.DisplayPath.IndexOf(b58Secret, StringComparison.Ordinal) >= 0 ||
                !f.DisplayPath.EndsWith("<redacted-secret-filename>.txt", StringComparison.Ordinal))
            {
                Console.Error.WriteLine("Self-test failed: DisplayPath secret filename redaction check");
                return 1;
            }

            Console.WriteLine("SELFTEST OK (wordlist=2048, base58=ok, ed25519=ok, detector=ok, masking=ok, redaction=ok)");
            return 0;
        }
    }
}
