// ---------------------------------------------------------------------------
// QaStressTests.cs
// PURPOSE:  Security, Privacy & Clip Guard boundary/stress QA suite:
//             Suite A: 50,000-char window seam tests (44,990, 47,990, 49,950,
//                      89,990, 95,990, 97,950) in 110,000-char .txt files +
//                      2,337-char indented JSON keypair across seams +
//                      multi-seed 'a...' non-collision + leading-zero Base58
//             Suite B: Corrupt & hostile file resilience (.docx/.xlsx random
//                      bytes, truncated PK headers, unclosed <w:t XML, 0-byte,
//                      NUL-binary, quotes/commas/unicode/secret filenames,
//                      DisplayPath redaction, and NotepadTabs.SanitizeLabel
//                      privacy probes)
//             Suite C: Directory reparse-point / NTFS single & twin junction
//                      loop guards + FileIdKey duplicate-root alias guard
//             Suite D: Standalone CLI stress, FileActions hostile path &
//                      TOCTOU reparse-point refusal, and headless MainForm UI
//             Suite E: Standalone zero-browser / zero-registry source audit
// ACCESS:   Operates strictly inside an isolated %TEMP%\aegis-qa-stress-<guid>
//           directory, inspects clipguard-helper/src/*.cs read-only, and spawns
//           bin\aegis-clipguard.exe against isolated temp paths only.
// NEVER:    No network. Never touches real user folders, real clipboard history,
//           real Notepad/StickyNotes state, or the Windows Registry.
// ---------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Aegis.ClipGuard;
using Aegis.ClipGuard.Crypto;
using Aegis.ClipGuard.Detection;
using Aegis.ClipGuard.Model;
using Aegis.ClipGuard.Sources;
using Aegis.ClipGuard.Ui;

internal static class QaStressTests
{
    private static int _passed;
    private static int _failed;
    private static readonly List<string> FailureLog = new List<string>();
    private static readonly List<string> JunctionPathsToRemoveFirst = new List<string>();

    private static int Main(string[] args)
    {
        string helperRoot = args.Length > 0
            ? Path.GetFullPath(args[0])
            : Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"..\.."));
        string exePath = args.Length > 1
            ? Path.GetFullPath(args[1])
            : Path.Combine(helperRoot, @"bin\aegis-clipguard.exe");

        string tempRoot = Path.Combine(
            Path.GetTempPath(),
            "aegis-qa-stress-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);

        Console.WriteLine("=== Aegis Clip Guard Standalone QA Boundary & Stress Suite ===");
        Console.WriteLine("Helper dir : " + helperRoot);
        Console.WriteLine("Helper exe : " + exePath);
        Console.WriteLine("Temp root  : " + tempRoot);
        Console.WriteLine();

        try
        {
            RunSuite("Suite A: 50,000-Char Window Seam, 2,337-Char JSON Seam & Multi-Seed Dedup", delegate ()
            {
                RunSuiteA_WindowSeams(Path.Combine(tempRoot, "suiteA"));
            });

            RunSuite("Suite B: Corrupt & Hostile File Resilience + DisplayPath & Label Privacy", delegate ()
            {
                RunSuiteB_CorruptAndHostileFiles(Path.Combine(tempRoot, "suiteB"));
            });

            RunSuite("Suite C: NTFS Single + Twin Junction Loop Guard & FileId Deduplication", delegate ()
            {
                RunSuiteC_JunctionLoopGuard(Path.Combine(tempRoot, "suiteC"));
            });

            RunSuite("Suite D: Standalone CLI Stress, FileActions Hardening & Headless UI", delegate ()
            {
                RunSuiteD_StandaloneCliAndHardening(exePath, Path.Combine(tempRoot, "suiteD"));
            });

            RunSuite("Suite E: Zero-Browser, Zero-Registry & Security Header Static Audit", delegate ()
            {
                RunSuiteE_StandaloneSourceAudit(helperRoot, exePath);
            });
        }
        finally
        {
            SafeCleanupTempRoot(tempRoot);
        }

        Console.WriteLine("================================================================");
        Console.WriteLine("QaStressTests Summary: " + _passed + " passed, " + _failed + " failed (" + (_passed + _failed) + " total checks)");
        if (FailureLog.Count > 0)
        {
            Console.WriteLine("--- Failed Checks ---");
            for (int i = 0; i < FailureLog.Count; i++)
            {
                Console.WriteLine("  " + (i + 1) + ". " + FailureLog[i]);
            }
        }
        Console.WriteLine("================================================================");
        return _failed == 0 && _passed > 0 ? 0 : 1;
    }

    private static void RunSuite(string title, Action body)
    {
        Console.WriteLine("--- " + title + " ---");
        try
        {
            body();
        }
        catch (Exception ex)
        {
            Check(false, title + " threw unexpected exception: " + ex.GetType().Name + ": " + ex.Message);
        }
        Console.WriteLine();
    }

    private static void Check(bool condition, string description)
    {
        if (condition)
        {
            _passed++;
            Console.WriteLine("  [PASS] " + description);
        }
        else
        {
            _failed++;
            FailureLog.Add(description);
            Console.WriteLine("  [FAIL] " + description);
        }
    }

    // -----------------------------------------------------------------------
    // Deterministic synthetic test material (never real wallets)
    // -----------------------------------------------------------------------
    private static byte[] MakeSyntheticSecretKey(byte tag, out string pubShort)
    {
        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) seed[i] = (byte)((tag * 37 + i * 19 + 11) & 0xFF);
        byte[] pub = Ed25519PublicKey.FromSeed(seed);
        pubShort = SecretDetector.ShortKey(pub);
        byte[] full = new byte[64];
        Array.Copy(seed, 0, full, 0, 32);
        Array.Copy(pub, 0, full, 32, 32);
        Array.Clear(seed, 0, seed.Length);
        return full;
    }

    private static string MakeBase58Key(byte tag, out string pubShort)
    {
        byte[] raw = MakeSyntheticSecretKey(tag, out pubShort);
        try { return Base58.Encode(raw); }
        finally { Array.Clear(raw, 0, raw.Length); }
    }

    private static string MakeIndentedJsonArrayKey(byte tag, int indentSpaces, out string pubShort)
    {
        byte[] raw = MakeSyntheticSecretKey(tag, out pubShort);
        try
        {
            string pad = new string(' ', indentSpaces);
            StringBuilder sb = new StringBuilder();
            sb.Append("[\n");
            for (int i = 0; i < raw.Length; i++)
            {
                sb.Append(pad);
                sb.Append(raw[i]);
                if (i < raw.Length - 1) sb.Append(',');
                sb.Append('\n');
            }
            sb.Append(']');
            return sb.ToString();
        }
        finally
        {
            Array.Clear(raw, 0, raw.Length);
        }
    }

    private static string MakeValidMnemonic12(byte firstByte, byte fillSeed, out string expectedMask)
    {
        byte[] entropy = new byte[16];
        entropy[0] = firstByte;
        for (int i = 1; i < 16; i++)
        {
            entropy[i] = (byte)((fillSeed * 29 + i * 43 + 5) & 0xFF);
        }

        byte[] hash;
        using (SHA256 sha = SHA256.Create())
        {
            hash = sha.ComputeHash(entropy);
        }

        string[] words = Bip39.Words;
        string[] chosen = new string[12];
        for (int w = 0; w < 12; w++)
        {
            int idx = 0;
            for (int b = 0; b < 11; b++)
            {
                int bitPos = w * 11 + b;
                int bit;
                if (bitPos < 128)
                {
                    bit = (entropy[bitPos / 8] >> (7 - (bitPos % 8))) & 1;
                }
                else
                {
                    int csPos = bitPos - 128;
                    bit = (hash[0] >> (7 - csPos)) & 1;
                }
                idx = (idx << 1) | bit;
            }
            chosen[w] = words[idx];
        }

        Array.Clear(entropy, 0, entropy.Length);
        Array.Clear(hash, 0, hash.Length);

        if (!Bip39.IsValidMnemonic(chosen, 0, 12))
        {
            throw new InvalidOperationException("Generated mnemonic failed BIP-39 validation");
        }

        expectedMask = "12 words, starts with " + chosen[0][0] + "\u2026";
        return string.Join(" ", chosen);
    }

    private static char[] Create110kLineGrid()
    {
        char[] buf = new char[110000];
        for (int line = 0; line < 1100; line++)
        {
            int start = line * 100;
            for (int c = 0; c < 99; c++) buf[start + c] = '.';
            buf[start + 99] = '\n';
        }
        return buf;
    }

    private static void EmbedTokenAt(char[] grid, int offset, string token)
    {
        if (offset > 0 && grid[offset - 1] != '\n') grid[offset - 1] = ' ';
        for (int i = 0; i < token.Length; i++)
        {
            grid[offset + i] = token[i];
        }
        int after = offset + token.Length;
        if (after < grid.Length && grid[after] != '\n') grid[after] = ' ';
    }

    // -----------------------------------------------------------------------
    // Suite A: 50,000-char Window Seam Test + 2,337-char JSON Seam + Multi-Seed
    // -----------------------------------------------------------------------
    private static void RunSuiteA_WindowSeams(string dir)
    {
        Directory.CreateDirectory(dir);

        string pub1, pub2, pub3, pubStep45;
        string key1 = MakeBase58Key(101, out pub1);
        string key2 = MakeBase58Key(102, out pub2);
        string key3 = MakeBase58Key(103, out pub3);
        string keyStep45 = MakeBase58Key(105, out pubStep45);

        string maskSeedA1, maskSeedZ, maskSeedL, maskSeedA2;
        string seedA1 = MakeValidMnemonic12(0x00, 0x11, out maskSeedA1); // starts with 'a' ("abandon...")
        string seedZ = MakeValidMnemonic12(0xFF, 0x22, out maskSeedZ);   // starts with 'z' ("zoo...")
        string seedL = MakeValidMnemonic12(0x80, 0x33, out maskSeedL);   // starts with 'l' ("legal...")
        string seedA2 = MakeValidMnemonic12(0x01, 0x44, out maskSeedA2); // starts with 'a' ("absorb..."), distinct wallet!

        Check(44990 + keyStep45.Length > 45000,
            "A1 setup: Base58 keyStep45 (" + keyStep45.Length + " chars) at 44,990 straddles Step=45,000 seam");
        Check(49950 + seedA1.Length > 50000 && 49950 + seedA1.Length <= 50050,
            "A1 setup: 12-word seedA1 (" + seedA1.Length + " chars) at 49,950 straddles Window=50,000 seam");

        // --- File 1 (110,000 chars): Base58 at 44,990 (Step=45k seam), Base58 at 47,990, 12w seed at 49,950 (Window=50k seam) ---
        char[] grid1 = Create110kLineGrid();
        EmbedTokenAt(grid1, 44990, keyStep45);
        EmbedTokenAt(grid1, 47990, key1);
        EmbedTokenAt(grid1, 49950, seedA1);
        string doc1 = new string(grid1);
        Check(doc1.Length == 110000, "A1: doc1 exact length == 110,000 chars");

        int expectedLineStep45 = TextRuns.LineAt(doc1, 44990);
        int expectedLineKey1 = TextRuns.LineAt(doc1, 47990);
        int expectedLineSeedA1 = TextRuns.LineAt(doc1, 49950);

        List<SecretFinding> det1 = SecretDetector.DetectAll(doc1);
        Check(det1.Count == 3, "A1 DetectAll: found 3/3 secrets across 45k, 48k & 50k seams (zero duplicates), got " + det1.Count);
        if (det1.Count == 3)
        {
            Check(det1[0].PublicKeyShort == pubStep45 && det1[0].Index == 44990,
                "A1 DetectAll: keyStep45 matched at exact offset 44,990");
            Check(det1[1].PublicKeyShort == pub1 && det1[1].Index == 47990,
                "A1 DetectAll: key1 matched at exact offset 47,990");
            Check(det1[2].Kind == SecretDetector.KindSeed && det1[2].WordCount == 12 && det1[2].Index == 49950,
                "A1 DetectAll: 12-word mnemonic matched at exact offset 49,950");
        }

        string file1 = Path.Combine(dir, "seam-45k-48k-50k.txt");
        File.WriteAllText(file1, doc1, new UTF8Encoding(false));

        // --- File 2 (110,000 chars): seeds & keys across 47,990, 49,950, 89,990 (2*Step=90k), 97,950 ---
        char[] grid2 = Create110kLineGrid();
        EmbedTokenAt(grid2, 47990, seedZ);
        EmbedTokenAt(grid2, 49950, key2);
        EmbedTokenAt(grid2, 89990, key3);
        EmbedTokenAt(grid2, 97950, seedL);
        string doc2 = new string(grid2);
        Check(doc2.Length == 110000, "A2: doc2 exact length == 110,000 chars");

        int expLine2SeedZ = TextRuns.LineAt(doc2, 47990);
        int expLine2Key2 = TextRuns.LineAt(doc2, 49950);
        int expLine2Key3 = TextRuns.LineAt(doc2, 89990);
        int expLine2SeedL = TextRuns.LineAt(doc2, 97950);

        List<SecretFinding> det2 = SecretDetector.DetectAll(doc2);
        Check(det2.Count == 4, "A2 DetectAll: found 4/4 seam secrets across 48k, 50k, 90k, 98k, got " + det2.Count);

        string file2 = Path.Combine(dir, "seam-seed48k-key50k-90k-98k.txt");
        File.WriteAllText(file2, doc2, new UTF8Encoding(false));

        SweepOptions sweepOpts = new SweepOptions();
        sweepOpts.Scope = "custom";
        sweepOpts.Paths.Add(file1);
        sweepOpts.Paths.Add(file2);
        sweepOpts.Ocr = false;
        SweepResult sweepRes = FileSweep.Run(sweepOpts, null, CancellationToken.None);

        Check(sweepRes.FilesScanned == 2, "A1+A2 FileSweep: scanned 2 seam files, got " + sweepRes.FilesScanned);
        Check(sweepRes.Findings.Count == 7,
            "A1+A2 FileSweep: found 7/7 seam secrets across both 110k files with zero duplicates, got " + sweepRes.Findings.Count);

        Finding fKey45 = FindByPathAndMask(sweepRes.Findings, "seam-45k-48k-50k.txt", pubStep45);
        Finding fKey1 = FindByPathAndMask(sweepRes.Findings, "seam-45k-48k-50k.txt", pub1);
        Finding fSeedA1 = FindByPathAndMask(sweepRes.Findings, "seam-45k-48k-50k.txt", maskSeedA1);
        Finding fSeedZ = FindByPathAndMask(sweepRes.Findings, "seam-seed48k-key50k-90k-98k.txt", maskSeedZ);
        Finding fKey2 = FindByPathAndMask(sweepRes.Findings, "seam-seed48k-key50k-90k-98k.txt", pub2);
        Finding fKey3 = FindByPathAndMask(sweepRes.Findings, "seam-seed48k-key50k-90k-98k.txt", pub3);
        Finding fSeedL = FindByPathAndMask(sweepRes.Findings, "seam-seed48k-key50k-90k-98k.txt", maskSeedL);

        Check(fKey45 != null && fKey45.Line == expectedLineStep45,
            "A1 FileSweep: keyStep45 at 44,990 exact 1-based line == " + expectedLineStep45);
        Check(fKey1 != null && fKey1.Line == expectedLineKey1,
            "A1 FileSweep: key1 at 47,990 exact 1-based line == " + expectedLineKey1);
        Check(fSeedA1 != null && fSeedA1.Line == expectedLineSeedA1,
            "A1 FileSweep: seedA1 at 49,950 exact 1-based line == " + expectedLineSeedA1);
        Check(fSeedZ != null && fSeedZ.Line == expLine2SeedZ,
            "A2 FileSweep: seedZ at 47,990 exact 1-based line == " + expLine2SeedZ);
        Check(fKey2 != null && fKey2.Line == expLine2Key2,
            "A2 FileSweep: key2 at 49,950 exact 1-based line == " + expLine2Key2);
        Check(fKey3 != null && fKey3.Line == expLine2Key3,
            "A2 FileSweep: key3 at 89,990 exact 1-based line == " + expLine2Key3);
        Check(fSeedL != null && fSeedL.Line == expLine2SeedL,
            "A2 FileSweep: seedL at 97,950 exact 1-based line == " + expLine2SeedL);

        // --- Subtest A3: Two distinct 12-word mnemonics starting with 'a' in same file (BUG-CG-4 fix!) ---
        char[] grid3 = Create110kLineGrid();
        EmbedTokenAt(grid3, 44990, seedA1);
        EmbedTokenAt(grid3, 49950, seedA2);
        string doc3 = new string(grid3);
        List<SecretFinding> det3 = SecretDetector.DetectAll(doc3);
        Check(det3.Count == 2,
            "A3 DetectAll: finds 2 distinct 'a...' 12-word seeds in same 110k doc, got " + det3.Count);

        string file3 = Path.Combine(dir, "two-a-seeds.txt");
        File.WriteAllText(file3, doc3, new UTF8Encoding(false));
        SweepOptions opts3 = new SweepOptions();
        opts3.Scope = "custom";
        opts3.Paths.Add(file3);
        SweepResult res3 = FileSweep.Run(opts3, null, CancellationToken.None);
        Check(res3.Findings.Count == 2,
            "A3 FileSweep BUG-CG-4 verification: two distinct 'a...' 12-word seeds in same file both reported (got " + res3.Findings.Count + ")");
        if (res3.Findings.Count == 2)
        {
            Check(res3.Findings[0].Masked == "12 words, starts with a\u2026" &&
                  res3.Findings[1].Masked == "12 words, starts with a\u2026",
                "A3 UI privacy: both 'a...' seed findings preserve masked UI display string");
        }

        // --- Subtest A4: Indented JSON keypair (~2,337 chars) straddling BOTH 44,990 (Step=45k) and 47,990..50,327 (Window=50k) ---
        string pubJsonSeamA, pubJsonSeamB;
        string indentedJsonA = MakeIndentedJsonArrayKey(104, 32, out pubJsonSeamA);
        string indentedJsonB = MakeIndentedJsonArrayKey(106, 32, out pubJsonSeamB);

        char[] grid4a = Create110kLineGrid();
        EmbedTokenAt(grid4a, 47990, indentedJsonA);
        string doc4a = new string(grid4a);
        List<SecretFinding> det4a = SecretDetector.DetectAll(doc4a);
        Check(det4a.Count == 1 && det4a[0].PublicKeyShort == pubJsonSeamA,
            "A4a BUG-CG-5 verification: " + indentedJsonA.Length +
            "-char indented JSON keypair straddling 47,990.." + (47990 + indentedJsonA.Length) +
            " caught across 5,000-char overlap (got " + det4a.Count + ")");

        char[] grid4b = Create110kLineGrid();
        EmbedTokenAt(grid4b, 44990, indentedJsonB);
        string doc4b = new string(grid4b);
        List<SecretFinding> det4b = SecretDetector.DetectAll(doc4b);
        Check(det4b.Count == 1 && det4b[0].PublicKeyShort == pubJsonSeamB,
            "A4b BUG-CG-5 verification: " + indentedJsonB.Length +
            "-char indented JSON keypair straddling Step=45,000 seam (44,990.." + (44990 + indentedJsonB.Length) +
            ") caught once with zero duplicates (got " + det4b.Count + ")");
    }

    private static Finding FindByPathAndMask(List<Finding> list, string fileSuffix, string mask)
    {
        foreach (Finding f in list)
        {
            if (f.Path != null &&
                f.Path.EndsWith(fileSuffix, StringComparison.OrdinalIgnoreCase) &&
                f.Masked == mask)
            {
                return f;
            }
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // Suite B: Corrupt & Hostile File Resilience + DisplayPath + SanitizeLabel
    // -----------------------------------------------------------------------
    private static void RunSuiteB_CorruptAndHostileFiles(string dir)
    {
        Directory.CreateDirectory(dir);

        string pubXmlPartial, pubQuotes, pubUnicode, pubSecretName, pubInNameItself, pubBinSkip;
        string keyXmlPartial = MakeBase58Key(111, out pubXmlPartial);
        string keyQuotes = MakeBase58Key(112, out pubQuotes);
        string keyUnicode = MakeBase58Key(113, out pubUnicode);
        string keySecretName = MakeBase58Key(114, out pubSecretName);
        string keyInNameItself = MakeBase58Key(115, out pubInNameItself);
        string keyBinSkip = MakeBase58Key(116, out pubBinSkip);

        // 1. Random non-ZIP bytes with .docx and .xlsx extensions
        byte[] randomBytes = new byte[512];
        Random rng = new Random(0xAE615);
        rng.NextBytes(randomBytes);
        randomBytes[0] = 0xDE; randomBytes[1] = 0xAD;
        File.WriteAllBytes(Path.Combine(dir, "random-garbage.docx"), randomBytes);
        File.WriteAllBytes(Path.Combine(dir, "random-garbage.xlsx"), randomBytes);

        // 2. Truncated PK zip headers
        File.WriteAllBytes(Path.Combine(dir, "truncated-pk6.docx"),
            new byte[] { 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00 });
        File.WriteAllBytes(Path.Combine(dir, "truncated-pk10.xlsx"),
            new byte[] { 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00 });

        // 3. Valid ZIP .docx with malformed XML: <w:t without closing '>' and broken XML entities
        CreateRawXmlDocx(
            Path.Combine(dir, "malformed-unclosed-only.docx"),
            "<w:document><w:body><w:p><w:r><w:t w:space=\"preserve\" broken_unclosed_tag");
        CreateRawXmlDocx(
            Path.Combine(dir, "malformed-after-key.docx"),
            "<w:document><w:body><w:p><w:r><w:t>Key: " + keyXmlPartial + " &amp &lt</w:t></w:r></w:p><w:p><w:r><w:t unclosed_no_gt");

        // 4. Valid ZIP .xlsx with missing sharedStrings.xml and malformed sheet1.xml
        using (FileStream fs = new FileStream(Path.Combine(dir, "malformed-sheet.xlsx"), FileMode.Create, FileAccess.Write))
        using (ZipArchive zip = new ZipArchive(fs, ZipArchiveMode.Create))
        {
            ZipArchiveEntry e = zip.CreateEntry("xl/worksheets/sheet1.xml");
            using (StreamWriter w = new StreamWriter(e.Open(), new UTF8Encoding(false)))
            {
                w.Write("<worksheet><sheetData><row><c><v unclosed_tag_without_bracket");
            }
        }

        // 5. Empty 0-byte files across text, Office, JSON, and image extensions
        File.WriteAllBytes(Path.Combine(dir, "empty.txt"), new byte[0]);
        File.WriteAllBytes(Path.Combine(dir, "empty.env"), new byte[0]);
        File.WriteAllBytes(Path.Combine(dir, "empty.json"), new byte[0]);
        File.WriteAllBytes(Path.Combine(dir, "empty.docx"), new byte[0]);
        File.WriteAllBytes(Path.Combine(dir, "empty.xlsx"), new byte[0]);
        File.WriteAllBytes(Path.Combine(dir, "empty.png"), new byte[0]);

        // 6. Corrupt image file with Ocr=true
        File.WriteAllBytes(Path.Combine(dir, "corrupt-image.png"),
            new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xFF, 0x00 });

        // 7. NUL-containing binary masquerading as .txt
        File.WriteAllBytes(Path.Combine(dir, "nul-masquerade.txt"),
            Encoding.UTF8.GetBytes("HDR\0\x01\x02 " + keyBinSkip));

        // 8. Filenames with spaces, single quotes, commas, parens, brackets, and Unicode
        string trickyQuotesName = "my 'wallet' notes, backup (1) [copy] #test.txt";
        File.WriteAllText(Path.Combine(dir, trickyQuotesName), "BACKUP=" + keyQuotes + "\n", Encoding.UTF8);

        string unicodeName = "кошелек_ウォレット_钱包_test.txt";
        File.WriteAllText(Path.Combine(dir, unicodeName), "SEED_KEY=" + keyUnicode + "\n", Encoding.UTF8);

        // 9. Filename that itself embeds a full Base58 secret key (Label + DisplayPath redaction test)
        string secretFileName = "leak_" + keyInNameItself + ".txt";
        string secretFileFullPath = Path.Combine(dir, secretFileName);
        File.WriteAllText(secretFileFullPath, keySecretName, Encoding.UTF8);

        SweepOptions opts = new SweepOptions();
        opts.Scope = "custom";
        opts.Paths.Add(dir);
        opts.Ocr = true;

        SweepResult res = null;
        Exception sweepEx = null;
        try
        {
            res = FileSweep.Run(opts, null, CancellationToken.None);
        }
        catch (Exception ex)
        {
            sweepEx = ex;
        }

        Check(sweepEx == null && res != null,
            "B1: FileSweep completed cleanly across 18 corrupt/empty/hostile files without throwing");
        if (res != null)
        {
            Check(res.FilesScanned == 12,
                "B1: 6 empty 0-byte files short-circuited cleanly and all 12 non-empty files scanned without aborting (got " + res.FilesScanned + ")");
            Check(FindByMask(res.Findings, pubXmlPartial) != null,
                "B1: Recovered valid secret inside .docx before unclosed <w:t tag");
            Check(FindByMask(res.Findings, pubQuotes) != null,
                "B1: Detected secret in filename with spaces, single quotes, commas, parens & brackets");
            Check(FindByMask(res.Findings, pubUnicode) != null,
                "B1: Detected secret in Cyrillic/Japanese/CJK Unicode filename");
            Check(FindByMask(res.Findings, pubBinSkip) == null,
                "B1: Skipped NUL-byte binary file masquerading as .txt");

            Finding redFinding = FindByMask(res.Findings, pubSecretName);
            Check(redFinding != null && redFinding.Label == "Local file (.txt)",
                "B1: Filename containing a secret key was redacted to 'Local file (.txt)' in Finding.Label");
            if (redFinding != null)
            {
                Check(redFinding.DisplayPath != null &&
                      redFinding.DisplayPath.EndsWith("<redacted-secret-filename>.txt", StringComparison.Ordinal) &&
                      redFinding.DisplayPath.IndexOf(keyInNameItself, StringComparison.Ordinal) < 0,
                    "B1 BUG-PRIV-2 verification: Finding.DisplayPath redacts secret filename to '<redacted-secret-filename>.txt'");
                Dictionary<string, object> locDict = (Dictionary<string, object>)redFinding.ToJson()["location"];
                Check((string)locDict["path"] == redFinding.DisplayPath,
                    "B1 BUG-PRIV-2 verification: Finding.ToJson() emits DisplayPath instead of raw Path");

                // Internal Path still enables local cleanup action
                FileActions.Execute(redFinding.FindingId, "delete");
                Check(!File.Exists(secretFileFullPath),
                    "B1 BUG-PRIV-2 verification: internal Finding.Path still deletes secret-named file cleanly");
            }
        }

        // B2: NotepadTabs.SanitizeLabel punctuation/numbering privacy probes (BUG-PRIV-1)
        string cleanSpaced = NotepadTabs.SanitizeLabel("1. abandon 2. ability MyWallet");
        Check(cleanSpaced.IndexOf("abandon", StringComparison.OrdinalIgnoreCase) < 0 &&
              cleanSpaced.IndexOf("ability", StringComparison.OrdinalIgnoreCase) < 0,
            "B2 SanitizeLabel: strips space-separated numbered BIP-39 words ('1. abandon 2. ability')");

        string cleanUnspaced = NotepadTabs.SanitizeLabel("1.abandon 2.ability 3.able");
        Check(cleanUnspaced.IndexOf("abandon", StringComparison.OrdinalIgnoreCase) < 0 &&
              cleanUnspaced.IndexOf("ability", StringComparison.OrdinalIgnoreCase) < 0 &&
              cleanUnspaced.IndexOf("able", StringComparison.OrdinalIgnoreCase) < 0,
            "B2 BUG-PRIV-1 verification: numbered BIP-39 words without space ('1.abandon 2.ability 3.able') stripped -> '" + cleanUnspaced + "'");

        string cleanAsterisk = NotepadTabs.SanitizeLabel("*abandon* /ability #zoo");
        Check(cleanAsterisk.IndexOf("abandon", StringComparison.OrdinalIgnoreCase) < 0 &&
              cleanAsterisk.IndexOf("ability", StringComparison.OrdinalIgnoreCase) < 0 &&
              cleanAsterisk.IndexOf("zoo", StringComparison.OrdinalIgnoreCase) < 0,
            "B2 BUG-PRIV-1 verification: markdown/slash/hash-wrapped BIP-39 words ('*abandon* /ability #zoo') stripped -> '" + cleanAsterisk + "'");
    }

    private static void CreateRawXmlDocx(string path, string rawDocumentXml)
    {
        using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (ZipArchive zip = new ZipArchive(fs, ZipArchiveMode.Create))
        {
            ZipArchiveEntry doc = zip.CreateEntry("word/document.xml");
            using (StreamWriter w = new StreamWriter(doc.Open(), new UTF8Encoding(false)))
            {
                w.Write(rawDocumentXml);
            }
        }
    }

    private static Finding FindByMask(List<Finding> list, string mask)
    {
        foreach (Finding f in list)
        {
            if (f.Masked == mask) return f;
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // Suite C: Directory Reparse Point / Junction Loop Guard (BUG-CG-2)
    // -----------------------------------------------------------------------
    private static void RunSuiteC_JunctionLoopGuard(string dir)
    {
        Directory.CreateDirectory(dir);

        // --- C1: Single self-referential NTFS junction dirA\loop -> dirA ---
        string dirA = Path.Combine(dir, "dirA");
        Directory.CreateDirectory(dirA);
        string pubLoop;
        string keyLoop = MakeBase58Key(121, out pubLoop);
        File.WriteAllText(Path.Combine(dirA, "wallet.txt"), "KEY=" + keyLoop, Encoding.UTF8);

        string loopJunction = Path.Combine(dirA, "loop");
        bool createdC1 = CreateDirectoryJunction(loopJunction, dirA);
        Check(createdC1, "C1 setup: created NTFS directory junction dirA\\loop -> dirA inside %TEMP%");

        if (createdC1)
        {
            uint reparseTag;
            bool gotTag = FileSweep.TryGetReparseTag(loopJunction, true, out reparseTag);
            Check(gotTag && reparseTag == FileSweep.IO_REPARSE_TAG_MOUNT_POINT,
                "C1 setup: TryGetReparseTag identified IO_REPARSE_TAG_MOUNT_POINT (0xA0000003)");

            SweepResult c1Res = null;
            Exception c1Ex = null;
            using (CancellationTokenSource cts = new CancellationTokenSource())
            {
                cts.CancelAfter(10000);
                try
                {
                    SweepOptions opts = new SweepOptions();
                    opts.Scope = "custom";
                    opts.Paths.Add(dirA);
                    c1Res = FileSweep.Run(opts, null, cts.Token);
                }
                catch (Exception ex)
                {
                    c1Ex = ex;
                }
            }

            Check(c1Ex == null && c1Res != null && !c1Res.Cancelled,
                "C1 crash-safety: FileSweep on single junction loop terminated without unhandled exception");
            if (c1Res != null)
            {
                Check(c1Res.FilesScanned == 1 && c1Res.Findings.Count == 1,
                    "C1 BUG-CG-2 verification: single physical file in dirA scanned once (FilesScanned=" +
                    c1Res.FilesScanned + ", Findings=" + c1Res.Findings.Count + ")");
            }

            // Defense-in-depth check: pass BOTH dirA and dirA\loop as explicit roots -> FileIdKey deduplicates!
            SweepOptions dupRootOpts = new SweepOptions();
            dupRootOpts.Scope = "custom";
            dupRootOpts.Paths.Add(dirA);
            dupRootOpts.Paths.Add(loopJunction);
            SweepResult dupRootRes = FileSweep.Run(dupRootOpts, null, CancellationToken.None);
            Check(dupRootRes.FilesScanned == 1 && dupRootRes.Findings.Count == 1,
                "C1 FileIdKey defense-in-depth: passing both dirA and dirA\\loop as roots still scans physical dir/file once (FilesScanned=" +
                dupRootRes.FilesScanned + ", Findings=" + dupRootRes.Findings.Count + ")");
        }

        // --- C2: Twin directory junctions dirB\j1 -> dirB and dirB\j2 -> dirB (2^depth blowup probe) ---
        string dirB = Path.Combine(dir, "dirB");
        Directory.CreateDirectory(dirB);
        File.WriteAllText(Path.Combine(dirB, "harmless.txt"), "nothing secret here", Encoding.UTF8);

        string j1 = Path.Combine(dirB, "j1");
        string j2 = Path.Combine(dirB, "j2");
        bool createdJ1 = CreateDirectoryJunction(j1, dirB);
        bool createdJ2 = CreateDirectoryJunction(j2, dirB);
        Check(createdJ1 && createdJ2, "C2 setup: created twin NTFS junctions dirB\\j1 -> dirB and dirB\\j2 -> dirB");

        if (createdJ1 && createdJ2)
        {
            SweepResult c2Res = null;
            Stopwatch sw = Stopwatch.StartNew();
            using (CancellationTokenSource cts = new CancellationTokenSource())
            {
                cts.CancelAfter(1500);
                SweepOptions opts = new SweepOptions();
                opts.Scope = "custom";
                opts.Paths.Add(dirB);
                c2Res = FileSweep.Run(opts, null, cts.Token);
            }
            sw.Stop();

            Check(c2Res != null && !c2Res.Cancelled && c2Res.FilesScanned == 1,
                "C2 BUG-CG-2 exponential junction DoS guard: twin junctions skipped cleanly (Cancelled=" +
                (c2Res != null && c2Res.Cancelled) + ", FilesScanned=" +
                (c2Res == null ? -1 : c2Res.FilesScanned) + ", ElapsedMs=" + sw.ElapsedMilliseconds + ")");
        }
    }

    private static bool CreateDirectoryJunction(string linkPath, string targetPath)
    {
        JunctionPathsToRemoveFirst.Add(linkPath);
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c mklink /J \"" + linkPath + "\" \"" + targetPath + "\"";
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        using (Process p = Process.Start(psi))
        {
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit(5000);
            return p.ExitCode == 0 && Directory.Exists(linkPath);
        }
    }

    // -----------------------------------------------------------------------
    // Suite D: Standalone CLI Stress, FileActions Hardening & Headless UI
    // -----------------------------------------------------------------------
    private static void RunSuiteD_StandaloneCliAndHardening(string exePath, string dir)
    {
        Check(File.Exists(exePath), "D0: Standalone binary exists at " + exePath);
        if (!File.Exists(exePath)) return;

        Directory.CreateDirectory(dir);

        // --- D1: FileActions.ValidateLocalFilePath hostile path tests (HARDENING-2) ---
        string[] hostilePaths = new string[]
        {
            "",
            "   ",
            "relative.txt",
            @"..\traversal\secret.txt",
            "C:drive-relative.txt",
            @"\root-relative.txt",
            @"\\127.0.0.1\c$\Windows\win.ini",
            "//server/share/secret.txt",
            "file:///C:/Users/test/secret.txt",
            "customscheme://example.com/secret.txt",
            "C:\\temp\\quote\"breakout.txt",
            "C:\\temp\\ctrl\u0007bell.txt",
            "C:\\temp\\newline\ninject.txt"
        };
        int rejectedCount = 0;
        for (int i = 0; i < hostilePaths.Length; i++)
        {
            try
            {
                FileActions.ValidateLocalFilePath(hostilePaths[i]);
            }
            catch (ClipGuardException)
            {
                rejectedCount++;
            }
        }
        Check(rejectedCount == hostilePaths.Length,
            "D1 HARDENING-2: FileActions.ValidateLocalFilePath rejected all " + rejectedCount +
            "/" + hostilePaths.Length + " relative/UNC/URI/quote/control-char hostile paths");

        // --- D2: FileActions TOCTOU reparse-point swap refusal ---
        string realTargetDir = Path.Combine(dir, "real-target");
        Directory.CreateDirectory(realTargetDir);
        string protectedFile = Path.Combine(realTargetDir, "keep.txt");
        File.WriteAllText(protectedFile, "do not delete", Encoding.UTF8);

        string swapPath = Path.Combine(dir, "swapped-entry");
        string pubSwap;
        string keySwap = MakeBase58Key(131, out pubSwap);
        File.WriteAllText(swapPath, keySwap, Encoding.UTF8);
        SecretFinding sfSwap = SecretDetector.Detect(keySwap).Findings[0];
        Finding swapFinding = Finding.From(sfSwap, "file", "swapped-entry");
        swapFinding.Path = swapPath;
        FindingStore.Register(swapFinding);

        // Simulate TOCTOU swap: replace file with NTFS junction before FileActions.Execute
        File.Delete(swapPath);
        bool swappedToJunction = CreateDirectoryJunction(swapPath, realTargetDir);
        Check(swappedToJunction, "D2 setup: replaced file path with NTFS reparse point");
        if (swappedToJunction)
        {
            bool refusedSwap = false;
            try
            {
                FileActions.Execute(swapFinding.FindingId, "delete");
            }
            catch (ClipGuardException ex)
            {
                refusedSwap = (ex.Code == "UnsafeReparseTarget");
            }
            Check(refusedSwap && File.Exists(protectedFile),
                "D2 HARDENING-2: FileActions threw UnsafeReparseTarget on swapped reparse point and kept target file intact");
        }

        // --- D3: Standalone CLI process stress (isolated custom-dir, selftest, invalid args) ---
        string cliIso = Path.Combine(dir, "cli-isolated");
        Directory.CreateDirectory(cliIso);
        string pubCli, pubNameCli;
        string keyCli = MakeBase58Key(132, out pubCli);
        string keyNameCli = MakeBase58Key(133, out pubNameCli);
        File.WriteAllText(Path.Combine(cliIso, "secret_" + keyNameCli + ".env"), "PRIVATE_KEY=" + keyCli + "\n", Encoding.UTF8);

        int selftestCode;
        string selftestOut, selftestErr;
        RunProcess(exePath, "--selftest", out selftestCode, out selftestOut, out selftestErr);
        Check(selftestCode == 0 && selftestOut.IndexOf("SELFTEST OK", StringComparison.Ordinal) >= 0,
            "D3.1: CLI --selftest exits 0 with SELFTEST OK");

        int scanCode;
        string scanOut, scanErr;
        RunProcess(exePath, "--ghost-scan --custom-dir \"" + cliIso + "\"", out scanCode, out scanOut, out scanErr);
        Check(scanCode == 0 && scanOut.IndexOf(pubCli, StringComparison.Ordinal) >= 0,
            "D3.2: CLI --ghost-scan --custom-dir finds synthetic .env secret and exits 0");
        Check(scanOut.IndexOf(keyCli, StringComparison.Ordinal) < 0 &&
              scanOut.IndexOf(keyNameCli, StringComparison.Ordinal) < 0 &&
              scanErr.IndexOf(keyCli, StringComparison.Ordinal) < 0 &&
              scanOut.IndexOf("<redacted-secret-filename>.env", StringComparison.Ordinal) >= 0,
            "D3.3: CLI --ghost-scan output masks secret and redacts secret .env filename");

        int missingDirCode;
        string missingDirOut, missingDirErr;
        RunProcess(exePath, "--ghost-scan --custom-dir", out missingDirCode, out missingDirOut, out missingDirErr);
        Check(missingDirCode == 1, "D3.4: CLI --ghost-scan --custom-dir (missing path) exits 1");

        int badDirCode;
        string badDirOut, badDirErr;
        RunProcess(exePath, "--ghost-scan --custom-dir \"" + Path.Combine(dir, "does-not-exist") + "\"", out badDirCode, out badDirOut, out badDirErr);
        Check(badDirCode == 1, "D3.5: CLI --ghost-scan --custom-dir (non-existent path) exits 1");

        int badFlagCode;
        string badFlagOut, badFlagErr;
        RunProcess(exePath, "--bogus-flag", out badFlagCode, out badFlagOut, out badFlagErr);
        Check(badFlagCode == 1 && badFlagErr.IndexOf("Usage:", StringComparison.Ordinal) >= 0,
            "D3.6: CLI unknown flag prints usage to stderr and exits 1");

        // --- D4: Headless MainForm STA resize & layout stress ---
        bool uiClean = ClipboardHistory.RunSta(delegate ()
        {
            using (MainForm form = new MainForm())
            {
                IntPtr h = form.Handle;
                if (h == IntPtr.Zero) return false;
                form.Size = new Size(1280, 820);
                form.PerformLayout();
                form.Size = new Size(920, 620);
                form.PerformLayout();
                using (Bitmap bmp = new Bitmap(form.Width, form.Height))
                {
                    form.DrawToBitmap(bmp, new Rectangle(0, 0, bmp.Width, bmp.Height));
                }
                return form.FindingsGrid.Columns.Count == 5 && !form.CancelScanButton.Enabled && form.ScanButton.Enabled;
            }
        });
        Check(uiClean, "D4: Headless MainForm STA instantiation, resize (1280x820 -> 920x620), paint, and Dispose succeeded cleanly");
    }

    private static void RunProcess(string exePath, string arguments, out int exitCode, out string stdOut, out string stdErr)
    {
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = exePath;
        psi.Arguments = arguments;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        psi.RedirectStandardInput = true;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.StandardOutputEncoding = Encoding.UTF8;
        psi.StandardErrorEncoding = Encoding.UTF8;
        using (Process p = Process.Start(psi))
        {
            p.StandardInput.Close();
            stdOut = p.StandardOutput.ReadToEnd();
            stdErr = p.StandardError.ReadToEnd();
            if (!p.WaitForExit(10000))
            {
                p.Kill();
                throw new TimeoutException("CLI process timed out: " + arguments);
            }
            exitCode = p.ExitCode;
        }
    }

    // -----------------------------------------------------------------------
    // Suite E: Standalone Zero-Coupling Static Audit
    // -----------------------------------------------------------------------
    private static void RunSuiteE_StandaloneSourceAudit(string helperRoot, string exePath)
    {
        string srcDir = Path.Combine(helperRoot, "src");
        Check(Directory.Exists(srcDir), "E1: clipguard-helper/src directory exists");
        Check(!Directory.Exists(Path.Combine(srcDir, "NativeMessaging")),
            "E2: src/NativeMessaging directory completely removed");
        Check(!Directory.Exists(Path.Combine(srcDir, "Install")),
            "E3: src/Install directory completely removed");
        Check(!File.Exists(Path.Combine(helperRoot, "PROTOCOL.md")),
            "E4: Obsolete PROTOCOL.md completely removed");

        string[] csFiles = Directory.GetFiles(srcDir, "*.cs", SearchOption.AllDirectories);
        Check(csFiles.Length >= 10, "E5: Found " + csFiles.Length + " C# source files under src/");

        bool anyRegistryRef = false;
        bool anyBrowserOriginRef = false;
        bool allHaveSecurityHeaders = true;

        for (int i = 0; i < csFiles.Length; i++)
        {
            string content = File.ReadAllText(csFiles[i], Encoding.UTF8);
            if (content.IndexOf("Microsoft.Win32", StringComparison.Ordinal) >= 0 ||
                content.IndexOf("Registry.CurrentUser", StringComparison.Ordinal) >= 0 ||
                content.IndexOf("Registry.LocalMachine", StringComparison.Ordinal) >= 0 ||
                content.IndexOf("RegistryKey", StringComparison.Ordinal) >= 0)
            {
                anyRegistryRef = true;
            }
            if (content.IndexOf("chrome-extension://", StringComparison.OrdinalIgnoreCase) >= 0 ||
                content.IndexOf("NativeMessagingHosts", StringComparison.Ordinal) >= 0)
            {
                anyBrowserOriginRef = true;
            }
            if (content.IndexOf("PURPOSE:", StringComparison.Ordinal) < 0 ||
                content.IndexOf("ACCESS:", StringComparison.Ordinal) < 0 ||
                content.IndexOf("NEVER:", StringComparison.Ordinal) < 0)
            {
                allHaveSecurityHeaders = false;
            }
        }

        Check(!anyRegistryRef, "E6: Zero Microsoft.Win32.Registry / RegistryKey references in src/*.cs");
        Check(!anyBrowserOriginRef, "E7: Zero browser extension / NativeMessagingHosts references in src/*.cs");
        Check(allHaveSecurityHeaders, "E8: Every src/*.cs file starts with PURPOSE / ACCESS / NEVER security header");
        Check(File.Exists(exePath) && new FileInfo(exePath).Length > 20000,
            "E9: Standalone bin/aegis-clipguard.exe built cleanly (" +
            (File.Exists(exePath) ? new FileInfo(exePath).Length : 0) + " bytes)");
    }

    // -----------------------------------------------------------------------
    // Safe %TEMP% cleanup (removes NTFS junctions BEFORE recursive delete!)
    // -----------------------------------------------------------------------
    private static void SafeCleanupTempRoot(string tempRoot)
    {
        for (int i = JunctionPathsToRemoveFirst.Count - 1; i >= 0; i--)
        {
            string jp = JunctionPathsToRemoveFirst[i];
            try
            {
                if (Directory.Exists(jp)) Directory.Delete(jp, false);
            }
            catch (Exception) { }
        }

        try
        {
            if (!Directory.Exists(tempRoot)) return;
            foreach (string f in Directory.GetFiles(tempRoot, "*", SearchOption.AllDirectories))
            {
                try { File.SetAttributes(f, FileAttributes.Normal); }
                catch (Exception) { }
            }
            Directory.Delete(tempRoot, true);
        }
        catch (Exception) { }
    }
}
