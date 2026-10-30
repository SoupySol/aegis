// ---------------------------------------------------------------------------
// ClipGuardTests.cs
// PURPOSE:  End-to-end and unit test suite for standalone Aegis Clip Guard:
//             1. Detector corpus parity (227 shared fixtures + windowing +
//                leading-zero Base58 keys + multi-seed Signature dedup)
//             2. Synthetic Notepad TabState scan, label sanitization,
//                NotepadRunning refusal, tab removal, and live watcher
//             3. Synthetic Sticky Notes raw SQLite + WAL scan & deduplication
//             4. Temp directory FileSweep (.txt, .env, .docx, .xlsx, NUL skip,
//                node_modules/.git skip, cloud-only attribute skip, flags,
//                line numbers, DisplayPath redaction, offline OCR smoke) &
//                FileActions validation/reparse-guard
//             5. Standalone CLI verification (--selftest, --help, isolated
//                --ghost-scan --custom-dir, and unknown-flag rejection)
//             6. Headless MainForm STA desktop UI & privacy smoke verification
// ACCESS:   Creates and cleans up an isolated folder under %TEMP% only, reads
//           shared-fixtures/detector-corpus.jsonl, and spawns bin\aegis-clipguard.exe
//           strictly against isolated %TEMP% paths.
// NEVER:    No network. Never scans real user folders, real clipboard history,
//           real Notepad tabs, real Sticky Notes, or the Windows Registry.
//           Never prints unmasked secret material.
// ---------------------------------------------------------------------------
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Aegis.ClipGuard;
using Aegis.ClipGuard.Crypto;
using Aegis.ClipGuard.Detection;
using Aegis.ClipGuard.Model;
using Aegis.ClipGuard.Sources;
using Aegis.ClipGuard.Ui;

internal static class ClipGuardTests
{
    private static int _passed;
    private static int _failed;

    private static readonly string SampleSeed12 =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    private static readonly string SecondSeed12SameInitial =
        "absurd abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon asthma";

    private static int Main(string[] args)
    {
        string corpusPath = args.Length > 0 ? args[0] : @"..\..\shared-fixtures\detector-corpus.jsonl";
        string exePath = args.Length > 1 ? args[1] : @"..\bin\aegis-clipguard.exe";
        corpusPath = Path.GetFullPath(corpusPath);
        exePath = Path.GetFullPath(exePath);

        string tempRoot = Path.Combine(
            Path.GetTempPath(),
            "aegis-clipguard-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);

        try
        {
            RunSuite("1. Detector corpus parity, leading-zero Base58 & seed dedup", delegate ()
            {
                TestDetectorCorpus(corpusPath);
                TestDetectAllWindowBoundary();
                TestLeadingZeroBase58AndSeedSignature();
            });

            RunSuite("2. Notepad TabState synthetic scan, sanitization, removal & watch", delegate ()
            {
                TestNotepadTabs(Path.Combine(tempRoot, "notepad"));
            });

            RunSuite("3. Sticky Notes synthetic SQLite + WAL scan & deduplication", delegate ()
            {
                TestStickyNotes(Path.Combine(tempRoot, "stickynotes"));
            });

            RunSuite("4. FileSweep, DisplayPath redaction & FileActions on isolated temp tree", delegate ()
            {
                TestFileSweepAndActions(Path.Combine(tempRoot, "sweep"));
            });

            RunSuite("5. Standalone CLI (--selftest, --ghost-scan --custom-dir, --help, unknown flag)", delegate ()
            {
                TestCliCommands(exePath, Path.Combine(tempRoot, "cli"));
            });

            RunSuite("6. Headless MainForm STA desktop UI instantiation & privacy check", delegate ()
            {
                TestHeadlessMainFormSta(Path.Combine(tempRoot, "ui"));
            });
        }
        finally
        {
            SafeCleanupTempDir(tempRoot);
        }

        Console.WriteLine("----------------------------------------------------------------");
        Console.WriteLine("ClipGuardTests summary: " + _passed + " assertions passed, " + _failed + " failed");
        return _failed == 0 && _passed > 0 ? 0 : 1;
    }

    private static void RunSuite(string name, Action body)
    {
        try
        {
            body();
            Console.WriteLine("[PASS] " + name);
        }
        catch (Exception ex)
        {
            _failed++;
            Console.WriteLine("[FAIL] " + name + " -> " + ex.GetType().Name + ": " + ex.Message);
        }
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            _failed++;
            throw new InvalidOperationException("Assertion failed: " + message);
        }
        _passed++;
    }

    private static JavaScriptSerializer CreateJsonSerializer()
    {
        JavaScriptSerializer js = new JavaScriptSerializer();
        js.MaxJsonLength = 16 * 1024 * 1024;
        return js;
    }

    // Generates a deterministic throwaway 64-byte Solana secret key from tag (never a real wallet).
    private static byte[] MakeSyntheticSecretKey(byte tag, out string pubShort)
    {
        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) seed[i] = (byte)((tag * 31 + i * 17 + 7) & 0xFF);
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

    private static string MakeJsonArrayKey(byte tag, out string pubShort)
    {
        byte[] raw = MakeSyntheticSecretKey(tag, out pubShort);
        try
        {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < raw.Length; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append(raw[i]);
            }
            sb.Append(']');
            return sb.ToString();
        }
        finally
        {
            Array.Clear(raw, 0, raw.Length);
        }
    }

    // -----------------------------------------------------------------------
    // 1. Detector corpus parity + leading-zero Base58 + multi-seed Signature
    // -----------------------------------------------------------------------
    private static void TestDetectorCorpus(string corpusPath)
    {
        Assert(File.Exists(corpusPath), "detector-corpus.jsonl exists");
        JavaScriptSerializer js = CreateJsonSerializer();
        string[] lines = File.ReadAllLines(corpusPath, Encoding.UTF8);

        int count = 0;
        for (int lineIdx = 0; lineIdx < lines.Length; lineIdx++)
        {
            string line = lines[lineIdx].Trim();
            if (line.Length == 0) continue;
            count++;

            Dictionary<string, object> row = (Dictionary<string, object>)js.DeserializeObject(line);
            string label = (string)row["label"];
            string text = (string)row["text"];
            IList expectedList = ToList(row["expected"]);

            DetectionResult res = SecretDetector.Detect(text);
            Assert(
                res.Findings.Count == expectedList.Count,
                "Corpus line " + (lineIdx + 1) + " (" + label + ") expected " +
                expectedList.Count + " findings, got " + res.Findings.Count);

            for (int i = 0; i < expectedList.Count; i++)
            {
                Dictionary<string, object> exp = (Dictionary<string, object>)expectedList[i];
                SecretFinding act = res.Findings[i];

                Assert(act.Kind == (string)exp["kind"],
                    "Corpus line " + (lineIdx + 1) + " kind mismatch");
                Assert(act.Format == (string)exp["format"],
                    "Corpus line " + (lineIdx + 1) + " format mismatch");

                if (exp.ContainsKey("publicKeyShort"))
                {
                    string expShort = (string)exp["publicKeyShort"];
                    Assert(act.PublicKeyShort == expShort,
                        "Corpus line " + (lineIdx + 1) + " publicKeyShort mismatch: got " + act.PublicKeyShort);
                    Assert(act.Masked == expShort,
                        "Corpus line " + (lineIdx + 1) + " masked key mismatch");
                }
                if (exp.ContainsKey("wordCount"))
                {
                    int expWords = Convert.ToInt32(exp["wordCount"]);
                    Assert(act.WordCount == expWords,
                        "Corpus line " + (lineIdx + 1) + " wordCount mismatch");
                    Assert(act.Masked.StartsWith(expWords + " words, starts with ", StringComparison.Ordinal),
                        "Corpus line " + (lineIdx + 1) + " seed mask format");
                }
            }
        }
        Assert(count == 227, "Expected 227 corpus cases, saw " + count);
        Console.WriteLine("  detector corpus: " + count + "/" + count + " cases matched");
    }

    private static void TestDetectAllWindowBoundary()
    {
        string pubShort;
        string b58 = MakeBase58Key(11, out pubShort);
        string prefix = new string('x', 49960) + "\n";
        string doc = prefix + b58 + "\n" + new string('y', 5000);

        List<SecretFinding> found = SecretDetector.DetectAll(doc);
        Assert(found.Count == 1, "DetectAll across 50k window boundary finds key once");
        Assert(found[0].PublicKeyShort == pubShort, "DetectAll boundary pubShort matches");
        Assert(TextRuns.LineAt(doc, found[0].Index) == 2, "DetectAll boundary line number == 2");
    }

    private static void TestLeadingZeroBase58AndSeedSignature()
    {
        // 64-byte Solana secret key with 18 leading zero bytes -> Base58 length < 84 chars
        byte[] seed = new byte[32];
        for (int i = 18; i < 32; i++) seed[i] = (byte)(i * 7 + 3);
        byte[] pub = Ed25519PublicKey.FromSeed(seed);
        string expectedShort = SecretDetector.ShortKey(pub);
        byte[] full = new byte[64];
        Array.Copy(seed, 0, full, 0, 32);
        Array.Copy(pub, 0, full, 32, 32);
        string shortB58 = Base58.Encode(full);
        Array.Clear(seed, 0, seed.Length);
        Array.Clear(full, 0, full.Length);

        Assert(shortB58.Length >= 72 && shortB58.Length < 84,
            "Leading-zero 64-byte Solana key encoded to <84 Base58 chars (len=" + shortB58.Length + ")");
        DetectionResult lzRes = SecretDetector.Detect("SOL_SECRET=" + shortB58);
        Assert(lzRes.Findings.Count == 1 && lzRes.Findings[0].PublicKeyShort == expectedShort,
            "Detector catches leading-zero <84-char Base58 Solana secret key");

        // Random 78-char Base58 string is NOT a valid Ed25519 keypair -> 0 false positives
        string fake78 = new string('2', 78);
        Assert(SecretDetector.Detect(fake78).Findings.Count == 0,
            "Random 78-char Base58 run does not trigger false positive");

        // Two distinct 'a...' mnemonics keep identical Masked UI strings but non-colliding Signatures
        DetectionResult m1 = SecretDetector.Detect(SampleSeed12);
        DetectionResult m2 = SecretDetector.Detect(SecondSeed12SameInitial);
        Assert(m1.Findings.Count == 1 && m2.Findings.Count == 1, "Both 'a...' mnemonics detected");
        Assert(m1.Findings[0].Masked == "12 words, starts with a\u2026" &&
               m2.Findings[0].Masked == "12 words, starts with a\u2026",
            "Both 'a...' mnemonics preserve UI Masked format");
        Assert(m1.Findings[0].Signature != m2.Findings[0].Signature,
            "Distinct 'a...' mnemonics produce distinct non-colliding Signatures");
    }

    // -----------------------------------------------------------------------
    // 2. Notepad TabState tests
    // -----------------------------------------------------------------------
    private static void TestNotepadTabs(string dir)
    {
        Directory.CreateDirectory(dir);

        string pub1;
        string key1 = MakeBase58Key(21, out pub1);
        string pub2;
        string key2 = MakeBase58Key(22, out pub2);

        // Verify SanitizeLabel never leaks BIP-39 words (even when numbered or punctuation-wrapped)
        string sanitizedSeedLine = NotepadTabs.SanitizeLabel("abandon ability MyScratchPad " + key1);
        Assert(sanitizedSeedLine.IndexOf("abandon", StringComparison.OrdinalIgnoreCase) < 0,
            "SanitizeLabel strips BIP-39 word 'abandon'");
        Assert(sanitizedSeedLine.IndexOf("ability", StringComparison.OrdinalIgnoreCase) < 0,
            "SanitizeLabel strips BIP-39 word 'ability'");
        Assert(sanitizedSeedLine.IndexOf(key1.Substring(0, 10), StringComparison.Ordinal) < 0,
            "SanitizeLabel strips long base58 token");
        Assert(sanitizedSeedLine.IndexOf("MyScratchPad", StringComparison.Ordinal) >= 0,
            "SanitizeLabel keeps non-secret label word");

        string numberedNoSpace = NotepadTabs.SanitizeLabel("1.abandon 2.ability");
        Assert(numberedNoSpace.IndexOf("abandon", StringComparison.OrdinalIgnoreCase) < 0 &&
               numberedNoSpace.IndexOf("ability", StringComparison.OrdinalIgnoreCase) < 0,
            "SanitizeLabel strips '1.abandon 2.ability'");

        string wrappedPunct = NotepadTabs.SanitizeLabel("*abandon* /ability");
        Assert(wrappedPunct.IndexOf("abandon", StringComparison.OrdinalIgnoreCase) < 0 &&
               wrappedPunct.IndexOf("ability", StringComparison.OrdinalIgnoreCase) < 0,
            "SanitizeLabel strips '*abandon* /ability'");

        // Write synthetic tab1.bin (odd 5-byte NP\0 header) + tab1.0.bin + tab1.2.bin (UTF-8 fallback) + innocent.bin
        string tab1Bin = Path.Combine(dir, "11111111-2222-3333-4444-555555555555.bin");
        string tab1Sib = Path.Combine(dir, "11111111-2222-3333-4444-555555555555.0.bin");
        string tab1Sib2 = Path.Combine(dir, "11111111-2222-3333-4444-555555555555.2.bin");
        string innocentBin = Path.Combine(dir, "99999999-8888-7777-6666-555555555555.bin");

        string pub3;
        string key3Utf8 = MakeBase58Key(23, out pub3);
        File.WriteAllBytes(tab1Bin, BuildOddAlignedNotepadBin("Scratchpad header\r\n" + key1));
        File.WriteAllBytes(tab1Sib, BuildSyntheticNotepadBin(SampleSeed12));
        File.WriteAllBytes(tab1Sib2, Encoding.UTF8.GetBytes("NP\0" + key3Utf8));
        File.WriteAllBytes(innocentBin, BuildSyntheticNotepadBin("Shopping list: apples, coffee, bread"));

        bool simulatedRunning = true;
        using (NotepadTabs tabs = new NotepadTabs(dir, delegate () { return simulatedRunning; }))
        {
            Assert(tabs.Supported, "NotepadTabs Supported == true on synthetic folder");
            List<Finding> found = tabs.Scan();
            Assert(found.Count == 3, "Expected 3 findings across odd-aligned .bin + .0.bin + UTF-8 .2.bin, got " + found.Count);

            foreach (Finding f in found)
            {
                Assert(f.LocationType == "notepad-tab", "Notepad LocationType");
                Assert(f.Flags.Contains("auto-saved-by-windows"), "Notepad auto-saved flag");
                // AEGIS-SECURITY: neither Masked nor Label may contain secret material.
                Assert(f.Masked.IndexOf(key1, StringComparison.Ordinal) < 0, "Masked hides key1");
                Assert(f.Masked.IndexOf(key3Utf8, StringComparison.Ordinal) < 0, "Masked hides key3Utf8");
                Assert(f.Masked.IndexOf("abandon", StringComparison.OrdinalIgnoreCase) < 0, "Masked hides seed");
                Assert(f.Label.IndexOf(key1, StringComparison.Ordinal) < 0, "Label hides key1");
                Assert(f.Label.IndexOf(key3Utf8, StringComparison.Ordinal) < 0, "Label hides key3Utf8");
                Assert(f.Label.IndexOf("abandon", StringComparison.OrdinalIgnoreCase) < 0, "Label hides seed");
            }

            // Refuse removal while Notepad is simulated running
            bool threwRunning = false;
            try
            {
                tabs.RemoveFindings(new string[] { found[0].FindingId });
            }
            catch (ClipGuardException ex)
            {
                threwRunning = (ex.Code == "NotepadRunning");
            }
            Assert(threwRunning, "RemoveFindings throws NotepadRunning when Notepad is open");
            Assert(File.Exists(tab1Bin) && File.Exists(tab1Sib) && File.Exists(tab1Sib2), "Tab files untouched when NotepadRunning");

            // Allow removal when Notepad is simulated closed
            simulatedRunning = false;
            int removed = tabs.RemoveFindings(new string[] { found[0].FindingId });
            Assert(removed == 1, "RemoveFindings removed == 1 when closed");
            Assert(!File.Exists(tab1Bin) && !File.Exists(tab1Sib) && !File.Exists(tab1Sib2), "All .bin, .0.bin, and .2.bin siblings deleted");
            Assert(File.Exists(innocentBin), "Unrelated innocent .bin file untouched");

            // Test live FileSystemWatcher secret-saved callback
            ManualResetEvent watchHit = new ManualResetEvent(false);
            List<Finding> liveFindings = null;
            bool watching = tabs.SetWatch(true, delegate (List<Finding> lf)
            {
                liveFindings = lf;
                watchHit.Set();
            });
            Assert(watching && tabs.Watching, "Notepad watcher started");

            string liveBin = Path.Combine(dir, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.bin");
            File.WriteAllBytes(liveBin, BuildSyntheticNotepadBin("LiveTab\r\n" + key2));

            bool signaled = watchHit.WaitOne(5000);
            watchHit.Dispose();
            Assert(signaled, "FileSystemWatcher fired callback within 5s");
            Assert(liveFindings != null && liveFindings.Count == 1, "Live callback reported 1 finding");
            Assert(liveFindings[0].Masked == pub2, "Live callback masked pubkey matches");

            Assert(!tabs.SetWatch(false, null) && !tabs.Watching, "Notepad watcher stopped cleanly");
        }
    }

    private static byte[] BuildSyntheticNotepadBin(string text)
    {
        byte[] header = new byte[] { 0x4E, 0x50, 0x00, 0x01, 0x03, 0x00, 0xFF, 0x00 };
        byte[] utf16 = Encoding.Unicode.GetBytes(text);
        byte[] trailer = new byte[] { 0x00, 0x00, 0x01, 0x05 };
        byte[] all = new byte[header.Length + utf16.Length + trailer.Length];
        Buffer.BlockCopy(header, 0, all, 0, header.Length);
        Buffer.BlockCopy(utf16, 0, all, header.Length, utf16.Length);
        Buffer.BlockCopy(trailer, 0, all, header.Length + utf16.Length, trailer.Length);
        return all;
    }

    private static byte[] BuildOddAlignedNotepadBin(string text)
    {
        // Real Windows 11 unsaved TabState header: "NP\0" + 0x00 (unsaved) + 1-byte ULEB128 length = 5-byte odd offset
        byte[] header = new byte[] { 0x4E, 0x50, 0x00, 0x00, (byte)(text.Length & 0x7F) };
        byte[] utf16 = Encoding.Unicode.GetBytes(text);
        byte[] crc32 = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        byte[] all = new byte[header.Length + utf16.Length + crc32.Length];
        Buffer.BlockCopy(header, 0, all, 0, header.Length);
        Buffer.BlockCopy(utf16, 0, all, header.Length, utf16.Length);
        Buffer.BlockCopy(crc32, 0, all, header.Length + utf16.Length, crc32.Length);
        return all;
    }

    // -----------------------------------------------------------------------
    // 3. Sticky Notes synthetic tests
    // -----------------------------------------------------------------------
    private static void TestStickyNotes(string dir)
    {
        Directory.CreateDirectory(dir);
        StickyNotes snEmpty = new StickyNotes(dir);
        Assert(!snEmpty.Supported, "StickyNotes Supported == false without plum.sqlite");

        string pubA;
        string keyA = MakeBase58Key(31, out pubA);
        string pubB;
        string keyB = MakeBase58Key(32, out pubB);

        // Put keyA + seed1 in plum.sqlite, and keyA (duplicate!) + SampleSeed12 (duplicate!) + SecondSeed12SameInitial (distinct 'a...'!) + keyB in plum.sqlite-wal
        File.WriteAllBytes(
            Path.Combine(dir, "plum.sqlite"),
            BuildSyntheticSqliteBytes("SQLite format 3\0", "Note 1: " + keyA + "\nNote 2: " + SampleSeed12));
        File.WriteAllBytes(
            Path.Combine(dir, "plum.sqlite-wal"),
            BuildSyntheticSqliteBytes("\x37\x7f\x06\x82",
                "WAL dup key: " + keyA + "\nWAL dup seed: " + SampleSeed12 + "\nWAL second 'a' seed: " + SecondSeed12SameInitial + "\nWAL new key: " + keyB));

        StickyNotes sn = new StickyNotes(dir);
        Assert(sn.Supported, "StickyNotes Supported == true with plum.sqlite");
        List<Finding> findings = sn.Scan();

        // Expect 4 findings: keyA (1), SampleSeed12 (1), SecondSeed12SameInitial (1), keyB (1)
        Assert(findings.Count == 4, "Expected 4 Sticky Notes findings (duplicates collapsed, distinct 'a...' seeds preserved), got " + findings.Count);
        int seedCount = 0;
        HashSet<string> masks = new HashSet<string>(StringComparer.Ordinal);
        foreach (Finding f in findings)
        {
            Assert(f.LocationType == "sticky-notes", "Sticky Notes LocationType");
            Assert(f.Flags.Contains("auto-saved-by-windows"), "Sticky Notes auto-saved flag");
            if (f.Kind == SecretDetector.KindSeed) seedCount++;
            masks.Add(f.Masked);
        }
        Assert(seedCount == 2, "Both distinct 'a...' seeds in Sticky Notes reported without collision");
        Assert(masks.Contains(pubA) && masks.Contains(pubB), "Both Sticky Notes keys detected & masked");
    }

    private static byte[] BuildSyntheticSqliteBytes(string magic, string payload)
    {
        byte[] m = Encoding.ASCII.GetBytes(magic);
        byte[] pad = new byte[] { 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0xFF, 0x80 };
        byte[] body = Encoding.UTF8.GetBytes(payload);
        byte[] all = new byte[m.Length + pad.Length + body.Length + 4];
        Buffer.BlockCopy(m, 0, all, 0, m.Length);
        Buffer.BlockCopy(pad, 0, all, m.Length, pad.Length);
        Buffer.BlockCopy(body, 0, all, m.Length + pad.Length, body.Length);
        return all;
    }

    // -----------------------------------------------------------------------
    // 4. FileSweep, DisplayPath redaction & FileActions tests
    // -----------------------------------------------------------------------
    private static void TestFileSweepAndActions(string root)
    {
        Directory.CreateDirectory(root);

        string pubTxt, pubEnv, pubDocx, pubXlsx, pubCloudSync, pubRecycle, pubBinSkip, pubNodeSkip, pubCloudSkip, pubNameSecret, pubInsideSecretNamed;
        string keyTxt = MakeBase58Key(41, out pubTxt);
        string keyEnv = MakeBase58Key(42, out pubEnv);
        string keyDocx = MakeBase58Key(43, out pubDocx);
        string keyXlsx = MakeJsonArrayKey(44, out pubXlsx);
        string keyCloudSync = MakeBase58Key(45, out pubCloudSync);
        string keyRecycle = MakeBase58Key(46, out pubRecycle);
        string keyBinSkip = MakeBase58Key(47, out pubBinSkip);
        string keyNodeSkip = MakeBase58Key(48, out pubNodeSkip);
        string keyCloudSkip = MakeBase58Key(49, out pubCloudSkip);
        string keyNameSecret = MakeBase58Key(50, out pubNameSecret);
        string keyInsideSecretNamed = MakeBase58Key(51, out pubInsideSecretNamed);

        // 1. Plain .txt with secret on line 4
        string txtPath = Path.Combine(root, "notes.txt");
        File.WriteAllText(txtPath, "line 1\nline 2\r\nline 3\nKEY=" + keyTxt + "\nline 5", Encoding.UTF8);

        // 2. .env file with secret on line 2
        string envPath = Path.Combine(root, ".env");
        File.WriteAllText(envPath, "# local test config\nSOLANA_KEY=" + keyEnv + "\n", Encoding.UTF8);

        // 3. .docx zip XML containing keyDocx + 12-word seed
        string docxPath = Path.Combine(root, "recovery.docx");
        CreateSyntheticDocx(docxPath, "Wallet notes", keyDocx, SampleSeed12);

        // 4. .xlsx zip XML containing JSON-array secret key
        string xlsxPath = Path.Combine(root, "export.xlsx");
        CreateSyntheticXlsx(xlsxPath, keyXlsx);

        // 5. Binary file (.txt extension but NUL byte in first 4 KB) -> must be skipped
        string binPath = Path.Combine(root, "compiled.txt");
        byte[] binBytes = Encoding.UTF8.GetBytes("HEADER\0BINARY_DATA " + keyBinSkip);
        File.WriteAllBytes(binPath, binBytes);

        // 6. Skipped directories: node_modules and .git -> must be skipped
        string nmDir = Path.Combine(Path.Combine(root, "node_modules"), "pkg");
        Directory.CreateDirectory(nmDir);
        File.WriteAllText(Path.Combine(nmDir, "index.js"), "const k = '" + keyNodeSkip + "';", Encoding.UTF8);

        string gitDir = Path.Combine(root, ".git");
        Directory.CreateDirectory(gitDir);
        File.WriteAllText(Path.Combine(gitDir, "config.txt"), keyNodeSkip, Encoding.UTF8);

        // 7. Cloud-synced folder path -> must receive "cloud-synced" flag
        string oneDriveDir = Path.Combine(root, "OneDrive");
        Directory.CreateDirectory(oneDriveDir);
        File.WriteAllText(Path.Combine(oneDriveDir, "backup.md"), keyCloudSync, Encoding.UTF8);

        // 8. $Recycle.Bin path -> must receive LocationType="recycle-bin" and "recycle-bin" flag
        string recycleDir = Path.Combine(Path.Combine(root, "$Recycle.Bin"), "S-1-5-21-000");
        Directory.CreateDirectory(recycleDir);
        File.WriteAllText(Path.Combine(recycleDir, "$R12345.txt"), keyRecycle, Encoding.UTF8);

        // 9. Secret-in-filename redaction test (DisplayPath vs internal Path)
        string secretNamedPath = Path.Combine(root, "backup_" + keyNameSecret + ".txt");
        File.WriteAllText(secretNamedPath, "CONTENT=" + keyInsideSecretNamed, Encoding.UTF8);

        // 10. Cloud-only placeholder files:
        string offlineFile = Path.Combine(root, "cloud-offline.txt");
        File.WriteAllText(offlineFile, keyCloudSkip, Encoding.UTF8);
        File.SetAttributes(offlineFile, (FileAttributes)FileSweep.AttrOffline);

        string recallFile = Path.Combine(root, "cloud-recall.txt");
        File.WriteAllText(recallFile, keyCloudSkip, Encoding.UTF8);

        Assert(FileSweep.IsCloudOnlyAttributes((FileAttributes)0x1000), "Attr 0x1000 is cloud-only");
        Assert(FileSweep.IsCloudOnlyAttributes((FileAttributes)0x40000), "Attr 0x40000 is cloud-only");
        Assert(FileSweep.IsCloudOnlyAttributes((FileAttributes)0x400000), "Attr 0x400000 is cloud-only");

        SweepResult sweep;
        using (FileStream exclusiveLock = new FileStream(
            recallFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            SweepOptions opts = new SweepOptions();
            opts.Scope = "custom";
            opts.Paths.Add(root);
            opts.Ocr = false;
            opts.AttributeReader = delegate (FileInfo fi)
            {
                if (string.Equals(fi.FullName, recallFile, StringComparison.OrdinalIgnoreCase))
                {
                    return (FileAttributes)FileSweep.AttrRecallOnDataAccess;
                }
                return fi.Attributes;
            };

            sweep = FileSweep.Run(opts, null, CancellationToken.None);
        }

        File.SetAttributes(offlineFile, FileAttributes.Normal);

        Assert(sweep.SkippedCloudOnly == 2,
            "Expected SkippedCloudOnly == 2 (0x1000 + 0x400000), got " + sweep.SkippedCloudOnly);

        Finding txtFinding = FindByMask(sweep.Findings, pubTxt);
        Assert(txtFinding != null, "Found key in notes.txt");
        Assert(txtFinding.Line == 4, "notes.txt finding Line == 4, got " + txtFinding.Line);
        Assert(txtFinding.LocationType == "file", "notes.txt LocationType == file");
        Assert(txtFinding.DisplayPath == txtPath, "Normal filename preserves DisplayPath");

        Finding envFinding = FindByMask(sweep.Findings, pubEnv);
        Assert(envFinding != null && envFinding.Line == 2, ".env finding found on line 2");

        Finding docxKeyFinding = FindByMask(sweep.Findings, pubDocx);
        Assert(docxKeyFinding != null, ".docx key finding found");
        bool docxSeedFound = false;
        foreach (Finding f in sweep.Findings)
        {
            if (f.Path != null &&
                f.Path.EndsWith("recovery.docx", StringComparison.OrdinalIgnoreCase) &&
                f.Kind == SecretDetector.KindSeed)
            {
                docxSeedFound = true;
            }
        }
        Assert(docxSeedFound, ".docx seed finding found");

        Finding xlsxFinding = FindByMask(sweep.Findings, pubXlsx);
        Assert(xlsxFinding != null && xlsxFinding.Format == "json-array", ".xlsx json-array key finding found");

        Finding cloudSyncFinding = FindByMask(sweep.Findings, pubCloudSync);
        Assert(cloudSyncFinding != null && cloudSyncFinding.Flags.Contains("cloud-synced"),
            "OneDrive finding flagged cloud-synced");

        Finding recycleFinding = FindByMask(sweep.Findings, pubRecycle);
        Assert(recycleFinding != null &&
               recycleFinding.LocationType == "recycle-bin" &&
               recycleFinding.Flags.Contains("recycle-bin"),
            "$Recycle.Bin finding has LocationType=recycle-bin and flag");

        Finding redactedFileFinding = FindByMask(sweep.Findings, pubInsideSecretNamed);
        Assert(redactedFileFinding != null, "Found secret inside secret-named file");
        Assert(redactedFileFinding.DisplayPath.EndsWith("<redacted-secret-filename>.txt", StringComparison.Ordinal),
            "DisplayPath redacts secret filename segment");
        Assert(redactedFileFinding.DisplayPath.IndexOf(keyNameSecret, StringComparison.Ordinal) < 0,
            "DisplayPath never leaks raw secret filename");
        Dictionary<string, object> jsonLoc = (Dictionary<string, object>)redactedFileFinding.ToJson()["location"];
        Assert((string)jsonLoc["path"] == redactedFileFinding.DisplayPath,
            "Finding.ToJson() serializes redacted DisplayPath rather than raw Path");

        Assert(FindByMask(sweep.Findings, pubBinSkip) == null, "Binary NUL file was skipped");
        Assert(FindByMask(sweep.Findings, pubNodeSkip) == null, "node_modules and .git were skipped");
        Assert(FindByMask(sweep.Findings, pubCloudSkip) == null, "Cloud-only placeholder files were skipped");

        // Verify OCR on synthetic screenshot PNG + graceful handling on corrupt JPG when Ocr=true
        string ocrDir = Path.Combine(root, "ocr-check");
        Directory.CreateDirectory(ocrDir);
        string seedPngPath = Path.Combine(ocrDir, "seed-screenshot.png");
        CreateSeedScreenshotPng(seedPngPath, SampleSeed12);
        File.WriteAllBytes(Path.Combine(ocrDir, "broken.jpg"), new byte[] { 1, 2, 3, 4, 5 });
        SweepOptions ocrOpts = new SweepOptions();
        ocrOpts.Scope = "custom";
        ocrOpts.Paths.Add(ocrDir);
        ocrOpts.Ocr = true;
        SweepResult ocrRes = FileSweep.Run(ocrOpts, null, CancellationToken.None);
        Assert(ocrRes.FilesScanned == 2, "OCR mode scanned .png and .jpg without throwing");
        if (FileSweep.IsOcrAvailable())
        {
            Assert(ocrRes.Findings.Count == 1 && ocrRes.Findings[0].Kind == SecretDetector.KindSeed,
                "Offline OCR detected 12-word seed phrase inside synthetic PNG screenshot");
        }

        // Verify FileActions path validation (including IsPathRooted BEFORE GetFullPath) & delete action
        bool rejectedUri = false;
        try { FileActions.ValidateLocalFilePath("customscheme://evil/test"); }
        catch (ClipGuardException) { rejectedUri = true; }
        Assert(rejectedUri, "FileActions rejects URI schemes");

        bool rejectedUnc = false;
        try { FileActions.ValidateLocalFilePath(@"\\server\share\file.txt"); }
        catch (ClipGuardException) { rejectedUnc = true; }
        Assert(rejectedUnc, "FileActions rejects UNC paths");

        bool rejectedRelative = false;
        try { FileActions.ValidateLocalFilePath(@"relative\notes.txt"); }
        catch (ClipGuardException) { rejectedRelative = true; }
        Assert(rejectedRelative, "FileActions rejects relative paths before GetFullPath");

        bool rejectedDriveRelative = false;
        try { FileActions.ValidateLocalFilePath("C:notes.txt"); }
        catch (ClipGuardException) { rejectedDriveRelative = true; }
        Assert(rejectedDriveRelative, "FileActions rejects drive-relative paths");

        Assert(File.Exists(txtPath), "notes.txt exists before FileActions delete");
        FileActions.Execute(txtFinding.FindingId, "delete");
        Assert(!File.Exists(txtPath), "FileActions delete removed temp notes.txt");
        Assert(FindingStore.Get(txtFinding.FindingId) == null, "Finding removed from FindingStore after delete");

        // Deleting redactedFileFinding still works via internal Path!
        Assert(File.Exists(secretNamedPath), "secretNamedPath exists before delete");
        FileActions.Execute(redactedFileFinding.FindingId, "delete");
        Assert(!File.Exists(secretNamedPath), "FileActions deleted secret-named file via internal Path");
    }

    private static Finding FindByMask(List<Finding> list, string mask)
    {
        foreach (Finding f in list)
        {
            if (f.Masked == mask) return f;
        }
        return null;
    }

    private static void CreateSyntheticDocx(string path, string heading, string key, string seed)
    {
        using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (ZipArchive zip = new ZipArchive(fs, ZipArchiveMode.Create))
        {
            ZipArchiveEntry doc = zip.CreateEntry("word/document.xml");
            using (StreamWriter w = new StreamWriter(doc.Open(), new UTF8Encoding(false)))
            {
                w.Write("<w:document><w:body>");
                w.Write("<w:p><w:r><w:t>" + heading + "</w:t></w:r></w:p>");
                w.Write("<w:p><w:r><w:t>" + key + "</w:t></w:r></w:p>");
                w.Write("<w:p><w:r><w:t>" + seed + "</w:t></w:r></w:p>");
                w.Write("</w:body></w:document>");
            }
        }
    }

    private static void CreateSeedScreenshotPng(string path, string text)
    {
        using (Bitmap bmp = new Bitmap(1600, 180))
        using (Graphics g = Graphics.FromImage(bmp))
        using (Font font = new Font("Arial", 22f, FontStyle.Regular))
        {
            g.Clear(Color.White);
            g.DrawString(text, font, Brushes.Black, new RectangleF(24f, 40f, 1550f, 120f));
            bmp.Save(path, ImageFormat.Png);
        }
    }

    private static void CreateSyntheticXlsx(string path, string jsonKey)
    {
        using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (ZipArchive zip = new ZipArchive(fs, ZipArchiveMode.Create))
        {
            ZipArchiveEntry sst = zip.CreateEntry("xl/sharedStrings.xml");
            using (StreamWriter w = new StreamWriter(sst.Open(), new UTF8Encoding(false)))
            {
                w.Write("<sst><si><t>Account export</t></si><si><t>" + jsonKey + "</t></si></sst>");
            }
        }
    }

    // -----------------------------------------------------------------------
    // 5. Standalone CLI verification (--selftest, --ghost-scan --custom-dir, --help, unknown flag)
    // -----------------------------------------------------------------------
    private static void TestCliCommands(string exePath, string cliTempDir)
    {
        Assert(File.Exists(exePath), "Compiled aegis-clipguard.exe exists at " + exePath);
        Directory.CreateDirectory(cliTempDir);

        // 5a. --selftest
        int stExit;
        string stOut, stErr;
        RunProcessCapture(exePath, "--selftest", out stExit, out stOut, out stErr);
        Assert(stExit == 0, "--selftest exit code == 0");
        Assert(stOut.IndexOf("SELFTEST OK", StringComparison.Ordinal) >= 0,
            "--selftest output contains 'SELFTEST OK'");

        // 5b. --help and -h
        int hExit;
        string hOut, hErr;
        RunProcessCapture(exePath, "--help", out hExit, out hOut, out hErr);
        Assert(hExit == 0 && hOut.IndexOf("--ghost-scan", StringComparison.Ordinal) >= 0,
            "--help prints CLI usage and exits 0");

        // 5c. Isolated --ghost-scan --custom-dir <tempDir> (touches ONLY tempDir!)
        string scanRoot = Path.Combine(cliTempDir, "isolated-scan");
        string npSub = Path.Combine(scanRoot, "TabState");
        string snSub = Path.Combine(scanRoot, "StickyNotes");
        string filesSub = Path.Combine(scanRoot, "Documents");
        Directory.CreateDirectory(npSub);
        Directory.CreateDirectory(snSub);
        Directory.CreateDirectory(filesSub);

        string pubNp, pubSn, pubFile, pubFileNameLeak;
        string keyNp = MakeBase58Key(61, out pubNp);
        string keySn = MakeBase58Key(62, out pubSn);
        string keyFile = MakeBase58Key(63, out pubFile);
        string keyFileNameLeak = MakeBase58Key(64, out pubFileNameLeak);

        File.WriteAllBytes(Path.Combine(npSub, "tabA.bin"), BuildSyntheticNotepadBin("Scratch\r\n" + keyNp));
        File.WriteAllBytes(Path.Combine(snSub, "plum.sqlite"), BuildSyntheticSqliteBytes("SQLite format 3\0", keySn));
        File.WriteAllText(Path.Combine(filesSub, "leak_" + keyFileNameLeak + ".txt"), "WALLET=" + keyFile, Encoding.UTF8);

        int gsExit;
        string gsOut, gsErr;
        RunProcessCapture(exePath, "--ghost-scan --custom-dir \"" + scanRoot + "\"", out gsExit, out gsOut, out gsErr);
        Assert(gsExit == 0, "--ghost-scan --custom-dir exit code == 0 (stderr=" + gsErr + ")");
        Assert(gsOut.IndexOf("Win+V Clipboard History : Skipped", StringComparison.Ordinal) >= 0,
            "Isolated --ghost-scan skips real Win+V Clipboard History");
        Assert(gsOut.IndexOf("Total Findings: 3", StringComparison.Ordinal) >= 0,
            "Isolated --ghost-scan reported all 3 synthetic findings across Notepad + StickyNotes + Files");
        Assert(gsOut.IndexOf(pubNp, StringComparison.Ordinal) >= 0 &&
               gsOut.IndexOf(pubSn, StringComparison.Ordinal) >= 0 &&
               gsOut.IndexOf(pubFile, StringComparison.Ordinal) >= 0,
            "Isolated --ghost-scan includes masked previews");
        Assert(gsOut.IndexOf("<redacted-secret-filename>.txt", StringComparison.Ordinal) >= 0,
            "Isolated --ghost-scan displays redacted DisplayPath");
        Assert(gsOut.IndexOf(keyNp, StringComparison.Ordinal) < 0 &&
               gsOut.IndexOf(keySn, StringComparison.Ordinal) < 0 &&
               gsOut.IndexOf(keyFile, StringComparison.Ordinal) < 0 &&
               gsOut.IndexOf(keyFileNameLeak, StringComparison.Ordinal) < 0,
            "Isolated --ghost-scan never prints raw secret keys or unredacted secret filenames");

        // 5d. Unknown flags and removed browser/registry flags must exit 1
        foreach (string badArg in new string[]
        {
            "--unknown-flag",
            "--register",
            "chrome-extension://ihpojnfbapdmblojonlfopnpchokokbd/"
        })
        {
            int badExit;
            string badOut, badErr;
            RunProcessCapture(exePath, badArg, out badExit, out badOut, out badErr);
            Assert(badExit == 1, "Invalid/removed flag '" + badArg + "' exited with code 1 (got " + badExit + ")");
            Assert(badErr.Length > 0, "Invalid/removed flag wrote usage message to stderr");
        }
    }

    // -----------------------------------------------------------------------
    // 6. Headless MainForm STA instantiation & UI privacy smoke check
    // -----------------------------------------------------------------------
    private static void TestHeadlessMainFormSta(string uiTempDir)
    {
        Directory.CreateDirectory(uiTempDir);
        string pubKey, pubNameLeak;
        string rawKey = MakeBase58Key(71, out pubKey);
        string rawNameLeak = MakeBase58Key(72, out pubNameLeak);

        ClipboardHistory.RunSta(delegate ()
        {
            using (MainForm form = new MainForm())
            {
                IntPtr handle = form.Handle;
                Assert(handle != IntPtr.Zero, "MainForm created Win32 window handle cleanly on STA thread");
                form.PerformLayout();

                Assert(form.ClientSize.Width == 980 && form.ClientSize.Height == 680,
                    "MainForm default ClientSize == 980x680");
                Assert(form.FindingsGrid.Columns.Count == 5,
                    "MainForm FindingsGrid has 5 columns");
                Assert(form.ScopeDropdown.Items.Count == 4,
                    "MainForm ScopeDropdown has 4 scope modes");
                Assert(form.FooterNoteLabel.Text.IndexOf("move funds from any exposed wallet", StringComparison.OrdinalIgnoreCase) >= 0,
                    "MainForm displays honest SSD/cloud security footer note");

                // Populate synthetic findings (never touching real user state) and verify redaction in UI grid
                SecretFinding sf = SecretDetector.Detect(rawKey).Findings[0];
                Finding fileFinding = Finding.From(sf, "file", "Local file (.txt)");
                fileFinding.Path = Path.Combine(uiTempDir, "key_" + rawNameLeak + ".txt");
                fileFinding.Line = 7;
                fileFinding.AddFlag("cloud-synced");
                FindingStore.Register(fileFinding);

                Finding npFinding = Finding.From(sf, "notepad-tab", "Notepad tab (untitled)");
                npFinding.AddFlag("auto-saved-by-windows");
                FindingStore.Register(npFinding);

                form.PopulateFindingsForView(new Finding[] { npFinding, fileFinding }, true);
                Assert(form.FindingsGrid.Items.Count == 2, "MainForm populated 2 synthetic rows");

                // Ghost item checked by default -> CleanGhostButton enabled
                Assert(form.CleanGhostButton.Enabled, "CleanGhostButton enabled when Notepad item is checked");

                // Verify UI cells never contain raw secrets or unredacted secret filenames
                for (int r = 0; r < form.FindingsGrid.Items.Count; r++)
                {
                    ListViewItem item = form.FindingsGrid.Items[r];
                    for (int c = 0; c < item.SubItems.Count; c++)
                    {
                        string cellText = item.SubItems[c].Text;
                        Assert(cellText.IndexOf(rawKey, StringComparison.Ordinal) < 0,
                            "ListView cell never contains raw secret key");
                        Assert(cellText.IndexOf(rawNameLeak, StringComparison.Ordinal) < 0,
                            "ListView cell never contains unredacted secret filename");
                    }
                }
                Assert(form.FindingsGrid.Items[1].SubItems[3].Text.IndexOf("<redacted-secret-filename>.txt : line 7", StringComparison.Ordinal) >= 0,
                    "ListView location cell displays redacted DisplayPath + line number");

                // Render offscreen bitmap to exercise custom dark owner-draw & panel paint handlers without displaying window
                using (Bitmap surface = new Bitmap(form.Width, form.Height))
                {
                    form.DrawToBitmap(surface, new Rectangle(0, 0, surface.Width, surface.Height));
                }
            }
            return true;
        });
    }

    private static void RunProcessCapture(
        string fileName,
        string arguments,
        out int exitCode,
        out string stdOut,
        out string stdErr)
    {
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = fileName;
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
                throw new TimeoutException("Process timed out: " + arguments);
            }
            exitCode = p.ExitCode;
        }
    }

    private static IList ToList(object val)
    {
        IList list = val as IList;
        if (list != null) return list;
        List<object> copy = new List<object>();
        IEnumerable seq = val as IEnumerable;
        if (seq != null)
        {
            foreach (object item in seq) copy.Add(item);
        }
        return copy;
    }

    private static void SafeCleanupTempDir(string dir)
    {
        try
        {
            if (!Directory.Exists(dir)) return;
            foreach (string f in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
            {
                try { File.SetAttributes(f, FileAttributes.Normal); }
                catch (Exception) { }
            }
            Directory.Delete(dir, true);
        }
        catch (Exception) { }
    }
}
