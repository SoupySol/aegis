// ---------------------------------------------------------------------------
// MainForm.cs
// PURPOSE:  Standalone dark-themed Windows desktop utility for Aegis Clip Guard.
//           Lets the user scan and clean local "ghost copies" of Solana secret
//           keys and BIP-39 seed phrases across Windows 11 Notepad unsaved tabs
//           (TabState\*.bin), Win+V Clipboard History, Sticky Notes, and local
//           folders — completely offline with zero browser or network coupling.
// ACCESS:   Invokes GhostScan, ClipboardHistory, NotepadTabs, and FileActions
//           strictly in response to explicit user clicks or opt-in checkboxes.
// NEVER:    No network. No Registry edits. Never displays, copies, or saves
//           unmasked secrets or unredacted secret filenames (uses Masked and
//           DisplayPath exclusively).
// ---------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Threading;
using System.Windows.Forms;
using Aegis.ClipGuard.Detection;
using Aegis.ClipGuard.Model;
using Aegis.ClipGuard.Sources;

namespace Aegis.ClipGuard.Ui
{
    public sealed class MainForm : Form
    {
        // Dark-slate palette (#0B0F17 canvas, #131A27 cards, emerald/amber/crimson accents)
        private static readonly Color BgCanvas = Color.FromArgb(0x0B, 0x0F, 0x17);
        private static readonly Color BgHeader = Color.FromArgb(0x0E, 0x14, 0x20);
        private static readonly Color BgCard = Color.FromArgb(0x13, 0x1A, 0x27);
        private static readonly Color BgTable = Color.FromArgb(0x0F, 0x15, 0x21);
        private static readonly Color BgTableAlt = Color.FromArgb(0x13, 0x1B, 0x29);
        private static readonly Color BgRowSelected = Color.FromArgb(0x1D, 0x2B, 0x42);
        private static readonly Color BgTableHeader = Color.FromArgb(0x18, 0x22, 0x34);
        private static readonly Color BorderSubtle = Color.FromArgb(0x24, 0x30, 0x47);

        private static readonly Color TextPrimary = Color.FromArgb(0xF1, 0xF5, 0xF9);
        private static readonly Color TextSecondary = Color.FromArgb(0x94, 0xA3, 0xB8);
        private static readonly Color TextBody = Color.FromArgb(0xCB, 0xD5, 0xE1);

        private static readonly Color AccentEmerald = Color.FromArgb(0x10, 0xB9, 0x81);
        private static readonly Color AccentEmeraldBtn = Color.FromArgb(0x05, 0x96, 0x69);
        private static readonly Color AccentEmeraldDark = Color.FromArgb(0x0D, 0x2E, 0x24);
        private static readonly Color AccentEmeraldText = Color.FromArgb(0x34, 0xD3, 0x99);

        private static readonly Color AccentAmber = Color.FromArgb(0xF5, 0x9E, 0x0B);
        private static readonly Color AccentAmberDark = Color.FromArgb(0x2D, 0x21, 0x0C);
        private static readonly Color AccentAmberText = Color.FromArgb(0xFB, 0xBF, 0x24);

        private static readonly Color AccentCrimson = Color.FromArgb(0xEF, 0x44, 0x44);
        private static readonly Color AccentCrimsonDark = Color.FromArgb(0x36, 0x14, 0x1B);
        private static readonly Color AccentCrimsonText = Color.FromArgb(0xF8, 0x71, 0x71);

        private static readonly Color BtnNeutralBg = Color.FromArgb(0x1A, 0x24, 0x36);
        private static readonly Color BtnDisabledBg = Color.FromArgb(0x14, 0x1B, 0x27);
        private static readonly Color BtnDisabledText = Color.FromArgb(0x47, 0x55, 0x69);

        // Managed GDI resources disposed in Dispose(bool)
        private readonly Font _fontRegular;
        private readonly Font _fontBold;
        private readonly Font _fontSmall;
        private readonly Font _fontSmallBold;
        private readonly Font _fontTitle;
        private readonly Font _fontMono;
        private readonly Icon _appIcon;

        // UI controls
        private Panel _alertBannerWrap;
        private Label _alertBannerLabel;
        private Button _scanBtn;
        private Button _cancelBtn;
        private ComboBox _scopeCombo;
        private CheckBox _ocrCheck;
        private CheckBox _liveWatchCheck;
        private Label _statusLabel;
        private DarkListView _findingsList;

        private Button _cleanGhostBtn;
        private Button _clearHistoryBtn;
        private Button _openFolderBtn;
        private Button _recycleFileBtn;
        private Button _deleteFileBtn;
        private Label _footerNoteLabel;

        // Session state
        private NotepadTabs _notepadTabs;
        private CancellationTokenSource _scanCts;
        private bool _isScanning;
        private string _customFolderPath;
        private bool _suppressScopePrompt;

        public MainForm()
        {
            _fontRegular = new Font("Segoe UI", 9f, FontStyle.Regular);
            _fontBold = new Font("Segoe UI", 9f, FontStyle.Bold);
            _fontSmall = new Font("Segoe UI", 8.25f, FontStyle.Regular);
            _fontSmallBold = new Font("Segoe UI", 8.25f, FontStyle.Bold);
            _fontTitle = new Font("Segoe UI", 12f, FontStyle.Bold);
            _fontMono = new Font("Consolas", 9f, FontStyle.Regular);
            _appIcon = BuildShieldIcon();

            _notepadTabs = new NotepadTabs(NotepadTabs.DefaultFolder, null);

            SuspendLayout();
            AutoScaleMode = AutoScaleMode.Dpi;
            Text = "Aegis Clip Guard";
            ClientSize = new Size(980, 680);
            MinimumSize = new Size(920, 620);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = BgCanvas;
            ForeColor = TextPrimary;
            Font = _fontRegular;
            if (_appIcon != null) Icon = _appIcon;

            BuildLayout();
            UpdateActionButtons();
            ResumeLayout(true);
        }

        // Public accessors for headless STA verification tests (read-only control inspection)
        public ListView FindingsGrid { get { return _findingsList; } }
        public Button ScanButton { get { return _scanBtn; } }
        public Button CancelScanButton { get { return _cancelBtn; } }
        public ComboBox ScopeDropdown { get { return _scopeCombo; } }
        public CheckBox OcrCheckBox { get { return _ocrCheck; } }
        public CheckBox LiveWatchCheckBox { get { return _liveWatchCheck; } }
        public Button CleanGhostButton { get { return _cleanGhostBtn; } }
        public Button ClearHistoryButton { get { return _clearHistoryBtn; } }
        public Button OpenLocationButton { get { return _openFolderBtn; } }
        public Button RecycleFileButton { get { return _recycleFileBtn; } }
        public Button DeleteFileButton { get { return _deleteFileBtn; } }
        public Label FooterNoteLabel { get { return _footerNoteLabel; } }

        private void BuildLayout()
        {
            // Note on WinForms Dock z-order: controls docked to the same edge stack from
            // back to front, and Dock.Fill occupies the remaining center space when added first.
            Panel tableOuterWrap = BuildFindingsTableSection();
            Panel bottomBar = BuildBottomCleanupSection();
            Panel toolbarWrap = BuildToolbarSection();
            _alertBannerWrap = BuildLiveAlertSection();
            Panel heroWrap = BuildHeroCalloutSection();
            Panel headerBar = BuildHeaderSection();

            Controls.Add(tableOuterWrap);
            Controls.Add(bottomBar);
            Controls.Add(toolbarWrap);
            Controls.Add(_alertBannerWrap);
            Controls.Add(heroWrap);
            Controls.Add(headerBar);
        }

        private Panel BuildHeaderSection()
        {
            BorderPanel header = new BorderPanel(BgHeader, BorderSubtle, false, true, false, false);
            header.Dock = DockStyle.Top;
            header.Height = 54;
            header.Padding = new Padding(18, 0, 18, 0);

            ShieldCrestControl crest = new ShieldCrestControl();
            crest.Size = new Size(28, 28);
            crest.Location = new Point(18, 13);

            Label title = new Label();
            title.Text = "AEGIS CLIP GUARD";
            title.Font = _fontTitle;
            title.ForeColor = TextPrimary;
            title.AutoSize = true;
            title.Location = new Point(54, 15);

            BorderPanel pill = new BorderPanel(AccentEmeraldDark, AccentEmerald, true, true, true, true);
            pill.Size = new Size(168, 26);
            pill.Location = new Point(header.Width - 186, 14);
            pill.Anchor = AnchorStyles.Top | AnchorStyles.Right;

            Label pillText = new Label();
            pillText.Dock = DockStyle.Fill;
            pillText.TextAlign = ContentAlignment.MiddleCenter;
            pillText.Font = _fontSmallBold;
            pillText.ForeColor = AccentEmeraldText;
            pillText.Text = "Offline Local Scanner";
            pill.Controls.Add(pillText);

            header.Controls.Add(pill);
            header.Controls.Add(title);
            header.Controls.Add(crest);
            return header;
        }

        private Panel BuildHeroCalloutSection()
        {
            Panel wrap = new Panel();
            wrap.Dock = DockStyle.Top;
            wrap.Height = 82;
            wrap.Padding = new Padding(16, 10, 16, 6);
            wrap.BackColor = BgCanvas;

            AccentCardPanel card = new AccentCardPanel(BgCard, BorderSubtle, AccentAmber);
            card.Dock = DockStyle.Fill;
            card.Padding = new Padding(16, 8, 14, 8);

            Label heading = new Label();
            heading.Text = "Windows 11 Notepad & Clipboard Cache";
            heading.Font = _fontBold;
            heading.ForeColor = AccentAmberText;
            heading.AutoSize = true;
            heading.Location = new Point(16, 8);

            Label body = new Label();
            body.Location = new Point(16, 28);
            body.Size = new Size(910, 34);
            body.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            body.Font = _fontSmall;
            body.ForeColor = TextBody;
            body.Text =
                "Windows 11 Notepad caches unsaved tabs to LocalState\\TabState\\*.bin alongside Win+V Clipboard History and Sticky Notes.\r\n" +
                "Scan locally to find and remove saved private keys and seed phrases.";

            card.Controls.Add(heading);
            card.Controls.Add(body);
            wrap.Controls.Add(card);
            return wrap;
        }

        private Panel BuildLiveAlertSection()
        {
            Panel wrap = new Panel();
            wrap.Dock = DockStyle.Top;
            wrap.Height = 42;
            wrap.Padding = new Padding(16, 0, 16, 6);
            wrap.BackColor = BgCanvas;
            wrap.Visible = false;

            BorderPanel banner = new BorderPanel(AccentAmberDark, AccentAmber, true, true, true, true);
            banner.Dock = DockStyle.Fill;

            _alertBannerLabel = new Label();
            _alertBannerLabel.Location = new Point(12, 8);
            _alertBannerLabel.Size = new Size(820, 20);
            _alertBannerLabel.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            _alertBannerLabel.Font = _fontSmallBold;
            _alertBannerLabel.ForeColor = AccentAmberText;
            _alertBannerLabel.AutoEllipsis = true;

            Button dismissBtn = CreateStyledButton("Dismiss", BtnNeutralBg, AccentAmber, AccentAmberText, 76, 24);
            dismissBtn.Font = _fontSmall;
            dismissBtn.Location = new Point(banner.Width - 86, 6);
            dismissBtn.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            dismissBtn.Click += delegate (object s, EventArgs e) { _alertBannerWrap.Visible = false; };

            banner.Controls.Add(dismissBtn);
            banner.Controls.Add(_alertBannerLabel);
            wrap.Controls.Add(banner);
            return wrap;
        }

        private Panel BuildToolbarSection()
        {
            Panel wrap = new Panel();
            wrap.Dock = DockStyle.Top;
            wrap.Height = 104;
            wrap.Padding = new Padding(16, 2, 16, 8);
            wrap.BackColor = BgCanvas;

            BorderPanel card = new BorderPanel(BgCard, BorderSubtle, true, true, true, true);
            card.Dock = DockStyle.Fill;

            _scanBtn = CreateStyledButton("Scan All Ghost Copies", AccentEmeraldBtn, AccentEmerald, Color.White, 190, 32);
            _scanBtn.Font = _fontBold;
            _scanBtn.Location = new Point(12, 10);
            _scanBtn.Click += OnScanClicked;

            _cancelBtn = CreateStyledButton("Cancel Scan", BtnNeutralBg, BorderSubtle, TextPrimary, 104, 32);
            _cancelBtn.Location = new Point(210, 10);
            _cancelBtn.Enabled = false;
            _cancelBtn.Click += OnCancelClicked;

            Label scopeLbl = new Label();
            scopeLbl.Text = "Folder Scope:";
            scopeLbl.Font = _fontSmallBold;
            scopeLbl.ForeColor = TextSecondary;
            scopeLbl.AutoSize = true;
            scopeLbl.Location = new Point(328, 18);

            _scopeCombo = new ComboBox();
            _scopeCombo.DropDownStyle = ComboBoxStyle.DropDownList;
            _scopeCombo.FlatStyle = FlatStyle.Flat;
            _scopeCombo.BackColor = BgCanvas;
            _scopeCombo.ForeColor = TextPrimary;
            _scopeCombo.Font = _fontRegular;
            _scopeCombo.Location = new Point(414, 13);
            _scopeCombo.Width = 258;
            _scopeCombo.Items.AddRange(new object[]
            {
                "Quick User Folders (Default)",
                "Notepad + Win+V + Sticky Notes Only",
                "Choose Custom Folder...",
                "Full User Profile"
            });
            _scopeCombo.SelectedIndex = 0;
            _scopeCombo.SelectedIndexChanged += OnScopeChanged;

            Button checkAllBtn = CreateStyledButton("Check All", BtnNeutralBg, BorderSubtle, TextSecondary, 82, 28);
            checkAllBtn.Font = _fontSmall;
            checkAllBtn.Location = new Point(card.Width - 180, 12);
            checkAllBtn.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            checkAllBtn.Click += delegate (object s, EventArgs e) { SetAllItemsChecked(true); };

            Button uncheckAllBtn = CreateStyledButton("Uncheck", BtnNeutralBg, BorderSubtle, TextSecondary, 82, 28);
            uncheckAllBtn.Font = _fontSmall;
            uncheckAllBtn.Location = new Point(card.Width - 92, 12);
            uncheckAllBtn.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            uncheckAllBtn.Click += delegate (object s, EventArgs e) { SetAllItemsChecked(false); };

            _ocrCheck = new CheckBox();
            _ocrCheck.Text = "Include Offline Screenshot OCR (.png/.jpg)";
            _ocrCheck.Font = _fontSmall;
            _ocrCheck.ForeColor = TextBody;
            _ocrCheck.BackColor = Color.Transparent;
            _ocrCheck.AutoSize = true;
            _ocrCheck.Location = new Point(14, 50);

            _liveWatchCheck = new CheckBox();
            _liveWatchCheck.Text = "Live Notepad Tab Watch (alert while open)";
            _liveWatchCheck.Font = _fontSmall;
            _liveWatchCheck.ForeColor = TextBody;
            _liveWatchCheck.BackColor = Color.Transparent;
            _liveWatchCheck.AutoSize = true;
            _liveWatchCheck.Location = new Point(268, 50);
            _liveWatchCheck.CheckedChanged += OnLiveWatchToggled;

            _statusLabel = new Label();
            _statusLabel.Location = new Point(14, 72);
            _statusLabel.Size = new Size(card.Width - 28, 18);
            _statusLabel.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            _statusLabel.Font = _fontSmall;
            _statusLabel.ForeColor = AccentEmeraldText;
            _statusLabel.AutoEllipsis = true;
            _statusLabel.Text = "Ready. Click 'Scan All Ghost Copies' to check Win+V, Notepad tabs, Sticky Notes, and local files.";

            card.Controls.Add(_scanBtn);
            card.Controls.Add(_cancelBtn);
            card.Controls.Add(scopeLbl);
            card.Controls.Add(_scopeCombo);
            card.Controls.Add(checkAllBtn);
            card.Controls.Add(uncheckAllBtn);
            card.Controls.Add(_ocrCheck);
            card.Controls.Add(_liveWatchCheck);
            card.Controls.Add(_statusLabel);
            wrap.Controls.Add(card);
            return wrap;
        }

        private Panel BuildFindingsTableSection()
        {
            Panel wrap = new Panel();
            wrap.Dock = DockStyle.Fill;
            wrap.Padding = new Padding(16, 0, 16, 8);
            wrap.BackColor = BgCanvas;

            BorderPanel card = new BorderPanel(BgTable, BorderSubtle, true, true, true, true);
            card.Dock = DockStyle.Fill;
            card.Padding = new Padding(1);

            _findingsList = new DarkListView();
            _findingsList.Dock = DockStyle.Fill;
            _findingsList.View = View.Details;
            _findingsList.FullRowSelect = true;
            _findingsList.CheckBoxes = true;
            _findingsList.OwnerDraw = true;
            _findingsList.BorderStyle = BorderStyle.None;
            _findingsList.BackColor = BgTable;
            _findingsList.ForeColor = TextPrimary;
            _findingsList.HeaderStyle = ColumnHeaderStyle.Nonclickable;

            _findingsList.Columns.Add("Source", 148);
            _findingsList.Columns.Add("Secret Type", 164);
            _findingsList.Columns.Add("Masked Preview", 192);
            _findingsList.Columns.Add("Location / Line", 276);
            _findingsList.Columns.Add("Flags", 160);

            _findingsList.DrawColumnHeader += OnDrawColumnHeader;
            _findingsList.DrawItem += OnDrawItem;
            _findingsList.DrawSubItem += OnDrawSubItem;
            _findingsList.ItemChecked += delegate (object s, ItemCheckedEventArgs e)
            {
                _findingsList.Invalidate(e.Item.Bounds);
                UpdateActionButtons();
            };
            _findingsList.SelectedIndexChanged += delegate (object s, EventArgs e)
            {
                UpdateActionButtons();
            };
            _findingsList.Resize += delegate (object s, EventArgs e)
            {
                AutoStretchLocationColumn();
            };

            card.Controls.Add(_findingsList);
            wrap.Controls.Add(card);
            return wrap;
        }

        private Panel BuildBottomCleanupSection()
        {
            BorderPanel bottom = new BorderPanel(BgHeader, BorderSubtle, true, false, false, false);
            bottom.Dock = DockStyle.Bottom;
            bottom.Height = 96;
            bottom.Padding = new Padding(16, 10, 16, 8);

            FlowLayoutPanel actionsRow = new FlowLayoutPanel();
            actionsRow.Dock = DockStyle.Top;
            actionsRow.Height = 36;
            actionsRow.FlowDirection = FlowDirection.LeftToRight;
            actionsRow.WrapContents = false;
            actionsRow.BackColor = Color.Transparent;
            actionsRow.Margin = new Padding(0);

            _cleanGhostBtn = CreateStyledButton(
                "Clean Selected Win+V / Notepad Items",
                AccentEmeraldDark, AccentEmerald, AccentEmeraldText, 244, 30);
            _cleanGhostBtn.Margin = new Padding(0, 0, 8, 0);
            _cleanGhostBtn.Click += OnCleanSelectedGhostItems;

            _clearHistoryBtn = CreateStyledButton(
                "Clear Entire Win+V History",
                BtnNeutralBg, AccentAmber, AccentAmberText, 174, 30);
            _clearHistoryBtn.Margin = new Padding(0, 0, 8, 0);
            _clearHistoryBtn.Click += OnClearEntireHistory;

            _openFolderBtn = CreateStyledButton(
                "Open File Location",
                BtnNeutralBg, BorderSubtle, TextPrimary, 134, 30);
            _openFolderBtn.Margin = new Padding(0, 0, 8, 0);
            _openFolderBtn.Click += OnOpenFileLocation;

            _recycleFileBtn = CreateStyledButton(
                "Move File to Recycle Bin",
                BtnNeutralBg, BorderSubtle, TextPrimary, 166, 30);
            _recycleFileBtn.Margin = new Padding(0, 0, 8, 0);
            _recycleFileBtn.Click += OnRecycleSelectedFiles;

            _deleteFileBtn = CreateStyledButton(
                "Delete File Permanently",
                AccentCrimsonDark, AccentCrimson, AccentCrimsonText, 166, 30);
            _deleteFileBtn.Margin = new Padding(0);
            _deleteFileBtn.Click += OnDeleteSelectedFiles;

            actionsRow.Controls.Add(_cleanGhostBtn);
            actionsRow.Controls.Add(_clearHistoryBtn);
            actionsRow.Controls.Add(_openFolderBtn);
            actionsRow.Controls.Add(_recycleFileBtn);
            actionsRow.Controls.Add(_deleteFileBtn);

            _footerNoteLabel = new Label();
            _footerNoteLabel.Dock = DockStyle.Fill;
            _footerNoteLabel.Padding = new Padding(0, 6, 0, 0);
            _footerNoteLabel.Font = _fontSmall;
            _footerNoteLabel.ForeColor = TextSecondary;
            _footerNoteLabel.Text =
                "Findings are masked in memory and never saved. Deleting a file on an SSD or synced folder may not erase flash blocks or cloud copies. Always move funds from any exposed wallet.";

            bottom.Controls.Add(_footerNoteLabel);
            bottom.Controls.Add(actionsRow);
            return bottom;
        }

        private Button CreateStyledButton(string text, Color bg, Color border, Color fg, int width, int height)
        {
            StyledActionButton b = new StyledActionButton(bg, border, fg, BtnDisabledBg, BtnDisabledText);
            b.Text = text;
            b.Size = new Size(width, height);
            b.Font = _fontSmallBold;
            b.FlatStyle = FlatStyle.Flat;
            b.FlatAppearance.BorderSize = 1;
            b.FlatAppearance.BorderColor = border;
            b.BackColor = bg;
            b.ForeColor = fg;
            b.Cursor = Cursors.Hand;
            b.UseVisualStyleBackColor = false;
            return b;
        }

        private void AutoStretchLocationColumn()
        {
            if (_findingsList == null || _findingsList.Columns.Count < 5) return;
            int total = _findingsList.ClientSize.Width;
            if (total <= 0) return;
            int fixedWidth = _findingsList.Columns[0].Width
                           + _findingsList.Columns[1].Width
                           + _findingsList.Columns[2].Width
                           + _findingsList.Columns[4].Width;
            int target = Math.Max(220, total - fixedWidth - 6);
            if (_findingsList.Columns[3].Width != target)
            {
                _findingsList.Columns[3].Width = target;
            }
        }

        // -------------------------------------------------------------------
        // Owner-drawn dark ListView rendering
        // -------------------------------------------------------------------
        private void OnDrawColumnHeader(object sender, DrawListViewColumnHeaderEventArgs e)
        {
            using (SolidBrush bg = new SolidBrush(BgTableHeader))
            using (Pen border = new Pen(BorderSubtle))
            {
                e.Graphics.FillRectangle(bg, e.Bounds);
                e.Graphics.DrawLine(border, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
                e.Graphics.DrawLine(border, e.Bounds.Right - 1, e.Bounds.Top + 4, e.Bounds.Right - 1, e.Bounds.Bottom - 5);
            }

            Rectangle textRect = new Rectangle(e.Bounds.X + 8, e.Bounds.Y, Math.Max(0, e.Bounds.Width - 12), e.Bounds.Height);
            TextRenderer.DrawText(
                e.Graphics,
                e.Header.Text,
                _fontSmallBold,
                textRect,
                TextSecondary,
                TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
        }

        private void OnDrawItem(object sender, DrawListViewItemEventArgs e)
        {
            // SubItems handle full cell rendering.
        }

        private void OnDrawSubItem(object sender, DrawListViewSubItemEventArgs e)
        {
            bool rowActive = e.Item.Selected || e.Item.Checked;
            Color rowBg = rowActive
                ? BgRowSelected
                : ((e.ItemIndex % 2 == 0) ? BgTable : BgTableAlt);

            using (SolidBrush bg = new SolidBrush(rowBg))
            using (Pen rowLine = new Pen(Color.FromArgb(0x19, 0x23, 0x35)))
            {
                e.Graphics.FillRectangle(bg, e.Bounds);
                e.Graphics.DrawLine(rowLine, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
            }

            int leftPad = 8;
            if (e.ColumnIndex == 0)
            {
                Rectangle box = new Rectangle(e.Bounds.X + 8, e.Bounds.Y + (e.Bounds.Height - 14) / 2, 14, 14);
                SmoothingMode prev = e.Graphics.SmoothingMode;
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                if (e.Item.Checked)
                {
                    using (SolidBrush fill = new SolidBrush(AccentEmerald))
                    using (Pen checkPen = new Pen(BgCanvas, 2f))
                    {
                        e.Graphics.FillRectangle(fill, box);
                        e.Graphics.DrawLines(checkPen, new Point[]
                        {
                            new Point(box.Left + 3, box.Top + 7),
                            new Point(box.Left + 6, box.Top + 10),
                            new Point(box.Left + 11, box.Top + 4)
                        });
                    }
                }
                else
                {
                    using (SolidBrush fill = new SolidBrush(BgCanvas))
                    using (Pen boxPen = new Pen(TextSecondary, 1f))
                    {
                        e.Graphics.FillRectangle(fill, box);
                        e.Graphics.DrawRectangle(boxPen, box);
                    }
                }
                e.Graphics.SmoothingMode = prev;
                leftPad = 28;
            }

            Font cellFont = e.ColumnIndex == 2 ? _fontMono : _fontRegular;
            Color cellColor = TextPrimary;
            if (e.ColumnIndex == 0)
            {
                Finding tagFinding = e.Item.Tag as Finding;
                if (tagFinding != null && (tagFinding.LocationType == "notepad-tab" || tagFinding.LocationType == "clipboard-history"))
                {
                    cellColor = AccentAmberText;
                }
            }
            else if (e.ColumnIndex == 2)
            {
                cellColor = AccentCrimsonText;
            }
            else if (e.ColumnIndex == 4)
            {
                cellColor = e.SubItem.Text == "-" ? TextSecondary : AccentAmberText;
            }

            Rectangle textBounds = new Rectangle(
                e.Bounds.X + leftPad,
                e.Bounds.Y,
                Math.Max(0, e.Bounds.Width - leftPad - 6),
                e.Bounds.Height);

            TextRenderer.DrawText(
                e.Graphics,
                e.SubItem.Text,
                cellFont,
                textBounds,
                cellColor,
                TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
        }

        // -------------------------------------------------------------------
        // Scope selection, scan execution & live Notepad TabState watch
        // -------------------------------------------------------------------
        private void OnScopeChanged(object sender, EventArgs e)
        {
            if (_suppressScopePrompt) return;
            if (_scopeCombo.SelectedIndex == 2)
            {
                ChooseCustomFolderInteractive();
            }
        }

        private bool ChooseCustomFolderInteractive()
        {
            // AEGIS-PERMISSION: lets the user choose a specific local folder to scan.
            using (FolderBrowserDialog dlg = new FolderBrowserDialog())
            {
                dlg.Description = "Select a local folder to scan for exposed Solana keys and BIP-39 seed phrases:";
                dlg.ShowNewFolderButton = false;
                if (!string.IsNullOrEmpty(_customFolderPath) && Directory.Exists(_customFolderPath))
                {
                    dlg.SelectedPath = _customFolderPath;
                }
                if (dlg.ShowDialog(this) == DialogResult.OK && !string.IsNullOrEmpty(dlg.SelectedPath))
                {
                    _customFolderPath = dlg.SelectedPath;
                    SetStatus("Custom folder selected: " + Finding.BuildDisplayPath(_customFolderPath), AccentEmeraldText);
                    return true;
                }
            }

            if (string.IsNullOrEmpty(_customFolderPath))
            {
                _suppressScopePrompt = true;
                _scopeCombo.SelectedIndex = 0;
                _suppressScopePrompt = false;
            }
            return false;
        }

        private void OnScanClicked(object sender, EventArgs e)
        {
            if (_isScanning) return;

            int scopeIdx = _scopeCombo.SelectedIndex;
            if (scopeIdx == 2 && (string.IsNullOrEmpty(_customFolderPath) || !Directory.Exists(_customFolderPath)))
            {
                if (!ChooseCustomFolderInteractive()) return;
            }

            GhostScanOptions opts = new GhostScanOptions();
            opts.Ocr = _ocrCheck.Checked;
            if (scopeIdx == 1)
            {
                opts.SkipFileSweep = true;
            }
            else if (scopeIdx == 2)
            {
                opts.SweepScope = "custom";
                opts.CustomPaths.Add(_customFolderPath);
            }
            else if (scopeIdx == 3)
            {
                opts.SweepScope = "profile";
            }
            else
            {
                opts.SweepScope = "quick";
            }

            _isScanning = true;
            _scanCts = new CancellationTokenSource();
            CancellationToken token = _scanCts.Token;

            _findingsList.Items.Clear();
            UpdateActionButtons();
            SetStatus("Scanning local files and clipboard caches...", AccentAmberText);

            Thread worker = new Thread(delegate ()
            {
                GhostScanReport report = null;
                Exception scanErr = null;
                try
                {
                    report = GhostScan.Run(
                        opts,
                        delegate (string progressText)
                        {
                            PostToUi(delegate ()
                            {
                                if (_isScanning) SetStatus(progressText, AccentAmberText);
                            });
                        },
                        token);
                }
                catch (Exception ex)
                {
                    scanErr = ex;
                }

                PostToUi(delegate ()
                {
                    FinishScanOnUi(report, scanErr);
                });
            });
            worker.IsBackground = true;
            worker.Name = "AegisGuiGhostScan";
            worker.Start();
        }

        private void OnCancelClicked(object sender, EventArgs e)
        {
            if (!_isScanning || _scanCts == null) return;
            try
            {
                _scanCts.Cancel();
                SetStatus("Cancelling scan...", AccentAmberText);
            }
            catch (Exception) { }
        }

        private void FinishScanOnUi(GhostScanReport report, Exception scanErr)
        {
            _isScanning = false;
            if (_scanCts != null)
            {
                _scanCts.Dispose();
                _scanCts = null;
            }

            if (scanErr != null || report == null)
            {
                SetStatus("Scan stopped due to a local read error (" +
                    (scanErr != null ? scanErr.GetType().Name : "Unknown") + ").", AccentCrimsonText);
                UpdateActionButtons();
                return;
            }

            PopulateFindingsForView(report.AllFindings, true);

            double secs = report.TotalDurationMs / 1000.0;
            string timeText = secs.ToString("0.0") + "s";
            if (report.Cancelled)
            {
                SetStatus("Scan cancelled after " + timeText + " (" +
                    report.AllFindings.Count + " finding(s) found so far).", AccentAmberText);
            }
            else if (report.AllFindings.Count == 0)
            {
                SetStatus("Clean (" + timeText + "): 0 exposed secrets found across Win+V (" +
                    report.HistoryStatus + "), Notepad tabs, Sticky Notes, and " +
                    report.FilesScanned + " local files.", AccentEmeraldText);
            }
            else
            {
                SetStatus("Found " + report.AllFindings.Count + " exposed secret(s) in " + timeText +
                    " (" + report.NotepadFindings.Count + " Notepad, " +
                    report.HistoryFindings.Count + " Win+V, " +
                    report.StickyNotesFindings.Count + " Sticky Notes, " +
                    report.FileFindings.Count + " file). Checked items are ready for cleanup.", AccentCrimsonText);
            }

            UpdateActionButtons();
        }

        /// <summary>
        /// Populates findings into the ListView using Masked previews and redacted DisplayPath only.
        /// </summary>
        public void PopulateFindingsForView(IList<Finding> findings, bool checkGhostItemsByDefault)
        {
            if (findings == null) return;
            _findingsList.BeginUpdate();
            try
            {
                for (int i = 0; i < findings.Count; i++)
                {
                    AddOrUpdateFindingRow(findings[i], checkGhostItemsByDefault);
                }
                AutoStretchLocationColumn();
            }
            finally
            {
                _findingsList.EndUpdate();
            }
            UpdateActionButtons();
        }

        private void AddOrUpdateFindingRow(Finding f, bool checkGhostByDefault)
        {
            if (f == null) return;

            // Avoid duplicate rows for the exact same location + masked signature
            for (int i = 0; i < _findingsList.Items.Count; i++)
            {
                Finding existing = _findingsList.Items[i].Tag as Finding;
                if (existing != null &&
                    existing.LocationType == f.LocationType &&
                    existing.Signature == f.Signature &&
                    string.Equals(existing.DisplayPath, f.DisplayPath, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(existing.Label, f.Label, StringComparison.Ordinal))
                {
                    _findingsList.Items[i].Tag = f;
                    return;
                }
            }

            // AEGIS-SECURITY: UI cells strictly receive Masked preview and DisplayPath / sanitized Label.
            ListViewItem item = new ListViewItem(FormatSourceName(f.LocationType));
            item.SubItems.Add(FormatSecretType(f));
            item.SubItems.Add(f.Masked ?? "");
            item.SubItems.Add(FormatLocationColumn(f));
            item.SubItems.Add(f.Flags != null && f.Flags.Count > 0
                ? string.Join(", ", f.Flags.ToArray())
                : "-");
            item.Tag = f;
            if (checkGhostByDefault && (f.LocationType == "notepad-tab" || f.LocationType == "clipboard-history"))
            {
                item.Checked = true;
            }
            _findingsList.Items.Add(item);
        }

        private static string FormatSourceName(string locationType)
        {
            if (locationType == "notepad-tab") return "Notepad Tab";
            if (locationType == "clipboard-history") return "Win+V History";
            if (locationType == "sticky-notes") return "Sticky Notes";
            if (locationType == "recycle-bin") return "Recycle Bin";
            return "Local File";
        }

        private static string FormatSecretType(Finding f)
        {
            if (f.Kind == SecretDetector.KindSecretKey)
            {
                return "Solana Key (" + (f.Format ?? "key") + ")";
            }
            if (f.Kind == SecretDetector.KindSeed)
            {
                return "Seed Phrase (" + f.WordCount + "w)";
            }
            if (f.Kind == SecretDetector.KindPossibleSeed)
            {
                return "Possible Seed (" + f.WordCount + "w)";
            }
            return f.Kind ?? "Secret";
        }

        private static string FormatLocationColumn(Finding f)
        {
            if (!string.IsNullOrEmpty(f.DisplayPath))
            {
                return f.Line > 0
                    ? (f.DisplayPath + " : line " + f.Line)
                    : f.DisplayPath;
            }
            return !string.IsNullOrEmpty(f.Label) ? f.Label : FormatSourceName(f.LocationType);
        }

        private void OnLiveWatchToggled(object sender, EventArgs e)
        {
            if (!_liveWatchCheck.Checked)
            {
                _notepadTabs.SetWatch(false, null);
                _alertBannerWrap.Visible = false;
                SetStatus("Live Notepad Tab Watch stopped.", TextSecondary);
                return;
            }

            if (!_notepadTabs.Supported)
            {
                _liveWatchCheck.Checked = false;
                SetStatus("Windows 11 Notepad TabState folder was not found on this PC.", AccentAmberText);
                return;
            }

            bool started = _notepadTabs.SetWatch(true, delegate (List<Finding> liveFound)
            {
                PostToUi(delegate ()
                {
                    if (liveFound == null || liveFound.Count == 0) return;
                    PopulateFindingsForView(liveFound, true);
                    _alertBannerLabel.Text =
                        "Live Notepad Alert: Windows just auto-saved " + liveFound.Count +
                        " secret(s) to Notepad TabState\\*.bin! Close Notepad and click 'Clean Selected Win+V / Notepad Items'.";
                    _alertBannerWrap.Visible = true;
                });
            });

            if (started)
            {
                SetStatus("Live Notepad Tab Watch active. Monitoring LocalState\\TabState\\*.bin.", AccentEmeraldText);
            }
            else
            {
                _liveWatchCheck.Checked = false;
                SetStatus("Unable to start Notepad TabState folder watcher.", AccentAmberText);
            }
        }

        // -------------------------------------------------------------------
        // Context-aware cleanup actions
        // -------------------------------------------------------------------
        private List<ListViewItem> GetTargetItems()
        {
            List<ListViewItem> target = new List<ListViewItem>();
            for (int i = 0; i < _findingsList.Items.Count; i++)
            {
                if (_findingsList.Items[i].Checked) target.Add(_findingsList.Items[i]);
            }
            if (target.Count > 0) return target;

            for (int i = 0; i < _findingsList.SelectedItems.Count; i++)
            {
                target.Add(_findingsList.SelectedItems[i]);
            }
            return target;
        }

        private void SetAllItemsChecked(bool state)
        {
            if (_findingsList.Items.Count == 0) return;
            _findingsList.BeginUpdate();
            try
            {
                for (int i = 0; i < _findingsList.Items.Count; i++)
                {
                    _findingsList.Items[i].Checked = state;
                }
            }
            finally
            {
                _findingsList.EndUpdate();
            }
            UpdateActionButtons();
        }

        private void UpdateActionButtons()
        {
            if (_scanBtn != null) _scanBtn.Enabled = !_isScanning;
            if (_cancelBtn != null) _cancelBtn.Enabled = _isScanning;
            if (_scopeCombo != null) _scopeCombo.Enabled = !_isScanning;
            if (_ocrCheck != null) _ocrCheck.Enabled = !_isScanning;

            int ghostCount = 0;
            int fileCount = 0;
            int recycleEligibleCount = 0;

            if (!_isScanning && _findingsList != null)
            {
                List<ListViewItem> targets = GetTargetItems();
                for (int i = 0; i < targets.Count; i++)
                {
                    Finding f = targets[i].Tag as Finding;
                    if (f == null) continue;
                    if (f.LocationType == "clipboard-history" || f.LocationType == "notepad-tab")
                    {
                        ghostCount++;
                    }
                    else if (f.LocationType == "file")
                    {
                        fileCount++;
                        recycleEligibleCount++;
                    }
                    else if (f.LocationType == "recycle-bin")
                    {
                        fileCount++;
                    }
                }
            }

            if (_cleanGhostBtn != null) _cleanGhostBtn.Enabled = !_isScanning && ghostCount > 0;
            if (_clearHistoryBtn != null) _clearHistoryBtn.Enabled = !_isScanning;
            if (_openFolderBtn != null) _openFolderBtn.Enabled = !_isScanning && fileCount > 0;
            if (_recycleFileBtn != null) _recycleFileBtn.Enabled = !_isScanning && recycleEligibleCount > 0;
            if (_deleteFileBtn != null) _deleteFileBtn.Enabled = !_isScanning && fileCount > 0;
        }

        private void OnCleanSelectedGhostItems(object sender, EventArgs e)
        {
            List<ListViewItem> targets = GetTargetItems();
            List<string> clipIds = new List<string>();
            List<ListViewItem> clipRows = new List<ListViewItem>();
            List<string> npIds = new List<string>();
            List<ListViewItem> npRows = new List<ListViewItem>();

            for (int i = 0; i < targets.Count; i++)
            {
                Finding f = targets[i].Tag as Finding;
                if (f == null) continue;
                if (f.LocationType == "clipboard-history")
                {
                    clipIds.Add(f.FindingId);
                    clipRows.Add(targets[i]);
                }
                else if (f.LocationType == "notepad-tab")
                {
                    npIds.Add(f.FindingId);
                    npRows.Add(targets[i]);
                }
            }

            int cleanedClip = 0;
            int cleanedNp = 0;

            if (clipIds.Count > 0)
            {
                try
                {
                    // AEGIS-PERMISSION: deletes only the selected secret items from Win+V Clipboard History.
                    cleanedClip = ClipboardHistory.DeleteFindings(clipIds);
                    RemoveRows(clipRows);
                }
                catch (ClipGuardException ex)
                {
                    MessageBox.Show(
                        this,
                        "Could not remove Win+V Clipboard History items (" + ex.Code + ").",
                        "Win+V Cleanup Notice",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                }
            }

            if (npIds.Count > 0)
            {
                try
                {
                    // AEGIS-PERMISSION: deletes only the selected auto-saved Notepad TabState .bin files.
                    cleanedNp = _notepadTabs.RemoveFindings(npIds);
                    RemoveRowsWhereGone(npRows);
                    _alertBannerWrap.Visible = false;
                }
                catch (ClipGuardException ex)
                {
                    if (ex.Code == "NotepadRunning")
                    {
                        MessageBox.Show(
                            this,
                            "Windows Notepad is currently running.\n\n" +
                            "Please close all open Notepad windows first so Windows releases its lock on TabState\\*.bin, then click 'Clean Selected Win+V / Notepad Items' again.",
                            "Close Notepad First",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Information);
                    }
                    else
                    {
                        MessageBox.Show(
                            this,
                            "Could not remove Notepad tab state (" + ex.Code + ").",
                            "Notepad Cleanup Notice",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Warning);
                    }
                }
            }

            if (cleanedClip > 0 || cleanedNp > 0)
            {
                SetStatus("Cleaned " + cleanedClip + " Win+V item(s) and " + cleanedNp + " Notepad tab(s).", AccentEmeraldText);
            }
            UpdateActionButtons();
        }

        private void OnClearEntireHistory(object sender, EventArgs e)
        {
            DialogResult confirm = MessageBox.Show(
                this,
                "Clear your entire Windows Clipboard History (Win+V)?\n\n" +
                "This removes all local items currently stored in Win+V Clipboard History.",
                "Confirm Clear Win+V History",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);

            if (confirm != DialogResult.Yes) return;

            try
            {
                // AEGIS-PERMISSION: clears Win+V Clipboard History on explicit user confirmation.
                bool ok = ClipboardHistory.Clear();
                List<ListViewItem> clipRows = new List<ListViewItem>();
                for (int i = 0; i < _findingsList.Items.Count; i++)
                {
                    Finding f = _findingsList.Items[i].Tag as Finding;
                    if (f != null && f.LocationType == "clipboard-history")
                    {
                        FindingStore.Remove(f.FindingId);
                        clipRows.Add(_findingsList.Items[i]);
                    }
                }
                RemoveRows(clipRows);
                SetStatus(ok
                    ? "Cleared entire Win+V Clipboard History."
                    : "Win+V Clipboard History is already empty or disabled.", AccentEmeraldText);
            }
            catch (ClipGuardException ex)
            {
                MessageBox.Show(
                    this,
                    "Could not clear Win+V Clipboard History (" + ex.Code + ").",
                    "Win+V History",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
            }
            UpdateActionButtons();
        }

        private void OnOpenFileLocation(object sender, EventArgs e)
        {
            List<ListViewItem> targets = GetTargetItems();
            int opened = 0;
            for (int i = 0; i < targets.Count; i++)
            {
                Finding f = targets[i].Tag as Finding;
                if (f == null || (f.LocationType != "file" && f.LocationType != "recycle-bin")) continue;
                try
                {
                    FileActions.Execute(f.FindingId, "open-location");
                    opened++;
                    if (opened >= 3) break; // avoid opening dozens of Explorer windows at once
                }
                catch (ClipGuardException ex)
                {
                    MessageBox.Show(
                        this,
                        "Could not open file location (" + ex.Code + "): " + (f.DisplayPath ?? ""),
                        "File Location",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    break;
                }
            }
        }

        private void OnRecycleSelectedFiles(object sender, EventArgs e)
        {
            ExecuteFileCleanup("recycle", false);
        }

        private void OnDeleteSelectedFiles(object sender, EventArgs e)
        {
            ExecuteFileCleanup("delete", true);
        }

        private void ExecuteFileCleanup(string action, bool permanent)
        {
            List<ListViewItem> targets = GetTargetItems();
            List<ListViewItem> fileRows = new List<ListViewItem>();
            HashSet<string> uniquePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            for (int i = 0; i < targets.Count; i++)
            {
                Finding f = targets[i].Tag as Finding;
                if (f == null) continue;
                if (f.LocationType == "file" || (permanent && f.LocationType == "recycle-bin"))
                {
                    fileRows.Add(targets[i]);
                    if (!string.IsNullOrEmpty(f.DisplayPath)) uniquePaths.Add(f.DisplayPath);
                }
            }
            if (fileRows.Count == 0) return;

            string prompt = permanent
                ? ("Permanently delete " + uniquePaths.Count + " local file(s) containing exposed wallet secrets?\n\n" +
                   "This bypasses the Recycle Bin and cannot be undone.")
                : ("Move " + uniquePaths.Count + " local file(s) to the Windows Recycle Bin?\n\n" +
                   "Note: files inside the Recycle Bin can still be scanned until emptied.");

            DialogResult confirm = MessageBox.Show(
                this,
                prompt,
                permanent ? "Confirm Permanent File Deletion" : "Move File to Recycle Bin",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);

            if (confirm != DialogResult.Yes) return;

            int acted = 0;
            HashSet<string> actedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < fileRows.Count; i++)
            {
                Finding f = fileRows[i].Tag as Finding;
                if (f == null) continue;
                if (!string.IsNullOrEmpty(f.Path) && actedPaths.Contains(f.Path))
                {
                    FindingStore.Remove(f.FindingId);
                    continue;
                }
                try
                {
                    FileActions.Execute(f.FindingId, action);
                    if (!string.IsNullOrEmpty(f.Path)) actedPaths.Add(f.Path);
                    acted++;
                }
                catch (ClipGuardException ex)
                {
                    if (ex.Code != "FileNotFound")
                    {
                        MessageBox.Show(
                            this,
                            "Could not " + (permanent ? "delete" : "recycle") + " file (" + ex.Code + "):\n" +
                            (f.DisplayPath ?? ""),
                            "File Cleanup Error",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Warning);
                    }
                }
            }

            // Remove all rows whose backing file no longer exists on disk
            List<ListViewItem> gone = new List<ListViewItem>();
            for (int i = 0; i < _findingsList.Items.Count; i++)
            {
                Finding f = _findingsList.Items[i].Tag as Finding;
                if (f != null && !string.IsNullOrEmpty(f.Path) && !File.Exists(f.Path))
                {
                    FindingStore.Remove(f.FindingId);
                    gone.Add(_findingsList.Items[i]);
                }
            }
            RemoveRows(gone);

            if (acted > 0)
            {
                SetStatus((permanent ? "Permanently deleted " : "Moved to Recycle Bin: ") +
                    acted + " file(s).", AccentEmeraldText);
            }
            UpdateActionButtons();
        }

        private void RemoveRows(List<ListViewItem> rows)
        {
            if (rows == null || rows.Count == 0) return;
            _findingsList.BeginUpdate();
            try
            {
                for (int i = 0; i < rows.Count; i++)
                {
                    _findingsList.Items.Remove(rows[i]);
                }
            }
            finally
            {
                _findingsList.EndUpdate();
            }
        }

        private void RemoveRowsWhereGone(List<ListViewItem> rows)
        {
            List<ListViewItem> removed = new List<ListViewItem>();
            for (int i = 0; i < rows.Count; i++)
            {
                Finding f = rows[i].Tag as Finding;
                if (f != null && FindingStore.Get(f.FindingId) == null)
                {
                    removed.Add(rows[i]);
                }
            }
            RemoveRows(removed);
        }

        private void SetStatus(string text, Color color)
        {
            if (_statusLabel == null) return;
            _statusLabel.ForeColor = color;
            _statusLabel.Text = text;
        }

        private void PostToUi(Action action)
        {
            if (IsDisposed) return;
            if (!IsHandleCreated) return;
            try
            {
                BeginInvoke((MethodInvoker)delegate ()
                {
                    if (!IsDisposed) action();
                });
            }
            catch (ObjectDisposedException) { }
            catch (InvalidOperationException) { }
        }

        internal static void PaintAShieldCrest(Graphics g, float size)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float s = size / 32f;
            PointF[] shieldOuter = new PointF[]
            {
                new PointF(16f * s, 2f * s),
                new PointF(28.2f * s, 5.8f * s),
                new PointF(27.2f * s, 17.2f * s),
                new PointF(16f * s, 30f * s),
                new PointF(4.8f * s, 17.2f * s),
                new PointF(3.8f * s, 5.8f * s)
            };
            PointF[] rightFacet = new PointF[]
            {
                new PointF(16f * s, 4f * s),
                new PointF(26.2f * s, 7.1f * s),
                new PointF(25.4f * s, 16.5f * s),
                new PointF(16f * s, 27.4f * s)
            };

            using (SolidBrush coreFill = new SolidBrush(Color.FromArgb(0x0E, 0x13, 0x1B)))
            using (SolidBrush facetFill = new SolidBrush(Color.FromArgb(0x14, 0x1C, 0x27)))
            using (Pen rimPen = new Pen(AccentEmerald, Math.Max(1.4f, 1.7f * s)))
            using (GraphicsPath aPath = new GraphicsPath(FillMode.Alternate))
            using (SolidBrush aBrush = new SolidBrush(TextPrimary))
            {
                g.FillPolygon(coreFill, shieldOuter);
                g.FillPolygon(facetFill, rightFacet);
                g.DrawPolygon(rimPen, shieldOuter);

                // Geometric 'A' monogram centered cleanly inside the shield core
                aPath.AddPolygon(new PointF[]
                {
                    new PointF(16f * s, 7.8f * s),
                    new PointF(10.3f * s, 20.6f * s),
                    new PointF(12.8f * s, 20.6f * s),
                    new PointF(13.95f * s, 17.8f * s),
                    new PointF(18.05f * s, 17.8f * s),
                    new PointF(19.2f * s, 20.6f * s),
                    new PointF(21.7f * s, 20.6f * s)
                });
                aPath.AddPolygon(new PointF[]
                {
                    new PointF(16f * s, 12.55f * s),
                    new PointF(14.75f * s, 15.6f * s),
                    new PointF(17.25f * s, 15.6f * s)
                });
                g.FillPath(aBrush, aPath);
            }
        }

        private static Icon BuildShieldIcon()
        {
            try
            {
                using (Bitmap bmp = new Bitmap(32, 32))
                using (Graphics g = Graphics.FromImage(bmp))
                {
                    g.Clear(Color.Transparent);
                    PaintAShieldCrest(g, 32f);
                    IntPtr hIcon = bmp.GetHicon();
                    try
                    {
                        using (Icon temp = Icon.FromHandle(hIcon))
                        {
                            return (Icon)temp.Clone();
                        }
                    }
                    finally
                    {
                        DestroyIcon(hIcon);
                    }
                }
            }
            catch (Exception)
            {
                return null;
            }
        }

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        private static extern bool DestroyIcon(IntPtr hIcon);

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (_scanCts != null)
            {
                try { _scanCts.Cancel(); }
                catch (Exception) { }
            }
            FileSweep.CancelAll();
            if (_notepadTabs != null)
            {
                _notepadTabs.SetWatch(false, null);
            }
            base.OnFormClosing(e);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_scanCts != null) { _scanCts.Dispose(); _scanCts = null; }
                if (_notepadTabs != null) { _notepadTabs.Dispose(); _notepadTabs = null; }
                if (_fontRegular != null) _fontRegular.Dispose();
                if (_fontBold != null) _fontBold.Dispose();
                if (_fontSmall != null) _fontSmall.Dispose();
                if (_fontSmallBold != null) _fontSmallBold.Dispose();
                if (_fontTitle != null) _fontTitle.Dispose();
                if (_fontMono != null) _fontMono.Dispose();
                if (_appIcon != null) _appIcon.Dispose();
            }
            base.Dispose(disposing);
        }

        // -------------------------------------------------------------------
        // Lightweight custom dark WinForms sub-controls
        // -------------------------------------------------------------------
        private sealed class DarkListView : ListView
        {
            public DarkListView()
            {
                DoubleBuffered = true;
            }
        }

        private sealed class ShieldCrestControl : Control
        {
            public ShieldCrestControl()
            {
                DoubleBuffered = true;
                SetStyle(ControlStyles.SupportsTransparentBackColor | ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint, true);
                BackColor = Color.Transparent;
                TabStop = false;
            }

            protected override void OnPaint(PaintEventArgs e)
            {
                base.OnPaint(e);
                PaintAShieldCrest(e.Graphics, Math.Min(ClientSize.Width, ClientSize.Height));
            }
        }

        private sealed class BorderPanel : Panel
        {
            private readonly Color _border;
            private readonly bool _top;
            private readonly bool _bottom;
            private readonly bool _left;
            private readonly bool _right;

            public BorderPanel(Color bg, Color border, bool top, bool bottom, bool left, bool right)
            {
                DoubleBuffered = true;
                BackColor = bg;
                _border = border;
                _top = top;
                _bottom = bottom;
                _left = left;
                _right = right;
                ResizeRedraw = true;
            }

            protected override void OnPaint(PaintEventArgs e)
            {
                base.OnPaint(e);
                using (Pen p = new Pen(_border, 1f))
                {
                    int w = ClientSize.Width - 1;
                    int h = ClientSize.Height - 1;
                    if (_top && _bottom && _left && _right)
                    {
                        e.Graphics.DrawRectangle(p, 0, 0, w, h);
                    }
                    else
                    {
                        if (_top) e.Graphics.DrawLine(p, 0, 0, w, 0);
                        if (_bottom) e.Graphics.DrawLine(p, 0, h, w, h);
                        if (_left) e.Graphics.DrawLine(p, 0, 0, 0, h);
                        if (_right) e.Graphics.DrawLine(p, w, 0, w, h);
                    }
                }
            }
        }

        private sealed class AccentCardPanel : Panel
        {
            private readonly Color _border;
            private readonly Color _accent;

            public AccentCardPanel(Color bg, Color border, Color accent)
            {
                DoubleBuffered = true;
                BackColor = bg;
                _border = border;
                _accent = accent;
                ResizeRedraw = true;
            }

            protected override void OnPaint(PaintEventArgs e)
            {
                base.OnPaint(e);
                int w = ClientSize.Width - 1;
                int h = ClientSize.Height - 1;
                using (Pen p = new Pen(_border, 1f))
                using (SolidBrush bar = new SolidBrush(_accent))
                {
                    e.Graphics.DrawRectangle(p, 0, 0, w, h);
                    e.Graphics.FillRectangle(bar, 1, 1, 4, Math.Max(0, ClientSize.Height - 2));
                }
            }
        }

        private sealed class StyledActionButton : Button
        {
            private readonly Color _enabledBg;
            private readonly Color _enabledBorder;
            private readonly Color _enabledFg;
            private readonly Color _disabledBg;
            private readonly Color _disabledFg;

            public StyledActionButton(
                Color enabledBg,
                Color enabledBorder,
                Color enabledFg,
                Color disabledBg,
                Color disabledFg)
            {
                _enabledBg = enabledBg;
                _enabledBorder = enabledBorder;
                _enabledFg = enabledFg;
                _disabledBg = disabledBg;
                _disabledFg = disabledFg;
            }

            protected override void OnEnabledChanged(EventArgs e)
            {
                base.OnEnabledChanged(e);
                BackColor = Enabled ? _enabledBg : _disabledBg;
                ForeColor = Enabled ? _enabledFg : _disabledFg;
                FlatAppearance.BorderColor = Enabled ? _enabledBorder : BorderSubtle;
            }

            protected override void OnPaint(PaintEventArgs pevent)
            {
                if (Enabled)
                {
                    base.OnPaint(pevent);
                    return;
                }

                // WinForms FlatStyle.Flat draws dark gray system text when disabled unless custom-painted
                using (SolidBrush bg = new SolidBrush(_disabledBg))
                using (Pen border = new Pen(BorderSubtle, 1f))
                {
                    pevent.Graphics.FillRectangle(bg, ClientRectangle);
                    pevent.Graphics.DrawRectangle(border, 0, 0, ClientSize.Width - 1, ClientSize.Height - 1);
                }
                TextRenderer.DrawText(
                    pevent.Graphics,
                    Text,
                    Font,
                    ClientRectangle,
                    _disabledFg,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
            }
        }
    }
}
