using System.Net;
using SharpPcap;
using microCut.Models;
using microCut.Services;

namespace microCut.Forms;

public sealed class MainForm : Form
{
    private readonly List<ILiveDevice> _interfaces = new();
    private readonly Dictionary<NetworkDevice, (long Rx, long Tx)> _lastCounters = new();
    private readonly System.Windows.Forms.Timer _statsTimer;

    private ComboBox _interfaceCombo = null!;
    private Button _scanButton = null!;
    private Button _killButton = null!;
    private CheckBox _permissionCheck = null!;
    private DataGridView _grid = null!;
    private ListBox _logList = null!;
    private DataGridViewTextBoxColumn _statusColumn = null!;
    private DataGridViewButtonColumn _actionColumn = null!;

    private List<NetworkDevice> _devices = new();
    private NetworkDevice? _gateway;
    private InterfaceInfo? _info;
    private BandwidthMonitor? _monitor;
    private SpoofEngine? _spoof;
    private bool _scanning;

    public MainForm()
    {
        Text = "microCut — Local Network Manager";
        ClientSize = new Size(980, 660);
        MinimumSize = new Size(880, 540);
        StartPosition = FormStartPosition.CenterScreen;
        Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);

        BuildUi();

        _statsTimer = new System.Windows.Forms.Timer { Interval = 1000 };
        _statsTimer.Tick += OnStatsTick;
        _statsTimer.Start();
    }

    private void BuildUi()
    {
        _grid = new DataGridView
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            AllowUserToResizeRows = false,
            RowHeadersVisible = false,
            MultiSelect = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
            BackgroundColor = SystemColors.Window,
            BorderStyle = BorderStyle.None
        };
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "IP Address", Name = "colIp", MinimumWidth = 120 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "MAC Address", Name = "colMac", MinimumWidth = 150 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Hostname", Name = "colHost", FillWeight = 130 });
        _statusColumn = new DataGridViewTextBoxColumn { HeaderText = "Status", Name = "colStatus", MinimumWidth = 70, FillWeight = 60 };
        _grid.Columns.Add(_statusColumn);
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Rx", Name = "colRx", MinimumWidth = 90, FillWeight = 70 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Tx", Name = "colTx", MinimumWidth = 90, FillWeight = 70 });
        _actionColumn = new DataGridViewButtonColumn
        {
            HeaderText = "Action",
            Name = "colAction",
            MinimumWidth = 90,
            FillWeight = 70,
            FlatStyle = FlatStyle.Flat,
            UseColumnTextForButtonValue = false
        };
        _grid.Columns.Add(_actionColumn);
        _grid.CellClick += OnGridCellClick;
        _grid.CellFormatting += OnGridCellFormatting;

        typeof(DataGridView)
            .GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
            ?.SetValue(_grid, true);

        _logList = new ListBox
        {
            Dock = DockStyle.Bottom,
            Height = 110,
            IntegralHeight = false,
            Font = new Font("Consolas", 9F),
            HorizontalScrollbar = true
        };

        var disclaimer = new Label
        {
            Dock = DockStyle.Bottom,
            AutoSize = false,
            Height = 46,
            Padding = new Padding(10, 5, 10, 5),
            TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = Color.FromArgb(90, 90, 90),
            Text = DisclaimerForm.DisclaimerText
        };

        var permissionPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Padding = new Padding(10, 2, 10, 2)
        };
        _permissionCheck = new CheckBox
        {
            AutoSize = true,
            Text = "I confirm I have permission to manage this network"
        };
        _permissionCheck.CheckedChanged += (_, _) =>
        {
            _killButton.Enabled = _permissionCheck.Checked;
            if (!_permissionCheck.Checked && _spoof != null)
                Log("Permission unchecked — cut/restore actions are now disabled.");
        };
        permissionPanel.Controls.Add(_permissionCheck);

        var topBar = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Padding = new Padding(10, 6, 10, 2)
        };
        topBar.Controls.Add(new Label { AutoSize = true, Text = "Interface:", Padding = new Padding(0, 6, 0, 0) });

        _interfaceCombo = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Width = 330,
            Margin = new Padding(6, 0, 12, 0)
        };
        _interfaceCombo.SelectedIndexChanged += OnInterfaceChanged;
        topBar.Controls.Add(_interfaceCombo);

        _scanButton = new Button
        {
            Text = "Scan Network",
            Width = 130,
            Margin = new Padding(0, 0, 8, 0)
        };
        _scanButton.Click += OnScanClick;
        topBar.Controls.Add(_scanButton);

        _killButton = new Button
        {
            Text = "Global Kill Switch",
            Width = 160,
            Enabled = false,
            ForeColor = Color.Firebrick
        };
        _killButton.Click += OnKillSwitchClick;
        topBar.Controls.Add(_killButton);

        // Dock order: added first = docked last, so Fill (grid) gets the leftover space.
        Controls.Add(_grid);
        Controls.Add(_logList);
        Controls.Add(disclaimer);
        Controls.Add(permissionPanel);
        Controls.Add(topBar);
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);

        if (!DisclaimerStore.IsAccepted)
        {
            using var dialog = new DisclaimerForm();
            if (dialog.ShowDialog(this) != DialogResult.OK)
            {
                Close();
                return;
            }
            DisclaimerStore.MarkAccepted();
        }

        LoadInterfaces();
    }

    private void LoadInterfaces()
    {
        try
        {
            _interfaces.Clear();
            _interfaceCombo.Items.Clear();
            _interfaces.AddRange(NetworkScanner.EnumerateDevices());
            _interfaceCombo.Items.AddRange(_interfaces.Select(d => d.Description).ToArray());

            if (_interfaces.Count == 0)
            {
                Log("No capture-capable network interfaces found. Check that Npcap is installed.");
                return;
            }

            _interfaceCombo.SelectedIndex = 0;
        }
        catch (Exception ex)
        {
            Log($"Failed to enumerate interfaces: {ex.Message}");
        }
    }

    private async void OnInterfaceChanged(object? sender, EventArgs e)
    {
        try
        {
            await RebuildServicesAsync();
        }
        catch (Exception ex)
        {
            Log($"Failed to start monitoring: {ex.Message}");
        }
    }

    private async Task RebuildServicesAsync()
    {
        if (_spoof != null)
            await _spoof.RestoreAllAsync();
        _monitor?.Dispose();
        _monitor = null;
        _spoof?.Dispose();
        _spoof = null;

        _devices.Clear();
        _gateway = null;
        _info = null;
        _grid.Rows.Clear();
        _lastCounters.Clear();

        if (_interfaceCombo.SelectedIndex < 0)
            return;

        ILiveDevice template = _interfaces[_interfaceCombo.SelectedIndex];
        _info = NetworkScanner.GetInterfaceInfo(template);
        if (_info == null)
        {
            Log("Could not determine IPv4 configuration for the selected interface.");
            return;
        }

        _monitor = new BandwidthMonitor(NetworkScanner.CloneDevice(template));
        _monitor.Log += Log;
        _monitor.Start();

        _spoof = new SpoofEngine(NetworkScanner.CloneDevice(template), _info);
        _spoof.Log += Log;

        Log($"Interface selected: {template.Description} ({_info.Ip}/{_info.Mask})");
    }

    private async void OnScanClick(object? sender, EventArgs e)
    {
        if (_scanning || _interfaceCombo.SelectedIndex < 0)
            return;
        if (_info == null)
        {
            Log("Select a valid interface before scanning.");
            return;
        }

        _scanning = true;
        _scanButton.Enabled = false;
        try
        {
            ILiveDevice template = _interfaces[_interfaceCombo.SelectedIndex];
            ILiveDevice scanDevice = NetworkScanner.CloneDevice(template);
            List<NetworkDevice> found = await NetworkScanner.ScanSubnetAsync(scanDevice, _info, Log, CancellationToken.None);

            _devices = found;
            _gateway = found.FirstOrDefault(d => d.IsGateway);
            _lastCounters.Clear();
            _monitor?.SetDevices(found);
            PopulateGrid();
        }
        catch (Exception ex)
        {
            Log($"Scan failed: {ex.Message}");
        }
        finally
        {
            _scanning = false;
            _scanButton.Enabled = true;
        }
    }

    private void PopulateGrid()
    {
        _grid.Rows.Clear();
        foreach (NetworkDevice device in _devices.OrderBy(d => IpToUInt(d.IpAddress)))
        {
            int index = _grid.Rows.Add(device.Ip, device.Mac, device.DisplayHostname, device.StatusText, "0", "0", ActionText(device));
            _grid.Rows[index].Tag = device;
            _lastCounters[device] = (device.RxBytes, device.TxBytes);
        }
    }

    private static uint IpToUInt(IPAddress ip) =>
        BitConverter.ToUInt32(ip.GetAddressBytes().Reverse().ToArray());

    private static string ActionText(NetworkDevice device) =>
        device.IsGateway ? "Gateway" : device.Status == DeviceStatus.Cut ? "Restore" : "Cut";

    private async void OnGridCellClick(object? sender, DataGridViewCellEventArgs e)
    {
        if (e.RowIndex < 0 || e.ColumnIndex != _actionColumn.Index)
            return;
        if (_grid.Rows[e.RowIndex].Tag is not NetworkDevice device)
            return;

        try
        {
            if (!_permissionCheck.Checked)
            {
                Log($"Action blocked for {device.Ip} — tick the permission checkbox first.");
                return;
            }
            if (device.IsGateway)
            {
                Log("Refusing to cut the gateway — that would sever the entire network.");
                return;
            }
            if (_gateway == null)
            {
                Log("No gateway found on this network — cannot cut devices.");
                return;
            }
            if (_spoof == null)
            {
                Log("Spoof engine not ready — select a valid interface.");
                return;
            }

            if (device.Status == DeviceStatus.Cut)
            {
                await _spoof.StopCutAsync(device);
            }
            else
            {
                _spoof.StartCut(device, _gateway);
            }
        }
        catch (Exception ex)
        {
            Log($"Action failed: {ex.Message}");
        }
    }

    private async void OnKillSwitchClick(object? sender, EventArgs e)
    {
        try
        {
            if (_spoof == null)
                return;
            await _spoof.RestoreAllAsync();
            Log("Global kill switch: restore requested for all devices.");
        }
        catch (Exception ex)
        {
            Log($"Global restore failed: {ex.Message}");
        }
    }

    private void OnStatsTick(object? sender, EventArgs e)
    {
        double dt = _statsTimer.Interval / 1000.0;
        foreach (DataGridViewRow row in _grid.Rows)
        {
            if (row.Tag is not NetworkDevice device)
                continue;

            (long lastRx, long lastTx) = _lastCounters[device];
            long rx = device.RxBytes;
            long tx = device.TxBytes;
            _lastCounters[device] = (rx, tx);

            row.Cells["colRx"].Value = FormatRate((rx - lastRx) / dt);
            row.Cells["colTx"].Value = FormatRate((tx - lastTx) / dt);
            row.Cells["colStatus"].Value = device.StatusText;
            row.Cells["colAction"].Value = ActionText(device);
        }
    }

    private void OnGridCellFormatting(object? sender, DataGridViewCellFormattingEventArgs e)
    {
        if (e.CellStyle != null && _grid.Columns[e.ColumnIndex] == _statusColumn && e.Value is string status)
        {
            e.CellStyle.ForeColor = status == "Cut" ? Color.Firebrick : Color.SeaGreen;
            e.CellStyle.Font = new Font(_grid.Font, FontStyle.Bold);
        }
    }

    private static string FormatRate(double bytesPerSecond)
    {
        if (bytesPerSecond >= 1024 * 1024)
            return $"{bytesPerSecond / (1024 * 1024):0.0} MB/s";
        if (bytesPerSecond >= 1024)
            return $"{bytesPerSecond / 1024:0.0} KB/s";
        return $"{bytesPerSecond:0} B/s";
    }

    private void Log(string message)
    {
        if (IsDisposed)
            return;
        if (InvokeRequired)
        {
            try { BeginInvoke(() => Log(message)); }
            catch { /* form closed */ }
            return;
        }
        _logList.Items.Add($"[{DateTime.Now:HH:mm:ss}] {message}");
        _logList.TopIndex = _logList.Items.Count - 1;
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        // Restore all ARP caches before exiting so no device is left cut.
        try { _spoof?.RestoreAllAsync().Wait(TimeSpan.FromSeconds(3)); }
        catch { }
        _monitor?.Dispose();
        _spoof?.Dispose();
        base.OnFormClosing(e);
    }
}
