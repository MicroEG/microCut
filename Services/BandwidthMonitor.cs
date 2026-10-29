using System.Collections.Concurrent;
using PacketDotNet;
using SharpPcap;
using microCut.Models;

namespace microCut.Services;

/// <summary>
/// Captures IP traffic on the selected interface and credits byte counts to
/// known devices by MAC address. For a cut (spoofed) device this shows its
/// outgoing attempts and retransmits; traffic is never forwarded.
/// </summary>
public sealed class BandwidthMonitor : IDisposable
{
    private readonly ILiveDevice _device;
    private ConcurrentDictionary<string, NetworkDevice> _devicesByMac = new();
    private volatile bool _capturing;

    public event Action<string>? Log;

    public BandwidthMonitor(ILiveDevice device)
    {
        _device = device;
    }

    public void SetDevices(IEnumerable<NetworkDevice> devices)
    {
        _devicesByMac = new ConcurrentDictionary<string, NetworkDevice>(
            devices.Select(d => new KeyValuePair<string, NetworkDevice>(NetworkScanner.NormalizeMac(d.MacAddress), d)));
    }

    public void Start()
    {
        if (_capturing)
            return;
        _device.Open(new DeviceConfiguration
        {
            Mode = DeviceModes.Promiscuous | DeviceModes.NoCaptureLocal,
            ReadTimeout = 1000
        });
        _device.Filter = "ip";
        _device.OnPacketArrival += OnPacketArrival;
        _device.StartCapture();
        _capturing = true;
        Log?.Invoke("Bandwidth monitoring started.");
    }

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            byte[] data = e.GetPacket().Data;
            var packet = Packet.ParsePacket(LinkLayers.Ethernet, data);
            if (packet is not EthernetPacket eth)
                return;

            string src = NetworkScanner.NormalizeMac(eth.SourceHardwareAddress);
            string dst = NetworkScanner.NormalizeMac(eth.DestinationHardwareAddress);

            // Tx = bytes the device sends, Rx = bytes sent to the device.
            if (_devicesByMac.TryGetValue(src, out NetworkDevice? from))
                from.AddTx(data.Length);
            if (_devicesByMac.TryGetValue(dst, out NetworkDevice? to))
                to.AddRx(data.Length);
        }
        catch
        {
            // malformed/truncated frame — ignore
        }
    }

    public void Stop()
    {
        if (!_capturing)
            return;
        try { _device.StopCapture(); } catch { }
        _device.OnPacketArrival -= OnPacketArrival;
        try { _device.Close(); } catch { }
        _capturing = false;
        Log?.Invoke("Bandwidth monitoring stopped.");
    }

    public void Dispose() => Stop();
}
