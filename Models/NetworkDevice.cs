using System.Net;
using System.Net.NetworkInformation;

namespace microCut.Models;

public enum DeviceStatus
{
    Online,
    Cut
}

/// <summary>
/// A device discovered on the local subnet. Bandwidth counters are updated
/// by the capture thread and read by the UI timer, so they use atomics.
/// </summary>
public sealed class NetworkDevice
{
    public required IPAddress IpAddress { get; init; }
    public required PhysicalAddress MacAddress { get; init; }

    public string Hostname { get; set; } = "";
    public bool IsGateway { get; set; }
    public DeviceStatus Status { get; set; } = DeviceStatus.Online;

    private long _rxBytes;
    private long _txBytes;

    public long RxBytes => Interlocked.Read(ref _rxBytes);
    public long TxBytes => Interlocked.Read(ref _txBytes);

    public string Ip => IpAddress.ToString();

    public string Mac => BitConverter.ToString(MacAddress.GetAddressBytes());

    public string DisplayHostname => string.IsNullOrWhiteSpace(Hostname) ? "(unknown)" : Hostname;

    public string StatusText => Status == DeviceStatus.Cut ? "Cut" : "Online";

    public void AddRx(long bytes) => Interlocked.Add(ref _rxBytes, bytes);

    public void AddTx(long bytes) => Interlocked.Add(ref _txBytes, bytes);

    public void ResetCounters()
    {
        Interlocked.Exchange(ref _rxBytes, 0);
        Interlocked.Exchange(ref _txBytes, 0);
    }
}
