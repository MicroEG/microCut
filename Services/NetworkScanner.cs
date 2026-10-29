using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using microCut.Models;

namespace microCut.Services;

public sealed record InterfaceInfo(IPAddress Ip, IPAddress Mask, IPAddress? Gateway, PhysicalAddress Mac);

public static class NetworkScanner
{
    private const int MaxProbeHosts = 256;

    /// <summary>All capture-capable interfaces (filters out ones without a MAC, e.g. loopback).</summary>
    public static IReadOnlyList<ILiveDevice> EnumerateDevices() =>
        CaptureDeviceList.Instance
            .Where(d => d.MacAddress != null && d.MacAddress.GetAddressBytes().Length == 6)
            .OrderBy(d => d.Description, StringComparer.OrdinalIgnoreCase)
            .ToList();

    /// <summary>
    /// Creates an independent handle to the same interface. Each service (monitor,
    /// spoof engine, scanner) must hold its own handle — a pcap device cannot be
    /// opened twice through the same ILiveDevice instance.
    /// </summary>
    public static ILiveDevice CloneDevice(ILiveDevice template) =>
        template is LibPcapLiveDevice { Interface: not null } live
            ? new LibPcapLiveDevice(live.Interface)
            : template;

    public static string NormalizeMac(PhysicalAddress? mac) =>
        mac == null
            ? ""
            : string.Concat(mac.GetAddressBytes().Select(b => b.ToString("X2")));

    /// <summary>
    /// Maps a capture device to its IPv4 configuration by matching the MAC
    /// address against the OS network interfaces; falls back to the pcap address list.
    /// </summary>
    public static InterfaceInfo? GetInterfaceInfo(ILiveDevice device)
    {
        string pcapMac = NormalizeMac(device.MacAddress);

        NetworkInterface? match = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(ni =>
                ni.OperationalStatus == OperationalStatus.Up &&
                (pcapMac.Length == 0
                    ? string.Equals(ni.Description, device.Description, StringComparison.OrdinalIgnoreCase)
                    : NormalizeMac(ni.GetPhysicalAddress()) == pcapMac));

        if (match == null)
            return FallbackFromPcap(device);

        var ipv4 = match.GetIPProperties().UnicastAddresses
            .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
        if (ipv4 == null)
            return FallbackFromPcap(device);

        IPAddress? gateway = match.GetIPProperties().GatewayAddresses
            .Select(g => g.Address)
            .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);

        return new InterfaceInfo(ipv4.Address, ipv4.IPv4Mask, gateway, match.GetPhysicalAddress());
    }

    private static InterfaceInfo? FallbackFromPcap(ILiveDevice device)
    {
        if (device is not LibPcapLiveDevice pcapDevice || pcapDevice.Interface == null)
            return null;

        PcapAddress? withIp = pcapDevice.Interface.Addresses.FirstOrDefault(a => SafeIp(a.Addr) != null);
        IPAddress? ip = withIp == null ? null : SafeIp(withIp.Addr);
        IPAddress? mask = withIp == null ? null : SafeIp(withIp.Netmask);
        if (ip == null || mask == null)
            return null;

        return new InterfaceInfo(ip, mask, null, pcapDevice.Interface.MacAddress ?? device.MacAddress!);
    }

    private static IPAddress? SafeIp(Sockaddr? addr)
    {
        try { return addr?.ipAddress; }
        catch { return null; }
    }

    public static int MaskToPrefix(IPAddress mask)
    {
        byte[] bytes = mask.GetAddressBytes();
        int prefix = 0;
        foreach (byte b in bytes)
            prefix += System.Numerics.BitOperations.PopCount(b);
        return prefix;
    }

    /// <summary>Enumerates usable host addresses of the subnet, capped to keep scans fast.</summary>
    public static List<IPAddress> EnumerateSubnet(IPAddress ip, IPAddress mask, Action<string>? log)
    {
        var list = new List<IPAddress>();
        byte[] ipB = ip.GetAddressBytes();
        byte[] maskB = mask.GetAddressBytes();
        if (ipB.Length != 4 || maskB.Length != 4)
            return list;

        uint ipU = BitConverter.ToUInt32(ipB.Reverse().ToArray());
        uint maskU = BitConverter.ToUInt32(maskB.Reverse().ToArray());
        uint network = ipU & maskU;
        uint broadcast = network | ~maskU;
        long hostCount = (long)broadcast - network - 1;

        if (hostCount > MaxProbeHosts)
            log?.Invoke($"Subnet contains {hostCount} hosts — scanning only the first {MaxProbeHosts}.");

        uint limit = Math.Min(broadcast, network + 1 + MaxProbeHosts);
        for (uint h = network + 1; h < limit; h++)
        {
            byte[] bytes = BitConverter.GetBytes(h);
            Array.Reverse(bytes);
            list.Add(new IPAddress(bytes));
        }

        return list;
    }

    public static void SendArpRequest(ILiveDevice device, PhysicalAddress senderMac, IPAddress senderIp, IPAddress targetIp)
    {
        var arp = new ArpPacket(
            ArpOperation.Request,
            PhysicalAddress.Parse("00-00-00-00-00-00"),
            targetIp,
            senderMac,
            senderIp);
        var eth = new EthernetPacket(senderMac, PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"), EthernetType.Arp)
        {
            PayloadPacket = arp
        };
        device.SendPacket(eth.Bytes);
    }

    /// <summary>
    /// ARP-scans the subnet of the given interface. Sends requests to every host,
    /// collects responses for a few seconds, then resolves hostnames (DNS → NetBIOS).
    /// </summary>
    public static async Task<List<NetworkDevice>> ScanSubnetAsync(
        ILiveDevice device,
        InterfaceInfo info,
        Action<string> log,
        CancellationToken ct)
    {
        var results = new ConcurrentDictionary<string, NetworkDevice>();
        var probeIps = EnumerateSubnet(info.Ip, info.Mask, log);
        log($"Scanning {probeIps.Count} hosts on {info.Ip}/{MaskToPrefix(info.Mask)}...");

        void OnPacketArrival(object sender, PacketCapture e)
        {
            try
            {
                var packet = Packet.ParsePacket(LinkLayers.Ethernet, e.GetPacket().Data);
                if (packet is not EthernetPacket eth)
                    return;
                if (eth.Extract<ArpPacket>() is not { Operation: ArpOperation.Response } arp)
                    return;
                if (arp.SenderProtocolAddress is not { AddressFamily: AddressFamily.InterNetwork } senderIp)
                    return;
                if (senderIp.Equals(info.Ip))
                    return;
                results[senderIp.ToString()] = new NetworkDevice
                {
                    IpAddress = senderIp,
                    MacAddress = arp.SenderHardwareAddress
                };
            }
            catch
            {
                // malformed/truncated frame — ignore
            }
        }

        device.Open(new DeviceConfiguration { Mode = DeviceModes.Promiscuous, ReadTimeout = 1000 });
        device.Filter = "arp";
        device.OnPacketArrival += OnPacketArrival;
        device.StartCapture();

        try
        {
            int sent = 0;
            foreach (IPAddress probeIp in probeIps)
            {
                ct.ThrowIfCancellationRequested();
                SendArpRequest(device, info.Mac, info.Ip, probeIp);
                if (++sent % 25 == 0)
                    Thread.Sleep(2); // let the driver drain the send queue
            }

            int waitMs = Math.Clamp(probeIps.Count * 12, 1500, 4000);
            try { await Task.Delay(waitMs, ct); }
            catch (OperationCanceledException) { }
        }
        finally
        {
            try { device.StopCapture(); } catch { }
            device.OnPacketArrival -= OnPacketArrival;
            try { device.Close(); } catch { }
        }

        var devices = results.Values.ToList();
        devices.RemoveAll(d => d.IpAddress.Equals(info.Ip));

        if (info.Gateway != null)
        {
            NetworkDevice? gateway = devices.FirstOrDefault(d => d.IpAddress.Equals(info.Gateway));
            if (gateway == null)
            {
                var gwMac = await ResolveMacAsync(device, info, info.Gateway, log, ct);
                if (gwMac != null)
                {
                    gateway = new NetworkDevice { IpAddress = info.Gateway, MacAddress = gwMac };
                    devices.Add(gateway);
                    log($"Gateway {info.Gateway} resolved via direct ARP request.");
                }
            }
            if (gateway != null)
                gateway.IsGateway = true;
        }
        else
        {
            log("Warning: no default gateway found for this interface.");
        }

        string[] names = await Task.WhenAll(devices.Select(d => ResolveHostnameAsync(d.IpAddress)));
        for (int i = 0; i < devices.Count; i++)
            devices[i].Hostname = names[i];

        log($"Scan complete — {devices.Count} devices found.");
        return devices;
    }

    /// <summary>Resolves a single MAC via repeated direct ARP requests (used for the gateway).</summary>
    public static async Task<PhysicalAddress?> ResolveMacAsync(
        ILiveDevice device,
        InterfaceInfo info,
        IPAddress targetIp,
        Action<string> log,
        CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<PhysicalAddress?>(TaskCreationOptions.RunContinuationsAsynchronously);

        void OnPacketArrival(object sender, PacketCapture e)
        {
            try
            {
                var packet = Packet.ParsePacket(LinkLayers.Ethernet, e.GetPacket().Data);
                if (packet is not EthernetPacket eth)
                    return;
                if (eth.Extract<ArpPacket>() is not { Operation: ArpOperation.Response } arp)
                    return;
                if (arp.SenderProtocolAddress?.Equals(targetIp) == true)
                    tcs.TrySetResult(arp.SenderHardwareAddress);
            }
            catch { }
        }

        try
        {
            device.Open(new DeviceConfiguration { Mode = DeviceModes.Promiscuous, ReadTimeout = 1000 });
            device.Filter = "arp";
            device.OnPacketArrival += OnPacketArrival;
            device.StartCapture();

            for (int i = 0; i < 3; i++)
            {
                ct.ThrowIfCancellationRequested();
                SendArpRequest(device, info.Mac, info.Ip, targetIp);
                await Task.Delay(400, ct);
            }

            Task completed = await Task.WhenAny(tcs.Task, Task.Delay(1500, ct));
            return completed == tcs.Task ? await tcs.Task : null;
        }
        finally
        {
            try { device.StopCapture(); } catch { }
            device.OnPacketArrival -= OnPacketArrival;
            try { device.Close(); } catch { }
        }
    }

    private static async Task<string> ResolveHostnameAsync(IPAddress ip)
    {
        try
        {
            IPHostEntry entry = await Dns.GetHostEntryAsync(ip).WaitAsync(TimeSpan.FromMilliseconds(350));
            if (!string.IsNullOrWhiteSpace(entry.HostName) &&
                !entry.HostName.Equals(ip.ToString(), StringComparison.OrdinalIgnoreCase))
                return entry.HostName;
        }
        catch { }

        try
        {
            return await Task.Run(() => QueryNbns(ip)).WaitAsync(TimeSpan.FromMilliseconds(500)) ?? "";
        }
        catch { return ""; }
    }

    // NetBIOS Name Service (NBNS) NBSTAT query on UDP 137.
    private static string? QueryNbns(IPAddress ip)
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.ReceiveTimeout = 500;
        udp.Connect(ip, 137);

        byte[] header =
        {
            0x00, 0x00,             // transaction id
            0x00, 0x00,             // flags: standard query
            0x00, 0x01,             // QDCOUNT
            0x00, 0x00, 0x00, 0x00, // ANCOUNT, NSCOUNT
            0x00, 0x00,             // ARCOUNT
        };
        byte[] qname = EncodeNbnsName("*");
        byte[] trailer = { 0x00, 0x21, 0x00, 0x01 }; // QTYPE=NBSTAT, QCLASS=IN
        byte[] request = header.Concat(qname).Concat(trailer).ToArray();

        udp.Send(request, request.Length);
        IPEndPoint? remote = null;
        byte[] resp;
        try { resp = udp.Receive(ref remote); }
        catch { return null; }

        // Name block starts after: 12-byte header + 37-byte question + 13-byte
        // answer RR (assuming compressed name pointer). Try the uncompressed
        // layout (34-byte name) as a fallback for non-compliant responders.
        return TryDecodeNameBlock(resp, 62) ?? TryDecodeNameBlock(resp, 94);
    }

    private static byte[] EncodeNbnsName(string name)
    {
        string padded = (name == "*" ? new string('*', 16) : name.PadRight(16, ' '))[..16];
        var bytes = new List<byte>(33) { 32 }; // length byte: 16 chars * 2
        foreach (char c in padded)
        {
            bytes.Add((byte)('A' + (c >> 4)));
            bytes.Add((byte)('A' + (c & 0x0F)));
        }
        return bytes.ToArray();
    }

    private static string? TryDecodeNameBlock(byte[] resp, int offset)
    {
        if (offset + 34 > resp.Length)
            return null;
        var sb = new StringBuilder();
        for (int i = offset; i < offset + 32; i += 2)
        {
            int hi = resp[i] - 0x41;
            int lo = resp[i + 1] - 0x41;
            if (hi is < 0 or > 15 || lo is < 0 or > 15)
                return null;
            char c = (char)((hi << 4) | lo);
            if (c == 0)
                break;
            sb.Append(c);
        }
        return sb.Length > 0 ? sb.ToString().Trim() : null;
    }
}
