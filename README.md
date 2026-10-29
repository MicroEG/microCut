# microCut

**microCut** is a Windows desktop application for managing devices on your local network. It discovers every device on the subnet, shows live per-device bandwidth, and lets you selectively **cut** (disconnect) or **restore** a device's internet access using ARP spoofing — without touching the router.

Built with C# / .NET 8 (WinForms), [SharpPcap](https://github.com/dotpcap/sharppcap) and [PacketDotNet](https://github.com/dotpcap/packetdotnet), running on [Npcap](https://npcap.com).

![app icon](Assets/app-icon.png)

## Features

- **Network discovery** — enumerate capture-capable interfaces, then ARP-scan the local subnet to list every active device (IP, MAC, hostname via DNS/NetBIOS).
- **Cut** — poison the ARP caches of a target device and the gateway so the device's traffic is redirected to your machine and dropped. Spoofed replies are re-sent every second to keep the cut active.
- **Restore** — stop poisoning and send corrective ARP replies so the device and gateway relearn the correct MAC mappings (sent 4× to survive a lost frame).
- **Bandwidth monitoring** — promiscuous packet capture with per-device Rx/Tx rates (1-second refresh). For a cut device this shows its retransmit attempts.
- **Global Kill Switch** — one click restores every cut device. The app also restores everything on exit and when you switch interfaces.
- **Safety gates** — first-launch legal disclaimer, a per-session "I confirm I have permission to manage this network" checkbox that enables cut/restore actions, and a hard block on cutting the gateway.

## Requirements

- Windows 10 or 11
- **Npcap** installed with **"WinPcap API-compatible Mode"** enabled (checked at startup)
- Administrator privileges (the app requests elevation via its manifest)
- A wired Ethernet or Wi-Fi connection to the network you manage

To build from source: [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) (the .NET 9 SDK also builds `net8.0` targets).

## Build & run

```bash
dotnet build                    # debug build
dotnet run                      # build + launch (UAC prompt appears)
```

Single-folder release build:

```bash
dotnet publish -c Release -o .\publish
```

Run `publish\microCut.exe` as administrator on the machine that will manage the network.

## Usage

1. Launch microCut (accept the UAC elevation prompt).
2. Read and accept the first-launch disclaimer, ticking **"I confirm I have permission to manage this network"**.
3. Select the network interface in the top bar (e.g. your Wi-Fi adapter) and click **Scan Network**.
4. To disconnect a device: tick the permission checkbox (if not already), then click **Cut** on its row. Status turns red.
5. To reconnect it: click **Restore**. Corrective ARP replies repair both caches.
6. **Global Kill Switch** restores all devices at once.

The status bar at the bottom logs every action (`Spoofing started for 192.168.1.5 — internet cut.`, `Restored 192.168.1.5`, …).

## How it works

### Cut

```
Victim  ──ARP──▶  "192.168.1.1 (gateway) is at  AA:BB:CC:DD:EE:FF (you)"
Gateway ──ARP──▶  "192.168.1.5 (victim)    is at  AA:BB:CC:DD:EE:FF (you)"
```

The victim now sends its internet traffic to the attacker's MAC; the gateway sends the victim's return traffic to the attacker's MAC. Because Windows does not forward these frames (IP routing stays off) and microCut never relays them, the victim's internet access is severed. The spoofing loop re-sends both replies every second, so the cut survives ARP cache refreshes.

### Restore

The spoof loop is cancelled and corrective ARP replies are sent (4 rounds):

```
Victim  ◀── "192.168.1.1 is at the gateway's real MAC"
Gateway ◀── "192.168.1.5 is at the victim's real MAC"
```

### Monitoring

A capture thread on the selected interface (promiscuous, `ip` filter, local-outbound excluded) credits frame sizes to devices by source/destination MAC. The UI computes 1-second deltas into Rx/Tx rates.

> Note: because microCut never forwards packets, "bandwidth" for a device that is *online* reflects only traffic visible on the wire (broadcast/multicast). A device that is **cut** shows real data — its retransmit attempts — since its traffic is being redirected to you. Full MITM monitoring of online devices would require an L2 relay mode, which is intentionally not implemented.

## Project structure

```
microCut/
├── microCut.csproj            # net8.0-windows, SharpPcap 6.3.1, PacketDotNet 1.4.8
├── app.manifest               # requireAdministrator → UAC at launch
├── Program.cs                 # admin + Npcap startup checks
├── DisclaimerStore.cs         # HKCU persistence of disclaimer acceptance
├── Assets/                    # app.ico + source art
├── Forms/
│   ├── MainForm.cs            # interface selector, scan, kill switch, device grid, log
│   └── DisclaimerForm.cs      # first-launch legal modal
├── Models/
│   └── NetworkDevice.cs       # device model + atomic Rx/Tx counters
└── Services/
    ├── NetworkScanner.cs      # interface enumeration, ARP scan, DNS/NBNS hostnames
    ├── SpoofEngine.cs         # periodic poisoning + corrective restore
    └── BandwidthMonitor.cs    # per-MAC byte accounting
```

## Troubleshooting

| Problem | Likely cause / fix |
|---|---|
| "Npcap is not installed" at startup | Install Npcap from npcap.com and enable **WinPcap API-compatible Mode** during setup. |
| "compatible mode is not enabled" | Re-run the Npcap installer and tick the WinPcap API-compatible Mode option. |
| No interfaces listed | Npcap driver issue, or running without elevation. Reinstall Npcap / restart. |
| Scan finds nothing | You may be on a guest/isolated Wi-Fi network (AP client isolation). Try the wired LAN, or check the firewall isn't blocking Npcap. |
| Cut doesn't disconnect a device | Some APs ignore unsolicited ARP (ARP storm protection); some devices use static ARP or probe the gateway constantly. Try cutting another device; power-cycle the target. |
| Whole network drops when cutting | The app blocks cutting the gateway — if the network still drops, an AP security feature may be reacting to the spoofing. Use the Global Kill Switch to restore. |
| Large subnet | Scanning is capped at the first 256 hosts for responsiveness (logged as a warning). |

## Smoke-test checklist

1. Run as admin on your own network → accept disclaimer.
2. Tick the permission checkbox; verify Cut buttons now work (log entry if not ticked).
3. Scan Network → devices appear with IP/MAC/hostname, gateway marked.
4. Cut a phone/tablet → confirm its internet drops within ~2 s and its Tx rate shows retransmit traffic.
5. Restore → confirm internet returns within ~1 s.
6. Cut two devices, press Global Kill Switch → both recover.
7. Close the app while a device is cut → device recovers (exit restore runs before shutdown).

---

## ⚠ Legal disclaimer

This tool is intended for educational purposes and authorized network administration (e.g., testing your own home network) only. Unauthorized interception or disruption of network traffic is illegal under laws such as the Computer Fraud and Abuse Act (CFAA) and equivalent statutes in other jurisdictions. The developer assumes no liability for misuse.
