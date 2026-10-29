using System.Security.Principal;
using Microsoft.Win32;
using microCut.Forms;

namespace microCut;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();

        if (!IsRunningAsAdministrator())
        {
            MessageBox.Show(
                "microCut requires Administrator privileges to send raw ARP packets.\n\n" +
                "Please right-click microCut.exe and select \"Run as administrator\".",
                "microCut — Administrator Required",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return;
        }

        string? npcapError = CheckNpcap();
        if (npcapError != null)
        {
            MessageBox.Show(
                npcapError,
                "microCut — Npcap Required",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return;
        }

        Application.Run(new MainForm());
    }

    private static bool IsRunningAsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// Verifies Npcap is installed AND that its WinPcap API-compatible mode is enabled,
    /// which installs wpcap.dll — the library SharpPcap loads at runtime.
    /// </summary>
    private static string? CheckNpcap()
    {
        string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string wpcapPath = Path.Combine(windowsDir, "System32", "Npcap", "wpcap.dll");

        // The Npcap driver registers itself as a kernel service; checking the
        // service registry key avoids an extra NuGet dependency.
        bool npcapServiceInstalled;
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\npcap");
            npcapServiceInstalled = key != null;
        }
        catch (Exception ex)
        {
            return $"Could not query the registry to verify Npcap.\n\n{ex.Message}";
        }

        if (!npcapServiceInstalled)
        {
            return "Npcap is not installed.\n\n" +
                   "microCut requires Npcap to capture and inject packets.\n" +
                   "1. Download the installer from https://npcap.com\n" +
                   "2. During setup, enable the \"WinPcap API-compatible Mode\" option.\n" +
                   "3. Restart microCut after installation.";
        }

        if (!File.Exists(wpcapPath))
        {
            return "Npcap is installed, but the WinPcap API-compatible mode is not enabled.\n\n" +
                   "SharpPcap cannot load wpcap.dll without it.\n" +
                   "1. Re-run the Npcap installer from https://npcap.com\n" +
                   "2. Check \"WinPcap API-compatible Mode\" during setup.\n" +
                   "3. Restart microCut.";
        }

        return null;
    }
}
