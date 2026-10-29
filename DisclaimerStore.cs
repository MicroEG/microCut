using Microsoft.Win32;

namespace microCut;

/// <summary>Persists first-launch disclaimer acceptance in HKCU (no admin needed).</summary>
internal static class DisclaimerStore
{
    private const string KeyPath = @"Software\microCut";
    private const string ValueName = "DisclaimerAccepted";

    public static bool IsAccepted
    {
        get
        {
            try
            {
                using RegistryKey? key = Registry.CurrentUser.OpenSubKey(KeyPath);
                return key?.GetValue(ValueName) as string == "yes";
            }
            catch
            {
                return false;
            }
        }
    }

    public static void MarkAccepted()
    {
        try
        {
            using RegistryKey key = Registry.CurrentUser.CreateSubKey(KeyPath);
            key.SetValue(ValueName, "yes");
        }
        catch
        {
            // failure only means the dialog will show again next launch
        }
    }
}
