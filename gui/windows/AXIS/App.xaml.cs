using System;
using System.Diagnostics;
using System.IO;
using System.Windows;

namespace AXIS;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        EnsureDaemonRunning();
    }

    private void EnsureDaemonRunning()
    {
        var axisDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "axis", "bin");
        var daemonPath = Path.Combine(axisDir, "axisd.exe");

        if (!File.Exists(daemonPath)) return;

        var processes = Process.GetProcessesByName("axisd");
        if (processes.Length > 0) return;

        var psi = new ProcessStartInfo
        {
            FileName = daemonPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        Process.Start(psi);
    }
}
