// AXIS Desktop — Windows native app with WebView2
// Provides system tray, window management, and hosts the shared frontend.

using Microsoft.UI.Xaml;
using Microsoft.Web.WebView2.Core;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;

namespace AXIS;

public partial class App : Application
{
    private Window? _mainWindow;

    public App()
    {
        this.InitializeComponent();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        _mainWindow = new MainWindow();
        _mainWindow.Activate();

        // Ensure axisd is running.
        EnsureDaemonRunning();
    }

    private void EnsureDaemonRunning()
    {
        var axisDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "axis", "bin");
        var daemonPath = Path.Combine(axisDir, "axisd.exe");

        if (!File.Exists(daemonPath)) return;

        // Check if already running.
        var processes = Process.GetProcessesByName("axisd");
        if (processes.Length > 0) return;

        // Start daemon in background.
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
