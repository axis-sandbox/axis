using Microsoft.UI.Xaml;
using Microsoft.Web.WebView2.Core;
using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Windows.Storage;

namespace AXIS;

public sealed partial class MainWindow : Window
{
    private const string GATEWAY_URL = "http://127.0.0.1:18519";

    public MainWindow()
    {
        this.InitializeComponent();
        Title = "AXIS — Agent Sandbox";

        // Set window icon and configure titlebar.
        this.ExtendsContentIntoTitleBar = true;

        InitializeWebView();
    }

    private async void InitializeWebView()
    {
        // Initialize WebView2 with user data folder in AppData.
        var userDataFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "axis", "webview2");

        var env = await CoreWebView2Environment.CreateAsync(
            browserExecutableFolder: null,
            userDataFolder: userDataFolder);

        await WebView.EnsureCoreWebView2Async(env);

        // Configure WebView2 settings.
        var settings = WebView.CoreWebView2.Settings;
        settings.AreDevToolsEnabled = false;
        settings.IsStatusBarEnabled = false;
        settings.AreDefaultContextMenusEnabled = false;

        // Set up native bridge: WebView -> C# communication.
        WebView.CoreWebView2.WebMessageReceived += OnWebMessage;

        // Inject AXIS configuration before page load.
        WebView.CoreWebView2.AddScriptToExecuteOnDocumentCreatedAsync($@"
            window.AXIS_CONFIG = {{
                gateway_url: '{GATEWAY_URL}',
                platform: 'windows'
            }};
            window.AXIS_NATIVE = {{
                showNotification: (title, body) => {{
                    window.chrome.webview.postMessage(JSON.stringify({{
                        type: 'notification', title, body
                    }}));
                }},
                openFileDialog: (opts) => {{
                    window.chrome.webview.postMessage(JSON.stringify({{
                        type: 'file_dialog', ...opts
                    }}));
                }},
                minimizeToTray: () => {{
                    window.chrome.webview.postMessage(JSON.stringify({{
                        type: 'minimize_to_tray'
                    }}));
                }}
            }};
        ");

        // Load the shared frontend.
        var webDir = Path.Combine(AppContext.BaseDirectory, "web");
        if (Directory.Exists(webDir))
        {
            // Production: load from bundled assets.
            WebView.CoreWebView2.SetVirtualHostNameToFolderMapping(
                "axis.local", webDir,
                CoreWebView2HostResourceAccessKind.Allow);
            WebView.CoreWebView2.Navigate("https://axis.local/index.html");
        }
        else
        {
            // Development: connect to Vite dev server.
            WebView.CoreWebView2.Navigate("http://localhost:3000");
        }
    }

    private void OnWebMessage(CoreWebView2 sender, CoreWebView2WebMessageReceivedEventArgs args)
    {
        var message = args.WebMessageAsJson;
        using var doc = JsonDocument.Parse(message);
        var type = doc.RootElement.GetProperty("type").GetString();

        switch (type)
        {
            case "notification":
                var title = doc.RootElement.GetProperty("title").GetString();
                var body = doc.RootElement.GetProperty("body").GetString();
                ShowToastNotification(title ?? "AXIS", body ?? "");
                break;

            case "minimize_to_tray":
                // TODO: Minimize to system tray.
                break;

            case "file_dialog":
                // TODO: Show native file picker.
                break;
        }
    }

    private void ShowToastNotification(string title, string body)
    {
        // TODO: Use Windows.UI.Notifications for toast notifications.
    }
}
