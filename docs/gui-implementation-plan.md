# AXIS Native GUI Applications — Implementation Plan

## Context

AXIS (v0.3.5) is a CLI-only agent sandbox runtime. Users currently interact exclusively through `axis` CLI and `axisd` daemon. The goal is to add native per-platform GUI applications that provide one-click agent installation/execution, real-time security monitoring, terminal embedding for agent TUIs, orchestration of agents and MCP servers, and local inference management — while keeping the CLI fully functional as the canonical interface.

## Architecture

```
+----------------------------------------------------------+
|              Native Platform GUI Application              |
|  macOS: Swift/AppKit    Win: WinUI3    Linux: GTK4-rs    |
|                                                           |
|  +-----------------------------------------------------+ |
|  |  WebView (WKWebView / WebView2 / WebKitGTK)         | |
|  |  Shared Solid+TypeScript bundle (xterm.js terminal,  | |
|  |  security monitor, orchestration editor, etc.)       | |
|  +-----------------------------------------------------+ |
+-----------|----------------|-----------------------------+
            | WebSocket      | REST
            | (PTY + events) | (commands)
+-----------|----------------|-----------------------------+
|              axisd (enhanced daemon)                      |
|  +----------+ +----------+ +-----------+ +----------+   |
|  | axis-pty | | EventBus | | Gateway   | | IPC      |   |
|  |          | | broadcast| | HTTP + WS | | (legacy) |   |
|  +----------+ +----------+ +-----------+ +----------+   |
|  +----------+ +----------+ +-----------+ +----------+   |
|  | Sandbox  | | Proxy    | | Inference | | GPU      |   |
|  | Manager  | | Manager  | | Router    | | Worker   |   |
|  +----------+ +----------+ +-----------+ +----------+   |
+----------------------------------------------------------+
```

**Key decisions:**
- Native apps (Swift, WinUI3, GTK4-rs) provide the shell, system integration, and WebView host
- A shared Solid+TypeScript frontend bundle runs inside the WebView for all dynamic UI
- xterm.js (full PTY) renders agent TUIs via WebSocket binary frames
- Daemon gets a new HTTP+WebSocket gateway (`axis-gateway` crate) alongside existing IPC
- New `axis-pty` crate handles cross-platform pseudoterminal allocation
- All GUI features backed by CLI commands — UI is purely additive

## Phase 1: Daemon Foundation (Weeks 1-4)

### 1.1 New crate: `axis-pty`

Cross-platform PTY allocation:
- Linux/macOS: `openpty(2)` via `nix` crate (already a dependency)
- Windows: ConPTY API (`CreatePseudoConsole`) via Win32 FFI

Structs:
- `PtySession { master: PtyMaster, slave_fd: RawFd/HANDLE, cols: u16, rows: u16 }`
- `PtyMaster` — async read/write (tokio `AsyncFd` on Unix, bridged via `tokio::io::duplex` on Windows)
- Resize support: `TIOCSWINSZ` / `ResizePseudoConsole`

### 1.2 Sandbox PTY integration

Modify `crates/axis-sandbox/src/sandbox.rs`:
- Add `PtyMode` enum to `SandboxConfig`: `None | Capture | Pty { cols: u16, rows: u16 }`
- `SandboxImpl` trait gets `fn pty_master(&self) -> Option<&PtyMaster>`
- Platform impls pass slave fd as child stdin/stdout/stderr when PTY mode active

### 1.3 New crate: `axis-gateway`

HTTP+WebSocket gateway on `127.0.0.1:18519` (configurable via `AXIS_GATEWAY_PORT`):

**REST endpoints:**
| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/sandboxes` | GET/POST | List / Create sandbox |
| `/api/v1/sandboxes/:id` | DELETE | Destroy |
| `/api/v1/sandboxes/:id/restart` | POST | Restart |
| `/api/v1/agents` | GET | List installed agents |
| `/api/v1/agents/:name/run` | POST | One-click: install + sandbox + PTY |
| `/api/v1/policies` | GET | List policies |
| `/api/v1/policies/validate` | POST | Validate YAML |
| `/api/v1/models` | GET/POST/DELETE | Model management |
| `/api/v1/inference/status` | GET | Inference status |
| `/api/v1/orchestrations` | GET/POST/DELETE | Orchestration CRUD |
| `/api/v1/health` | GET | Health check |

**WebSocket endpoints:**
| Endpoint | Description |
|---|---|
| `/ws/v1/events` | Broadcast audit events (filterable by sandbox, category, severity) |
| `/ws/v1/sandboxes/:id/pty` | Bidirectional PTY stream (binary frames) |

### 1.4 Event bus (`axis-core`)

- New `BroadcastSink` impl of `AuditSink` backed by `tokio::sync::broadcast`
- Make `AuditLog` thread-safe (`Arc<RwLock<...>>`)
- Emit sandbox state transitions as first-class `SandboxLifecycle` events

### 1.5 Daemon integration

- `SandboxManager` wrapped in `Arc<tokio::sync::Mutex<...>>` (currently `&mut`)
- Gateway starts alongside IPC server in `axis-daemon/src/main.rs`
- PTY sessions tracked in `ManagedSandbox`

**New dependency:** `tokio-tungstenite` (WebSocket)

## Phase 2: Shared Frontend (Weeks 3-6)

### Location: `gui/shared/`

Solid + TypeScript + Vite. Single bundle loaded by all platform WebViews.

**Key components:**
- `Terminal.tsx` — xterm.js + WebGL renderer, connects to `/ws/v1/sandboxes/:id/pty`, binary framing (0x00=data, 0x01=resize, 0x02=close)
- `SecurityMonitor.tsx` — real-time event stream from `/ws/v1/events`, color-coded by severity, blocked-action warnings
- `SandboxList.tsx` — sandbox lifecycle management
- `AgentLauncher.tsx` — one-click install + run
- `OrchEditor.tsx` — graph editor for agent + MCP server orchestrations
- `ModelManager.tsx` — model pull/remove, inference status

**npm deps:** `solid-js`, `@xterm/xterm`, `@xterm/addon-fit`, `@xterm/addon-webgl`, `vite`

## Phase 3: macOS App (Weeks 5-8)

### Location: `gui/macos/`

Swift + AppKit, Xcode project.

- **WKWebView** loads `shared/dist/index.html` from app bundle
- **Menu bar** `NSStatusItem` with sandbox count, agent dropdown
- **Spotlight-like launcher** — global hotkey (Cmd+Shift+A), fuzzy agent search
- **Daemon lifecycle** — checks for `axisd`, offers to start, `launchd` plist for auto-start
- **Native bridge** — `WKUserContentController` for file picker, notifications, window management
- **Distribution** — `.dmg` (signed + notarized), Homebrew cask

## Phase 4: Windows App (Weeks 7-10)

### Location: `gui/windows/`

WinUI3 / XAML, Visual Studio solution.

- **WebView2** loads `shared/dist/index.html` from `ms-appx-web:///web/`
- **System tray** — WinRT `NotifyIcon`, sandbox count badge, right-click menu
- **Jump List** — recently used agents in Start Menu
- **Native bridge** — `CoreWebView2.WebMessageReceived`
- **Distribution** — MSIX package, `winget` manifest, auto-update

## Phase 5: Linux App (Weeks 9-12)

### Location: `gui/linux/`

GTK4 via `gtk4-rs` (Rust bindings — keeps language count at 1 beyond the shared TS frontend).

- **WebKitGTK** WebView loads `shared/dist/index.html`
- **System tray** — `libappindicator3`
- **Desktop integration** — `.desktop` file, D-Bus activation
- **Native bridge** — custom URI scheme handler
- **Distribution** — Flatpak (primary), `.deb`, `.rpm`

## Phase 6: Orchestration & Polish (Weeks 11-14)

### Orchestration engine (daemon)

```rust
struct Orchestration {
    id: OrchestrationId,
    name: String,
    nodes: Vec<OrchNode>,    // sandboxes + MCP servers
    edges: Vec<OrchEdge>,    // stdin/stdout pipes, MCP connections
    status: OrchestrationStatus,
}
```

- YAML schema for defining orchestration graphs
- Start/stop all nodes, pipe stdio between sandboxes
- MCP server stdin/stdout piping

### New CLI commands (for CLI parity)

| Command | Description |
|---|---|
| `axis orchestrate create --file graph.yaml` | Create orchestration |
| `axis orchestrate start/stop/list/status` | Manage orchestrations |
| `axis events [--follow] [--sandbox ID] [--category] [--severity-min]` | Stream audit events |
| `axis agents run <name> [-- args...]` | One-click install + sandbox + PTY |
| `axis gateway start` | Start HTTP+WS gateway explicitly |

## Project Structure

```
axis/
├── crates/
│   ├── axis-pty/            # NEW: cross-platform PTY
│   ├── axis-gateway/        # NEW: HTTP+WebSocket gateway
│   ├── axis-core/           # MODIFIED: BroadcastSink, thread-safe audit
│   ├── axis-sandbox/        # MODIFIED: PtyMode in SandboxConfig
│   ├── axis-daemon/         # MODIFIED: starts gateway, Arc<Mutex<>> SandboxMgr
│   ├── axis-cli/            # MODIFIED: new subcommands
│   └── ... (others unchanged)
├── gui/
│   ├── shared/              # Solid+TS frontend bundle
│   │   ├── src/components/  # Terminal, SecurityMonitor, AgentLauncher, etc.
│   │   ├── src/api/         # REST + WebSocket client
│   │   └── dist/            # Built bundle
│   ├── macos/               # Swift + AppKit
│   ├── windows/             # WinUI3 / XAML
│   └── linux/               # GTK4-rs
└── dist/                    # Packaging scripts (DMG, MSIX, Flatpak)
```

## Critical Files to Modify

- `crates/axis-daemon/src/ipc.rs` — refactor `SandboxManager` sharing
- `crates/axis-daemon/src/sandbox_mgr.rs` — add PTY tracking, `Arc<Mutex<>>`
- `crates/axis-sandbox/src/sandbox.rs` — add `PtyMode` to config
- `crates/axis-core/src/audit.rs` — add `BroadcastSink`, thread-safe
- `crates/axis-daemon/src/main.rs` — start gateway

## Verification

1. **Phase 1**: `axis agents run claude-code` attaches a full PTY — Claude Code TUI renders correctly in terminal
2. **Phase 2**: Open `gui/shared/dist/index.html` in browser, connect to daemon on `localhost:18519`, verify terminal + event stream
3. **Phase 3-5**: Launch native app, verify agent TUI renders in embedded WebView, security events appear in real-time
4. **Phase 6**: Define a 2-node orchestration (agent + MCP server), verify stdio piping works via CLI and UI

## Alternatives Considered

- **Tauri**: Would give cross-platform from single codebase with Rust backend and web frontend. Rejected because user explicitly wants truly native apps per platform for maximum native feel and platform-specific features (Spotlight, Jump Lists, etc.).
- **Electron**: Universal but 100MB+ binary, memory overhead. Rejected for same reason.
- **egui/Slint (Rust-native GUI)**: No mature terminal emulator component, limited platform integration (no menu bar items, system tray requires extra work). Rejected.
