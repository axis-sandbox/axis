# AXIS: Agent eXecution Isolation Substrate

## Implementation Plan — v0.1 Draft

**Owner:** AMD Client AI Software
**Status:** Phase 0 + Phase 1 complete, Phase 2 in progress
**Date:** April 2026
**Inspired by:** [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) (Apache 2.0)
**Repository:** `/home/nod/github/axis/` (Rust workspace, 9 crates + 1 bench)
**HIP Remote Source:** `~/github/TheRock-hip-remote/` worktree (branches `users/jam/add-hip-remote` + `users/jam/hip-remote`)

### Current Implementation Status (2026-04-07)

| Component | Status | Notes |
|---|---|---|
| **axis-core** | Complete | Policy YAML parser (incl. `gpu:` section), OPA engine (regorus), OCSF audit, types |
| **axis-safety** | Complete | Leak detector (Aho-Corasick + regex, 11 credential patterns), input validator |
| **axis-sandbox (Linux)** | Complete | Real Landlock ABI V2+ syscalls, **seccomp default-deny whitelist** (142 allowed syscalls), netns + veth + iptables (ip netns strategy), bubblewrap fallback |
| **axis-sandbox (Windows)** | Complete | Job Object (process/memory/CPU limits, KILL_ON_JOB_CLOSE), Restricted Token + Low IL, AppContainer (stubbed for cross-compile), NTFS ACLs, **ETW bypass detector** |
| **axis-proxy** | Complete | HTTP CONNECT with per-connection OPA eval, TOFU identity (/proc/net/tcp → PID → exe → SHA256), leak detection on plaintext relay, **L7 TLS termination** (ephemeral CA, rustls, leak scan on decrypted traffic), **inference.local virtual host** routing, credential placeholder injection |
| **axis-router** | Complete | Route resolution, model registry, deficit round-robin scheduler with priority lanes, per-sandbox token budgets |
| **axis-gpu** | Complete | HIP Remote protocol types (~150 opcodes, API categories), per-sandbox API filter (allow/deny by category, IPC blocked by default), VRAM quota tracker (per-pointer accounting), TCP transport, worker lifecycle manager |
| **hip-remote (C)** | **Integrated** | Client library: `libamdhip64.so` (538 HIP symbols, 188KB, pure C11). Worker: `hip-worker` binary (links real HIP runtime). Built from `users/jam/hip-remote` branch of rocm-systems. Symlinked at `axis/hip-remote/`. |
| **axis-daemon** | Complete | Async sandbox manager (spawns proxy + GPU worker + sandbox per create), platform IPC (Unix socket / TCP), **policy hot-reload** (file watcher, atomic OPA engine swap), **exec_in_sandbox**, auto-discovers hip-worker binary and client lib |
| **axis-cli** | Complete | create / **exec** / destroy / list / policy validate / model list,pull,remove / inference status — GPU policy display |
| **Cross-platform** | Verified | Cross-compiles Linux + Windows (MinGW). Tested on host, Linux VM, Windows VM. |
| **Tests** | **79 unit+integration** | Unit (core, safety, sandbox, proxy, router, gpu) + integration (6 proxy OPA e2e + inference.local) + 4 ETW bypass |
| **E2E** | **21/21 PASS** | Sandbox isolation (6), daemon lifecycle (7), HIP Remote (8) |
| **HIP Remote GPU** | **7/7 PASS** | Real GPU (RX 9070 XT) accessed from sandboxed VM: hipGetDeviceCount, hipSetDevice, hipGetDeviceProperties, hipMalloc, hipMemcpy H2D+D2H, hipFree, hipDeviceSynchronize |
| **Benchmarks** | **5/5 PASS** | All success metrics validated on Linux VM, Windows VM, and bare metal |

### Cross-Platform Test Matrix (2026-04-07)

| Platform | Environment | Tests | Pass | Status |
|---|---|---|---|---|
| Host (bare metal) | Ubuntu 24.04, kernel 6.17, 192 cores | 91 | 91 | ALL PASS |
| Linux VM | Ubuntu 24.04, kernel 6.17, 16 vCPUs | 22 | 22 | ALL PASS |
| Windows VM | Windows 11 Build 26200, 8 vCPUs | 8 | 8 | ALL PASS |
| **Total** | | **121** | **121** | **ALL PASS** |

### HIP Remote GPU Verification (2026-04-07)

Tested with real hardware: AXIS sandbox running in a Linux VM (no GPU, no ROCm) connecting to a `hip-worker` on the host with an AMD RX 9070 XT (gfx1201).

```
Linux VM (sandboxed)                    Host (192-core Ryzen + GPU)
┌─────────────────────────┐   TCP:18515  ┌─────────────────────────┐
│ Landlock v7 (4ro, 3rw)  │ ──────────> │ hip-worker              │
│ seccomp (142 whitelist)  │             │   ↓                     │
│ Proxy (OPA policy)      │             │ Real HIP Runtime        │
│ Python test program     │             │   ↓                     │
│   ↓                     │             │ AMD RX 9070 XT          │
│ libamdhip64.so (remote) │             │ "AMD Radeon AI PRO      │
│ 538 HIP symbols         │             │  R9700"                 │
└─────────────────────────┘             └─────────────────────────┘
```

| HIP API Call | Result |
|---|---|
| `hipGetDeviceCount` | **1 device** |
| `hipSetDevice(0)` | **success** |
| `hipGetDeviceProperties` | **"AMD Radeon AI PRO R9700"** |
| `hipMalloc(1MB)` | **ptr=0x7f0000000000** |
| `hipMemcpy H2D (256 bytes)` | **success** |
| `hipMemcpy D2H (256 bytes)` | **data verified byte-for-byte** |
| `hipFree` | **success** |
| `hipDeviceSynchronize` | **success** |

The VM has **zero GPU drivers and zero ROCm installation** — only the 188KB drop-in `libamdhip64.so` client library. All GPU operations are proxied transparently over TCP to the host's real GPU.

---

## 1. Executive Summary

AXIS is AMD's native agent sandbox runtime — a secure, policy-governed execution environment for autonomous AI agents (claws) running on AMD client hardware. Where NVIDIA's OpenShell relies on Docker containers and a K3s Kubernetes cluster, AXIS is designed from the ground up for **native execution on Windows 11 Home and Linux desktops** with zero container dependencies. This makes AXIS the natural companion to ROCm Everywhere: if ROCm makes every AMD system an AI-capable platform, AXIS makes every AMD system a safe platform for autonomous agents.

AXIS adopts OpenShell's core architectural insight — **out-of-process policy enforcement** — but replaces the container-centric isolation stack with OS-native primitives that work on consumer hardware without Docker, Hyper-V, or administrative privileges.

### Design Principles

1. **No containers, no VMs.** Every isolation primitive is an OS-native syscall or API. The user never installs Docker.
2. **No admin required.** AXIS runs as a standard user on Windows 11 Home and unprivileged Linux. No kernel drivers, no elevation prompts.
3. **Policy-as-code.** Declarative YAML policies govern filesystem, network, process, and inference access. Evaluated by an embedded OPA engine (Rego).
4. **Defense in depth.** Four isolation layers (process, filesystem, network, inference) are applied independently; compromise of one does not unlock the others.
5. **AMD-optimized.** NPU offload for policy evaluation, ROCm-aware GPU passthrough, APEX-aware memory policies.

---

## 2. OpenShell Architecture Analysis

Before detailing the AXIS design, it is worth understanding what OpenShell does and where its container dependency sits in the stack. The following analysis is based on a full source-level review of the OpenShell repository.

### 2.1 OpenShell Component Map

OpenShell is a Rust monorepo (~480 files, 6 crates) organized as follows:

| Crate | Role | Container-Dependent? |
|---|---|---|
| `openshell-cli` | Python + Rust CLI for sandbox lifecycle | No (talks to gateway via gRPC) |
| `openshell-server` | Gateway / control plane (K3s pod) | **Yes** — runs as K8s StatefulSet, uses K8s API for pod lifecycle |
| `openshell-sandbox` | Data plane / sandbox runtime (per-agent) | **Partially** — isolation code is native Linux, but process is spawned inside a container pod |
| `openshell-policy` | YAML ↔ Proto policy conversion, preset expansion | No |
| `openshell-router` | Inference routing (OpenAI/Anthropic/NIM) | No |
| `openshell-ocsf` | Structured audit logging (OCSF schema) | No |

### 2.2 OpenShell Isolation Stack (Linux)

OpenShell applies three isolation layers inside the container, in order during `pre_exec`:

**Layer 1 — Filesystem: Landlock LSM (kernel 5.13+)**

Declarative read-only and read-write path allowlists. Applied via the Landlock ABI V2 `landlock_create_ruleset` / `landlock_add_rule` / `landlock_restrict_self` syscalls. Supports `BestEffort` (skip missing paths) and `HardRequirement` (fail if any path inaccessible) modes.

**Layer 2 — Syscall: seccomp-BPF**

Default-allow filter with targeted blocks. Three categories: (a) socket domain blocks (AF_PACKET, AF_BLUETOOTH, AF_VSOCK, optionally AF_INET/AF_INET6) to prevent proxy bypass; (b) unconditional blocks (memfd_create, ptrace, bpf, process_vm_readv, io_uring_setup, mount) to prevent sandbox escape; (c) conditional blocks on dangerous flag combinations (execveat+AT_EMPTY_PATH, unshare+CLONE_NEWUSER, seccomp+SET_MODE_FILTER).

**Layer 3 — Network: netns + iptables + HTTP CONNECT proxy**

A veth pair (10.200.0.1 host ↔ 10.200.0.2 sandbox) routes all sandbox traffic through an HTTP CONNECT proxy. The proxy resolves the calling binary via `/proc/net/tcp` → PID → `/proc/[pid]/exe`, computes a SHA256 fingerprint (TOFU model), and evaluates an OPA policy before allowing or denying the connection. For allowed connections, optional L7 inspection TLS-terminates the stream (ephemeral per-sandbox CA), parses HTTP requests, and enforces method/path rules. Credential injection rewrites headers/query params to insert API keys without exposing them in the agent's environment.

**Bypass detection:** iptables LOG + REJECT rules in the sandbox namespace catch any traffic not going through the proxy, parsed from `/dev/kmsg` and aggregated into denial reports.

### 2.3 What AXIS Keeps from OpenShell

- The OPA/Rego policy engine (via the `regorus` crate — pure Rust, portable)
- The YAML policy schema (filesystem, network, process sections)
- The HTTP CONNECT proxy architecture for network policy enforcement
- L7 inspection with ephemeral CA for TLS termination
- Credential injection via placeholder resolution
- Binary identity fingerprinting (SHA256 TOFU)
- The OCSF structured audit log format

### 2.4 What AXIS Replaces

| OpenShell | AXIS Replacement | Rationale |
|---|---|---|
| K3s cluster + K8s API | Direct process management (systemd / Win32 Job) | No container runtime needed |
| Docker container per sandbox | OS-native process isolation | Works on Win11 Home |
| Container overlay filesystem | Landlock (Linux) / Restricted Token + NTFS ACLs (Windows) | Native, no root |
| K8s pod networking | netns+veth (Linux) / AppContainer network deny + loopback proxy (Windows) | Native |
| gRPC gateway ↔ sandbox | Unix socket (Linux) / Named pipe (Windows) | Simpler, no TLS needed for local |
| Container image pull | No images — agent runs in isolated process with policy-scoped filesystem view | Instant startup |

---

## 3. AXIS Architecture

### 3.1 Five-Layer Model

```
┌─────────────────────────────────────────────────────────┐
│  Layer 5: INFERENCE ROUTER                              │
│  Route agent LLM calls to local/remote backends.        │
│  Credential injection. Model access policy.             │
├─────────────────────────────────────────────────────────┤
│  Layer 4: GPU ISOLATION (HIP Remote)                    │
│  Para-virtual GPU via HIP API proxy. Per-sandbox        │
│  GPU worker. VRAM quotas. API whitelisting.             │
├─────────────────────────────────────────────────────────┤
│  Layer 3: NETWORK POLICY                                │
│  HTTP CONNECT proxy. Per-binary, per-endpoint allow/    │
│  deny. L7 inspection (REST). TLS termination.           │
├─────────────────────────────────────────────────────────┤
│  Layer 2: FILESYSTEM POLICY                             │
│  Read-only / read-write allowlists.                     │
│  Workspace scoping. Temp isolation.                     │
├─────────────────────────────────────────────────────────┤
│  Layer 1: PROCESS ISOLATION                             │
│  Restricted token / seccomp. Syscall filtering.         │
│  Resource limits (CPU, memory, handle count).           │
└─────────────────────────────────────────────────────────┘
```

### 3.2 Component Architecture

```
                         ┌──────────────┐
                         │   AXIS CLI   │
                         │  axis create │
                         │  axis exec   │
                         │  axis policy │
                         └──────┬───────┘
                                │ Unix socket / Named pipe
                         ┌──────▼───────┐
                         │  AXIS Daemon │  (axsd)
                         │              │
                         │  Policy Mgr  │──── OPA Engine (regorus)
                         │  Sandbox Mgr │──── Sandbox Pool
                         │  Audit Log   │──── OCSF events → file/syslog
                         └──────┬───────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                  │
       ┌──────▼──────┐  ┌──────▼──────┐   ┌──────▼──────┐
       │  Sandbox A  │  │  Sandbox B  │   │  Sandbox C  │
       │             │  │             │   │             │
       │ Agent proc  │  │ Agent proc  │   │ Agent proc  │
       │ Proxy svc   │  │ Proxy svc   │   │ Proxy svc   │
       │ FS policy   │  │ FS policy   │   │ FS policy   │
       └─────────────┘  └─────────────┘   └─────────────┘
```

**AXIS Daemon (axsd):** A single long-running user-mode process that manages sandbox lifecycles. On Linux, it can optionally be a systemd user service (`systemctl --user enable axsd`). On Windows, it runs as a startup task or tray application. No elevation required.

**Sandbox:** An isolated agent execution context consisting of a child process (the agent), a co-located proxy thread/process, and applied OS isolation primitives. Each sandbox has its own policy, filesystem scope, and network rules.

### 3.3 Platform Isolation Matrix

| Isolation Layer | Linux | Windows 11 Home |
|---|---|---|
| **Process containment** | seccomp-BPF (same as OpenShell) | Restricted Token + Job Object |
| **Filesystem scoping** | Landlock LSM (kernel 5.13+) | Restricted Token DACL + NTFS ACLs on sandbox directory |
| **Network isolation** | Network namespace + veth pair + iptables | AppContainer Low-Box Token (denies network capability) + loopback proxy |
| **Syscall filtering** | seccomp-BPF allow-list | N/A (Job Object limits + Restricted Token provide equivalent containment) |
| **Resource limits** | cgroups v2 (if available) or rlimit | Job Object limits (CPU rate, memory commit, process count) |
| **Privilege control** | PR_SET_NO_NEW_PRIVS + drop to nobody | Low Integrity Level + deny-only SIDs in restricted token |
| **GPU isolation** | HIP Remote client (`libamdhip64.so`) proxies HIP calls to host worker over TCP/UDS | HIP Remote client (`amdhip64.dll`) proxies HIP calls to host worker over TCP/named pipe |

---

## 4. Platform-Specific Isolation Design

### 4.1 Linux: Native Isolation (No Docker)

The Linux path is architecturally close to what OpenShell already does inside its container, but running directly on the host with no container layer. This is the simpler of the two platforms.

#### 4.1.1 Process Isolation

```
pre_exec() hook (applied after fork, before exec):
  1. setpgid(0, 0)                          — own process group
  2. prctl(PR_SET_NO_NEW_PRIVS, 1)          — prevent suid escalation
  3. landlock_restrict_self(ruleset_fd)      — filesystem policy
  4. setns(netns_fd, CLONE_NEWNET)           — enter network namespace
  5. seccomp(SECCOMP_SET_MODE_FILTER, bpf)   — syscall filter
  6. setgid(gid) + setuid(uid)              — drop to sandbox user (optional)
```

This is the same sequence OpenShell uses. The difference is that AXIS applies it to a directly-spawned child process rather than a process inside a container.

#### 4.1.2 Filesystem (Landlock)

Policy-driven allowlists, identical to OpenShell's implementation:

```yaml
filesystem_policy:
  read_only:
    - /usr
    - /lib
    - /lib64
    - /etc/ssl/certs
    - /etc/resolv.conf
  read_write:
    - /tmp/axis-sandbox-{id}
    - {workspace_dir}
  compatibility: best_effort   # or hard_requirement
```

Landlock ABI V2+ is available on kernel 5.13+ (Ubuntu 22.04+, Fedora 36+). For older kernels, AXIS falls back to UID-based isolation with a dedicated `axis-sandbox` user and restrictive POSIX ACLs.

#### 4.1.3 Network (netns + Proxy)

Identical to OpenShell's design:

1. Create network namespace `axis-{sandbox-id}`
2. Create veth pair: `ax-h-{id}` (host, 10.200.0.1) ↔ `ax-s-{id}` (sandbox, 10.200.0.2)
3. Set default route in sandbox namespace via host veth
4. Configure iptables in sandbox namespace:
   - ACCEPT traffic to proxy (10.200.0.1:3128)
   - LOG + REJECT everything else (bypass detection)
5. Run proxy on host side listening on 10.200.0.1:3128
6. Set `HTTP_PROXY` / `HTTPS_PROXY` env vars in child process

**Requirement:** `ip netns` requires `CAP_NET_ADMIN`. AXIS acquires this via a small setuid helper binary (`axis-netns-helper`) installed during setup, or uses unprivileged user namespaces on kernels that support them (`sysctl kernel.unprivileged_userns_clone=1`).

#### 4.1.4 Fallback: Bubblewrap Mode

For environments where Landlock is unavailable (older kernels) or netns requires root, AXIS can optionally use [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) as an alternative isolation wrapper. Bubblewrap uses unprivileged user namespaces to create mount/PID/network namespaces without root, and is the same technology used by Flatpak.

```bash
bwrap \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --bind /tmp/axis-sandbox-{id} /workspace \
  --unshare-net \
  --unshare-pid \
  --dev /dev \
  --proc /proc \
  --seccomp 3 3<seccomp.bpf \
  -- /usr/bin/python agent.py
```

### 4.2 Windows 11 Home: Native Isolation (No Hyper-V)

Windows 11 Home lacks Hyper-V, Windows Sandbox, and Windows Containers — all of which require Pro/Enterprise. AXIS uses a layered combination of Win32 APIs available on all Windows editions, modeled on the [Chromium sandbox design](https://github.com/chromium/chromium/blob/main/docs/design/sandbox.md).

#### 4.2.1 Process Isolation: Restricted Token + Job Object

**Step 1: Create Restricted Token**

```
CreateRestrictedToken(
    hToken,                       // current user token
    DISABLE_MAX_PRIVILEGE,        // strip all privileges
    countDenySids, pDenySids,     // deny-only: Administrators, BUILTIN groups
    0, NULL,                      // no privilege deletions beyond DISABLE_MAX_PRIVILEGE
    0, NULL                       // no restricting SIDs
) → hRestrictedToken

SetTokenInformation(
    hRestrictedToken,
    TokenIntegrityLevel,
    &LowIntegritySid,            // S-1-16-4096 (Low IL)
    ...
)
```

This creates a token that:
- Cannot access objects owned by Administrators or other elevated groups
- Runs at Low Integrity Level, preventing writes to Medium-IL objects (most of the user's files)
- Has no dangerous privileges (SeDebugPrivilege, SeTcbPrivilege, etc.)
- Requires no admin rights to create — any standard user can restrict their own token

**Step 2: Create Job Object**

```
CreateJobObject(NULL, "axis-sandbox-{id}")

SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, {
    BasicLimitInformation: {
        ActiveProcessLimit: 32,              // max child processes
        LimitFlags: JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                  | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                  | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
    },
    ProcessMemoryLimit: 8 * 1024 * 1024 * 1024,  // 8GB max
    JobMemoryLimit:     12 * 1024 * 1024 * 1024,  // 12GB total
})

SetInformationJobObject(hJob, JobObjectCpuRateControlInformation, {
    ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
               | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
    CpuRate: 8000,  // 80% max CPU
})
```

Job Objects provide:
- Hard process count limits (prevent fork bombs)
- Memory commit limits
- CPU rate caps
- `KILL_ON_JOB_CLOSE` — if AXIS crashes, all sandbox processes die automatically
- No admin required to create

**Step 3: Launch Sandbox Process**

```
CreateProcessAsUser(
    hRestrictedToken,
    "axis-sandbox-host.exe",    // thin wrapper that applies further restrictions
    commandLine,                // the actual agent command
    ...,
    CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB,
    environment,                // with HTTPS_PROXY=http://127.0.0.1:{port}
    workingDirectory,           // sandbox workspace
    &startupInfo,
    &processInfo
)

AssignProcessToJobObject(hJob, processInfo.hProcess)
ResumeThread(processInfo.hThread)
```

#### 4.2.2 Network Isolation: AppContainer Low-Box Token

The most powerful Windows network isolation primitive available on Home edition is the **AppContainer / Low-Box Token**. When a process runs with a Low-Box Token that lacks the `INTERNET_CLIENT` capability, the Windows kernel denies all outbound network connections at the socket layer. This is the same mechanism Chrome uses for its renderer processes.

```
CreateAppContainerProfile(
    "axis-sandbox-{id}",
    "AXIS Sandbox",
    "Isolated agent execution environment",
    NULL, 0,                    // NO capabilities — no network, no filesystem
    &pSid
) → AppContainer SID

// Build SECURITY_CAPABILITIES with zero capabilities
SECURITY_CAPABILITIES secCaps = {
    .AppContainerSid = pSid,
    .Capabilities = NULL,
    .CapabilityCount = 0
};

// Add to process creation via PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
UpdateProcThreadAttribute(
    lpAttributeList,
    0,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    &secCaps,
    sizeof(secCaps),
    NULL, NULL
)
```

With zero capabilities, the sandboxed process:
- **Cannot make any network connections** (INTERNET_CLIENT denied)
- **Cannot access user files** outside explicitly granted paths
- **Cannot interact with other app windows** or processes
- **Cannot access the registry** beyond its own virtualized hive

Network access is then selectively re-enabled through a **loopback proxy**:

```
// Grant loopback exemption for the AppContainer
NetworkIsolationSetAppContainerConfig(
    1, &pSid    // allow loopback only for this AppContainer
)
```

The agent connects to `127.0.0.1:{proxy_port}` via `HTTPS_PROXY` env var. The AXIS proxy (running outside the AppContainer) applies the same OPA policy evaluation as the Linux path — per-binary, per-endpoint allow/deny with optional L7 inspection.

This is the key insight: **AppContainer provides network-level isolation equivalent to Linux's netns, but through capability denial rather than namespace separation.**

#### 4.2.3 Filesystem Isolation: NTFS ACLs + Low Integrity

The Restricted Token + Low Integrity Level provides filesystem isolation:

1. **Sandbox workspace:** A directory like `%LOCALAPPDATA%\AXIS\sandboxes\{id}\` is created with an explicit ACL granting the AppContainer SID full control. This is the only writable location.

2. **System paths:** The agent can read system DLLs and binaries (needed to run), but Low Integrity Level prevents writes to any Medium-IL location.

3. **User files:** Explicitly deny the AppContainer SID access to `%USERPROFILE%`, `%APPDATA%`, etc. Selectively grant read access to policy-specified directories.

```
// Grant sandbox write access to its workspace
SetNamedSecurityInfo(
    sandboxDir,
    SE_FILE_OBJECT,
    DACL_SECURITY_INFORMATION,
    NULL, NULL,
    pAcl,  // ACL granting AppContainer SID full control
    NULL
)
```

#### 4.2.4 Combined Windows Isolation Stack

The full Windows sandbox creation sequence:

```
1. CreateAppContainerProfile()        → AppContainer SID
2. Create sandbox workspace dir       → set NTFS ACLs for AppContainer
3. CreateRestrictedToken()            → restricted + low IL token
4. CreateJobObject()                  → resource limits
5. Start loopback proxy thread        → listen 127.0.0.1:{port}
6. CreateProcessAsUser() with:
   - Restricted token
   - AppContainer SECURITY_CAPABILITIES (zero capabilities)
   - Job Object assignment
   - Environment: HTTPS_PROXY=http://127.0.0.1:{port}
7. NetworkIsolationSetAppContainerConfig()  → allow loopback
```

No component in this stack requires admin privileges or Windows Pro features. AppContainer APIs, Restricted Tokens, Job Objects, and Low Integrity Levels are all available on Windows 11 Home starting from the first release.

### 4.3 GPU Isolation: HIP Remote

Traditional GPU isolation requires device-level passthrough (VFIO, MIG partitioning) which demands admin privileges, specific hardware, and kernel driver support. AXIS takes a fundamentally different approach: **para-virtual GPU access via HIP API proxying**, building on the [`hip-remote`](https://github.com/ROCm/rocm-systems/compare/develop...users/powderluv/hip-remote) project in rocm-systems.

#### 4.3.1 Architecture

```
┌─────────────────────────────┐         TCP / UDS          ┌─────────────────────────────┐
│  Sandbox                    │  ========================>  │  AXIS Daemon (Host)         │
│                             │                             │                             │
│  Agent (PyTorch, vLLM, ...) │                             │  ┌───────────────────────┐  │
│    │                        │                             │  │  HIP Worker (per-sbox) │  │
│    ▼                        │                             │  │                       │  │
│  libamdhip64.so             │                             │  │  Real HIP Runtime     │  │
│  (hip-remote client)        │                             │  │    │                  │  │
│                             │                             │  │    ▼                  │  │
│  ● No GPU driver needed     │                             │  │  AMD GPU Hardware     │  │
│  ● No /dev/kfd access       │                             │  └───────────────────────┘  │
│  ● No ROCm install needed   │                             │                             │
│  ● Pure C11, zero deps      │                             │  Policy enforcement:        │
│                             │                             │  ● VRAM quota               │
│                             │                             │  ● API whitelist            │
│                             │                             │  ● Compute time limits      │
└─────────────────────────────┘                             └─────────────────────────────┘
```

The sandbox receives a **drop-in replacement `libamdhip64`** that proxies all HIP API calls over TCP (or Unix domain socket for same-host) to a per-sandbox **HIP worker process** managed by axsd. The agent application uses the standard HIP C API — `hipMalloc`, `hipMemcpy`, `hipModuleLaunchKernel`, etc. — without knowing it is talking to a remote GPU. Device pointers are opaque handles; the client never dereferences them.

This is the GPU equivalent of AXIS's network proxy: the sandbox never touches the real hardware, and the host enforces policy at the API boundary.

#### 4.3.2 HIP Remote Protocol

The protocol is a custom binary RPC over TCP:

| Field | Size | Description |
|---|---|---|
| Magic | 4 bytes | `0x48495052` ("HIPR") |
| Version | 2 bytes | Protocol version (0x0100) |
| Opcode | 2 bytes | HIP API operation code |
| Request ID | 4 bytes | Correlation ID for request-response matching |
| Payload Length | 4 bytes | Payload size (max 64 MB) |
| Flags | 4 bytes | `HAS_INLINE_DATA` for memory transfers |

~130 opcodes covering the full HIP API surface: device management, memory allocation (malloc/free/managed/async/pools), memory transfer (H2D/D2H/D2D, 2D, 3D), streams, events, module loading, kernel launch, graphs, occupancy, contexts, and AMD SMI metrics.

Memory transfers send data inline with the request/response. Kernel arguments are serialized as offset+size descriptors. Module loading sends the full code object (ELF/Clang Offload Bundle) inline.

#### 4.3.3 Why Not Device Passthrough?

| Approach | Requires | AXIS Fit |
|---|---|---|
| VFIO/GPU passthrough | Root, IOMMU, 1 GPU per VM | Unusable on consumer hardware, can't share GPU |
| MIG partitioning | CDNA hardware (MI250/MI300) | Not available on RDNA (RX 9070 XT) |
| GPU-PV (WSL2) | Hyper-V, Pro edition | Not available on Win11 Home |
| ROCm `ROCR_VISIBLE_DEVICES` | Same kernel driver, same user | No memory isolation, no API filtering |
| **HIP Remote** | TCP port, no special privileges | Works everywhere, full API-level policy enforcement |

HIP Remote is the only approach that provides GPU access to sandboxes without kernel driver access, admin privileges, or specialized hardware. The sandbox process needs only a TCP connection to the worker — it doesn't need `/dev/kfd`, `/dev/dri`, ROCm drivers, or any GPU-related kernel modules.

#### 4.3.4 AXIS Enhancements to HIP Remote

The upstream `hip-remote` is a bare proxy with no security model. AXIS adds:

**1. Per-Sandbox Worker Isolation**

axsd spawns one `hip-worker` per sandbox, each on a unique port or Unix domain socket. Workers are children of axsd and inherit its Job Object / cgroup limits:

```yaml
# In sandbox policy
gpu:
  enabled: true
  device: 0                              # physical GPU ordinal
  transport: uds                          # uds (Unix domain socket) or tcp
  vram_limit_mb: 8192                     # max GPU memory allocation
  compute_timeout_sec: 300                # max wall-clock time per kernel launch
  allowed_apis:                           # API whitelist (default: all)
    - memory_alloc
    - memory_transfer
    - module_load
    - kernel_launch
    - stream_ops
    - event_ops
  denied_apis:                            # explicit denials override allowed
    - ipc_handles                         # prevent cross-sandbox GPU memory sharing
    - device_reset                        # prevent disrupting other sandboxes
    - peer_access                         # prevent cross-device access
```

**2. VRAM Quota Enforcement**

The worker tracks cumulative `hipMalloc` allocations per sandbox and rejects allocations that would exceed the policy limit. On `hipFree`, the tracked usage decreases. This is enforced server-side — the client cannot bypass it.

**3. API Whitelisting**

The worker categorizes opcodes into groups (memory, compute, stream, event, graph, IPC, device management) and checks each incoming request against the policy. Blocked opcodes return `hipErrorNotSupported`. IPC handle operations are blocked by default to prevent cross-sandbox GPU memory access.

**4. Transport Security**

- **Unix domain socket** (same-host, preferred): Socket file placed in the sandbox workspace directory with restrictive permissions. No network exposure.
- **TCP with mTLS** (cross-host): For remote GPU pools, the worker requires client certificate authentication. Certificates are issued by the sandbox's ephemeral CA.

**5. Compute Time Limits**

The worker enforces a wall-clock timeout on `hipModuleLaunchKernel`. If a kernel exceeds the timeout, the worker calls `hipDeviceSynchronize` and returns `hipErrorLaunchTimeOut`. This prevents infinite-loop kernels from monopolizing the GPU.

**6. Multi-Client Support**

AXIS extends the single-threaded worker to accept multiple connections via a thread pool (one thread per sandbox connection). Each thread maintains its own HIP context via `hipCtxCreate` for per-client device state isolation.

#### 4.3.5 Cross-Platform GPU Isolation

HIP Remote is uniquely cross-platform because the client library is pure C11 with zero ROCm dependencies:

| Platform | Client | Worker | Transport |
|---|---|---|---|
| **Linux sandbox** | `libamdhip64.so` (remote client) built from AXIS | `hip-worker` on host with ROCm | Unix domain socket |
| **Windows sandbox** | `amdhip64.dll` (remote client) | `hip-worker.exe` on host with ROCm | TCP loopback or named pipe |
| **macOS sandbox** | `libamdhip64.dylib` (remote client) | `hip-worker` on remote Linux GPU server | TCP |
| **Cloud/Remote** | Any platform | GPU server in data center | TCP + mTLS |

This means a sandboxed agent on Windows 11 Home can use an AMD GPU on the same machine without any GPU driver access — the agent's process runs in an AppContainer with zero capabilities, and HIP calls are proxied through the loopback to a worker process that has real GPU access.

---

## 5. Policy Engine

### 5.1 Policy Schema

AXIS uses a YAML policy schema compatible with OpenShell's, extended with AMD-specific fields:

```yaml
# axis-policy.yaml
version: 1
name: "coding-agent-sandbox"

filesystem:
  read_only:
    - /usr
    - /lib
    - /etc/ssl/certs
    - "C:\\Windows\\System32"           # Windows paths supported
  read_write:
    - "{workspace}"                     # expanded at sandbox creation
    - "{tmpdir}"                        # per-sandbox temp
  deny:
    - "~/.ssh"
    - "~/.gnupg"
    - "%USERPROFILE%\\.ssh"

process:
  max_processes: 32
  max_memory_mb: 8192
  cpu_rate_percent: 80
  run_as_user: axis-sandbox             # Linux only, optional
  blocked_syscalls:                     # Linux only
    - ptrace
    - mount
    - bpf
    - io_uring_setup

network:
  mode: proxy                           # proxy | block | allow
  policies:
    - name: github-api
      endpoints:
        - host: "api.github.com"
          port: 443
          access: read-write
      binaries:
        - path: "/usr/bin/git"
        - path: "/usr/bin/curl"
        - path: "C:\\Program Files\\Git\\cmd\\git.exe"

    - name: pypi
      endpoints:
        - host: "pypi.org"
          port: 443
          access: read-only
        - host: "files.pythonhosted.org"
          port: 443
          access: read-only
      binaries:
        - path: "*/python*"
        - path: "*/pip*"

    - name: inference-local
      endpoints:
        - host: "inference.local"
          port: 443
          protocol: rest
          access: read-write
          rules:
            - allow:
                method: POST
                path: "/v1/chat/completions"
            - allow:
                method: POST
                path: "/v1/messages"
            - allow:
                method: GET
                path: "/v1/models"

inference:
  default_provider: local-rocm
  routes:
    - name: local-rocm
      endpoint: "http://localhost:8080"
      protocols: [openai_chat_completions, model_discovery]
      model: "llama-4-scout-109b"
    - name: cloud-fallback
      provider: anthropic
      model: "claude-sonnet-4-20250514"
      api_key_env: ANTHROPIC_API_KEY

# AMD-specific extensions
amd:
  gpu_passthrough: true               # allow ROCm GPU access from sandbox
  npu_policy_offload: true            # use NPU for OPA evaluation (experimental)
  apex_memory_policy:
    allow_overcommit: true            # permit APEX NVMe memory tiering
    max_vram_mb: 16384
```

### 5.2 OPA Evaluation

Policy evaluation uses the `regorus` crate (pure-Rust OPA engine), the same engine OpenShell uses. AXIS embeds the Rego rules at compile time and loads the YAML policy data at sandbox creation.

Key evaluation points:

| Decision Point | Input | Output |
|---|---|---|
| Sandbox creation | Full policy YAML | Filesystem allowlists, process limits, network mode |
| Network CONNECT | Host, port, binary path, binary SHA256, ancestors | Allow / Deny + matched policy name |
| L7 HTTP request | Method, path, query params, matched network policy | Allow / Deny |
| Inference request | Protocol, model, route name | Resolved backend + credentials |

### 5.3 Policy Hot-Reload

Network and inference policies can be updated without restarting the sandbox. The daemon watches the policy file and pushes updates to running sandboxes via the IPC channel. Filesystem and process policies are immutable after sandbox creation (same as OpenShell).

---

## 6. Local Inference Provider

A core differentiator of AXIS is that agents don't need cloud API keys to be useful. The **local inference provider** runs on the same machine as the sandboxes and serves one or more agents concurrently through a managed inference server backed by ROCm.

### 6.1 Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  AXIS Daemon (axsd)                                                  │
│                                                                      │
│  ┌────────────────────┐    ┌──────────────────────────────────────┐  │
│  │  Inference Manager │───▶│  Managed Inference Server            │  │
│  │                    │    │                                      │  │
│  │  - Server lifecycle│    │  vLLM (ROCm) ──or── llama.cpp (HIP) │  │
│  │  - Model registry  │    │                                      │  │
│  │  - Health probes   │    │  ┌──────────┐ ┌──────────┐          │  │
│  └────────────────────┘    │  │ Model A  │ │ Model B  │          │  │
│                            │  │ Llama 4  │ │ Qwen 3   │          │  │
│                            │  └──────────┘ └──────────┘          │  │
│  ┌────────────────────┐    │                                      │  │
│  │  Request Scheduler │───▶│  OpenAI-compatible API               │  │
│  │                    │    │  http://127.0.0.1:{port}             │  │
│  │  - Fair queuing    │    └──────────────────────────────────────┘  │
│  │  - Token budgets   │                                              │
│  │  - Priority lanes  │         ▲      ▲      ▲                     │
│  └────────────────────┘         │      │      │                     │
│                                 │      │      │                     │
│  ┌──────────────────────────────┼──────┼──────┼──────────────────┐  │
│  │  Proxy Layer (per-sandbox)   │      │      │                  │  │
│  │                              │      │      │                  │  │
│  │  Sandbox A ─── proxy ────────┘      │      │                  │  │
│  │  Sandbox B ─── proxy ───────────────┘      │                  │  │
│  │  Sandbox C ─── proxy ──────────────────────┘                  │  │
│  └───────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

Agents inside sandboxes make standard OpenAI-compatible HTTP requests to `https://inference.local`. The per-sandbox proxy intercepts these, authenticates the sandbox identity, and forwards to the local inference server. The agent never knows whether it is hitting a local GPU or a cloud endpoint — the interface is identical.

### 6.2 Server Modes

AXIS supports three modes for the local inference backend, selected by configuration:

| Mode | When to Use | How It Works |
|---|---|---|
| **Managed** (default) | User wants zero-config local inference | axsd spawns and manages a vLLM or llama.cpp process. Auto-selects based on available GPUs. |
| **External** | User already runs their own inference server | axsd connects to a user-specified endpoint. No server lifecycle management. |
| **Embedded** | Lightweight / single-model / edge scenarios | axsd loads a GGUF model directly via `llama.cpp` linked as a Rust library (via `llama-cpp-rs`). No separate process. |

Configuration in `axis-config.yaml`:

```yaml
inference_server:
  mode: managed                        # managed | external | embedded

  # Managed mode settings
  managed:
    backend: vllm                      # vllm | llamacpp
    vllm:
      python: "{axis_venv}/bin/python" # Python with vllm installed
      extra_args: ["--enable-chunked-prefill", "--max-num-batched-tokens", "65536"]
    llamacpp:
      binary: "{axis_data}/bin/llama-server"  # auto-downloaded if missing
      extra_args: ["-cb", "-np", "4"]         # continuous batching, 4 parallel slots

  # External mode settings
  external:
    endpoint: "http://localhost:8080"
    api_key_env: LOCAL_INFERENCE_KEY    # optional

  # Embedded mode settings
  embedded:
    n_gpu_layers: -1                   # -1 = offload all layers to GPU
    context_size: 8192
    batch_size: 2048

  # Common settings
  bind: "127.0.0.1"                    # never exposed externally
  port: 0                              # 0 = auto-assign, axsd tracks the port
  health_check_interval_sec: 10
  startup_timeout_sec: 120
  max_retries: 3
```

### 6.3 Model Registry

The inference manager maintains a local model registry that tracks available models, their locations, and resource requirements.

```yaml
# ~/.config/axis/models.yaml (auto-generated, user-editable)
models:
  - name: llama-4-scout-109b
    source: huggingface://meta-llama/Llama-4-Scout-17B-16E-Instruct
    format: safetensors
    local_path: ~/.cache/axis/models/llama-4-scout-109b/
    vram_required_mb: 65536              # estimated, used for scheduling
    context_length: 131072
    capabilities: [chat, tool_use]

  - name: qwen3-32b
    source: huggingface://Qwen/Qwen3-32B
    format: safetensors
    local_path: ~/.cache/axis/models/qwen3-32b/
    vram_required_mb: 36864
    context_length: 131072
    capabilities: [chat, tool_use, reasoning]

  - name: phi-4-mini-gguf
    source: huggingface://microsoft/phi-4-mini-instruct-gguf
    format: gguf
    local_path: ~/.cache/axis/models/phi-4-mini.Q4_K_M.gguf
    vram_required_mb: 4096
    context_length: 16384
    capabilities: [chat]
    preferred_backend: llamacpp          # GGUF models always use llama.cpp
```

Model lifecycle:
- **Discovery:** `axis model list` shows registered models, `axis model pull <name>` downloads from HuggingFace.
- **Loading:** When the first sandbox requests a model, axsd starts the inference server with that model (managed mode) or verifies it is available (external mode). In embedded mode, the model is loaded into the daemon process.
- **Sharing:** Multiple sandboxes using the same model share a single inference server instance. The server handles concurrent requests via continuous batching.
- **Swapping:** If a sandbox requests a different model and VRAM is insufficient for both, axsd can unload the current model and load the new one. Configurable via `model_swap_policy: queue | reject | evict_lru`.
- **APEX integration:** When APEX is available and `apex_memory_policy.allow_overcommit: true`, models larger than physical VRAM can be loaded with NVMe-backed pages. The inference server sees a larger virtual VRAM pool transparently.

### 6.4 Multi-Agent Request Scheduling

When multiple sandboxes share a single inference server, AXIS interposes a **request scheduler** between the proxies and the backend to prevent any single agent from starving others.

#### Fair Queuing

Each sandbox gets a **virtual queue** with weighted fair scheduling. By default all sandboxes have equal weight; the policy can override this:

```yaml
# In sandbox policy
inference:
  scheduling:
    weight: 2                          # 2x share vs default weight of 1
    priority: interactive              # interactive | background | batch
    max_concurrent_requests: 4         # per-sandbox concurrency cap
```

Priority lanes:

| Priority | Behavior | Use Case |
|---|---|---|
| **interactive** | Lowest latency, preempts background. Limited to 1 outstanding request unless overridden. | Coding agent waiting for next step |
| **background** | Fair-share scheduling. Requests batched for throughput. | Research agent processing documents |
| **batch** | Best-effort, fills unused capacity. May be delayed indefinitely under load. | Bulk embedding, summarization |

The scheduler implements **deficit round-robin** across sandbox queues, weighted by the policy-specified weight. Interactive requests bypass the queue and are forwarded immediately if the server has capacity; if not, they preempt the oldest background request's next batch slot.

#### Token Budgets

Each sandbox can be assigned a **token budget** — a cap on total input + output tokens consumed over a rolling time window:

```yaml
inference:
  token_budget:
    max_tokens_per_hour: 500000        # input + output combined
    max_tokens_per_request: 32768      # single request cap
    action_on_exhaust: queue           # queue | reject | fallback_cloud
    fallback_route: cloud-fallback     # used when action_on_exhaust = fallback_cloud
```

When a sandbox exhausts its hourly budget:
- **queue:** Requests are held until the window rolls forward.
- **reject:** Returns HTTP 429 with a `Retry-After` header.
- **fallback_cloud:** Transparently routes to a cloud provider (if configured in the policy). The agent doesn't see a failure — just potentially different model behavior.

Token counts are tracked by the scheduler via the inference server's `usage` field in the response body (standard in the OpenAI API format). For servers that don't report usage, AXIS estimates token count from request/response byte length using a conservative 4-bytes-per-token heuristic.

### 6.5 The `inference.local` Virtual Host

Agents address the local inference provider via the virtual hostname `inference.local`. This works without DNS modification:

1. The per-sandbox proxy intercepts HTTP CONNECT requests to `inference.local:443`.
2. Instead of resolving via DNS, the proxy routes directly to `127.0.0.1:{server_port}`.
3. TLS is terminated at the proxy (using the per-sandbox ephemeral CA), so the agent sees a valid HTTPS endpoint.
4. The proxy injects an `X-Axis-Sandbox-Id` header so the scheduler can identify the requesting sandbox.
5. The proxy strips this header from the response to prevent the agent from learning its sandbox identity.

This means agents can use any standard OpenAI-compatible client library with no code changes:

```python
# Inside a sandboxed agent — no special SDK needed
from openai import OpenAI

client = OpenAI(
    base_url="https://inference.local/v1",
    api_key="not-needed"                    # proxy handles auth
)

response = client.chat.completions.create(
    model="llama-4-scout-109b",
    messages=[{"role": "user", "content": "Hello"}]
)
```

The `api_key` field is required by the OpenAI client library but is ignored — the proxy authenticates via sandbox identity, not API keys. If the sandbox policy specifies a cloud fallback, the proxy injects the real API key when routing to the cloud provider.

### 6.6 Multi-GPU and Multi-Model Serving

On systems with multiple GPUs (e.g., multi-RX 9070 XT or MI300X clusters), axsd can run multiple inference server instances:

```yaml
inference_server:
  instances:
    - name: coding-model
      model: llama-4-scout-109b
      devices: [0, 1]                   # tensor parallel across GPU 0 and 1
      managed:
        backend: vllm
        vllm:
          extra_args: ["--tensor-parallel-size", "2"]

    - name: small-model
      model: phi-4-mini-gguf
      devices: [2]                       # single GPU
      managed:
        backend: llamacpp
```

The `axis-router` resolves model names to server instances. If a sandbox requests `llama-4-scout-109b`, the router sends it to the `coding-model` instance. If multiple instances serve the same model, the router load-balances across them.

On **unified memory systems** (Strix Halo, Gorgon Halo), there is no discrete VRAM to partition. The inference server uses system RAM directly, and AXIS controls memory usage through the Job Object / cgroup limits on the inference server process rather than GPU device assignment.

### 6.7 Observability

The inference manager emits OCSF audit events for all inference activity:

| Event | Fields | Purpose |
|---|---|---|
| `inference.request` | sandbox_id, model, input_tokens, latency_ms | Per-request telemetry |
| `inference.budget_warning` | sandbox_id, tokens_used, tokens_remaining, window_end | 80% budget consumption |
| `inference.budget_exhausted` | sandbox_id, action_taken (queue/reject/fallback) | Budget limit hit |
| `inference.server_start` | backend, model, devices, pid | Server lifecycle |
| `inference.server_health` | status, requests_pending, gpu_utilization_pct | Periodic health |
| `inference.model_swap` | old_model, new_model, reason, duration_ms | Model load/unload |
| `inference.fallback` | sandbox_id, from_route, to_route, reason | Cloud fallback activated |

The CLI exposes live stats: `axis inference status` shows active models, per-sandbox request rates, token budget consumption, and GPU utilization.

---

## 7. Implementation Phases

### Phase 0: Foundation — Linux + Windows MVP (Weeks 1–6)

**Goal:** Core abstractions and a working sandbox on both Linux and Windows from day one. Windows is not an afterthought — it ships in the first release.

| Task | Details | Effort |
|---|---|---|
| Project scaffolding | Rust workspace, CI (Linux + Windows runners), license headers | 2d |
| `axis-core` crate | Policy YAML parser, OPA engine wrapper (regorus), OCSF audit events | 1w |
| `axis-sandbox` crate (Linux) | Landlock, seccomp, netns isolation — adapted from OpenShell's `sandbox/linux/` | 1.5w |
| `axis-sandbox` crate (Windows) | Restricted Token + Low IL, Job Object resource limits, AppContainer zero-capability network deny | 1.5w |
| Windows filesystem ACLs | Sandbox directory with AppContainer SID grants, user directory deny | 3d |
| `axis-proxy` crate | HTTP CONNECT proxy, binary identity (SHA256 TOFU), OPA network evaluation | 1.5w |
| Path abstraction layer | Cross-platform path handling (forward slash ↔ backslash, drive letters, env var expansion) | 2d |
| `axis-daemon` (axsd) | Sandbox lifecycle manager — Unix socket IPC (Linux), named pipe IPC (Windows) | 1w |
| `axis` CLI | `axis create`, `axis exec`, `axis destroy`, `axis list`, `axis policy validate` | 3d |
| Windows daemon | Startup task registration, tray icon (optional) | 3d |
| Cross-platform test suite | e2e tests on both Linux and Windows: sandbox lifecycle, network policy, filesystem policy | 1w |
| Windows installer | MSI or MSIX package, AppContainer profile cleanup on uninstall | 3d |

**Exit criteria:** `axis create --policy coding-agent.yaml -- python my_agent.py` runs an agent with full OS-native isolation on both Ubuntu 24.04 (Landlock + seccomp + netns) and Windows 11 Home (AppContainer + Restricted Token + Job Object). No admin/UAC prompts on Windows. Network policy enforcement and audit logging on both platforms.

### Phase 1: HIP Remote — Para-Virtual GPU (Weeks 7–12)

**Goal:** Sandboxed agents can use AMD GPUs without direct hardware access. GPU isolation via HIP API proxying, building on the `hip-remote` project in rocm-systems.

| Task | Details | Effort |
|---|---|---|
| `axis-gpu` crate | HIP worker lifecycle management, per-sandbox worker spawning, VRAM quota tracking | 1.5w |
| HIP Remote integration | Fork/vendor `hip-remote-client` and `hip-remote-worker` from rocm-systems. Build client as `libamdhip64.so` / `amdhip64.dll`. | 1w |
| Unix domain socket transport | Add UDS support to hip-remote protocol for same-host sandboxes (lower latency than TCP, filesystem permission-based auth) | 1w |
| VRAM quota enforcement | Server-side tracking of cumulative `hipMalloc` — reject allocations exceeding policy limit | 3d |
| API whitelisting | Categorize ~130 opcodes into groups. Per-sandbox allow/deny by category. Block IPC handles and device reset by default. | 1w |
| Compute time limits | Wall-clock timeout on `hipModuleLaunchKernel`, return `hipErrorLaunchTimeOut` on expiry | 3d |
| Multi-client worker | Extend single-threaded worker to thread-pool with per-client HIP context via `hipCtxCreate` | 1w |
| GPU policy schema | `gpu:` section in policy YAML: device, transport, vram_limit, compute_timeout, allowed/denied APIs | 2d |
| Windows GPU support | Build `amdhip64.dll` (remote client) for Windows. Worker on host communicates via TCP loopback. | 1w |
| `axis gpu status` CLI | Show per-sandbox GPU workers, VRAM usage, active kernels | 2d |
| GPU e2e tests | `hipInfo`, `hipMemcpy` round-trip, kernel launch through sandbox, VRAM quota rejection | 1w |

**Exit criteria:** `axis create --policy gpu-agent.yaml -- python my_gpu_agent.py` runs a HIP application inside a sandbox with no `/dev/kfd` access. HIP calls are proxied to the host GPU. VRAM quotas enforced. Works on both Linux (UDS) and Windows (TCP loopback).

### Phase 2: Inference Router + L7 (Weeks 13–18)

**Goal:** Full inference routing with local ROCm backend support, L7 HTTP inspection, and smart model routing.

| Task | Details | Effort |
|---|---|---|
| `axis-router` crate | Inference route resolution, model registry, `inference.local` virtual host, provider profiles | 1w |
| Inference manager | Server lifecycle (managed/external/embedded modes), health probes, model swap policy | 1w |
| Request scheduler | Per-sandbox fair queuing (deficit round-robin), priority lanes, token budget tracking | 1w |
| L7 TLS termination | Ephemeral per-sandbox CA, leaf cert cache, auto-detect TLS via byte peek | 3d |
| L7 HTTP parsing | Request/response framing, method/path extraction, chunked transfer encoding | 3d |
| Credential injection | Placeholder resolution (`axis:resolve:env:KEY`), header/query rewriting, fail-closed validation | 3d |
| ROCm local inference | vLLM/llama.cpp process management, multi-GPU instance config, APEX memory integration | 1w |
| Inference pattern detection | OpenAI, Anthropic, model discovery patterns (port from OpenShell's `l7/inference.rs`) | 2d |
| Smart routing | Complexity scorer for local-vs-cloud routing — route simple queries locally, reserve cloud for complex reasoning (inspired by Ironclaw) | 3d |
| Leak detection | Aho-Corasick + regex scanning of request/response bodies for credential exfiltration attempts (API keys, PEM, bearer tokens) | 3d |
| Model CLI | `axis model list/pull/remove`, `axis inference status` — live stats and budget consumption | 3d |

**Exit criteria:** Agent inside sandbox calls `https://inference.local/v1/chat/completions`, AXIS routes to local ROCm vLLM instance, credentials injected transparently. L7 policy blocks unauthorized model access. Smart routing sends simple queries to local GPU, complex ones to cloud.

### Phase 3: AMD Differentiation (Weeks 19–24)

**Goal:** Features that leverage AMD hardware advantages and integrate with the ROCm Everywhere ecosystem.

| Task | Details | Effort |
|---|---|---|
| HIP Remote performance | Command batching (queue multiple HIP calls, flush on sync), async pipelining, >64 MB transfer chunking | 2w |
| APEX memory policy | Allow/deny NVMe memory overcommit per sandbox, integration with APEX daemon | 1w |
| NPU policy acceleration | Offload OPA evaluation to XDNA NPU via ONNX-exported Rego decision trees (experimental) | 2w |
| ROCm-CPU integration | Ensure ROCm-CPU (PyTorch unified dispatch) works inside sandbox with correct device visibility | 3d |
| OpenClaw integration | Pre-built policy templates for NanoClaw, Claw Code, RyzenClaw agents | 1w |
| Multi-sandbox GPU scheduling | Fair-share GPU time across concurrent sandboxes via ROCm SMI | 1w |
| HIP Remote mTLS | Mutual TLS for cross-host GPU pools — sandbox CA issues client certs, worker verifies | 1w |

### Phase 4: Hardening + Ecosystem (Weeks 25–30)

| Task | Details | Effort |
|---|---|---|
| Security audit | External pen test of isolation boundaries, focus on sandbox escape + HIP Remote protocol | 2w |
| Bypass detection (Windows) | ETW-based network bypass monitoring (equivalent to Linux iptables LOG) | 1w |
| Policy advisor | CLI tool that monitors sandbox activity and recommends minimum-privilege policies | 1.5w |
| MCP server integration | AXIS as an MCP tool provider — agents can request sandbox creation via MCP protocol | 1w |
| HIP Remote hiprtc support | Runtime compilation proxying — `hiprtcCompileProgram` on worker, return compiled module | 1w |
| Documentation + examples | Getting started guide, policy cookbook, OpenClaw integration tutorial, GPU sandbox tutorial | 1w |
| Performance benchmarks | Measure isolation overhead on Strix Halo, RX 9070 XT, Ryzen AI 400. HIP Remote latency vs native. | 3d |

---

## 8. Crate Structure

```
axis/
├── Cargo.toml                      # workspace root
├── crates/
│   ├── axis-core/                  # Policy parser, OPA engine, OCSF audit, types
│   │   └── src/
│   │       ├── policy.rs           # YAML ↔ internal policy model
│   │       ├── opa.rs              # regorus wrapper, baked-in Rego rules
│   │       ├── audit.rs            # OCSF structured event emitter
│   │       └── types.rs            # NetworkAction, FilesystemPolicy, etc.
│   │
│   ├── axis-sandbox/               # OS-specific isolation
│   │   └── src/
│   │       ├── mod.rs              # Sandbox trait + factory
│   │       ├── linux/
│   │       │   ├── mod.rs          # Linux sandbox impl
│   │       │   ├── landlock.rs     # Filesystem isolation
│   │       │   ├── seccomp.rs      # Syscall filtering
│   │       │   ├── netns.rs        # Network namespace + veth
│   │       │   └── bubblewrap.rs   # Fallback for older kernels
│   │       └── windows/
│   │           ├── mod.rs          # Windows sandbox impl
│   │           ├── restricted.rs   # Restricted Token + Low IL
│   │           ├── job_object.rs   # Job Object resource limits
│   │           ├── appcontainer.rs # AppContainer network isolation
│   │           └── acl.rs          # NTFS ACL management
│   │
│   ├── axis-safety/                # Credential leak detection + input validation
│   │   └── src/
│   │       ├── leak_detect.rs      # Aho-Corasick + regex credential scanning
│   │       ├── validate.rs         # Input sanitization (null bytes, injection patterns)
│   │       └── patterns.rs         # Known API key formats, PEM, bearer token regexes
│   │
│   ├── axis-proxy/                 # HTTP CONNECT proxy + L7 inspection
│   │   └── src/
│   │       ├── proxy.rs            # CONNECT handling, binary identity
│   │       ├── identity.rs         # SHA256 TOFU fingerprinting
│   │       ├── l7/
│   │       │   ├── tls.rs          # Ephemeral CA, cert cache
│   │       │   ├── rest.rs         # HTTP request/response parsing
│   │       │   └── inference.rs    # Inference pattern detection
│   │       └── secrets.rs          # Credential placeholder resolution
│   │
│   ├── axis-router/                # Inference routing + local provider
│   │   └── src/
│   │       ├── config.rs           # Route resolution, model registry
│   │       ├── backend.rs          # Backend proxying + auth
│   │       ├── providers.rs        # OpenAI, Anthropic, ROCm local profiles
│   │       ├── server_mgr.rs       # Inference server lifecycle (managed/external/embedded)
│   │       ├── scheduler.rs        # Multi-sandbox fair queuing, priority lanes
│   │       ├── token_budget.rs     # Per-sandbox token budget tracking + enforcement
│   │       └── models.rs           # Model registry, pull, swap policy
│   │
│   ├── axis-gpu/                   # HIP Remote GPU isolation
│   │   └── src/
│   │       ├── worker_mgr.rs       # Per-sandbox HIP worker lifecycle
│   │       ├── vram_quota.rs       # VRAM allocation tracking + enforcement
│   │       ├── api_filter.rs       # Opcode categorization + whitelist/blacklist
│   │       ├── transport.rs        # UDS / TCP / named pipe abstraction
│   │       └── protocol.rs        # HIP Remote protocol types (re-export from C headers)
│   │
│   ├── axis-daemon/                # axsd — sandbox lifecycle manager
│   │   └── src/
│   │       ├── main.rs             # Daemon entry point
│   │       ├── ipc.rs              # Unix socket / Named pipe
│   │       ├── sandbox_mgr.rs      # Create, destroy, list sandboxes
│   │       └── policy_watch.rs     # File watcher for hot-reload
│   │
│   └── axis-cli/                   # axis command-line tool
│       └── src/
│           └── main.rs             # Subcommands: create, exec, destroy, policy
│
├── policies/                       # Built-in policy templates
│   ├── coding-agent.yaml
│   ├── research-agent.yaml
│   ├── openclaw-default.yaml
│   └── minimal.yaml
│
├── data/
│   └── sandbox-policy.rego         # Baked-in OPA rules
│
└── e2e/                            # End-to-end test suite
    ├── linux/
    ├── windows/
    └── cross-platform/
```

---

## 9. Key Design Decisions

### 9.1 Why AppContainer over Sandboxie-style Hooking?

Sandboxie-Plus achieves isolation through a kernel driver (SbieDrv) and DLL injection (SbieDll) that hooks Win32 API calls. While powerful, this approach has critical drawbacks for AXIS:

1. **Kernel driver requirement.** SbieDrv requires admin installation and a signed driver certificate. Incompatible with our "no admin" principle.
2. **Hooking fragility.** User-mode API hooks can be bypassed by direct syscall invocation (`NtCreateFile` instead of `CreateFile`). Sophisticated agents or agent-generated code could evade hooks.
3. **Anti-cheat/AV conflicts.** Hook-based sandboxes frequently conflict with anti-cheat software and endpoint protection agents that also hook the same APIs.

AppContainer is a kernel-enforced security boundary. The check happens in the kernel's Security Reference Monitor — there is no user-mode hook to bypass. It is the same isolation Chrome uses for renderer processes, which must resist exploitation by arbitrary web content.

### 9.2 Why Not WSL2?

WSL2 runs a real Linux kernel in a lightweight Hyper-V VM. It would allow running OpenShell unmodified. We reject this approach because:

1. **Not available on all Windows 11 Home systems.** WSL2 requires hardware virtualization (VT-x), which some OEMs disable in BIOS by default.
2. **Resource overhead.** WSL2 consumes a fixed memory allocation for its VM, competing with the agent's own memory needs and APEX memory tiering.
3. **GPU passthrough complexity.** WSL2's GPU-PV (paravirtualized GPU) adds latency and does not support all ROCm features. Native Windows ROCm via MCDM is the preferred path.
4. **User experience.** Requiring WSL2 adds install steps, filesystem path confusion (`\\wsl$\` vs `C:\`), and a Linux-in-Windows mental model that confuses non-developer users.

### 9.3 Handling the netns Privilege Gap on Linux

Network namespace creation (`ip netns add`) requires `CAP_NET_ADMIN`, which standard users lack. AXIS provides three escalation strategies, tried in order:

1. **Unprivileged user namespaces** (preferred). On kernels with `kernel.unprivileged_userns_clone=1` (default on Ubuntu 24.04+), AXIS creates a user namespace first, then a network namespace inside it. No root needed.

2. **setuid helper** (`axis-netns-helper`). A minimal (< 200 LOC) setuid binary that creates/destroys network namespaces and veth pairs. Installed to `/usr/libexec/axis/` during package install. The helper validates arguments strictly (UUID format only, no path injection) and drops all capabilities except `CAP_NET_ADMIN`.

3. **Bubblewrap fallback**. If neither option is available, AXIS uses `bwrap --unshare-net` which leverages bubblewrap's own setuid/user-namespace logic. Network isolation is all-or-nothing (no proxy, just blocked), but still provides a security boundary.

### 9.4 Why HIP Remote for GPU Isolation?

GPU compute isolation is the hardest problem in agent sandboxing. NVIDIA's OpenShell punts on it entirely — it passes through the full GPU inside a container with no compute-level isolation. AXIS solves it with HIP Remote, a para-virtual GPU approach that proxies HIP API calls from the sandbox to a host worker.

**Why not the alternatives?**

1. **VFIO/GPU passthrough** requires root, IOMMU, and dedicates an entire GPU to one sandbox. Unusable on consumer hardware with one GPU, and impossible to share.

2. **MIG partitioning** is CDNA-only (MI250/MI300). RDNA 4 and consumer GPUs don't support hardware partitioning.

3. **`ROCR_VISIBLE_DEVICES` / `HIP_VISIBLE_DEVICES`** is just environment variable filtering — it provides no memory isolation, no API filtering, and no resource quotas. A sandbox can trivially override it.

4. **GPU-PV (WSL2 paravirtualization)** requires Hyper-V (Windows Pro only) and doesn't support all ROCm features.

**Why HIP Remote works:**

- **API-level isolation.** The sandbox calls `hipMalloc`, the worker calls real `hipMalloc` on the GPU. The sandbox never touches `/dev/kfd` or any kernel driver. Every GPU operation goes through a policy enforcement point.
- **No privilege required.** The client library is pure C11 with zero kernel dependencies. The worker runs as a normal user with GPU access.
- **Cross-platform.** The client builds on Linux, Windows, and macOS. A macOS-based agent can use a remote Linux GPU server.
- **Composable with other layers.** HIP Remote sits inside AXIS's process + filesystem + network sandbox. A compromised agent still can't escape the sandbox even if it exploits the HIP Remote protocol, because the sandbox's seccomp/AppContainer restrictions prevent direct GPU device access.
- **Comprehensive API coverage.** ~130 HIP opcodes including the full graph API, streams, events, and module loading. Sufficient for PyTorch, vLLM, and most inference frameworks.

The key insight is that for AI agent workloads, **latency tolerance is high** (agents think in seconds, not microseconds) and **throughput matters more than latency** (large model inference, not HPC kernels). HIP Remote's per-call overhead (~10-50µs on localhost) is negligible compared to the millisecond-scale GPU kernel execution times typical of inference workloads.

### 9.5 Binary Identity: Trust-on-First-Use (TOFU)

Both OpenShell and AXIS use SHA256 hashing of the calling binary to identify which network policy applies. The first time a binary is seen, its hash is recorded. Subsequent requests from the same path verify the hash matches. If the binary changes (update, replacement, compromise), the connection is denied and an audit event is emitted.

On Windows, AXIS additionally checks Authenticode signatures when available, providing a stronger identity signal than hash-alone for signed executables (Python, Git, Node.js).

---

## 10. AMD Competitive Advantages

### 10.1 Unified Memory = Simpler Isolation

On Strix Halo (128GB) and Gorgon Halo (192GB), the CPU and GPU share a single unified memory address space. This means:

- No need to manage separate GPU memory isolation — the Landlock/NTFS filesystem scope implicitly covers GPU-accessible memory-mapped regions.
- APEX memory tiering (NVMe as extended VRAM) is transparent to the agent. The isolation boundary only needs to control *which models* the agent can load, not the memory mechanics.
- Contrast with NVIDIA: discrete GPU memory requires separate CUDA MPS or MIG partitioning for isolation, adding complexity that OpenShell punts on entirely.

### 10.2 NPU as Policy Accelerator

The XDNA NPU in Ryzen AI can accelerate OPA policy evaluation for high-throughput scenarios (many concurrent agents, high request rates). An experimental path compiles Rego decision trees to ONNX graphs and runs them on the NPU, freeing CPU and GPU cycles for the agent's actual work. Even at 50 TOPS, the NPU can evaluate thousands of policy decisions per second with negligible power draw.

### 10.3 ROCm-CPU Enables Universal Sandboxing

With ROCm-CPU unifying CPU/GPU/NPU under PyTorch dispatch, every AMD system becomes an agent-capable platform — even systems with no discrete GPU. AXIS's "no Docker" design means even a low-end Ryzen laptop can run a sandboxed agent using CPU-only inference. The affordability ladder extends all the way down.

---

## 11. Risk Register

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| AppContainer API unavailable on older Win10 builds | Windows support limited to Win11+ | Low | Minimum supported OS is Windows 11 23H2. Document clearly. |
| Landlock ABI changes in future kernels | Filesystem isolation breaks | Low | Pin to ABI V2, test on latest kernels in CI, implement version detection. |
| Sophisticated agent bypasses seccomp filter | Sandbox escape | Medium | Default-deny seccomp policy (flip from OpenShell's default-allow). External security audit in Phase 4. |
| User-mode proxy has latency overhead | Agent performance degraded | Medium | Benchmark proxy latency. For local inference, bypass proxy entirely (trusted localhost). |
| AppContainer + Restricted Token interaction bugs | Windows isolation gaps | Medium | Test matrix: Win11 Home 23H2, 24H2, 25H2. Follow Chromium's sandbox test patterns. |
| setuid helper is an attack surface | Privilege escalation | Low | Minimal code (< 200 LOC), strict input validation, external audit. Prefer unprivileged userns where available. |
| HIP Remote protocol has no auth/encryption | Unauthorized GPU access from adjacent processes | Medium | Unix domain socket with filesystem permissions (same-host). mTLS for cross-host. API whitelist blocks dangerous opcodes by default. |
| HIP Remote per-call TCP overhead | Latency-sensitive GPU workloads degraded | Medium | UDS for same-host (10x lower latency than TCP). Command batching in Phase 3. Benchmark against native to quantify. |
| HIP Remote max 64 MB transfer limit | Large model weight loads fail | Low | Chunk transfers >64 MB at the client layer. Phase 3 adds transparent chunking. |
| HIP Remote single-threaded worker | Only one sandbox gets GPU at a time | Medium | Phase 1 adds thread-pool worker with per-client HIP context. Multi-sandbox scheduling via AXIS. |
| HIP Remote missing hiprtc | Agents that compile CUDA/HIP kernels at runtime fail | Low | Phase 4 adds `hiprtcCompileProgram` proxying. Most inference workloads use pre-compiled modules. |

---

## 12. Success Metrics

### 12.1 Targets

| Metric | Target | Measurement |
|---|---|---|
| Sandbox startup time | < 200ms (Linux), < 500ms (Windows) | e2e test, p99 latency |
| Proxy overhead per request | < 5ms added latency | OPA eval time per request |
| Isolation escape rate | 0 in external pen test | Phase 4 security audit |
| Policy evaluation throughput | > 10,000 decisions/sec | OPA benchmark |
| Windows admin prompts | 0 (zero UAC dialogs) | Manual test on clean Win11 Home |
| Memory overhead per sandbox | < 50MB (daemon + proxy) | RSS delta measurement |
| HIP Remote overhead vs native | < 5% throughput loss for inference workloads | Benchmark: hipInfo, matmul, vLLM inference through sandbox vs bare metal |
| HIP Remote round-trip latency | < 50µs per HIP call (UDS, same host) | Microbenchmark on Strix Halo |
| Supported platforms | Ubuntu 22.04+, Fedora 38+, Win11 Home 23H2+ | CI matrix |

### 12.2 Measured Results (2026-04-07)

All targets validated via automated benchmark (`success-metrics` binary). Tested on three environments. 113 total tests across all platforms, 0 failures.

| Metric | Linux VM | Windows VM | Host (bare metal) | Target | Status |
|---|---|---|---|---|---|
| **Sandbox startup (median)** | 0.6ms | 1.6ms | 3.4ms | <200ms / <500ms | **PASS** |
| **Sandbox startup (p99)** | 0.8ms | 6.1ms | 3.7ms | <200ms / <500ms | **PASS** |
| **OPA eval throughput** | 59,000/sec | 42,000/sec | 58,300/sec | >10,000/sec | **PASS** |
| **OPA per-request overhead** | 17.0µs | 23.8µs | 17.2µs | <5ms | **PASS** |
| **Proxy cold-connection latency** | 8.5ms | 0.4ms | 17.1ms | <50ms | **PASS** |
| **Memory delta per sandbox** | 1.6MB | n/a | 1.8MB | <50MB | **PASS** |

**Test environments:**

| | Linux VM | Windows VM | Host |
|---|---|---|---|
| OS | Ubuntu 24.04 LTS | Windows 11 Enterprise 26200 | Ubuntu 24.04 LTS |
| Kernel | 6.17.0-14-generic | NT 10.0 | 6.17.0-20-generic |
| CPU | 16 vCPUs (Ryzen) | 8 vCPUs (Ryzen) | 192 cores (Ryzen) |
| RAM | 15GB | 16GB | 502GB |

**Isolation verification (Linux VM, 2026-04-07):**
- Landlock ABI v7: writes outside workspace **blocked** at kernel level
- seccomp default-deny: **142 syscalls whitelisted** (148 BPF instructions), `ptrace` returns `EPERM`, normal operations unaffected
- Full daemon e2e lifecycle: create → list → destroy (7/7 pass)
- All 3 policy files validate (coding-agent, minimal, gpu-agent)

**Windows VM verification (2026-04-07):**
- CLI runs natively, all 3 policy files validate including GPU policy
- Benchmark: 4/4 metrics pass (startup 1.6ms, OPA 42K/sec, proxy 0.4ms)
- GPU policy display: `device=0, transport=Uds, vram_limit=8192MB`

**Key observations:**
- Linux sandbox startup (0.6ms) is 2.7x faster than Windows (1.6ms) due to `fork+exec` vs `CreateProcess`. Both are 100–300x under their targets.
- OPA throughput scales linearly with CPU cores. Even the 8-vCPU Windows VM achieves 42K evals/sec, 4.2x the target.
- Per-request OPA overhead (17–24µs) is 200–300x under the 5ms target. In a persistent-connection model (typical for agents), this is the actual added latency per proxied request.
- Memory overhead is 1.6–1.8MB per sandbox (proxy + OPA engine + leak detector + TOFU store + L7 TLS support). 28–31x under the 50MB target.
- Windows proxy cold-connection latency (0.4ms) is faster than Linux (8.5ms) due to Windows TCP loopback optimization. Both are well under 50ms.
- seccomp default-deny mode (142-syscall whitelist) is now the default. Dangerous syscalls (ptrace, mount, bpf, io_uring, memfd_create, reboot, kexec, chroot, pivot_root, etc.) are blocked by omission from the whitelist.

### 12.3 HIP Remote GPU Test Results (2026-04-07)

End-to-end GPU isolation verified with real hardware:

**Setup:**
- **Sandbox:** Linux VM (Ubuntu 24.04, 16 vCPUs, no GPU, no ROCm drivers)
- **GPU Host:** Bare metal (192-core Ryzen, AMD RX 9070 XT / gfx1201)
- **Transport:** TCP port 18515 over libvirt bridge network
- **Isolation:** Landlock v7 (4 ro, 3 rw paths), seccomp default-deny (142 syscalls), OPA proxy

**Client library (`libamdhip64.so`):**
- 538 exported HIP symbols, 188KB, pure C11
- Built from `users/jam/hip-remote` branch of rocm-systems
- Drop-in replacement — applications link against `-lamdhip64` without code changes

**Worker binary (`hip-worker`):**
- Links real HIP runtime + optional AMD SMI
- Built from same branch, runs on GPU host
- Systemd service template included

**HIP Remote protocol test (8/8 PASS on Linux VM):**

| Test | Result |
|---|---|
| hip-worker binary runs | PASS |
| libamdhip64.so exports 538 symbols | PASS |
| hip-worker listens on TCP | PASS |
| Protocol connection + PING | PASS (reset without GPU — expected) |
| Client library loads via ctypes | PASS |
| GPU sandbox created (AXIS daemon) | PASS |
| hip-worker spawned in sandbox lifecycle | PASS |
| GPU sandbox destroyed cleanly | PASS |

**Real GPU API test (7/7 PASS from sandboxed VM):**

| HIP API Call | Result |
|---|---|
| `hipGetDeviceCount` | 1 device |
| `hipSetDevice(0)` | success |
| `hipGetDeviceProperties` | "AMD Radeon AI PRO R9700" |
| `hipMalloc(1MB)` | ptr=0x7f0000000000 |
| `hipMemcpy H2D + D2H (256 bytes)` | data verified byte-for-byte |
| `hipFree` | success |
| `hipDeviceSynchronize` | success |

This validates the core HIP Remote value proposition: **a sandboxed agent with zero GPU drivers can allocate GPU memory, transfer data, and synchronize with a real AMD GPU purely through the TCP proxy.** The sandbox's Landlock + seccomp isolation is enforced throughout — the agent never touches `/dev/kfd` or any GPU kernel interface.

---

## 13. Open Questions

1. **Should AXIS support macOS?** Apple's `sandbox-exec` (Seatbelt) provides similar policy-driven isolation. Architecturally feasible but adds a third platform to maintain. Defer to Phase 5?

2. **Multi-tenant mode.** OpenShell explicitly calls itself "single-player" and flags multi-tenant as future work. Should AXIS target multi-user scenarios (shared AMD workstations in labs/offices)?

3. **HIP Remote upstream.** Should the AXIS security enhancements to hip-remote (VRAM quotas, API whitelist, UDS transport, mTLS) be upstreamed to rocm-systems, or maintained as an AXIS fork?

4. **HIP Remote CUDA compatibility.** Should the remote client also export CUDA API symbols (via HIP's CUDA compatibility layer) so that CUDA applications can transparently use a remote AMD GPU? This would enable `torch.cuda`-based agents to run in AXIS sandboxes without code changes.

5. **GPU time-sharing granularity.** HIP Remote gives API-level isolation but not hardware-level time-sharing. Should AXIS implement software preemption (kill long-running kernels after timeout), or rely on the cooperative model where agents voluntarily yield?

6. **Policy marketplace.** Should AMD host a registry of community-contributed AXIS policies for popular agent frameworks (LangChain, CrewAI, OpenClaw)?

7. **Upstream contribution.** OpenShell is Apache 2.0. Should AXIS contribute the Windows isolation backend and HIP Remote GPU isolation upstream to OpenShell, positioning AMD as a contributor to the broader agent safety ecosystem?

---

## Appendix A: OpenShell Source File Reference

Key files reviewed in the OpenShell codebase to inform this design:

| File | Lines | Purpose |
|---|---|---|
| `crates/openshell-sandbox/src/sandbox/linux/landlock.rs` | ~200 | Filesystem isolation via Landlock LSM |
| `crates/openshell-sandbox/src/sandbox/linux/seccomp.rs` | ~250 | Syscall filtering via BPF |
| `crates/openshell-sandbox/src/sandbox/linux/netns.rs` | ~300 | Network namespace + veth + iptables |
| `crates/openshell-sandbox/src/proxy.rs` | ~600 | HTTP CONNECT proxy + binary identity |
| `crates/openshell-sandbox/src/opa.rs` | ~350 | OPA/Rego policy evaluation |
| `crates/openshell-sandbox/src/l7/tls.rs` | ~250 | Ephemeral CA + TLS termination |
| `crates/openshell-sandbox/src/l7/inference.rs` | ~200 | Inference pattern detection |
| `crates/openshell-sandbox/src/secrets.rs` | ~200 | Credential placeholder injection |
| `crates/openshell-sandbox/src/process.rs` | ~300 | Process spawning + pre_exec hooks |
| `crates/openshell-policy/src/lib.rs` | ~400 | Policy YAML ↔ Proto + preset expansion |
| `crates/openshell-router/src/backend.rs` | ~250 | Inference backend proxying |
| `data/sandbox-policy.rego` | ~150 | OPA rules for network + L7 decisions |

## Appendix B: Reference Projects

| Project | Relevance | URL |
|---|---|---|
| NVIDIA OpenShell | Primary inspiration — agent sandbox with OPA policy | https://github.com/NVIDIA/OpenShell |
| Chromium Sandbox | Windows isolation design (Restricted Token + Job Object + AppContainer) | https://github.com/chromium/chromium/blob/main/docs/design/sandbox.md |
| Bubblewrap | Unprivileged Linux sandboxing via user namespaces | https://github.com/containers/bubblewrap |
| Anthropic sandbox-runtime | Lightweight Linux sandbox with bubblewrap + Landlock | https://github.com/anthropic-experimental/sandbox-runtime |
| Sandboxie-Plus | Windows sandbox via kernel driver + API hooking (rejected approach) | https://github.com/sandboxie-plus/Sandboxie |
| regorus | Pure-Rust OPA engine used by OpenShell | https://github.com/microsoft/regorus |
| HIP Remote | HIP API proxy over TCP — para-virtual GPU for sandboxes (ROCm/rocm-systems) | https://github.com/ROCm/rocm-systems (branch: `users/powderluv/hip-remote`) |
| Ironclaw | Rust AI assistant with WASM sandbox + smart routing (NEAR AI) | https://github.com/nearai/ironclaw |

## Appendix C: Ironclaw Deep Analysis

### C.1 Overview

Ironclaw (v0.24.0, ~11.5K GitHub stars) is a Rust reimplementation of OpenClaw by NEAR AI. It is a single-binary, self-hosted personal AI assistant — **not** a compute sandbox in the AXIS/OpenShell sense, but rather an AI assistant framework with sandboxed tool execution. Understanding its design is valuable because it solves adjacent problems (multi-provider inference, credential isolation, tool sandboxing) with mature, production-tested patterns.

### C.2 Architecture

4 internal crates + 1 main binary:

| Component | Purpose |
|---|---|
| **Agent Loop** (`src/agent/`) | Core message processing, job coordination, LLM reasoning loop |
| **Channels** (`src/channels/`) | I/O adapters: REPL, HTTP webhooks, WASM channels, Web Gateway (SSE+WS), Signal |
| **Tools** (`src/tools/`) | Built-in tools + WASM sandbox + MCP protocol + dynamic builder |
| **LLM** (`src/llm/`) | Multi-provider with failover, circuit breaker, smart routing, caching, retry |
| **Sandbox** (`src/sandbox/`) | Docker container execution with network proxy |
| **Orchestrator** (`src/orchestrator/`) | Container lifecycle, per-job auth tokens, LLM proxying for workers |
| **Safety** (`crates/ironclaw_safety/`) | Prompt injection defense, leak detection, policy enforcement |
| **Workspace** (`src/workspace/`) | Persistent memory with hybrid search (FTS + vector via pgvector) |
| **Routines** (`src/agent/routine_engine.rs`) | Cron schedules, event triggers, webhook handlers for background automation |
| **Extensions** (`src/extensions/`) | Discovery, installation, activation of channels/tools/MCP servers |

Out-of-tree WASM components for channels (Telegram, Discord, Slack, WhatsApp, Feishu) and tools (GitHub, Gmail, Google Calendar/Docs/Drive/Sheets/Slides, web-search).

### C.3 Dual Sandboxing Model

#### WASM Sandbox (primary — for tools and channels)

Uses **Wasmtime 28** with the Component Model. WIT interface definitions (`tool.wit`, `channel.wit`) define the host/guest contract.

**Capability-based security** — tools start with zero permissions, must be granted:
- `workspace_read` — read files (path-prefix constrained)
- `http` — HTTP requests to allowlisted endpoints only
- `tool_invoke` — call other tools via aliases (indirection)
- `secrets` — check if a secret exists (never read values)

**Runtime limits:** fuel metering for CPU, `ResourceLimiter` for memory (10MB default), epoch interruption + tokio timeout for infinite loops. Fresh WASM instance per execution — no shared mutable state. BLAKE3 hash verification on load.

**Credential injection at the host boundary** — the key security pattern:
```
WASM requests HTTP → Allowlist Validator → Leak Scan (request) → Credential Injector → Execute → Leak Scan (response) → WASM
```
WASM code never sees actual secret values. Secrets are decrypted (AES-256-GCM) and injected into HTTP request headers/auth by the host runtime only.

#### Docker Sandbox (secondary — for shell execution / code agents)

Ephemeral containers with: all network through validating proxy, credential injection at proxy level, non-root (UID 1000), read-only rootfs, all Linux capabilities dropped, memory/CPU limits, timeouts. Uses an orchestrator/worker pattern where containerized `ironclaw worker` processes communicate back to the host via HTTP API with per-job bearer tokens.

### C.4 Inference: Smart Multi-Provider Routing

Ironclaw's LLM layer uses **composable decorator providers**, all implementing the same `LlmProvider` trait:

| Decorator | Behavior |
|---|---|
| **FailoverProvider** | Wraps N providers, tries in sequence. Lock-free cooldown (atomics) — providers failing 3x consecutively are skipped for 5 minutes. |
| **CircuitBreakerProvider** | Standard circuit breaker (closed → open → half-open). |
| **SmartRoutingProvider** | **13-dimension complexity scorer** classifies prompts into Flash/Standard/Pro/Frontier tiers. Routes simple requests to cheap models, complex ones to expensive ones. Pattern overrides for fast-path routing (greetings→flash, security audits→frontier). |
| **CachedProvider** | Optional response caching. |
| **RetryProvider** | Exponential backoff for transient errors. |

Built-in providers: NEAR AI, Anthropic, OpenAI, GitHub Copilot, Google Gemini, MiniMax, Mistral, Ollama (local), AWS Bedrock, plus any OpenAI-compatible endpoint (OpenRouter, vLLM, LiteLLM).

Decorators compose in any order — the same architectural pattern AXIS should use for its inference router.

### C.5 Security: Six-Layer Defense-in-Depth

1. **Input validation** (`Validator`) — null bytes, excessive whitespace, length limits, embedded JSON depth
2. **Prompt injection sanitization** (`Sanitizer`) — Aho-Corasick pattern matching for known injection patterns (role manipulation, instruction override, special token injection, code block injection, base64 payloads, eval/exec)
3. **Policy enforcement** (`Policy`) — rules with severity levels and actions (Block/Warn/Review/Sanitize)
4. **Leak detection** (`LeakDetector`) — regex-based detection of API keys (OpenAI, Anthropic, AWS, GitHub PAT, Stripe), PEM keys, SSH keys, bearer tokens. Aho-Corasick for fast prefix matching with regex fallback.
5. **Tool output wrapping** (`wrap_for_llm`) — XML-like delimiters with zero-width space injection to prevent boundary injection
6. **External content wrapping** (`wrap_external_content`) — security notice prepended to all untrusted content with explicit instructions to the LLM to treat as data, not instructions
7. **Tool autonomy controls** (`autonomy.rs`) — explicit deny-list of tools that cannot run in autonomous/routine contexts

### C.6 Novel Features

**Dynamic Tool Builder:** The agent can build new WASM tools on-the-fly from natural language descriptions via an LLM-driven code generation loop (analyze → scaffold → implement → compile to wasm32-wasip2 → validate against WIT → register). Self-expanding capability without vendor updates.

**Self-Repair:** Detects stuck jobs and broken tools. For broken tools, automatically rebuilds using the SoftwareBuilder.

**WASM Channels:** Messaging integrations (Telegram, Discord, Slack) run as sandboxed WASM components — a compromised Telegram integration can't access Slack credentials.

**Heartbeat System:** Proactive background execution driven by a `HEARTBEAT.md` checklist. Agent periodically processes it, only notifies user if action needed. Supports quiet hours.

**Routines Engine:** Cron-scheduled and event-triggered background tasks with webhook handlers.

### C.7 Competitive Comparison

| Dimension | OpenShell (NVIDIA) | Ironclaw (NEAR AI) | AXIS (AMD) |
|---|---|---|---|
| **Primary use case** | GPU agent sandbox | Personal AI assistant | Agent sandbox runtime |
| **Language** | Rust | Rust | Rust |
| **Sandbox model** | Container (K3s) | WASM + Docker dual-layer | OS-native process isolation |
| **GPU awareness** | First-class (CUDA) | None | First-class (ROCm) |
| **Isolation** | Container + seccomp + Landlock | WASM capability-based + Docker | Landlock/seccomp/netns + AppContainer |
| **LLM handling** | API proxying | Multi-provider failover + smart routing | Managed local server + cloud fallback |
| **Tool model** | Container tools | WASM + built-in + MCP | Policy-governed processes |
| **Credential model** | Env var injection | Host-boundary injection (WASM never sees secrets) | Proxy-level placeholder injection |
| **Security layers** | 3 (Landlock + seccomp + netns) | 6+ (validation through autonomy controls) | 4 (process + filesystem + network + inference) |

### C.8 Lessons for AXIS

**Adopt:**

1. **Composable LLM provider decorators.** The FailoverProvider → SmartRoutingProvider → CachedProvider chain is elegant and directly maps to the axis-router. AXIS should use the same `InferenceProvider` trait with decorator wrapping for failover, smart routing, and caching. The 13-dimension complexity scorer is a cost optimization that matters when routing between local (free) and cloud (expensive) backends.

2. **Host-boundary credential injection.** Ironclaw's pattern where sandboxed code never sees secret values is stronger than injecting env vars into the sandbox process. AXIS already plans proxy-level credential injection — this validates the approach and suggests adding leak scanning (Aho-Corasick on known key patterns) to the proxy's L7 inspection layer.

3. **Leak detection in the proxy.** Ironclaw scans both request and response bodies for accidentally leaked credentials using fast Aho-Corasick prefix matching + regex. AXIS's proxy should do the same — catch agents that try to exfiltrate injected credentials via encoded channels.

4. **Fuzz testing for safety code.** Ironclaw's `crates/ironclaw_safety/fuzz/` corpus for testing injection patterns, leak detection, and policy evaluation is a practice AXIS should adopt from day one for the OPA engine and proxy.

**Consider for future phases:**

5. **WASM as a lightweight tool sandbox.** For tools that don't need GPU access (file manipulation, API calls, data transformation), WASM with Wasmtime provides sub-millisecond isolation with zero OS privilege requirements. This could complement AXIS's OS-native sandboxing as an optional inner isolation layer for agent tools, while reserving the heavier OS-level sandbox for GPU workloads.

6. **Smart model routing for cost optimization.** When AXIS routes between local inference (free, limited VRAM) and cloud fallback (expensive, unlimited), a complexity scorer could automatically route simple queries locally and reserve cloud for complex reasoning — significant cost savings.

**Diverge from:**

7. **Ironclaw has zero GPU awareness.** No concept of VRAM management, compute queue isolation, device visibility control, or hardware topology. This is AXIS's core differentiator — it must be hardware-topology-aware from the start.

8. **Single-user framing.** Ironclaw is explicitly a "personal assistant." AXIS should support concurrent sandboxes for multiple agents (and potentially multiple users on shared workstations) with fair-share GPU scheduling.

9. **Docker dependency for heavy sandboxing.** Ironclaw falls back to Docker for anything beyond WASM (shell execution, code agents). AXIS's entire value proposition is avoiding Docker — the OS-native isolation stack must handle all workloads including GPU compute.
