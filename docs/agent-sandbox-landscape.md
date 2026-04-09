# Securing AI Agents: Landscape Assessment and the AXIS Approach

**Date:** April 2026

---

## 1. The Problem

Self-hosted AI agents combine two dangerous supply chains into a single execution loop: **untrusted code** (skills, extensions, plugins) and **untrusted instructions** (external content, prompt injection). Both execute with the user's credentials, filesystem access, and network connectivity.

The Microsoft Defender Security Research team articulated this clearly in their February 2026 assessment of OpenClaw runtimes:

> *"OpenClaw should be treated as untrusted code execution with persistent credentials. It is not appropriate to run on a standard personal or enterprise workstation."*

Their recommended mitigations — dedicated VMs, manual credential rotation, periodic state review, and a stack of enterprise monitoring products — are sound defensive advice. But they are also an acknowledgment that today's agent runtimes lack proper isolation primitives.

This document surveys the current landscape of agent sandboxing technologies, assesses their strengths and gaps, and describes how AXIS addresses each concern at the kernel level — without VMs, containers, or enterprise licensing.

---

## 2. Agent Framework Sandboxing: Current State

### 2.1 Comparison Matrix

| Framework | Isolation Mechanism | Startup | GPU | Network Isolation | Credential Protection | Root Required | Platforms |
|---|---|---|---|---|---|---|---|
| **AXIS** | Landlock + seccomp + netns (Linux), AppContainer + Job Object (Windows), Seatbelt (macOS) | **0.6ms** | **HIP Remote** (538 APIs, VRAM quotas) | netns + iptables + OPA proxy | Proxy-level injection + leak detection | **No** | Linux, macOS, Windows |
| **Claude Code** | bubblewrap (Linux), Seatbelt (macOS) | ~ms | None | Proxy-based filtering | Allowlist-only FS | No | Linux, macOS |
| **Codex CLI** | Seatbelt (macOS), bubblewrap (Linux), native (Windows) | ~ms | None | Disabled by default | Workspace-scoped FS | No | macOS, Linux, Windows |
| **Cursor** | Seatbelt (macOS), Landlock+seccomp (Linux), WSL2 (Windows) | ~ms | None | Disabled by default | Workspace + overlay FS | No | macOS, Linux, Windows |
| **OpenClaw** | Docker container | ~seconds | Optional (Docker GPU) | `network: none` | Bind-mount restrictions | Docker daemon | Linux |
| **Devin** | Cloud VM (per-session) | N/A (cloud) | Not documented | VM-level | Single-tenant VPC | N/A | Cloud only |
| **Cline / Roo Code** | **None** (permission prompts only) | N/A | N/A | None | None | No | Any (VS Code) |
| **NVIDIA OpenShell** | K3s container + Landlock + seccomp + netns | ~seconds | Experimental (NVIDIA Container Toolkit) | Policy-enforced egress | OPA policy engine | Docker daemon | Linux |

### 2.2 Key Observations

**The industry has converged on OS-native primitives.** Claude Code, Codex CLI, and Cursor all use the same approach: Seatbelt on macOS, bubblewrap or Landlock+seccomp on Linux. This validates the architecture AXIS uses. The difference is that these tools apply sandboxing only to their own tool-execution subprocess — not to the full agent runtime with GPU, inference, and network policy.

**No framework addresses GPU isolation.** Claude Code, Codex, and Cursor don't provide GPU access at all. OpenClaw uses Docker GPU passthrough (full device access, no isolation). OpenShell has experimental NVIDIA Container Toolkit support. None provide per-sandbox VRAM quotas, API whitelisting, or compute timeouts.

**Cline/Roo Code have zero sandboxing.** They rely entirely on application-layer permission prompts, which any indirect prompt injection can bypass by manipulating the agent's reasoning.

**Container-based approaches (OpenClaw, OpenShell) require Docker daemon access**, which is effectively root-equivalent. They also have multi-second startup times and GB-scale memory overhead.

---

## 3. Standalone Sandboxing Technologies

### 3.1 Comparison Matrix

| Technology | Mechanism | Startup | Memory | GPU | Root Required | Platform |
|---|---|---|---|---|---|---|
| **AXIS** | Landlock + seccomp + netns + OPA proxy | **0.6ms** | **1.6MB** | **HIP Remote** | **No** | Linux, macOS, Windows |
| **Bubblewrap** | Linux user namespaces (pid/net/mount/uts) + seccomp | ~ms | Negligible | No | No | Linux |
| **Firecracker** | KVM microVM (own kernel) | ~125ms | <5 MiB | **No** (no PCIe passthrough) | Yes (KVM) | Linux |
| **gVisor** | User-space kernel (Go), syscall interception | ~seconds | ~84 MiB | NVIDIA only (nvproxy) | No (ptrace mode) | Linux |
| **Kata Containers** | Lightweight VM (QEMU/Cloud-Hypervisor) | ~150-300ms | ~20-30 MiB | VFIO passthrough | Yes (hypervisor) | Linux |
| **Anthropic sandbox-runtime** | bubblewrap + Landlock + proxy | ~ms | Negligible | No | No | Linux, macOS |

### 3.2 Assessment

**Bubblewrap** is the gold standard for lightweight Linux sandboxing — fast, no root, well-tested (used by Flatpak). AXIS uses it as a fallback when Landlock or netns aren't available. Its limitation: no network policy (it's all-or-nothing network deny), no GPU support, no credential injection.

**Firecracker** provides the strongest isolation (own kernel, own memory space) with impressive startup (~125ms, <5 MiB). However, it **cannot provide GPU access** — there is no PCIe passthrough in the microVM model. This is a fundamental limitation for AI agent workloads that need local inference. It also requires KVM (root/admin).

**gVisor** intercepts syscalls in a user-space kernel written in Go. It offers GPU support via `nvproxy` (NVIDIA only, limited ioctl allowlist), but at ~84 MiB overhead per sandbox and multi-second startup. The user-space kernel adds latency to every syscall.

**Kata Containers** uses lightweight VMs for container workloads. It supports GPU via VFIO passthrough, but this dedicates an entire GPU to one container — no sharing, no quotas. Requires a hypervisor (root).

**Anthropic sandbox-runtime** is the closest to AXIS's approach — bubblewrap + Landlock + network proxy. It's designed for Anthropic's own model evaluation sandboxes. No GPU support, limited policy configurability, no Windows/macOS.

---

## 4. How AXIS Addresses Each Concern

The Microsoft Defender Security Research article identifies six control domains for agent security. Here's how each is addressed:

### 4.1 Identity: Credential Protection

| Approach | Mechanism | Strength |
|---|---|---|
| Microsoft Defender Recommendation | Entra ID least-privilege + manual token rotation | Cloud-only, doesn't protect local credential files |
| OpenClaw | Docker bind-mount hides host dirs | Can be bypassed via /proc/self/root ([Snyk, March 2026](https://labs.snyk.io/resources/bypass-openclaw-security-sandbox/)) |
| Claude Code | Allowlist-only filesystem | Effective for tool execution, not full agent runtime |
| **AXIS** | Landlock denies `~/.ssh`, `~/.aws`, `~/.gnupg` at kernel level + proxy-level credential injection | Agent never sees real credentials. Kernel-enforced, not bypassable. |

**AXIS advantage:** Credentials are injected by the proxy at the HTTP boundary using placeholders (`axis:resolve:env:KEY`). The sandbox process never has the real credential in memory. Additionally, the leak detector scans all outbound traffic (including L7-decrypted HTTPS) for 11 credential patterns and blocks exfiltration.

### 4.2 Execution: Code Containment

| Approach | Mechanism | Syscall Coverage |
|---|---|---|
| Microsoft Defender Recommendation | VM (separate kernel) | Full isolation |
| OpenClaw | Docker container | ~300 syscalls (Docker default seccomp) |
| Codex/Claude Code | bubblewrap + seccomp | Varies |
| **AXIS** | seccomp default-deny whitelist | **142 syscalls allowed** of ~400. ptrace, mount, bpf, io_uring, memfd_create, reboot, kexec, chroot all blocked. |

**AXIS advantage:** Default-deny is strictly stronger than Docker's default-allow-with-blocklist. The 142-syscall whitelist was curated for Python/shell agent execution — everything not on the list returns EPERM. No framework other than AXIS uses default-deny seccomp for agents.

### 4.3 Network: Egress Control

| Approach | Mechanism | Bypassable? |
|---|---|---|
| Microsoft Defender Recommendation | Defender URL filtering (user-mode) | Yes (raw sockets, DNS tunneling) |
| OpenClaw | Docker `network: none` | All-or-nothing, no proxy |
| Claude Code | HTTP/SOCKS5 proxy | Application-level (agent could bypass) |
| **AXIS** | Kernel network namespace + veth + iptables + OPA proxy | **No** (kernel-enforced, iptables LOG detects bypass attempts) |

**AXIS advantage:** The sandbox has its own network stack (network namespace). The only route to the internet is through the AXIS proxy on 10.200.0.1. iptables rules LOG and REJECT any bypass attempt. Every CONNECT request is evaluated by the OPA engine against per-host, per-port, per-binary policy. On Windows, AppContainer with zero capabilities achieves the same kernel-level network deny. On macOS, Seatbelt profiles restrict network to localhost only.

### 4.4 Persistence: State Isolation

| Approach | Mechanism |
|---|---|
| Microsoft Defender Recommendation | "Review .openclaw/workspace/ regularly" (manual) |
| OpenClaw | Container ephemeral filesystem |
| **AXIS** | Landlock-enforced workspace-only writes + immutable policy |

**AXIS advantage:** The agent can only write to its workspace directory. Policy files are managed by the daemon, not the agent. `axis run` creates ephemeral sandboxes that are destroyed on exit — no persistent state to poison. Hot-reload of network/inference policy is daemon-managed; the agent cannot influence it.

### 4.5 GPU: Compute Isolation

| Approach | Mechanism | Sharing | Quotas |
|---|---|---|---|
| Microsoft Defender Recommendation | Not addressed | N/A | N/A |
| Firecracker | No GPU support | N/A | N/A |
| gVisor | nvproxy (NVIDIA only) | No | No |
| Kata | VFIO (full device) | No | No |
| OpenShell | NVIDIA Container Toolkit | Limited | No |
| **AXIS** | HIP Remote (TCP proxy, 538 HIP APIs) | **Yes** (multiple sandboxes share one GPU) | **Yes** (per-sandbox VRAM quotas, API whitelisting, compute timeouts) |

**AXIS advantage:** HIP Remote is the only technology that provides GPU isolation without hardware partitioning or device passthrough. The sandbox has zero GPU driver access — all HIP calls are proxied over TCP to a worker process. VRAM quotas prevent one agent from exhausting GPU memory. IPC and device-reset operations are blocked by default. Tested end-to-end: a sandboxed VM with no ROCm installation ran `hipMalloc`, `hipMemcpy`, and `hipDeviceSynchronize` on an AMD RX 9070 XT.

### 4.6 Monitoring: Audit and Detection

| Approach | Cost |
|---|---|
| Microsoft Defender Recommendation | Defender XDR + Sentinel + Purview ($50K+/yr) |
| **AXIS** | Built-in OCSF audit events + health endpoint ($0) |

**AXIS advantage:** Every policy decision (allow/deny), credential leak detection, sandbox lifecycle event, and bypass attempt is logged as a structured OCSF audit event. The daemon exposes an HTTP `/health` endpoint with sandbox count, uptime, and version. `axis logs <id>` shows per-sandbox stdout/stderr + audit events. No external monitoring product required.

---

## 5. Feature Gaps and Recommended Additions

Based on this landscape assessment, the following capabilities would further differentiate AXIS:

### 5.1 High Priority

| Feature | Rationale | Effort |
|---|---|---|
| **Skill/extension signing and verification** | OpenClaw's "poisoned skill" attack works because skills are unsigned code. AXIS should verify code signatures before allowing execution inside sandboxes. | 1-2 weeks |
| **Agent memory isolation** | Microsoft identifies memory/state poisoning as a key persistence vector. AXIS should offer encrypted, integrity-checked agent state that the agent can read but not tamper with (HMAC-verified). | 1 week |
| **Indirect prompt injection defense** | Ironclaw's sanitizer approach (Aho-Corasick for injection patterns, XML-wrapped tool output) should be integrated into AXIS's proxy L7 layer to scan inference responses before they reach the agent. | 1-2 weeks |
| **MCP tool sandboxing** | As agents increasingly use MCP servers, each MCP tool invocation should run in its own sub-sandbox with scoped permissions — not inherited from the parent agent sandbox. | 2 weeks |

### 5.2 Medium Priority

| Feature | Rationale | Effort |
|---|---|---|
| **NVIDIA GPU support via gVisor nvproxy** | HIP Remote covers AMD GPUs. For NVIDIA GPUs, integrate gVisor's nvproxy approach to provide sandboxed CUDA access without full device passthrough. | 2-3 weeks |
| **Firecracker microVM mode** | For highest-security deployments, offer a Firecracker backend as an alternative to process-level sandboxing. Trade 0.6ms → 125ms startup for full kernel isolation. | 2 weeks |
| **Workspace encryption at rest** | Encrypt the sandbox workspace directory with a per-sandbox key. Prevents data recovery from destroyed sandboxes. | 1 week |
| **Multi-agent communication policy** | When multiple sandboxed agents need to collaborate, define explicit inter-sandbox communication channels with policy-governed message passing. | 2 weeks |

### 5.3 Lower Priority

| Feature | Rationale | Effort |
|---|---|---|
| **ClawHub skill scanner** | Automatically scan skills before installation for known malicious patterns, obfuscated code, suspicious API usage. | 2 weeks |
| **Agent behavior profiling** | Build a baseline of normal agent behavior (syscalls, network destinations, file access patterns) and alert on deviations. Similar to the Microsoft Defender hunting queries but automated and built-in. | 3 weeks |
| **Supply chain attestation** | SLSA-style provenance attestation for agent skills and models. Verify the build chain from source to execution. | 2 weeks |

---

## 6. Conclusion

The agent sandboxing landscape is converging on OS-native primitives (Landlock, seccomp, Seatbelt) for lightweight isolation — Claude Code, Codex CLI, Cursor, and AXIS all use this approach. The question is no longer *whether* to sandbox agents but *how comprehensively*.

AXIS is unique in four ways:

1. **GPU isolation** — no other sandbox technology provides per-agent GPU access with VRAM quotas and API whitelisting
2. **Credential injection** — the agent never sees real credentials; they're injected at the proxy boundary
3. **Default-deny seccomp** — the strictest syscall policy of any agent sandbox (142 of ~400 allowed)
4. **Cross-platform from day one** — Linux (Landlock + seccomp + netns), Windows (AppContainer + Job Object), macOS (Seatbelt) with no admin privileges on any platform

The VM-based approach recommended by Microsoft Defender provides strong isolation but at unacceptable cost (startup, memory, admin, licensing) for the agent use case where sandboxes are created and destroyed continuously. Firecracker offers a middle ground but cannot do GPU. gVisor handles NVIDIA GPUs but at 84 MiB per sandbox.

AXIS provides kernel-level isolation at process-level cost: 0.6ms startup, 1.6MB memory, zero admin, zero licensing. For the specific threat model of AI agents — untrusted code + untrusted instructions + credential access + GPU compute — it is the most complete solution available.

---

## References

- [Microsoft: Running OpenClaw Safely](https://www.microsoft.com/en-us/security/blog/2026/02/19/running-openclaw-safely-identity-isolation-runtime-risk/) — Feb 2026
- [Anthropic: Claude Code Sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing)
- [OpenAI: Codex Sandboxing](https://developers.openai.com/codex/concepts/sandboxing)
- [Cursor: Agent Sandboxing](https://cursor.com/blog/agent-sandboxing)
- [OpenClaw Sandboxing Docs](https://docs.openclaw.ai/gateway/sandboxing)
- [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell)
- [Snyk: OpenClaw Sandbox Bypass](https://labs.snyk.io/resources/bypass-openclaw-security-sandbox/) — March 2026
- [Bubblewrap](https://github.com/containers/bubblewrap)
- [Firecracker](https://github.com/firecracker-microvm/firecracker)
- [gVisor GPU Support](https://gvisor.dev/docs/user_guide/gpu/)
- [Kata Containers GPU](https://github.com/kata-containers/kata-containers/blob/main/docs/use-cases/GPU-passthrough-and-Kata.md)
- [Anthropic sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
