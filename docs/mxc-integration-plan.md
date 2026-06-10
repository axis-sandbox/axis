# AXIS MXC Integration Plan

## Status And Scope

This is the current plan for integrating Microsoft Execution Containers (MXC)
as a selectable AXIS containment substrate. It defines the capability model,
backend coverage, verification requirements, and packaging constraints needed
for cross-platform backend support. The normative policy semantics are defined
in [AXIS Isolation Contract](axis-isolation-contract.md).

## Purpose

AXIS should be able to launch sandboxes through MXC backends while preserving
AXIS policy semantics for filesystem, network, process, credentials, inference,
resources, lifecycle, and audit. MXC should simplify backend execution where it
can enforce the requested behavior exactly. AXIS must continue to own policy
planning and fail-closed validation.

The integration must not treat MXC as a blanket security boundary. MXC is an
early preview and its own README warns that current profiles can be overly
permissive. AXIS therefore needs explicit capability checks, backend-specific
rejection paths, and tests that prove the observable sandbox behavior rather
than assuming a backend name implies a security property.

## Source Review Summary

### MXC Findings

MXC exposes a cross-platform JSON configuration model and a set of concrete
backends:

- Windows: `processcontainer`, `windows_sandbox`, `wslc`, `microvm`,
  `hyperlight`, `isolation_session`.
- Linux: `bubblewrap`, `lxc`, `microvm`, `hyperlight`.
- macOS: `seatbelt`.

Backend details to validate:

- Windows `processcontainer` resolves through MXC's process-container path and
  may use newer BaseProcessContainer APIs when available. AXIS must probe which
  OS features are actually active and gate host-impacting fallbacks such as
  DACL mutation behind explicit consent.
- Windows `windows_sandbox` is a VM backend with a daemon and guest agent. It
  provides a stronger boundary but currently ignores the shared filesystem and
  network policy sections in favor of VM mapping and guest firewall behavior.
- Windows `wslc` is an experimental WSL2 container path with image, resource,
  GPU, storage, and port-mapping configuration. AXIS must treat it as a
  container backend with Windows-hosted Linux semantics.
- Windows `isolation_session` is experimental and targets OS-managed agent
  sessions and identities. It is tied to newer Windows APIs and currently has
  one-shot and state-aware lifecycle considerations.
- Linux `bubblewrap` uses user, PID, IPC, and UTS namespaces; bind mounts the
  host root read-only; applies read-write, read-only, and denied path mounts;
  clears the environment; and runs through `sh -c`.
- Linux `bubblewrap` full network block is unprivileged through
  `--unshare-net`. Host allow/block lists can use firewall rules, but that path
  needs root or `CAP_NET_ADMIN` and is IPv4-focused.
- Linux `bubblewrap` proxy mode is cooperative: MXC injects proxy environment
  variables and shares the host network namespace. This is useful for tools
  that honor proxy variables but is not equivalent to AXIS strict proxy mode.
- Linux `lxc` provides a container rootfs, namespaces, bind mounts, and
  veth-scoped firewall policy. It requires LXC runtime setup and either root or
  an unprivileged LXC configuration.
- macOS `seatbelt` applies a generated TinyScheme profile through
  `sandbox_init`, supports filesystem, network, UI, nested PTY, keychain, and
  launch-method controls, and has no extra runtime dependency.
- macOS `seatbelt` is process-scoped rather than container-scoped. MXC does not
  support `network.proxy` on macOS.
- `microvm` and `hyperlight` are experimental VM-style backends. Nanvix
  `microvm` requires runtime artifacts and WHP/KVM access; current Nanvix docs
  say denied paths and networking are constrained. `hyperlight` is x86_64-only
  and KVM/WHP-backed; current code supports filesystem preopens and host-proxied
  network allow/block policy but rejects `network.proxy`. AXIS must probe exact
  semantics before depending on either backend for agent execution.
- MXC has useful validation patterns: experimental gates, parser tests, mock
  runners, explicit rejection of mixed backend sections, and test-only proxy
  binaries that are not production proxies.

### Behavioral References

OpenShell is useful as a behavioral reference for agent sandboxes, not as a
design template to copy wholesale. The patterns worth carrying forward are:

- explicit `inference.local` routing instead of rewriting arbitrary provider
  hosts;
- provider credentials projected to sandbox processes as placeholders while
  raw secrets stay on the host side;
- REST, WebSocket, and GraphQL L7 policy surfaces;
- dynamic updates for network, provider, and inference policy;
- managed e2e harnesses that create sandboxes and delete them on drop;
- bypass tests that assert raw TCP connections fail quickly when proxy-only
  networking is requested;
- GPU and runtime tests that compare sandbox behavior against a plain runtime
  and skip with explicit capability reasons when prerequisites are absent.

Bubblewrap is useful as a testing reference because its tests exercise
unprivileged namespace behavior directly, gate optional kernel features with
clear skips, and keep root-required setup in repeatable CI paths.

## Design Principles

### Contract Structure

The shared policy contract is defined in
[AXIS Isolation Contract](axis-isolation-contract.md). Backend and platform
work should be structured as:

- a cross-platform AXIS isolation contract that defines shared policy
  semantics, lifecycle invariants, credential rules, fail-closed behavior, and
  evidence requirements;
- platform appendices for Windows, Linux, and macOS that describe how each OS
  or backend can enforce those shared semantics;
- backend capability matrices that mark each policy surface as applied,
  rejected, ignored, weaker-only, or AXIS-owned.

Platform-specific material belongs in appendices or backend plans. The
normative top-level contract should be the shared AXIS policy contract.

### AXIS Owns Semantics

The AXIS policy schema remains the source of truth. Backend adapters translate
that policy into backend-specific config only after the planner has proven that
the backend can enforce the requested behavior.

Unsupported combinations must fail before spawn. A warning is not an acceptable
fallback for a security requirement.

### MXC Owns Backend Execution When Exact

MXC should own process, container, or VM launch when the selected backend can
represent the AXIS policy exactly enough for that mode. If MXC cannot represent
a required behavior, AXIS must either:

- enforce the behavior in an AXIS-owned layer around the MXC process;
- select another backend that can enforce it;
- reject the policy before spawn.

### Weaker Modes Must Be Named

Cooperative proxying is materially weaker than strict proxy isolation because
raw sockets and clients that ignore proxy variables can bypass it. AXIS may
support it only as an explicitly named policy or backend mode, never as an
implicit implementation of `network.mode: proxy`.

### Platform Code Stays Layered

Linux, macOS, and Windows backend details must stay behind platform adapters.
Shared AXIS code may reason about capabilities, but it must not inherit
platform-specific primitives such as Landlock, seccomp, cgroups, netns,
iptables, Seatbelt, Job Objects, AppContainers, or Hyper-V/WHP controls.

## Target Architecture

```text
AXIS policy
  -> policy validation
  -> backend capability planner
  -> backend adapter
       - AXIS native platform backends
       - MXC Windows process/container/VM backends
       - MXC Linux process/container/VM backends
       - MXC macOS seatbelt
       - MXC experimental VM-style backends
  -> AXIS-owned layers
       - strict proxy and bypass denial
       - provider placeholder and credential injection
       - inference.local routing
       - audit and denial reporting
       - lifecycle and cleanup accounting
```

Every backend adapter must expose:

- static capabilities;
- runtime probes;
- required host dependencies;
- exact, weaker, and unsupported policy outcomes;
- config translation;
- spawn and cleanup behavior;
- test hooks for fake and real executors.

## Capability Model

Add a backend capability model that records the following fields for each
backend:

- platform;
- backend name;
- stability: stable, preview, experimental;
- required executable or runtime artifacts;
- whether special host privileges are required;
- filesystem support: read-only, read-write, denied path masking, copy-in/out;
- process support: user identity, process group, pty, timeout, exec reuse;
- network support: block, allow, host allow/block, strict proxy, cooperative
  proxy, no network;
- resource support: process count, memory, CPU, cgroup, backend-native limits;
- credential handling surface: environment, argv, config file, host-only;
- inference compatibility: `inference.local`, TLS interception, streaming;
- stateful lifecycle support;
- cleanup responsibilities.

The planner should produce the contract-defined outcome for every
policy/backend pair:

| Outcome | Meaning |
| --- | --- |
| `Exact` | The backend and AXIS-owned layers can enforce the requested policy. |
| `ExactWithHostDependency` | The policy is enforceable only if a declared dependency is present. Missing dependency fails before spawn. |
| `WeakerOnly` | The backend offers a weaker behavior that must be selected explicitly by policy. |
| `Unsupported` | The policy/backend pair is rejected before spawn. |

The repository-owned backend map lives in `axis_core::capability_map`. Platform
adapters should consume those maps rather than inferring security properties
from backend names, executable names, or host-specific probes alone.

Process-style backend selection lives in `axis_core::process_backend`. That
facade catalogs AXIS-native and MXC process backends, records the config format
each adapter must generate, and returns only planner-approved launch plans to
platform code.

Container-style backend selection lives in `axis_core::container_backend`.
That facade keeps rootfs/image source, storage, bind mounts, and destroy-on-exit
requirements visible to the planner before an adapter emits MXC LXC or WSLC
configuration.

## Platform Coverage

Each platform needs the same planning artifacts: capability map, dependency
map, exact/weaker/unsupported policy outcomes, tests, packaging decisions, and
dead-code audit.

### Windows

Windows planning should map AXIS policy to MXC's process, session, container,
and VM backends while preserving AXIS expectations for AppContainer,
Restricted Token, Job Object, filesystem, UI, network, credentials, and
inference behavior.

Backends to evaluate:

- `processcontainer` for process-level isolation;
- `isolation_session` for OS-managed agent identity and state-aware sessions;
- `windows_sandbox` for VM isolation;
- `wslc` for Linux containers from a Windows host;
- `microvm` and `hyperlight` where experimental requirements are met.

Requirements:

- probe whether `processcontainer` is using legacy AppContainer behavior,
  BaseProcessContainer behavior, or a fallback path;
- gate host-impacting fallbacks such as DACL mutation behind explicit operator
  consent;
- reject policies that depend on host allow/block network filtering if the
  selected Windows backend cannot enforce them;
- keep UI, clipboard, input injection, keychain-equivalent, and desktop
  controls separate from Unix-specific policy concepts;
- map Job Object and backend-native resource limits into the shared capability
  model;
- preserve provider placeholder handling and host-side credential injection;
- prove `inference.local` behavior through mock providers;
- document Windows edition, build, feature, SDK, Hyper-V/WHP, WSL2, and
  Windows Sandbox prerequisites per backend.

### Linux

Linux planning should map AXIS policy to MXC process, container, and VM-style
backends while keeping the native Landlock + seccomp backend as a selectable
path until data justifies changing that.

Backends to evaluate:

- AXIS native Landlock + seccomp process backend;
- MXC `bubblewrap` process backend;
- MXC `lxc` container backend;
- MXC `microvm` and `hyperlight` experimental VM-style backends.

Requirements:

- translate filesystem read-only, read-write, and deny policies without losing
  deny-path masking or rejection semantics;
- use MXC `bubblewrap` block mode only when it maps to unprivileged
  `--unshare-net`;
- reject AXIS strict proxy policies unless AXIS strict proxy networking is
  installed around the MXC-launched process;
- represent MXC cooperative proxy only as a named weaker mode;
- keep AXIS seccomp enforcement where MXC does not provide equivalent syscall
  filtering;
- keep native Landlock + seccomp tests independent of MXC;
- expose LXC rootfs/image selection through a documented AXIS launch option or
  policy extension;
- probe KVM, LXC runtime, Hyperlight snapshot, cgroup, seccomp-notify, and
  user-namespace availability without mutating the host;
- benchmark native Linux, MXC Bubblewrap, MXC LXC, and experimental VM-style
  backends when available.

Host dependencies:

- `lxc-exec` from the pinned MXC build for MXC runtime validation;
- `bwrap` for real Bubblewrap tests;
- LXC runtime packages for LXC tests;
- KVM access and runtime artifacts for MicroVM/Hyperlight tests;
- no privileged helper for block-mode tests.

### macOS

macOS planning should map AXIS policy to MXC `seatbelt` while preserving the
current no-extra-runtime macOS model.

Backends to evaluate:

- AXIS native Seatbelt path;
- MXC `seatbelt`.

Requirements:

- map filesystem read-only, read-write, and deny policy to generated Seatbelt
  rules;
- map network block, allow, per-host allow/block, and proxy-related policy
  outcomes, rejecting `network.proxy` because MXC does not support it on
  macOS;
- model GUI access, LaunchServices launch mode, nested PTY, Keychain access,
  clipboard, and input-injection controls explicitly;
- preserve quickstart behavior without additional runtime packages;
- keep macOS-specific TinyScheme and launch-method details behind a macOS
  adapter;
- compare native AXIS Seatbelt and MXC Seatbelt policy coverage and startup
  behavior before deciding which one should be the default;
- document Xcode Command Line Tools and build-target requirements for source
  testing, while keeping runtime dependencies minimal for installed builds.

### Experimental VM-Style Backends

MicroVM and Hyperlight planning should stay cross-platform because both have
Windows and Linux variants in MXC.

Requirements:

- detect WHP/KVM, architecture, cargo features, runtime binaries, snapshots,
  and image homes;
- reject policies involving unsupported shell, pty, working-directory,
  network, denied-path, or subprocess semantics;
- prove command execution, timeout, stdout/stderr, copy-in/out, and cleanup
  behavior where supported;
- benchmark cold start, warm start, memory, and density;
- document whether each backend is suitable for full agent sessions, agent tool
  snippets, Python-only workloads, or high-risk task execution.

### Native Backend Retention

AXIS native platform backends remain valid alternatives until MXC-backed paths
match the required behavior.
Current process-backend retention decisions are documented in
[Native Backend Retention](native-backend-retention.md).
Current backend default decisions and benchmark evidence requirements are
documented in [Backend Default Decisions](backend-default-decisions.md).

Exit criteria for replacing a native backend:

- the MXC path matches required AXIS policy semantics;
- test coverage reaches the native path's relevant coverage;
- benchmark deltas are acceptable for the default use case;
- native-only capabilities are either replaced or intentionally dropped in
  public docs.

## Agent, Provider, And Inference Targets

The maintained target matrix is
[Agent, Provider, And Inference Targets](agent-provider-inference-targets.md).
AXIS should keep support for the existing agent policy templates and make MXC
backend selection transparent to the agent command where possible.

Targets:

- Claude Code, Codex, OpenCode, GitHub Copilot CLI, Gemini CLI, OpenClaw,
  Hermes-style agents, and BYO commands;
- provider profiles or equivalent config for OpenAI, Anthropic, GitHub,
  GitLab, Copilot, Google Vertex AI, generic providers, and local
  OpenAI-compatible endpoints;
- sandbox-visible provider values are placeholders or dummy values, not raw
  secrets;
- raw provider secrets are resolved only in the host-side AXIS proxy/router;
- `inference.local` remains the explicit managed inference endpoint;
- external provider hosts are governed by ordinary network policy rather than
  implicit inference interception;
- OpenAI-compatible chat completions, completions, responses, embeddings, and
  model discovery;
- Anthropic messages;
- local ROCm inference through the existing AXIS infrastructure when enabled.

HIP Remote remains in scope for compatibility, but MXC backend work should not
block on new HIP Remote functionality.

## Testing Strategy

Testing must be delivered by the repository and must not depend on installing a
locally built artifact with root privileges on a developer machine.

The shared tier model, default no-dependency harness, gates, and skip rules are
defined in [Security Test Tiers](security-test-tiers.md).

### Test Tiers

| Tier | Name | Privilege model | Purpose |
| --- | --- | --- | --- |
| 0 | Unit and translation | No special host dependencies | Policy validation, capability planning, config generation, unsupported combinations, secret stripping, cleanup branches. |
| 1 | Fake executor e2e | No special host dependencies | AXIS lifecycle with fake MXC executors, config secrecy, cleanup, timeout, logging, and platform adapter behavior. |
| 2 | Unprivileged real runtime | Optional installed tools | Real backend smoke tests for installed non-privileged runtimes such as MXC executors, Bubblewrap, and macOS Seatbelt. |
| 3 | Capability-gated runtime | Host feature required | Windows Sandbox, WSL2, WHP/KVM, LXC, Hyperlight snapshots, cgroups, seccomp notify, user namespaces, and platform build features. Missing features skip or fail based on explicit env gates. |
| 4 | Privileged disposable CI | Repeatable CI/container/VM setup | Narrow helper proofs, capability proofs, firewall proofs, VM feature setup, and strict bypass tests that require privileged runner setup. |

Tier 0 and Tier 1 must run everywhere. Tier 2 and Tier 3 may skip with explicit
reasons. Tier 4 belongs only in a disposable runner that builds artifacts from
the current checkout, installs them inside that runner, proves behavior as a
non-root user where appropriate, and tears the environment down.

### Required Security Tests

Each backend workstream must include tests for:

- policy combinations that must be rejected before spawn;
- no raw credentials in MXC JSON, argv, environment, logs, inherited file
  descriptors, or sandbox-visible files;
- direct network bypass denial for strict proxy mode;
- cooperative proxy bypass documented and tested as weaker behavior;
- deny-path overlap rejection or exact masking behavior;
- timeout cleanup of the full process group or backend lifecycle;
- cgroup/resource cleanup when limits are requested;
- state cleanup after partial spawn failure;
- no fallback to host execution after backend setup failure;
- exact skip messages for missing platform dependencies such as `bwrap`, MXC
  executors, LXC, KVM, WHP, Windows Sandbox, WSL2, cgroups, user namespaces,
  Xcode Command Line Tools, or helper privileges.

### Invalid Test Dependencies

The following are not acceptable as normal test requirements:

- administrator- or root-installing an AXIS-built helper on a developer
  machine;
- setting setuid, file capabilities, OS feature flags, privileged firewall
  state, or machine-wide runtime settings on local build output outside a
  disposable CI runner;
- relying on a helper installed by a previous test or development session;
- weakening a policy so a test passes on the current host;
- using real cloud provider credentials in e2e tests.

## Packaging And Install

Release archives and packages should include the MXC executor version AXIS is
tested against. Source-tree development may point at an explicitly supplied
executor path for tests, but that path is a test dependency, not a host install
instruction.

Install vectors:

- default user install: AXIS binaries and platform executors that do not need
  privileged host setup;
- Windows package install: AXIS binaries plus the MXC Windows executor pieces
  needed for selected backends, with optional OS features documented per
  backend;
- Linux package install: AXIS binaries plus non-privileged MXC executor and
  seccomp launcher;
- macOS package install: AXIS binaries plus the MXC macOS executor where AXIS
  selects the MXC Seatbelt path;
- optional privileged helper or capability install: explicit flag only,
  platform-specific, and documented as broader than the default install path;
- test-only privileged setup: disposable CI/container/VM script only.

## Dead-Code And Simplification Audit

Each milestone must identify code that MXC makes unnecessary or duplicate.

Audit targets:

- duplicate filesystem translation logic;
- duplicate environment sanitization logic;
- stale Bubblewrap fallback paths;
- helper discovery mixed into generic backend code;
- resource planning hidden inside backend-specific spawn code;
- docs claiming unsupported completion states;
- tests that assert implementation details instead of policy behavior.

Removal rule:

- remove old code only after replacement behavior has equivalent policy
  semantics, tests, and benchmark data;
- if MXC cannot provide an AXIS-required capability, keep the AXIS-owned layer
  and document it as intentional.

## Workstreams

### Cross-Platform Capability Planner

Deliverables:

- backend capability structs and runtime probes;
- policy/backend planner with `Exact`, `ExactWithHostDependency`,
  `WeakerOnly`, and `Unsupported` outcomes;
- unit tests for every policy branch and backend branch;
- docs for host dependencies and skip/fail behavior.

### Platform Backend Maps

Deliverables:

- Windows backend map for `processcontainer`, `isolation_session`,
  `windows_sandbox`, `wslc`, `microvm`, and `hyperlight`;
- Linux backend map for native process isolation, `bubblewrap`, `lxc`,
  `microvm`, and `hyperlight`;
- macOS backend map for native Seatbelt and MXC Seatbelt;
- explicit list of capabilities MXC does not provide and AXIS must own;
- dead-code candidates by platform.

### Backend MVP Acceptance

Deliverables:

- backend paths wired through AXIS policy planning, config generation, fake
  executor tests, and gated real runtime tests;
- exact rejection of policy combinations a selected backend cannot enforce;
- provider placeholder and config secrecy tests;
- baseline benchmark for startup, teardown, memory, descriptors, and process
  count where a platform can report them.

### Strict Proxy And Inference Integration

Deliverables:

- AXIS strict proxy integration for every backend that claims strict proxy
  support;
- raw bypass denial tests where strict proxy is supported;
- cooperative proxy tests and documentation where only cooperative enforcement
  is available;
- `inference.local` mock-provider e2e;
- binary-attribution rejection when the selected launch path cannot provide
  connect-time identity.

### Resource And Cleanup Hardening

Deliverables:

- resource planning separated from backend launch;
- platform-specific resource adapters for Job Object, cgroups, MXC native
  resource settings, and backend-specific VM/container limits;
- cleanup proofs for timeout, failed spawn, normal exit, daemon shutdown, and
  repeated destroy;
- benchmarks for startup, teardown, memory, descriptors, and process count.

### Container And VM Backend Sweep

Deliverables:

- Windows WSLC, Windows Sandbox, and Isolation Session evaluation;
- Linux LXC evaluation;
- MXC MicroVM and Hyperlight evaluation across supported host platforms;
- exact unsupported-policy rejection tests;
- narrow workload proofs where supported;
- recommendation on whether each backend should remain experimental, become a
  supported AXIS backend, or stay out of AXIS.

### Default Backend Decisions

Deliverables:

- benchmark and coverage comparison for native and MXC paths on each platform;
- public decision record for default backend selection per platform;
- removal or quarantine plan for superseded code;
- list of AXIS-owned policy layers that remain necessary even with MXC.

## Review Requirements

Each implementation workstream must include a security-focused self-review in
the change description or associated test notes. The review must explicitly
cover:

- whether the backend can enforce every requested AXIS policy exactly;
- whether any behavior is weaker than the policy name suggests;
- whether raw credentials can appear in config, argv, env, logs, files, or
  inherited descriptors;
- whether all cleanup and timeout branches are tested;
- whether host dependencies are detected without mutating the host;
- whether platform-specific logic leaks across abstraction boundaries.

## Open Questions

- Should cooperative proxy mode be part of the public AXIS policy schema, or
  only an internal backend option for policies that explicitly accept weaker
  enforcement?
- Should native platform backends remain the default until MXC-backed paths
  have equivalent semantics and benchmark data?
- Should provider profiles be AXIS-owned or aligned structurally with common
  agent sandbox provider profile models?
- Which local inference paths are required for MXC-backed e2e coverage:
  external OpenAI-compatible mock, vLLM, llama.cpp, or all three?
- What minimum benchmark suite is required before changing a default backend on
  any platform?

## References Reviewed

- MXC source and documentation: https://github.com/microsoft/mxc
- OpenShell source and documentation: https://github.com/NVIDIA/OpenShell
- Bubblewrap source and tests: https://github.com/containers/bubblewrap
