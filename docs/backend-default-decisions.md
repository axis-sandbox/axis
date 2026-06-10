# Backend Default Decisions

Backend defaults are selected from policy coverage, dependency cost, startup and
teardown behavior, cleanup behavior, resource overhead, density, and security
evidence. MXC is a substrate candidate where it can enforce AXIS semantics
exactly or where AXIS-owned layers supply the missing enforcement before spawn.
It is not selected by preference alone.

The machine-readable source of truth for this matrix is
`axis_core::backend_defaults`. To inspect it as JSON:

```bash
cargo run -p axis-bench --bin backend-defaults
```

Security coverage and unsupported-policy counts are emitted from the shared
capability planner with:

```bash
cargo run -p axis-bench --bin backend-evidence
```

Policy-specific proxy request throughput, with optional MXC Bubblewrap
proxy-mode runs when a safe MXC executor is available, is emitted with:

```bash
cargo run -p axis-bench --bin opa-scenarios
```

See [OPA Proxy Benchmarks](opa-proxy-benchmarks.md) for the inputs and
iteration controls.

Current-host MXC backend/network-mode runtime checks, plus the AXIS native
filesystem-boundary comparison, are emitted with:

```bash
cargo run -p axis-bench --bin mxc-isolation-matrix
```

See [MXC Isolation Matrix](mxc-isolation-matrix.md) for row definitions,
dependency gates, and status meanings.

## Current Defaults

| Platform | Current process default | Decision |
| --- | --- | --- |
| Linux | `mxc-linux-bubblewrap` | Use the MXC process backend by default while AXIS supplies seccomp, resource, credential, proxy policy, and cleanup layers around it. |
| macOS | `axis-native-macos-seatbelt` | Retain native default while direct Seatbelt profile generation remains the proven no-extra-runtime path. |
| Windows | `axis-native-windows` | Retain native default while Job Object, Low Integrity, and AXIS-owned process lifecycle behavior remain the proven baseline. |

Non-default MXC process backends are candidates. They can become defaults only
after they match AXIS policy semantics and have benchmark evidence for startup,
teardown, maximum RSS, file descriptors, process count, density, host dependency
cost, security coverage, unsupported-policy counts, and cleanup failures.
The current default smoke benchmark command is:

```bash
cargo run -p axis-bench --bin success-metrics
```

## Candidate And Experimental Backends

| Backend | Class | Status | Benchmark gate |
| --- | --- | --- | --- |
| `axis-native-linux` | Process | Retained | `cargo run -p axis-bench --bin success-metrics` |
| `mxc-macos-seatbelt` | Process | Candidate | `AXIS_BENCH_MXC_MACOS_SEATBELT=1` |
| `mxc-windows-processcontainer` | Process | Candidate | `AXIS_BENCH_MXC_WINDOWS_PROCESSCONTAINER=1` |
| `mxc-linux-lxc` | Container | Candidate | `AXIS_BENCH_MXC_LXC=1` |
| `mxc-windows-wslc` | Container | Candidate | `AXIS_BENCH_MXC_WINDOWS_WSLC=1` |
| `mxc-linux-microvm` | VM | Experimental opt-in | `AXIS_BENCH_MXC_MICROVM=1` |
| `mxc-linux-hyperlight` | VM | Experimental opt-in | `AXIS_BENCH_MXC_HYPERLIGHT=1` |
| `mxc-windows-isolation-session` | VM | Experimental opt-in | `AXIS_BENCH_MXC_WINDOWS_ISOLATION_SESSION=1` |
| `mxc-windows-sandbox` | VM | Experimental opt-in | `AXIS_BENCH_MXC_WINDOWS_SANDBOX=1` |
| `mxc-windows-microvm` | VM | Experimental opt-in | `AXIS_BENCH_MXC_WINDOWS_MICROVM=1` |
| `mxc-windows-hyperlight` | VM | Experimental opt-in | `AXIS_BENCH_MXC_WINDOWS_HYPERLIGHT=1` |

Container and VM backends are not process-default replacements by default. They
may be better choices for specific high-risk or image-oriented workloads, but
their image/runtime dependencies and lifecycle costs must be visible in the
benchmark output.

## Evidence Requirements

Every non-default backend needs:

- planner exact, weaker, unsupported, and host-dependency outcome counts;
- negative tests for unsupported or weaker policy surfaces;
- credential-boundary and proxy-bypass coverage;
- cleanup failure and resource-leak coverage;
- benchmark output for cold and warm behavior where the backend has a cold/warm
  distinction;
- density measurements under the relevant dependency gate;
- skipped dependency explanations that name the missing primitive.

Benchmark fixtures must be repeatable from the repository. They must not require
root-installing locally built artifacts onto a developer host. Dependency-heavy
runs belong behind explicit gates and should build or resolve their runtime
inputs in the test environment that executes the gate.
