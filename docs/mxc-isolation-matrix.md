# MXC Isolation Matrix

`mxc-isolation-matrix` emits a current-host JSON report for MXC backend and
network-mode combinations, plus an AXIS native filesystem-boundary comparison.

```bash
cargo run -p axis-bench --bin mxc-isolation-matrix
```

The command does not install local artifacts. If `lxc-exec` is not on `PATH`,
set `AXIS_TEST_MXC_EXECUTOR` to a trusted executor path:

```bash
AXIS_TEST_MXC_EXECUTOR=/path/to/lxc-exec cargo run -p axis-bench --bin mxc-isolation-matrix
```

Increase proxy request-loop iterations with:

```bash
AXIS_MXC_MATRIX_ITERS=1000 cargo run -p axis-bench --bin mxc-isolation-matrix
```

Run a subset of MXC backends with `AXIS_MXC_MATRIX_BACKENDS`. Values are
comma-separated and accept `bubblewrap`, `lxc`, `microvm`, `hyperlight`, or
`all`:

```bash
AXIS_MXC_MATRIX_BACKENDS=bubblewrap cargo run -p axis-bench --bin mxc-isolation-matrix
```

## Rows

On Linux, the MXC section attempts:

- `mxc-linux-bubblewrap`
- `mxc-linux-lxc`
- `mxc-linux-microvm`
- `mxc-linux-hyperlight`

The suite intentionally reports only the current platform's MXC backends.
It does not emit Windows or macOS rows on a Linux host.

Each MXC backend is tried with:

- `network.defaultPolicy.allow`
- `network.defaultPolicy.block`
- `network.enforcementMode.capabilities`
- `network.enforcementMode.firewall`
- `network.enforcementMode.both`
- `network.proxy.localhost`
- `network.proxy.url`
- `network.proxy.builtinTestServer`

The proxy rows are different from the host-filter rows. `network.proxy.*`
configures cooperative proxy routing for proxy-aware clients. MXC currently
accepts that proxy shape for Bubblewrap on Linux and ProcessContainer on
Windows. Host filtering is represented by `defaultPolicy`, `allowedHosts`, and
`enforcementMode`; the `firewall` and `both` modes may require host firewall
privileges such as `CAP_NET_ADMIN`.

The AXIS native row is not an MXC backend. It launches the native process
sandbox and verifies that a writable workspace remains writable while a
separate denied path cannot be read.

## Result Status

- `passed`: the row executed and emitted the expected marker.
- `failed`: the backend ran but the security expectation was not met.
- `unsupported`: MXC rejected the backend/mode combination.
- `unavailable`: a host dependency, runtime image, executor feature, or
  privilege prerequisite was missing.

Only `passed` rows include performance metrics. Failed, unsupported, and
unavailable rows include diagnostics but no timing numbers.

## Dependencies

The no-executor case is valid: the MXC section reports the missing executor
gate, and the AXIS native comparison still runs where supported.

Real MXC rows require a safe `lxc-exec`. Individual rows may also require:

- `bwrap` for Bubblewrap;
- `linux-test-proxy` next to the executor for `network.proxy.builtinTestServer`;
- LXC user namespace and image setup for LXC;
- KVM and runtime artifacts for MicroVM and Hyperlight;
- firewall privileges for `network.enforcementMode.firewall` and `both`.

These are runtime prerequisites for the machine running the suite. They are not
normal test requirements and must not be satisfied by root-installing a
checkout-built artifact as part of ordinary tests.
