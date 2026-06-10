# macOS Capability Matrix

| Capability | Gate | Coverage |
| --- | --- | --- |
| MXC Seatbelt benchmark | `AXIS_BENCH_MXC_MACOS_SEATBELT=1 bash e2e/macos/bench_mxc_runtime.sh` | Reports JSON for cold lifecycle, warm lifecycle distribution, maximum RSS, and density. Tunables: `AXIS_MXC_MACOS_BENCH_RUNS`, `AXIS_MXC_MACOS_BENCH_DENSITY`, `AXIS_MXC_MACOS_BENCH_TIMEOUT_SECONDS`, and `AXIS_MXC_MACOS_BENCH_OUTPUT`. Reports metric gaps for teardown, descriptor count, and process count until richer host metrics are collected. |
