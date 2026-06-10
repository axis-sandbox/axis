# Windows Capability Matrix

| Capability | Gate | Coverage |
| --- | --- | --- |
| MXC ProcessContainer benchmark | `AXIS_BENCH_MXC_WINDOWS_PROCESSCONTAINER=1 pwsh -NoProfile -File e2e/windows/bench_mxc_runtime.ps1` | Reports JSON for cold lifecycle, warm lifecycle distribution, executor peak working set, and density. Tunables: `AXIS_MXC_WINDOWS_BENCH_RUNS`, `AXIS_MXC_WINDOWS_BENCH_DENSITY`, `AXIS_MXC_WINDOWS_BENCH_TIMEOUT_SECONDS`, and `AXIS_MXC_WINDOWS_BENCH_OUTPUT`. |
| MXC WSLC benchmark | `AXIS_BENCH_MXC_WINDOWS_WSLC=1 pwsh -NoProfile -File e2e/windows/bench_mxc_runtime.ps1` | Reports JSON for WSLC cold/warm lifecycle, executor peak working set, and density when `AXIS_MXC_WSLC_IMAGE_TAR_PATH` names repeatable input. Optional inputs: `AXIS_MXC_WSLC_IMAGE` and `AXIS_MXC_WSLC_STORAGE_PATH`. |
| MXC Windows VM-style benchmark | `AXIS_BENCH_MXC_WINDOWS_SANDBOX=1`, `AXIS_BENCH_MXC_WINDOWS_ISOLATION_SESSION=1`, `AXIS_BENCH_MXC_WINDOWS_MICROVM=1`, or `AXIS_BENCH_MXC_WINDOWS_HYPERLIGHT=1` with `pwsh -NoProfile -File e2e/windows/bench_mxc_runtime.ps1` | Reports JSON for cold start, warm start distribution, executor peak working set, and density for the selected VM-style backend. Reports metric gaps for teardown, descriptor count, and process count until richer host metrics are collected. |
