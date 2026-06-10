# OPA Proxy Benchmarks

The README performance table uses `success-metrics` for the single synthetic
OPA throughput number. For policy-specific proxy request timing, run:

```bash
cargo run -p axis-bench --bin opa-scenarios
```

The command emits JSON and fails instead of reporting timing when a selected
scenario does not return the expected policy denial. It does not enumerate
unsupported backend combinations.

The `axis_proxy_reports` section always runs. It starts an AXIS proxy once per
policy scenario, sends repeated denied `CONNECT` requests through that already
running proxy with test connect-attribution records, and reports only
request-loop timing. Startup and teardown are outside `total_ns`.

The `mxc_bubblewrap` section is optional. On Linux, when a safe MXC executor is
provided through `AXIS_TEST_MXC_EXECUTOR` or `lxc-exec` is on `PATH`, the
benchmark starts AXIS proxy instances and launches MXC Bubblewrap with:

- `network.proxy.localhost`, pointing at the AXIS proxy;
- `network.proxy.url`, pointing at the AXIS proxy by URL;
- `network.proxy.builtinTestServer`, when `linux-test-proxy` is available next
  to the executor.

The first two modes measure MXC's cooperative proxy environment by pointing it
at a benchmark-owned external deny proxy. The builtin test proxy mode measures
MXC's test proxy denial path and is reported separately as
`mxc_linux_test_proxy`. These MXC rows prove proxy routing behavior, not AXIS
OPA policy evaluation.

Increase the request iteration count when collecting stable numbers:

```bash
AXIS_OPA_SCENARIO_BENCH_ITERS=50000 cargo run -p axis-bench --bin opa-scenarios
```
