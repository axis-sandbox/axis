# Linux e2e capability matrix

The Linux e2e suite is split by privilege and kernel capability so local
quickstart testing does not depend on sudo or a developer-installed helper.

| Group | Script or command | Privilege model | Expected behavior |
| --- | --- | --- | --- |
| Unprivileged standalone | `bash e2e/linux/test_sandbox.sh [axis]` | Non-root, no host mutation | Runs built `axis run` with generated policies. Verifies policy validation, workspace-only writes, block-mode socket denial, policy-aware seccomp, and timeout behavior. Missing kernel/resource support is reported as an explicit skip. |
| Unprivileged daemon | `bash e2e/linux/test_e2e_daemon.sh [axis]` | Non-root, no host mutation | Starts `axisd` with a throwaway socket and `XDG_DATA_HOME`. Verifies create, list, contained exec, destroy, timeout cleanup, and process-tree cleanup. Missing kernel/resource support is reported as an explicit skip. |
| Helper-gated proxy | `AXIS_RUN_PRIVILEGED_E2E=1 bash e2e/linux/test_netns_helper_launch.sh` | Ephemeral CI/container/VM with passwordless sudo | Builds `axis-netns-helper` from the current checkout, refuses to overwrite any preexisting helper, installs it setuid-root only inside the disposable runner, and removes it during cleanup. Runs the non-root helper launch proof and a built `axis` proxy-mode proof for allowed CONNECT with tunneled bytes, denied CONNECT, and direct-bypass firewall denial. Set `AXIS_REQUIRE_BUILT_AXIS_PROXY_E2E=1` when a runner is expected to provide every proxy prerequisite. |
| Helper-gated bypass audit | `AXIS_RUN_PRIVILEGED_E2E=1 bash e2e/linux/test_netns_helper_launch.sh` | Same disposable runner, plus non-root readable `/dev/kmsg` | After the built `axis` proxy proof, starts a throwaway `axisd` with a temporary socket and log directory, triggers a direct-bypass attempt from a proxy-mode sandbox, and verifies the daemon log contains the matching sandbox id and rejected destination port. Set `AXIS_REQUIRE_KMSG_AUDIT_E2E=1` when readable `/dev/kmsg` is expected. |
| Bubblewrap-gated fallback | `AXIS_RUN_BWRAP_E2E=1 bash e2e/linux/test_bwrap_fallback.sh` | Non-root with safe `bwrap` on `PATH` | Builds `axis` and, on a runner where Landlock is unavailable, proves the built binary selects the bwrap fallback for workspace writes and block-mode network denial. On normal Landlock-capable runners, runs the crate-level gated bwrap fallback proof for mounts, network denial, and descriptor handling. Skips when the runner has no trusted bubblewrap executable. |
| Capability-gated kernel proofs | `AXIS_REAL_NETNS_TESTS=1`, `AXIS_REAL_CGROUP_TESTS=1`, or other targeted cargo tests | Non-root only when delegated kernel resources are available | Exercises native netns/cgroup behavior against the real kernel. These are not prerequisites for quickstart; missing capabilities must produce visible skips or failures, never false confidence. |

The default local proof is the unprivileged standalone plus daemon group. Any
test that mutates `/usr`, requires setuid helper installation, changes firewall
state, assumes writable cgroups, or reads kernel logs must live in a gated group
and describe the missing prerequisite when skipped.
