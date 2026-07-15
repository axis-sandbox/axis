#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Privileged Linux e2e proof for axis-netns-helper launch mode.
#
# This is intentionally an ephemeral-runner harness, not a local developer
# install path. It mutates /usr/libexec/axis only after an explicit opt-in so
# ordinary repo tests never depend on a host setuid helper.
# shellcheck disable=SC2317 # Callback functions are invoked indirectly by name.
set -euo pipefail

run_preflight_namespace_state_machine() {
    local namespace="$1"
    local exists_fn="$2"
    local add_fn="$3"
    local configure_fn="$4"
    local delete_fn="$5"
    local status=0

    if "$exists_fn" "$namespace"; then
        echo "ERROR: refusing to use preexisting preflight namespace: $namespace" >&2
        return 126
    else
        status=$?
        if [ "$status" -ne 1 ]; then
            return "$status"
        fi
    fi
    "$add_fn" "$namespace" || return $?
    "$configure_fn" "$namespace" || status=$?
    if ! "$delete_fn" "$namespace"; then
        echo "ERROR: failed to remove owned preflight namespace: $namespace" >&2
        return 125
    fi
    return "$status"
}

kmsg_gate_status() {
    local required="$1"
    local readable="$2"
    if [ "$readable" = "1" ]; then
        return 0
    fi
    if [ "$required" = "1" ]; then
        return 1
    fi
    return 77
}

run_rootless_harness_self_tests() {
    local add_count=0
    local delete_count=0
    fake_exists() { return 0; }
    fake_add() { add_count=$((add_count + 1)); }
    fake_configure() { return 0; }
    fake_delete() { delete_count=$((delete_count + 1)); }

    local status=0
    run_preflight_namespace_state_machine collision fake_exists fake_add fake_configure fake_delete \
        >/dev/null 2>&1 || status=$?
    if [ "$status" -ne 126 ] || [ "$add_count" -ne 0 ] || [ "$delete_count" -ne 0 ]; then
        echo "ERROR: preflight collision self-test deleted or replaced a preexisting namespace"
        return 1
    fi

    fake_absent() { return 1; }
    fake_add_failure() { return 42; }
    status=0
    run_preflight_namespace_state_machine add-failure fake_absent fake_add_failure \
        fake_configure fake_delete >/dev/null 2>&1 || status=$?
    if [ "$status" -ne 42 ] || [ "$delete_count" -ne 0 ]; then
        echo "ERROR: failed preflight add triggered deletion without ownership"
        return 1
    fi

    fake_owned_add() { add_count=$((add_count + 1)); }
    fake_configure_failure() { return 41; }
    status=0
    run_preflight_namespace_state_machine owned fake_absent fake_owned_add \
        fake_configure_failure fake_delete >/dev/null 2>&1 || status=$?
    if [ "$status" -ne 41 ] || [ "$add_count" -ne 1 ] || [ "$delete_count" -ne 1 ]; then
        echo "ERROR: owned preflight namespace was not cleaned after configuration failure"
        return 1
    fi

    fake_delete_failure() {
        delete_count=$((delete_count + 1))
        return 1
    }
    status=0
    run_preflight_namespace_state_machine cleanup-failure fake_absent fake_owned_add \
        fake_configure fake_delete_failure >/dev/null 2>&1 || status=$?
    if [ "$status" -ne 125 ] || [ "$add_count" -ne 2 ] || [ "$delete_count" -ne 2 ]; then
        echo "ERROR: preflight namespace cleanup failure was not surfaced"
        return 1
    fi

    if kmsg_gate_status 1 0; then
        echo "ERROR: strict kmsg gate accepted an unavailable audit source"
        return 1
    fi
    status=0
    kmsg_gate_status 0 0 || status=$?
    if [ "$status" -ne 77 ]; then
        echo "ERROR: optional kmsg gate did not return the skip status"
        return 1
    fi
    kmsg_gate_status 1 1
    echo "PASS: rootless preflight ownership and strict kmsg gate self-tests"
}

if [ "${1:-}" = "--self-test" ]; then
    run_rootless_harness_self_tests
    exit 0
fi

if [ "${AXIS_REQUIRE_NETNS_HELPER_E2E:-}" = "1" ] && [ "${AXIS_RUN_PRIVILEGED_E2E:-}" != "1" ]; then
    echo "ERROR: AXIS_REQUIRE_NETNS_HELPER_E2E=1 requires AXIS_RUN_PRIVILEGED_E2E=1"
    exit 1
fi
if [ "${AXIS_RUN_PRIVILEGED_E2E:-}" != "1" ]; then
    echo "SKIP: set AXIS_RUN_PRIVILEGED_E2E=1 in an ephemeral CI/container runner"
    exit 77
fi

if [ "$(id -u)" -eq 0 ]; then
    echo "ERROR: helper launch proof must run cargo test as a non-root user"
    exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
    echo "ERROR: sudo is required to install the helper inside the ephemeral test runner"
    exit 1
fi

for tool in cargo install stat timeout tail readlink python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: required tool not found on PATH: $tool"
        exit 1
    fi
done

for tool in ip iptables sysctl python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: required netns proof tool not found on PATH: $tool"
        exit 1
    fi
done

bounded() {
    local seconds="$1"
    shift
    local status=0
    timeout --kill-after=1s "${seconds}s" "$@" || status=$?
    if [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; then
        echo "ERROR: command exceeded ${seconds}s deadline: $*" >&2
        return 125
    fi
    return "$status"
}

bounded_sudo() {
    local seconds="$1"
    shift
    bounded "$((seconds + 2))" sudo -n timeout --kill-after=1s "${seconds}s" "$@"
}

if ! bounded_sudo 2 true >/dev/null 2>&1; then
    echo "ERROR: bounded passwordless sudo is required in the ephemeral test runner"
    exit 1
fi

if [ "${AXIS_REQUIRE_NETNS_HELPER_E2E:-}" = "1" ] && [ -z "${AXIS_EXPECT_MXC_EXECUTOR:-}" ]; then
    echo "ERROR: strict helper proof requires AXIS_EXPECT_MXC_EXECUTOR"
    exit 1
fi
expected_executor="${AXIS_EXPECT_MXC_EXECUTOR:-/usr/local/bin/lxc-exec}"
if [ "$expected_executor" != "/usr/local/bin/lxc-exec" ]; then
    echo "ERROR: helper proof executor must use /usr/local/bin/lxc-exec"
    exit 1
fi
executor_build="${AXIS_MXC_EXECUTOR_BUILD:-}"
if [ -z "$executor_build" ] || [ ! -x "$executor_build" ]; then
    echo "ERROR: AXIS_MXC_EXECUTOR_BUILD must name the locally built executable"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TMP_ROOT="$(mktemp -d /tmp/axis-netns-helper-e2e-XXXXXX)"
SERVER_PID=""
DIRECT_SERVER_PID=""
AXSD_PID=""
PROXY_PROOF_PID=""
PROXY_PROOF_START_TIME=""
PREFLIGHT_NS=""
PREFLIGHT_NS_CREATED=0
HELPER_INSTALL="/usr/libexec/axis/axis-netns-helper"
INSTALLED_HELPER=0
INSTALLED_MXC_EXECUTOR=0
CREATED_HELPER_DIR=0
KMSG_PROVISIONED=0
KMSG_ORIGINAL_MODE=""
KMSG_ORIGINAL_DMESG_RESTRICT=""
# shellcheck disable=SC2317,SC2329 # Invoked indirectly by the EXIT trap.
cleanup() {
    local original_status=$?
    local cleanup_failed=0
    set +e
    stop_background_servers
    if [ -n "$AXSD_PID" ]; then
        terminate_background_process "$AXSD_PID" "axisd cleanup"
    fi
    if [ -n "$PROXY_PROOF_PID" ]; then
        terminate_background_process "$PROXY_PROOF_PID" "proxy proof cleanup"
    fi
    if [ "$INSTALLED_HELPER" -eq 1 ]; then
        if ! bounded_sudo 5 rm -f "$HELPER_INSTALL"; then
            echo "ERROR: failed to remove installed helper: $HELPER_INSTALL" >&2
            cleanup_failed=1
        fi
    fi
    if [ "$CREATED_HELPER_DIR" -eq 1 ]; then
        if ! bounded_sudo 5 rmdir /usr/libexec/axis; then
            echo "ERROR: failed to remove owned helper install directory: /usr/libexec/axis" >&2
            cleanup_failed=1
        fi
    fi
    if [ "$INSTALLED_MXC_EXECUTOR" -eq 1 ]; then
        if ! bounded_sudo 5 rm -f "$expected_executor"; then
            echo "ERROR: failed to remove installed MXC executor: $expected_executor" >&2
            cleanup_failed=1
        fi
    fi
    if [ "$PREFLIGHT_NS_CREATED" -eq 1 ] && [ -n "$PREFLIGHT_NS" ]; then
        if ! bounded_sudo 5 ip netns del "$PREFLIGHT_NS"; then
            echo "ERROR: failed to remove owned preflight namespace: $PREFLIGHT_NS" >&2
            cleanup_failed=1
        fi
    fi
    if [ "$KMSG_PROVISIONED" -eq 1 ]; then
        if ! bounded_sudo 5 chmod "$KMSG_ORIGINAL_MODE" /dev/kmsg; then
            echo "ERROR: failed to restore /dev/kmsg mode" >&2
            cleanup_failed=1
        fi
        if ! bounded_sudo 5 sysctl -q -w \
            "kernel.dmesg_restrict=${KMSG_ORIGINAL_DMESG_RESTRICT}"; then
            echo "ERROR: failed to restore kernel.dmesg_restrict" >&2
            cleanup_failed=1
        fi
    fi
    rm -f /tmp/axis-helper-lifecycle-*"$$".sock
    if ! rm -rf "$TMP_ROOT"; then
        echo "ERROR: failed to remove helper test directory: $TMP_ROOT" >&2
        cleanup_failed=1
    fi
    trap - EXIT
    if [ "$original_status" -ne 0 ]; then
        exit "$original_status"
    fi
    if [ "$cleanup_failed" -ne 0 ]; then
        exit 1
    fi
}
trap cleanup EXIT

provision_kmsg_audit_source() {
    [ -r /dev/kmsg ] && return 0
    [ "${AXIS_PROVISION_KMSG_AUDIT_E2E:-}" = "1" ] || return 0
    if [ ! -e /dev/kmsg ]; then
        echo "ERROR: strict kmsg provisioning requires /dev/kmsg"
        return 1
    fi
    KMSG_ORIGINAL_MODE="$(bounded_sudo 2 stat -c '%a' /dev/kmsg)"
    KMSG_ORIGINAL_DMESG_RESTRICT="$(bounded_sudo 2 sysctl -n kernel.dmesg_restrict)"
    KMSG_PROVISIONED=1
    bounded_sudo 5 sysctl -q -w kernel.dmesg_restrict=0
    bounded_sudo 5 chmod o+r /dev/kmsg
    if [ ! -r /dev/kmsg ]; then
        echo "ERROR: provisioned /dev/kmsg is still unreadable by the test user"
        return 1
    fi
}

reject_preexisting_privileged_path() {
    local path="$1"
    local label="$2"
    local status=0
    if bounded_sudo 2 test -e "$path"; then
        echo "ERROR: refusing to overwrite preexisting $label: $path"
        return 1
    else
        status=$?
        if [ "$status" -ne 1 ]; then
            echo "ERROR: timed out or failed while checking $label path: $path"
            return "$status"
        fi
    fi
    if bounded_sudo 2 test -L "$path"; then
        echo "ERROR: refusing to overwrite preexisting $label symlink: $path"
        return 1
    else
        status=$?
        if [ "$status" -ne 1 ]; then
            echo "ERROR: timed out or failed while checking $label symlink: $path"
            return "$status"
        fi
    fi
}

validate_privileged_directory() {
    local path="$1"
    local label="$2"
    local metadata=""
    local owner=""
    local kind=""
    local mode=""
    local status=0

    bounded_sudo 2 test -L "$path" || status=$?
    if [ "$status" -eq 0 ]; then
        echo "ERROR: $label must not be a symlink: $path"
        return 1
    elif [ "$status" -ne 1 ]; then
        echo "ERROR: failed or timed out checking $label symlink: $path"
        return "$status"
    fi
    metadata="$(bounded_sudo 2 stat -c '%u|%F|%a' "$path")" || return $?
    IFS='|' read -r owner kind mode <<<"$metadata"
    if [ "$owner" != "0" ] || [ "$kind" != "directory" ] ||
        [[ ! "$mode" =~ ^[0-7]{3,4}$ ]] || ((8#$mode & 022)); then
        echo "ERROR: $label must be a root-owned non-writable real directory: $path ($metadata)"
        return 1
    fi
}

validate_privileged_directory /usr/local/bin "MXC executor parent"
reject_preexisting_privileged_path "$expected_executor" "MXC executor"
INSTALLED_MXC_EXECUTOR=1
bounded_sudo 5 install -o root -g root -m 0755 "$executor_build" "$expected_executor"
resolved_executor="$(bounded 2 readlink -f "$(command -v lxc-exec)")"
if [ "$resolved_executor" != "$expected_executor" ]; then
    echo "ERROR: lxc-exec resolves to $resolved_executor, expected $expected_executor"
    exit 1
fi
executor_metadata="$(bounded 2 stat -c '%u:%g %a' "$expected_executor")"
if [ "$executor_metadata" != "0:0 755" ]; then
    echo "ERROR: trusted lxc-exec mode mismatch: $executor_metadata"
    exit 1
fi

terminate_background_process() {
    local pid="$1"
    local label="$2"
    bounded 2 kill -KILL "$pid" 2>/dev/null || true
    if bounded 2 tail --pid="$pid" -f /dev/null >/dev/null 2>&1; then
        wait "$pid" 2>/dev/null || true
    else
        echo "WARNING: $label process $pid did not exit within cleanup deadline" >&2
    fi
}

process_start_time() {
    local pid="$1"
    bounded 2 python3 - "$pid" <<'PY'
import pathlib
import sys

path = pathlib.Path("/proc") / sys.argv[1] / "stat"
try:
    contents = path.read_text()
except FileNotFoundError:
    raise SystemExit(1)
except OSError as error:
    print(f"ERROR: read {path}: {error}", file=sys.stderr)
    raise SystemExit(2)
fields = contents.rsplit(")", 1)
if len(fields) != 2:
    print(f"ERROR: malformed process stat for {sys.argv[1]}", file=sys.stderr)
    raise SystemExit(2)
remainder = fields[1].split()
if len(remainder) <= 19:
    print(f"ERROR: incomplete process stat for {sys.argv[1]}", file=sys.stderr)
    raise SystemExit(2)
print(remainder[19])
PY
}

process_identity_matches() {
    local pid="$1"
    local expected_start_time="$2"
    local actual_start_time=""
    local status=0
    actual_start_time="$(process_start_time "$pid")" || status=$?
    if [ "$status" -eq 1 ]; then
        return 1
    fi
    if [ "$status" -ne 0 ]; then
        return 2
    fi
    [ "$actual_start_time" = "$expected_start_time" ]
}

namespace_exists() {
    local namespace="$1"
    local listing=""
    local names=""
    listing="$(bounded_sudo 5 ip netns list)" || return 2
    # shellcheck disable=SC2016 # The awk field expression is literal.
    names="$(bounded 2 awk '{print $1}' <<<"$listing")" || return 2
    grep -Fxq "$namespace" <<<"$names"
}

host_veth_exists() {
    bounded 5 ip link show "$1" >/dev/null 2>&1
}

stop_background_servers() {
    if [ -n "$SERVER_PID" ]; then
        terminate_background_process "$SERVER_PID" "TCP server cleanup"
        SERVER_PID=""
    fi
    if [ -n "$DIRECT_SERVER_PID" ]; then
        terminate_background_process "$DIRECT_SERVER_PID" "direct server cleanup"
        DIRECT_SERVER_PID=""
    fi
}

wait_for_port_file() {
    local port_file="$1"
    for _ in $(seq 1 50); do
        [ -s "$port_file" ] && return 0
        sleep 0.1
    done
    return 1
}

wait_for_socket_path() {
    local socket_path="$1"
    for _ in $(seq 1 50); do
        [ -S "$socket_path" ] && return 0
        sleep 0.1
    done
    return 1
}

capability_skip_output() {
    grep -Fq "resources: process count rlimit fallback requires a dedicated run_as_user" <<<"$1" ||
        grep -Fq "resources: CPU rate limits require writable cgroups v2" <<<"$1" ||
        grep -Fq "resources: cgroups v2 is unavailable" <<<"$1" ||
        grep -Fq "resources: cgroups v2 is read-only" <<<"$1" ||
        grep -Fq "seccomp: seccomp is unavailable" <<<"$1" ||
        grep -Fq "filesystem: Landlock unavailable" <<<"$1"
}

helper_launch_capability_skip_output() {
    grep -Fq "netns helper setup failed:" <<<"$1" &&
        grep -Fq "/iptables -A OUTPUT" <<<"$1"
}

skip_or_require() {
    local require_var="$1"
    local message="$2"
    echo "SKIP: $message"
    if [ "${!require_var:-}" = "1" ]; then
        echo "ERROR: $require_var=1 makes this skip a failure"
        exit 1
    fi
    exit 0
}

start_tcp_server() {
    local port_file="$1"
    local bind_addr="$2"
    local pid_var="$3"
    python3 - "$port_file" "$bind_addr" <<'PY' &
import pathlib
import socket
import sys

port_file = pathlib.Path(sys.argv[1])
bind_addr = sys.argv[2]
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((bind_addr, 0))
server.listen(1)
server.settimeout(30)
port_file.write_text(str(server.getsockname()[1]))
try:
    conn, _ = server.accept()
    conn.settimeout(30)
    try:
        data = conn.recv(1)
        if data:
            conn.sendall(b"AXIS-ECHO")
    except socket.timeout:
        pass
    conn.close()
except socket.timeout:
    pass
finally:
    server.close()
PY
    printf -v "$pid_var" '%s' "$!"
}

write_proxy_policy() {
    local policy_file="$1"
    local policy_name="$2"
    local allowed_port="$3"
    local runtime_provider="${4:-auto}"
    local include_proc="${5:-0}"
    cat >"$policy_file" <<EOF
version: 1
name: ${policy_name}

runtime:
  containment: process
  provider: ${runtime_provider}

filesystem:
  read_only:
EOF
    for path in /bin /sbin /usr /lib /lib64 /etc /nix/store; do
        if [ -e "$path" ]; then
            printf '    - %s\n' "$path" >>"$policy_file"
        fi
    done
    if [ "$include_proc" = "1" ]; then
        printf '    - /proc\n' >>"$policy_file"
    fi
    cat >>"$policy_file" <<EOF
  read_write:
    - "{workspace}"

process:
  max_processes: 0
  max_memory_mb: 0
  cpu_rate_percent: 0

network:
  mode: proxy
  policies:
    - name: local-target
      endpoints:
        - host: "127.0.0.1"
          port: ${allowed_port}
EOF
}

snapshot_helper_states() {
    local output_file="$1"
    bounded_sudo 5 find /run/axis/netns -mindepth 1 -maxdepth 1 \
        ! -name .lock \
        -printf '%f\n' 2>/dev/null | bounded 2 sort >"$output_file"
}

wait_for_new_helper_state() {
    local before_file="$1"
    local current_file="$2"
    local owner_pid="$3"
    local owner_start_time="$4"
    local sandbox_id=""
    for _ in $(seq 1 100); do
        snapshot_helper_states "$current_file"
        sandbox_id="$(comm -13 "$before_file" "$current_file" | \
            grep -Em1 '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || true)"
        if [ -n "$sandbox_id" ]; then
            printf '%s\n' "$sandbox_id"
            return 0
        fi
        local probe_status=0
        process_identity_matches "$owner_pid" "$owner_start_time" || probe_status=$?
        if [ "$probe_status" -eq 2 ]; then
            return 2
        fi
        if [ "$probe_status" -ne 0 ]; then
            return 1
        fi
        sleep 0.1
    done
    return 1
}

wait_for_process_exit_bounded() {
    local pid="$1"
    local label="$2"
    if ! bounded 10 tail --pid="$pid" -f /dev/null; then
        echo "ERROR: $label process $pid did not exit within 10 seconds"
        return 1
    fi
    local status=0
    wait "$pid" || status=$?
    printf 'INFO: %s process exited with status %s\n' "$label" "$status"
}

assert_helper_lifecycle_cleanup() {
    local sandbox_id="$1"
    local veth_name="$2"
    local payload_pids_file="$3"
    local state_path="/run/axis/netns/${sandbox_id}"
    local namespace="axis-${sandbox_id}"

    for _ in $(seq 1 100); do
        local state_exists=0
        local namespace_present=0
        local veth_exists=0
        local probe_status=0
        bounded_sudo 2 test -e "$state_path" || probe_status=$?
        if [ "$probe_status" -eq 0 ]; then
            state_exists=1
        elif [ "$probe_status" -ne 1 ]; then
            return 1
        fi
        probe_status=0
        namespace_exists "$namespace" || probe_status=$?
        if [ "$probe_status" -eq 0 ]; then
            namespace_present=1
        elif [ "$probe_status" -ne 1 ]; then
            return 1
        fi
        probe_status=0
        host_veth_exists "$veth_name" || probe_status=$?
        if [ "$probe_status" -eq 0 ]; then
            veth_exists=1
        elif [ "$probe_status" -ne 1 ]; then
            return 1
        fi
        if [ "$state_exists" -eq 0 ] && [ "$namespace_present" -eq 0 ] && [ "$veth_exists" -eq 0 ]; then
            break
        fi
        sleep 0.1
    done

    local probe_status=0
    bounded_sudo 2 test -e "$state_path" || probe_status=$?
    if [ "$probe_status" -eq 0 ]; then
        echo "ERROR: helper state survived lifecycle cleanup: $state_path"
        return 1
    elif [ "$probe_status" -ne 1 ]; then
        return 1
    fi
    probe_status=0
    namespace_exists "$namespace" || probe_status=$?
    if [ "$probe_status" -eq 0 ]; then
        echo "ERROR: network namespace survived lifecycle cleanup: $namespace"
        return 1
    elif [ "$probe_status" -ne 1 ]; then
        return 1
    fi
    probe_status=0
    host_veth_exists "$veth_name" || probe_status=$?
    if [ "$probe_status" -eq 0 ]; then
        echo "ERROR: host veth survived lifecycle cleanup: $veth_name"
        return 1
    elif [ "$probe_status" -ne 1 ]; then
        return 1
    fi
    probe_status=0
    bounded_sudo 5 ip netns exec "$namespace" iptables -S OUTPUT >/dev/null 2>&1 || probe_status=$?
    if [ "$probe_status" -eq 0 ]; then
        echo "ERROR: namespace firewall remained reachable after lifecycle cleanup: $namespace"
        return 1
    elif [ "$probe_status" -eq 125 ]; then
        return 1
    fi

    while read -r pid start_time; do
        [ -n "$pid" ] || continue
        probe_status=0
        process_identity_matches "$pid" "$start_time" || probe_status=$?
        if [ "$probe_status" -eq 0 ]; then
            echo "ERROR: payload namespace member survived lifecycle cleanup: $pid $start_time"
            return 1
        elif [ "$probe_status" -ne 1 ]; then
            return 1
        fi
    done <"$payload_pids_file"

    local stale_temp=""
    stale_temp="$(bounded_sudo 5 find /run/axis/netns -mindepth 1 -maxdepth 1 \
        -name ".tmp-u$(id -u)-*" -print -quit)"
    if [ -n "$stale_temp" ]; then
        echo "ERROR: attributable helper state temp survived lifecycle cleanup: $stale_temp"
        return 1
    fi
}

# shellcheck disable=SC2317,SC2329 # Invoked indirectly by the per-case EXIT trap.
cleanup_helper_lifecycle_case() {
    local original_status=$?
    local owner_pid="$1"
    local helper_pid="$2"
    local sandbox_id="$3"
    local _namespace="$4"
    local _veth_name="$5"
    local socket_path="$6"
    local _before_states="$7"
    local _current_states="$8"
    local owner_start_time="$9"
    local helper_start_time="${10}"
    local state_path=""
    local destroy_token=""
    local cleanup_failed=0
    local probe_status=0
    set +e

    if [ -n "$owner_pid" ] && [ -n "$owner_start_time" ] &&
        process_identity_matches "$owner_pid" "$owner_start_time"; then
        if ! bounded 2 kill -KILL "$owner_pid"; then
            echo "ERROR: failed to terminate lifecycle owner $owner_pid" >&2
            cleanup_failed=1
        fi
    fi
    if [ -n "$helper_pid" ] && [ -n "$helper_start_time" ] &&
        process_identity_matches "$helper_pid" "$helper_start_time"; then
        if ! bounded 2 kill -KILL "$helper_pid"; then
            echo "ERROR: failed to terminate lifecycle helper $helper_pid" >&2
            cleanup_failed=1
        fi
    fi
    if [ -n "$owner_pid" ]; then
        if bounded 2 tail --pid="$owner_pid" -f /dev/null >/dev/null 2>&1; then
            wait "$owner_pid" 2>/dev/null || true
        else
            echo "ERROR: lifecycle owner $owner_pid did not exit within cleanup deadline" >&2
            cleanup_failed=1
        fi
    fi
    if [ -n "$sandbox_id" ]; then
        state_path="/run/axis/netns/${sandbox_id}"
        bounded_sudo 2 test -e "$state_path"
        probe_status=$?
        if [ "$probe_status" -eq 0 ]; then
            # shellcheck disable=SC2016 # The awk field expression is literal.
            destroy_token="$(bounded_sudo 2 awk 'NR == 2 { print $1 }' "$state_path")"
            if [[ ! "$destroy_token" =~ ^[[:xdigit:]]{64}$ ]]; then
                echo "ERROR: refusing lifecycle cleanup with malformed state token: $state_path" >&2
                cleanup_failed=1
            elif ! bounded 5 "$HELPER_INSTALL" destroy-token "$sandbox_id" "$destroy_token"; then
                echo "ERROR: authenticated lifecycle cleanup failed for $sandbox_id" >&2
                cleanup_failed=1
            fi
        elif [ "$probe_status" -ne 1 ]; then
            echo "ERROR: failed to inspect lifecycle helper state: $state_path" >&2
            cleanup_failed=1
        fi
    elif [ "$original_status" -ne 0 ]; then
        echo "ERROR: lifecycle case failed before resource ownership could be identified; refusing name-only cleanup" >&2
    fi
    if ! rm -f "$socket_path"; then
        echo "ERROR: failed to remove lifecycle socket: $socket_path" >&2
        cleanup_failed=1
    fi
    trap - EXIT
    if [ "$original_status" -ne 0 ]; then
        exit "$original_status"
    fi
    if [ "$cleanup_failed" -ne 0 ]; then
        exit 1
    fi
}

run_helper_lifecycle_case() (
    local provider="$1"
    local failure_mode="$2"
    local case_name="${provider}-${failure_mode}"
    local case_root="${TMP_ROOT}/lifecycle-${case_name}"
    local workspace="${case_root}/workspace"
    local policy="${case_root}/policy.yaml"
    local output="${case_root}/axis.out"
    local before_states="${case_root}/states.before"
    local current_states="${case_root}/states.current"
    local raw_payload_pids="${case_root}/payload-host-pids.raw"
    local payload_pids="${case_root}/payload-host-pids"
    local socket_path="/tmp/axis-helper-lifecycle-${case_name}-$$.sock"
    local owner_pid=""
    local owner_start_time=""
    local helper_pid=""
    local helper_start_time=""
    local sandbox_id=""
    local namespace=""
    local veth_name=""
    trap 'cleanup_helper_lifecycle_case "$owner_pid" "$helper_pid" "$sandbox_id" "$namespace" "$veth_name" "$socket_path" "$before_states" "$current_states" "$owner_start_time" "$helper_start_time"' EXIT
    mkdir -p "$workspace"
    if [ "$provider" = "axis_native" ]; then
        write_proxy_policy "$policy" "helper-lifecycle-${case_name}" 9 "$provider" 1
    else
        write_proxy_policy "$policy" "helper-lifecycle-${case_name}" 9 "$provider"
    fi
    snapshot_helper_states "$before_states"

    (
        cd "$workspace"
        exec env AXIS_SOCKET="$socket_path" "$AXIS_RELEASE" --socket "$socket_path" \
            run --policy "$policy" -- "$PYTHON_BIN" -c "$LIFECYCLE_PROBE"
    ) >"$output" 2>&1 &
    owner_pid=$!
    owner_start_time="$(process_start_time "$owner_pid")"

    if ! sandbox_id="$(wait_for_new_helper_state "$before_states" "$current_states" "$owner_pid" "$owner_start_time")"; then
        echo "ERROR: $case_name did not create helper state"
        cat "$output"
        return 1
    fi
    local state_path="/run/axis/netns/${sandbox_id}"
    namespace="axis-${sandbox_id}"
    veth_name="axh$(tr -d '-' <<<"$sandbox_id" | cut -c1-12)"

    for _ in $(seq 1 100); do
        [ -s "$workspace/lifecycle-ready" ] && break
        local probe_status=0
        process_identity_matches "$owner_pid" "$owner_start_time" || probe_status=$?
        if [ "$probe_status" -eq 2 ]; then
            return 1
        fi
        if [ "$probe_status" -ne 0 ]; then
            break
        fi
        sleep 0.1
    done
    if [ ! -s "$workspace/lifecycle-ready" ]; then
        echo "ERROR: $case_name payload did not reach its ready marker"
        cat "$output"
        return 1
    fi
    if [ -s "$workspace/leaked-helper-fds" ]; then
        echo "ERROR: $case_name payload inherited helper-only descriptors"
        cat "$workspace/leaked-helper-fds"
        return 1
    fi
    local probe_status=0
    namespace_exists "$namespace" || probe_status=$?
    if [ "$probe_status" -ne 0 ]; then
        echo "ERROR: $case_name namespace was not present before termination: $namespace"
        return 1
    fi
    probe_status=0
    host_veth_exists "$veth_name" || probe_status=$?
    if [ "$probe_status" -ne 0 ]; then
        echo "ERROR: $case_name host veth was not present before termination: $veth_name"
        return 1
    fi
    local firewall_rules=""
    firewall_rules="$(bounded_sudo 5 ip netns exec "$namespace" iptables -S OUTPUT)" || return 1
    if ! grep -Fq -- '-j REJECT' <<<"$firewall_rules"; then
        echo "ERROR: $case_name firewall deny rule was not present before termination"
        return 1
    fi
    bounded_sudo 5 ip netns pids "$namespace" >"$raw_payload_pids"
    : >"$payload_pids"
    while read -r pid; do
        [ -n "$pid" ] || continue
        local start_time=""
        local identity_status=0
        start_time="$(process_start_time "$pid")" || identity_status=$?
        if [ "$identity_status" -eq 1 ]; then
            continue
        fi
        if [ "$identity_status" -ne 0 ]; then
            return 1
        fi
        printf '%s %s\n' "$pid" "$start_time" >>"$payload_pids"
    done <"$raw_payload_pids"
    if [ "$(wc -l <"$payload_pids")" -lt 5 ]; then
        echo "ERROR: $case_name did not create the expected payload descendant tree"
        cat "$payload_pids"
        return 1
    fi
    if [ "$provider" = "mxc" ]; then
        local expected_executor_seen=0
        while read -r pid _start_time; do
            [ -n "$pid" ] || continue
            local executable=""
            local readlink_status=0
            executable="$(bounded_sudo 2 readlink -f "/proc/${pid}/exe" 2>/dev/null)" || readlink_status=$?
            if [ "$readlink_status" -eq 125 ]; then
                return 1
            fi
            if [ "$readlink_status" -ne 0 ]; then
                continue
            fi
            if [ "$executable" = "$expected_executor" ]; then
                expected_executor_seen=1
                break
            fi
        done <"$payload_pids"
        if [ "$expected_executor_seen" -ne 1 ]; then
            echo "ERROR: $case_name did not execute trusted MXC binary $expected_executor"
            while read -r pid _start_time; do
                bounded_sudo 2 readlink -f "/proc/${pid}/exe" 2>/dev/null || true
            done <"$payload_pids"
            return 1
        fi
    fi

    local boundary_pid
    # shellcheck disable=SC2016 # The awk field expression is literal.
    boundary_pid="$(bounded_sudo 2 awk 'NR == 4 && $1 == "payload" { print $2 }' "$state_path")"
    if [ -z "$boundary_pid" ]; then
        echo "ERROR: $case_name helper state did not record its PID namespace init"
        return 1
    fi
    helper_pid="$(bounded 2 ps -o ppid= -p "$boundary_pid" | bounded 2 tr -d '[:space:]')"
    if [ -z "$helper_pid" ]; then
        echo "ERROR: $case_name could not identify the setuid helper process"
        return 1
    fi
    helper_start_time="$(process_start_time "$helper_pid")"

    case "$failure_mode" in
        owner-death)
            process_identity_matches "$owner_pid" "$owner_start_time"
            bounded 2 kill -KILL "$owner_pid"
            ;;
        helper-sigkill)
            process_identity_matches "$helper_pid" "$helper_start_time"
            bounded 2 kill -KILL "$helper_pid"
            ;;
        *) echo "ERROR: unknown lifecycle failure mode: $failure_mode"; return 1 ;;
    esac
    wait_for_process_exit_bounded "$owner_pid" "$case_name owner"
    owner_pid=""
    assert_helper_lifecycle_cleanup "$sandbox_id" "$veth_name" "$payload_pids"
    helper_pid=""
    echo "PASS: $case_name removed payloads, helper state, namespace, firewall, and veth"
)

cd "$REPO_ROOT"

cargo build --locked -p axis-sandbox --bin axis-netns-helper

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
case "$TARGET_DIR" in
    /*) ;;
    *) TARGET_DIR="${REPO_ROOT}/${TARGET_DIR}" ;;
esac

HELPER_BUILD="${TARGET_DIR}/debug/axis-netns-helper"

if [ ! -x "$HELPER_BUILD" ]; then
    echo "ERROR: helper build output missing: $HELPER_BUILD"
    exit 1
fi

if ! reject_preexisting_privileged_path "$HELPER_INSTALL" "helper on an e2e runner"; then
    echo "Run this proof only in a disposable CI/container/VM without a preinstalled helper."
    exit 1
fi

validate_privileged_directory /usr/libexec "helper install parent"
helper_dir_status=0
bounded_sudo 2 test -e /usr/libexec/axis || helper_dir_status=$?
if [ "$helper_dir_status" -eq 0 ]; then
    validate_privileged_directory /usr/libexec/axis "helper install directory"
elif [ "$helper_dir_status" -eq 1 ]; then
    helper_dir_symlink_status=0
    bounded_sudo 2 test -L /usr/libexec/axis || helper_dir_symlink_status=$?
    if [ "$helper_dir_symlink_status" -eq 0 ]; then
        echo "ERROR: refusing dangling helper install directory symlink: /usr/libexec/axis"
        exit 1
    elif [ "$helper_dir_symlink_status" -ne 1 ]; then
        echo "ERROR: failed to inspect helper install directory symlink: /usr/libexec/axis"
        exit "$helper_dir_symlink_status"
    fi
    bounded_sudo 5 install -d -o root -g root -m 0755 /usr/libexec/axis
    CREATED_HELPER_DIR=1
else
    echo "ERROR: failed to inspect helper install directory: /usr/libexec/axis"
    exit "$helper_dir_status"
fi
INSTALLED_HELPER=1
bounded_sudo 5 install -o root -g root -m 4755 "$HELPER_BUILD" "$HELPER_INSTALL"

owner="$(bounded 2 stat -c '%u:%g %a' "$HELPER_INSTALL")"
if [ "$owner" != "0:0 4755" ]; then
    echo "ERROR: helper install mode mismatch: $owner"
    exit 1
fi

set +e
helper_check_output="$(bounded 10 "$HELPER_INSTALL" check 2>&1)"
helper_check_status=$?
set -e
if [ "$helper_check_status" -ne 0 ]; then
    echo "ERROR: installed helper failed availability check"
    echo "$helper_check_output"
    exit "$helper_check_status"
fi

preflight_suffix="$(tr -d '-' </proc/sys/kernel/random/uuid | cut -c1-16)"
PREFLIGHT_NS="axis-helper-preflight-${preflight_suffix}-$$"
preflight_namespace_exists() {
    namespace_exists "$1"
}
preflight_namespace_add() {
    bounded_sudo 5 ip netns add "$1"
    PREFLIGHT_NS_CREATED=1
}
preflight_namespace_configure() {
    bounded_sudo 5 ip netns exec "$1" iptables -A OUTPUT -o lo -j ACCEPT
}
preflight_namespace_delete() {
    bounded_sudo 5 ip netns del "$1"
    PREFLIGHT_NS_CREATED=0
}
set +e
preflight_output_file="${TMP_ROOT}/preflight.out"
run_preflight_namespace_state_machine \
    "$PREFLIGHT_NS" \
    preflight_namespace_exists \
    preflight_namespace_add \
    preflight_namespace_configure \
    preflight_namespace_delete >"$preflight_output_file" 2>&1
preflight_status=$?
preflight_output="$(cat "$preflight_output_file")"
set -e
if [ "$preflight_status" -ne 0 ]; then
    if [ "$preflight_status" -eq 126 ]; then
        echo "$preflight_output"
        exit 1
    fi
    if [ "$preflight_status" -eq 125 ]; then
        echo "ERROR: netns helper preflight exceeded its command deadline"
        echo "$preflight_output"
        exit 1
    fi
    skip_or_require \
        AXIS_REQUIRE_NETNS_HELPER_E2E \
        "netns helper launch proof requires privileged iptables in network namespaces: ${preflight_output//$'\n'/ }"
fi

HELPER_TEST_OUTPUT="${TMP_ROOT}/helper-test.out"
set +e
bounded 300 env AXIS_TEST_NETNS_HELPER_LAUNCH=1 cargo test --locked -p axis-sandbox \
    gated_netns_helper_launch_starts_proxy_mode_sandbox_as_unprivileged_daemon \
    -- --nocapture >"$HELPER_TEST_OUTPUT" 2>&1
helper_test_status=$?
set -e
if [ "$helper_test_status" -ne 0 ]; then
    helper_test_output="$(cat "$HELPER_TEST_OUTPUT")"
    if capability_skip_output "$helper_test_output" ||
        helper_launch_capability_skip_output "$helper_test_output"; then
        tail -n 120 "$HELPER_TEST_OUTPUT"
        skip_or_require \
            AXIS_REQUIRE_NETNS_HELPER_E2E \
            "netns helper launch proof is unavailable on this runner"
    fi
    cat "$HELPER_TEST_OUTPUT"
    exit "$helper_test_status"
fi
cat "$HELPER_TEST_OUTPUT"

echo ""
echo "=== Built axis proxy-mode proof ==="

cargo build --locked --release -p axis-cli -p axis-sandbox --bins
AXIS_RELEASE="${TARGET_DIR}/release/axis"
if [ ! -x "$AXIS_RELEASE" ]; then
    echo "ERROR: release axis binary missing: $AXIS_RELEASE"
    exit 1
fi
if [ ! -x "${TARGET_DIR}/release/axis-seccomp-launcher" ]; then
    echo "ERROR: release axis-seccomp-launcher binary missing: ${TARGET_DIR}/release/axis-seccomp-launcher"
    exit 1
fi

PYTHON_BIN="$(command -v python3)"

read -r -d '' LIFECYCLE_PROBE <<'PY' || true
import os
import pathlib
import time

workspace = pathlib.Path.cwd()
leaked = []
for name in os.listdir("/proc/self/fd"):
    try:
        fd = int(name)
        if fd <= 2:
            continue
        target = os.readlink(f"/proc/self/fd/{fd}")
    except (OSError, ValueError):
        continue
    leaked.append(f"{fd} {target}")

if leaked:
    (workspace / "leaked-helper-fds").write_text("\n".join(leaked) + "\n")
    raise SystemExit(91)
(workspace / "payload-fds").write_text("stdio-only\n")

def hold(mode):
    if mode == "session":
        os.setsid()
    else:
        os.setpgid(0, 0)
    descendant = os.fork()
    if descendant == 0:
        while True:
            time.sleep(1)
    while True:
        time.sleep(1)

def churn():
    os.setpgid(0, 0)
    while True:
        worker = os.fork()
        if worker == 0:
            orphan = os.fork()
            if orphan == 0:
                time.sleep(0.05)
                os._exit(0)
            os._exit(0)
        try:
            os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            pass
        time.sleep(0.005)

for mode in ("session", "process-group"):
    child = os.fork()
    if child == 0:
        hold(mode)

churner = os.fork()
if churner == 0:
    churn()

(workspace / "lifecycle-ready").write_text("ready\n")
while True:
    time.sleep(1)
PY

echo ""
echo "=== Helper PID namespace lifecycle proof ==="
for provider in axis_native mxc; do
    for failure_mode in owner-death helper-sigkill; do
        run_helper_lifecycle_case "$provider" "$failure_mode"
    done
done

SERVER_PORT_FILE="${TMP_ROOT}/server.port"
start_tcp_server "$SERVER_PORT_FILE" "127.0.0.1" SERVER_PID

if ! wait_for_port_file "$SERVER_PORT_FILE"; then
    echo "ERROR: local proxy target server did not publish a port"
    exit 1
fi
SERVER_PORT="$(cat "$SERVER_PORT_FILE")"

DIRECT_PORT_FILE="${TMP_ROOT}/direct.port"
start_tcp_server "$DIRECT_PORT_FILE" "0.0.0.0" DIRECT_SERVER_PID

if ! wait_for_port_file "$DIRECT_PORT_FILE"; then
    echo "ERROR: direct-bypass target server did not publish a port"
    exit 1
fi
DIRECT_PORT="$(cat "$DIRECT_PORT_FILE")"

PROXY_POLICY="${TMP_ROOT}/proxy-policy.yaml"
write_proxy_policy "$PROXY_POLICY" "helper-proxy-e2e" "$SERVER_PORT"

read -r -d '' PROXY_PROBE <<PY || true
import os
import socket
import sys
from urllib.parse import urlparse

proxy_url = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
if not proxy_url:
    print("missing proxy environment")
    sys.exit(1)
proxy = urlparse(proxy_url)
proxy_host = proxy.hostname
proxy_port = proxy.port
if not proxy_host or not proxy_port:
    print(f"invalid proxy environment: {proxy_url!r}")
    sys.exit(1)

def connect_request(host, port):
    s = socket.create_connection((proxy_host, proxy_port), timeout=3)
    request = f"CONNECT {host}:{port} HTTP/1.1\\r\\nHost: {host}:{port}\\r\\n\\r\\n"
    s.sendall(request.encode())
    response = s.recv(256)
    return s, response

allowed_socket, allowed = connect_request("127.0.0.1", ${SERVER_PORT})
if b"200" not in allowed.splitlines()[0]:
    print(f"allowed CONNECT did not return 200: {allowed!r}")
    sys.exit(2)
allowed_socket.sendall(b"!")
tunneled = allowed_socket.recv(9)
allowed_socket.close()
if tunneled != b"AXIS-ECHO":
    print(f"allowed CONNECT did not tunnel bytes to target: {tunneled!r}")
    sys.exit(5)

denied_socket, denied = connect_request("denied.example.invalid", 443)
denied_socket.close()
if b"403" not in denied.splitlines()[0]:
    print(f"denied CONNECT did not return 403: {denied!r}")
    sys.exit(3)

try:
    direct = socket.create_connection((proxy_host, ${DIRECT_PORT}), timeout=1)
except OSError:
    pass
else:
    direct.close()
    print("direct non-proxy connection unexpectedly succeeded")
    sys.exit(4)

print("proxy allowed/denied/direct-bypass checks passed", flush=True)
import time
time.sleep(10)
PY

PROXY_OUTPUT="${TMP_ROOT}/proxy-proof.out"
AXIS_SOCKET="/tmp/axis-proxy-e2e-$$.sock" \
    timeout 30 "$AXIS_RELEASE" --socket "/tmp/axis-proxy-e2e-$$.sock" \
    run --policy "$PROXY_POLICY" -- "$PYTHON_BIN" -c "$PROXY_PROBE" \
    >"$PROXY_OUTPUT" 2>&1 &
PROXY_PROOF_PID=$!
PROXY_PROOF_START_TIME="$(process_start_time "$PROXY_PROOF_PID")"

for _ in $(seq 1 100); do
    grep -Fq "proxy allowed/denied/direct-bypass checks passed" "$PROXY_OUTPUT" && break
    probe_status=0
    process_identity_matches "$PROXY_PROOF_PID" "$PROXY_PROOF_START_TIME" || probe_status=$?
    if [ "$probe_status" -eq 2 ]; then
        exit 1
    fi
    if [ "$probe_status" -ne 0 ]; then
        break
    fi
    sleep 0.1
done

if ! grep -Fq "proxy allowed/denied/direct-bypass checks passed" "$PROXY_OUTPUT"; then
    echo "ERROR: built axis proof did not reach the strict proxy listener marker"
    cat "$PROXY_OUTPUT"
    exit 1
fi

proxy_address="$(sed -n 's/^AXIS: proxy on \([^[:space:]]*\).*$/\1/p' "$PROXY_OUTPUT" | head -n1)"
if [ -z "$proxy_address" ]; then
    echo "ERROR: built axis proof did not advertise its strict proxy address"
    cat "$PROXY_OUTPUT"
    exit 1
fi
bounded 10 "$PYTHON_BIN" - "$proxy_address" "$SERVER_PORT" <<'PY'
import socket
import sys

host, port = sys.argv[1].rsplit(":", 1)
target_port = int(sys.argv[2])
with socket.create_connection((host, int(port)), timeout=3) as connection:
    request = f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
    connection.sendall(request.encode())
    response = connection.recv(256)
if b"403" not in response.splitlines()[0]:
    print(f"host-side strict proxy connection was not rejected: {response!r}")
    sys.exit(1)
if b"unauthenticated sandbox peer" not in response:
    print(f"host-side request was not rejected by peer authentication: {response!r}")
    sys.exit(2)
print("host-side strict proxy peer rejected")
PY

set +e
wait "$PROXY_PROOF_PID"
proxy_status=$?
set -e
PROXY_PROOF_PID=""
PROXY_PROOF_START_TIME=""
proxy_output="$(cat "$PROXY_OUTPUT")"
if [ "$proxy_status" -ne 0 ]; then
    if [ "$proxy_status" -eq 124 ] || [ "$proxy_status" -eq 125 ] || [ "$proxy_status" -eq 137 ]; then
        echo "ERROR: built axis proxy proof exceeded its command deadline"
        echo "$proxy_output"
        exit 1
    fi
    if capability_skip_output "$proxy_output"; then
        skip_or_require \
            AXIS_REQUIRE_BUILT_AXIS_PROXY_E2E \
            "built axis proxy proof unavailable on this runner: ${proxy_output//$'\n'/ }"
    fi
    echo "$proxy_output"
    exit "$proxy_status"
fi
echo "$proxy_output"

stop_background_servers

echo ""
echo "=== Kmsg bypass audit proof ==="

provision_kmsg_audit_source
kmsg_status=0
kmsg_gate_status "${AXIS_REQUIRE_KMSG_AUDIT_E2E:-0}" "$([ -r /dev/kmsg ] && echo 1 || echo 0)" || kmsg_status=$?
if [ "$kmsg_status" -eq 1 ]; then
    echo "ERROR: AXIS_REQUIRE_KMSG_AUDIT_E2E=1 requires a readable /dev/kmsg audit source"
    exit 1
elif [ "$kmsg_status" -eq 77 ]; then
    skip_or_require AXIS_REQUIRE_KMSG_AUDIT_E2E "bypass audit proof requires non-root readable /dev/kmsg"
fi

cargo build --locked --release -p axis-daemon
AXISD_RELEASE="${TARGET_DIR}/release/axisd"
if [ ! -x "$AXISD_RELEASE" ]; then
    echo "ERROR: release axisd binary missing: $AXISD_RELEASE"
    exit 1
fi

AUDIT_SOCKET="${TMP_ROOT}/axisd-audit.sock"
AUDIT_LOG_DIR="${TMP_ROOT}/logs"
mkdir -p "$AUDIT_LOG_DIR"
SERVER_PORT_FILE="${TMP_ROOT}/audit-server.port"
DIRECT_PORT_FILE="${TMP_ROOT}/audit-direct.port"
start_tcp_server "$SERVER_PORT_FILE" "127.0.0.1" SERVER_PID
start_tcp_server "$DIRECT_PORT_FILE" "0.0.0.0" DIRECT_SERVER_PID
if ! wait_for_port_file "$SERVER_PORT_FILE"; then
    echo "ERROR: audit proxy target server did not publish a port"
    exit 1
fi
if ! wait_for_port_file "$DIRECT_PORT_FILE"; then
    echo "ERROR: audit direct-bypass target server did not publish a port"
    exit 1
fi
AUDIT_SERVER_PORT="$(cat "$SERVER_PORT_FILE")"
AUDIT_DIRECT_PORT="$(cat "$DIRECT_PORT_FILE")"
AUDIT_POLICY="${TMP_ROOT}/audit-proxy-policy.yaml"
write_proxy_policy "$AUDIT_POLICY" "helper-proxy-audit-e2e" "$AUDIT_SERVER_PORT"

AXIS_LOG_LEVEL="axis=info,axis::audit=info" \
AXIS_LOG_DIR="$AUDIT_LOG_DIR" \
XDG_DATA_HOME="${TMP_ROOT}/xdg-audit" \
AXIS_SOCKET="$AUDIT_SOCKET" \
    "$AXISD_RELEASE" >"${TMP_ROOT}/axisd-audit.stderr" 2>&1 &
AXSD_PID=$!

if ! wait_for_socket_path "$AUDIT_SOCKET"; then
    echo "ERROR: audit axisd did not create IPC socket"
    cat "${TMP_ROOT}/axisd-audit.stderr" || true
    exit 1
fi

read -r -d '' AUDIT_PROBE <<PY || true
import os
import socket
import sys
import time
from urllib.parse import urlparse

proxy_url = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
if not proxy_url:
    print("missing proxy environment")
    sys.exit(1)
proxy = urlparse(proxy_url)
if not proxy.hostname:
    print(f"invalid proxy environment: {proxy_url!r}")
    sys.exit(1)
try:
    direct = socket.create_connection((proxy.hostname, ${AUDIT_DIRECT_PORT}), timeout=1)
except OSError:
    print("direct bypass rejected")
    time.sleep(3)
    sys.exit(0)
else:
    direct.close()
    print("direct bypass unexpectedly succeeded")
    sys.exit(4)
PY

set +e
create_output="$(bounded 20 "$AXIS_RELEASE" --socket "$AUDIT_SOCKET" create --policy "$AUDIT_POLICY" -- "$PYTHON_BIN" -c "$AUDIT_PROBE" 2>&1)"
create_status=$?
set -e
if [ "$create_status" -ne 0 ]; then
    if capability_skip_output "$create_output"; then
        skip_or_require \
            AXIS_REQUIRE_KMSG_AUDIT_E2E \
            "bypass audit proof unavailable on this runner: ${create_output//$'\n'/ }"
    fi
    echo "$create_output"
    echo "ERROR: audit sandbox was not created"
    exit "$create_status"
fi
if ! grep -Eq 'Sandbox created: [0-9a-f-]+' <<<"$create_output"; then
    echo "$create_output"
    echo "ERROR: audit sandbox was not created"
    exit 1
fi
audit_sandbox_id="$(grep -oE '[0-9a-f]{8}-[0-9a-f-]{27}' <<<"$create_output" | head -n1)"

for _ in $(seq 1 40); do
    if grep -q "network bypass attempt" "${AUDIT_LOG_DIR}/axisd.log" 2>/dev/null &&
        grep -q "$audit_sandbox_id" "${AUDIT_LOG_DIR}/axisd.log" 2>/dev/null &&
        grep -q ":${AUDIT_DIRECT_PORT}" "${AUDIT_LOG_DIR}/axisd.log" 2>/dev/null; then
        echo "PASS: bypass audit event recorded"
        if ! bounded 10 "$AXIS_RELEASE" --socket "$AUDIT_SOCKET" destroy "$audit_sandbox_id"; then
            echo "ERROR: failed to destroy audited sandbox: $audit_sandbox_id"
            exit 1
        fi
        exit 0
    fi
    sleep 0.25
done

cat "${AUDIT_LOG_DIR}/axisd.log" 2>/dev/null || true
echo "ERROR: bypass audit event was not recorded"
if ! bounded 10 "$AXIS_RELEASE" --socket "$AUDIT_SOCKET" destroy "$audit_sandbox_id"; then
    echo "ERROR: failed to destroy unaudited sandbox: $audit_sandbox_id"
fi
exit 1
