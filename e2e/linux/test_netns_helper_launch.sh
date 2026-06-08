#!/usr/bin/env bash
# Privileged Linux e2e proof for axis-netns-helper launch mode.
#
# This is intentionally an ephemeral-runner harness, not a local developer
# install path. It mutates /usr/libexec/axis only after an explicit opt-in so
# ordinary repo tests never depend on a host setuid helper.
set -euo pipefail

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

if ! sudo -n true >/dev/null 2>&1; then
    echo "ERROR: passwordless sudo is required in the ephemeral test runner"
    exit 1
fi

for tool in cargo install stat; do
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TMP_ROOT="$(mktemp -d /tmp/axis-netns-helper-e2e-XXXXXX)"
SERVER_PID=""
DIRECT_SERVER_PID=""
AXSD_PID=""
HELPER_INSTALL="/usr/libexec/axis/axis-netns-helper"
INSTALLED_HELPER=0
cleanup() {
    stop_background_servers
    if [ -n "$AXSD_PID" ]; then
        kill "$AXSD_PID" 2>/dev/null || true
        wait "$AXSD_PID" 2>/dev/null || true
    fi
    if [ "$INSTALLED_HELPER" -eq 1 ]; then
        sudo rm -f "$HELPER_INSTALL" 2>/dev/null || true
    fi
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

stop_background_servers() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
    if [ -n "$DIRECT_SERVER_PID" ]; then
        kill "$DIRECT_SERVER_PID" 2>/dev/null || true
        wait "$DIRECT_SERVER_PID" 2>/dev/null || true
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
    cat >"$policy_file" <<EOF
version: 1
name: ${policy_name}

filesystem:
  read_only:
EOF
    for path in /bin /sbin /usr /lib /lib64 /etc /nix/store; do
        if [ -e "$path" ]; then
            printf '    - %s\n' "$path" >>"$policy_file"
        fi
    done
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

cd "$REPO_ROOT"

cargo build -p axis-sandbox --bin axis-netns-helper

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

if [ -e "$HELPER_INSTALL" ]; then
    echo "ERROR: refusing to overwrite preexisting helper on an e2e runner: $HELPER_INSTALL"
    echo "Run this proof only in a disposable CI/container/VM without a preinstalled helper."
    exit 1
fi

sudo install -d -o root -g root -m 0755 /usr/libexec/axis
sudo install -o root -g root -m 4755 "$HELPER_BUILD" "$HELPER_INSTALL"
INSTALLED_HELPER=1

owner="$(stat -c '%u:%g %a' "$HELPER_INSTALL")"
if [ "$owner" != "0:0 4755" ]; then
    echo "ERROR: helper install mode mismatch: $owner"
    exit 1
fi

AXIS_TEST_NETNS_HELPER_LAUNCH=1 \
    cargo test -p axis-sandbox \
    gated_netns_helper_launch_starts_proxy_mode_sandbox_as_unprivileged_daemon \
    -- --nocapture

echo ""
echo "=== Built axis proxy-mode proof ==="

cargo build --release -p axis-cli
AXIS_RELEASE="${TARGET_DIR}/release/axis"
if [ ! -x "$AXIS_RELEASE" ]; then
    echo "ERROR: release axis binary missing: $AXIS_RELEASE"
    exit 1
fi

PYTHON_BIN="$(command -v python3)"
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

print("proxy allowed/denied/direct-bypass checks passed")
PY

PROXY_OUTPUT="${TMP_ROOT}/proxy-proof.out"
set +e
AXIS_SOCKET="/tmp/axis-proxy-e2e-$$.sock" \
    timeout 30 "$AXIS_RELEASE" --socket "/tmp/axis-proxy-e2e-$$.sock" \
    run --policy "$PROXY_POLICY" -- "$PYTHON_BIN" -c "$PROXY_PROBE" \
    >"$PROXY_OUTPUT" 2>&1
proxy_status=$?
set -e
proxy_output="$(cat "$PROXY_OUTPUT")"
if [ "$proxy_status" -ne 0 ]; then
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

if [ ! -r /dev/kmsg ]; then
    skip_or_require AXIS_REQUIRE_KMSG_AUDIT_E2E "bypass audit proof requires non-root readable /dev/kmsg"
fi

cargo build --release -p axis-daemon
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
create_output="$("$AXIS_RELEASE" --socket "$AUDIT_SOCKET" create --policy "$AUDIT_POLICY" -- "$PYTHON_BIN" -c "$AUDIT_PROBE" 2>&1)"
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
        "$AXIS_RELEASE" --socket "$AUDIT_SOCKET" destroy "$audit_sandbox_id" >/dev/null 2>&1 || true
        exit 0
    fi
    sleep 0.25
done

cat "${AUDIT_LOG_DIR}/axisd.log" 2>/dev/null || true
echo "ERROR: bypass audit event was not recorded"
"$AXIS_RELEASE" --socket "$AUDIT_SOCKET" destroy "$audit_sandbox_id" >/dev/null 2>&1 || true
exit 1
