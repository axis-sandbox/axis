#!/bin/bash
set -euo pipefail

AXIS=~/axis/axis
echo "=== AXIS E2E Test on $(hostname) ==="
echo "Kernel: $(uname -r)"
echo ""

PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

# ── Test 1: Landlock ABI ──
echo "--- Test 1: Landlock ABI ---"
python3 -c "
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
ret = libc.syscall(444, None, 0, 1)
if ret >= 1: print(f'ABI version {ret}')
else: exit(1)
" && pass "Landlock available" || fail "Landlock unavailable"

# ── Test 2: Policy validation ──
echo "--- Test 2: Policy Validation ---"
$AXIS policy validate ~/axis/policies/coding-agent.yaml >/dev/null && pass "coding-agent.yaml" || fail "coding-agent.yaml"
$AXIS policy validate ~/axis/policies/minimal.yaml >/dev/null && pass "minimal.yaml" || fail "minimal.yaml"

# ── Test 3: Landlock filesystem isolation ──
echo "--- Test 3: Landlock Filesystem Isolation ---"
WORKSPACE=$(mktemp -d /tmp/axis-ws-XXXXXX)
python3 - "$WORKSPACE" << 'PYEOF'
import ctypes, ctypes.util, os, sys

workspace = sys.argv[1]
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

pid = os.fork()
if pid == 0:
    ACCESS_ALL = (1<<0)|(1<<1)|(1<<2)|(1<<3)|(1<<4)|(1<<5)|(1<<7)|(1<<8)|(1<<13)|(1<<14)
    ACCESS_RO  = (1<<0)|(1<<2)|(1<<3)

    class RulesetAttr(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64), ("handled_access_net", ctypes.c_uint64)]
    class PathBeneathAttr(ctypes.Structure):
        _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int)]

    attr = RulesetAttr(ACCESS_ALL, 0)
    fd = libc.syscall(444, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    assert fd >= 0, "create_ruleset failed"

    # workspace: read-write
    ws_fd = os.open(workspace, os.O_PATH)
    libc.syscall(445, fd, 1, ctypes.byref(PathBeneathAttr(ACCESS_ALL, ws_fd)), 0)
    os.close(ws_fd)

    # /usr, /lib, /etc: read-only
    for p in ["/usr", "/lib", "/lib64", "/etc", "/bin", "/sbin"]:
        try:
            pfd = os.open(p, os.O_PATH)
            libc.syscall(445, fd, 1, ctypes.byref(PathBeneathAttr(ACCESS_RO, pfd)), 0)
            os.close(pfd)
        except: pass

    libc.prctl(38, 1, 0, 0, 0)
    assert libc.syscall(446, fd, 0) == 0, "restrict_self failed"
    os.close(fd)

    # Test write inside workspace
    with open(os.path.join(workspace, "test.txt"), "w") as f:
        f.write("hello")
    print("WRITE_WORKSPACE: OK")

    # Test read /usr/bin
    n = len(os.listdir("/usr/bin"))
    print(f"READ_USR_BIN: OK ({n} entries)")

    # Test write to /tmp (should be BLOCKED)
    try:
        with open("/tmp/axis-escape.txt", "w") as f:
            f.write("bad")
        print("WRITE_TMP: NOT_BLOCKED")
        os._exit(1)
    except PermissionError:
        print("WRITE_TMP: BLOCKED")

    os._exit(0)
else:
    _, status = os.waitpid(pid, 0)
    sys.exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1)
PYEOF
if [ $? -eq 0 ]; then
    pass "Landlock blocks writes outside workspace"
else
    fail "Landlock isolation"
fi
rm -rf "$WORKSPACE"

# ── Test 4: seccomp blocks ptrace ──
echo "--- Test 4: seccomp Blocks ptrace ---"
python3 << 'PYEOF'
import ctypes, ctypes.util, os, sys, struct, errno as errno_mod

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

pid = os.fork()
if pid == 0:
    libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS

    # BPF filter: load syscall nr, block ptrace(101), allow rest
    # struct sock_filter: { u16 code, u8 jt, u8 jf, u32 k }
    insns  = struct.pack("HBBI", 0x20, 0, 0, 0)         # LD ABS [0] (syscall nr)
    insns += struct.pack("HBBI", 0x15, 0, 1, 101)        # JEQ ptrace -> deny : allow
    insns += struct.pack("HBBI", 0x06, 0, 0, 0x00050001) # RET ERRNO(EPERM)
    insns += struct.pack("HBBI", 0x06, 0, 0, 0x7fff0000) # RET ALLOW

    # struct sock_fprog: { u16 len, sock_filter* filter }
    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    filter_buf = ctypes.create_string_buffer(insns)
    prog = SockFprog(len=4, filter=ctypes.addressof(filter_buf))

    # seccomp(SECCOMP_SET_MODE_FILTER=1, flags=0, prog)
    ret = libc.syscall(317, 1, 0, ctypes.byref(prog))
    if ret < 0:
        print(f"seccomp syscall failed: errno={ctypes.get_errno()}")
        os._exit(1)

    # Now ptrace should fail with EPERM
    ret = libc.ptrace(0, 0, 0, 0)
    err = ctypes.get_errno()
    if err == errno_mod.EPERM:
        print("PTRACE: BLOCKED by seccomp")
    else:
        print(f"PTRACE: NOT BLOCKED (ret={ret} errno={err})")
        os._exit(1)

    print(f"GETPID: OK ({os.getpid()})")
    os._exit(0)
else:
    _, status = os.waitpid(pid, 0)
    sys.exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1)
PYEOF
[ $? -eq 0 ] && pass "seccomp blocks ptrace, allows getpid" || fail "seccomp"

# ── Test 5: Success metrics ──
echo "--- Test 5: Success Metrics ---"
~/axis/success-metrics 2>/dev/null | grep -q "5/5" && pass "All 5/5 metrics pass" || fail "Metrics"

# ── Summary ──
echo ""
echo "  ─────────────────────────────────────────────────────────"
echo "  Result: $PASS/$((PASS+FAIL)) tests passed, $FAIL failed"
[ $FAIL -eq 0 ] && echo "  All e2e tests passed."
