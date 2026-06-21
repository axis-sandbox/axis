#!/usr/bin/env bash
# Validate the Linux MXC packaging and installer contract without sudo.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TMP_ROOT="$(mktemp -d /tmp/mxc-packaging-XXXXXX)"

cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

assert_file() {
    local path="$1"
    [ -f "$path" ] || fail "expected file: $path"
}

assert_executable() {
    local path="$1"
    [ -x "$path" ] || fail "expected executable: $path"
}

assert_contains() {
    local path="$1"
    local pattern="$2"
    grep -Fq -- "$pattern" "$path" || fail "expected '$pattern' in $path"
}

write_fake_binary() {
    local path="$1"
    cat >"$path" <<'EOF'
#!/bin/sh
exit 0
EOF
    chmod 0755 "$path"
}

make_archive() {
    local archive="$1"
    shift
    local root="$TMP_ROOT/archive-$(basename "$archive" .tar.gz)"
    mkdir -p "$root"
    for bin in "$@"; do
        write_fake_binary "$root/$bin"
    done
    tar czf "$archive" -C "$root" .
}

run_installer() {
    local archive="$1"
    local home="$2"
    shift 2
    HOME="$home" AXIS_INSTALL_ARCHIVE="$archive" sh "$REPO_ROOT/install.sh" "$@"
}

FULL_ARCHIVE="$TMP_ROOT/pkg-linux-x86_64.tar.gz"
MISSING_MXC_ARCHIVE="$TMP_ROOT/pkg-linux-x86_64-missing-mxc.tar.gz"
MISSING_SECCOMP_ARCHIVE="$TMP_ROOT/pkg-linux-x86_64-missing-seccomp.tar.gz"
INSTALL_HOME="$TMP_ROOT/home"
INSTALL_PREFIX="$INSTALL_HOME/.local/bin"
INSTALL_DEPS_DOC="$REPO_ROOT/docs/install-and-runtime-dependencies.md"
SETUP_DOC="$REPO_ROOT/docs/setup-and-install.md"
CI_WORKFLOW="$REPO_ROOT/.github/workflows/ci.yml"

mkdir -p "$INSTALL_HOME"
make_archive "$FULL_ARCHIVE" axis axisd axis-seccomp-launcher lxc-exec axis-netns-helper
make_archive "$MISSING_MXC_ARCHIVE" axis axisd axis-seccomp-launcher
make_archive "$MISSING_SECCOMP_ARCHIVE" axis axisd lxc-exec

sh -n "$REPO_ROOT/install.sh"

run_installer "$FULL_ARCHIVE" "$INSTALL_HOME" --prefix "$INSTALL_PREFIX" >/"$TMP_ROOT/install.log"
for bin in axis axisd axis-seccomp-launcher lxc-exec; do
    assert_file "$INSTALL_PREFIX/$bin"
    assert_executable "$INSTALL_PREFIX/$bin"
done
if [ -e "$INSTALL_PREFIX/axis-netns-helper" ]; then
    fail "default installer must not install the privileged netns helper"
fi

if run_installer "$MISSING_MXC_ARCHIVE" "$INSTALL_HOME" --prefix "$TMP_ROOT/missing/bin" \
    >"$TMP_ROOT/missing.log" 2>&1; then
    fail "installer succeeded without lxc-exec"
fi
assert_contains "$TMP_ROOT/missing.log" "archive does not contain lxc-exec"

if run_installer "$MISSING_SECCOMP_ARCHIVE" "$INSTALL_HOME" --prefix "$TMP_ROOT/missing-seccomp/bin" \
    >"$TMP_ROOT/missing-seccomp.log" 2>&1; then
    fail "installer succeeded without axis-seccomp-launcher"
fi
assert_contains "$TMP_ROOT/missing-seccomp.log" "archive does not contain axis-seccomp-launcher"

if run_installer "$FULL_ARCHIVE" "$INSTALL_HOME" --with-cap-net-admin --prefix "$INSTALL_HOME/cap-bin" \
    >"$TMP_ROOT/cap-home.log" 2>&1; then
    fail "--with-cap-net-admin accepted an explicit user prefix"
fi
assert_contains "$TMP_ROOT/cap-home.log" "--with-cap-net-admin requires a root-owned install prefix"

if run_installer "$FULL_ARCHIVE" "$INSTALL_HOME" --with-netns-helper --with-cap-net-admin \
    >"$TMP_ROOT/conflict.log" 2>&1; then
    fail "installer accepted conflicting privileged network options"
fi
assert_contains "$TMP_ROOT/conflict.log" "choose either --with-netns-helper or --with-cap-net-admin"

assert_contains "$REPO_ROOT/crates/axis-daemon/Cargo.toml" '["target/release/lxc-exec", "usr/bin/", "755"]'
assert_contains "$REPO_ROOT/crates/axis-daemon/Cargo.toml" 'dest = "/usr/bin/lxc-exec"'
if grep -Fq 'axis-netns-helper", "usr/libexec/axis/", "4755"' "$REPO_ROOT/crates/axis-daemon/Cargo.toml"; then
    fail "base deb package must not install axis-netns-helper setuid content"
fi
if grep -Fq 'axis-netns-helper", mode = "4755"' "$REPO_ROOT/crates/axis-daemon/Cargo.toml"; then
    fail "base rpm package must not install axis-netns-helper setuid content"
fi

for workflow in "$REPO_ROOT/.github/workflows/release.yml" "$REPO_ROOT/.github/workflows/nightly.yml"; do
    assert_contains "$workflow" "RUST_TOOLCHAIN: 1.95.0"
    assert_contains "$workflow" 'rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal'
    assert_contains "$workflow" 'rustup toolchain install $env:RUST_TOOLCHAIN --profile minimal'
    assert_contains "$workflow" 'rustup default "$RUST_TOOLCHAIN"'
    assert_contains "$workflow" 'rustup default $env:RUST_TOOLCHAIN'
    assert_contains "$workflow" "MXC_REPOSITORY: https://github.com/microsoft/mxc"
    assert_contains "$workflow" "MXC_REF: 1736b48398c3fe4d1315b2311c0951cc893eb3ae"
    assert_contains "$workflow" 'mxc_dir="$(mktemp -d "$RUNNER_TEMP/mxc-XXXXXX")"'
    assert_contains "$workflow" 'cargo build --release --manifest-path "$mxc_dir/src/Cargo.toml" -p lxc --no-default-features --locked'
    assert_contains "$workflow" 'cp "$mxc_dir/src/target/release/lxc-exec"'
    assert_contains "$workflow" "cp target/\${{ matrix.target }}/release/lxc-exec dist/axis-\${{ matrix.platform }}/"
    assert_contains "$workflow" 'grep -F "axis-${{ matrix.platform }}/lxc-exec"'
    assert_contains "$workflow" 'grep -F "axis-${{ matrix.platform }}/axis-seccomp-launcher"'
done

assert_contains "$CI_WORKFLOW" "RUST_TOOLCHAIN: 1.95.0"
assert_contains "$CI_WORKFLOW" "timeout-minutes: 30"
assert_contains "$CI_WORKFLOW" "Acquire::Retries=3"
assert_contains "$CI_WORKFLOW" "Build MXC Linux executor"
assert_contains "$CI_WORKFLOW" "cargo build --release --manifest-path \"\$mxc_dir/src/Cargo.toml\" -p lxc --no-default-features --locked"
assert_contains "$CI_WORKFLOW" "cp \"\$mxc_dir/src/target/release/lxc-exec\" target/release/lxc-exec"
assert_contains "$REPO_ROOT/e2e/linux/test_netns_helper_launch.sh" "cargo build --release -p axis-cli -p axis-sandbox --bins"

assert_contains "$REPO_ROOT/.github/workflows/release.yml" "CARGO_DEB_VERSION: 3.6.4"
assert_contains "$REPO_ROOT/.github/workflows/release.yml" "CARGO_GENERATE_RPM_VERSION: 0.21.0"
assert_contains "$REPO_ROOT/.github/workflows/release.yml" 'cargo install cargo-deb --version "$CARGO_DEB_VERSION" --locked'
assert_contains "$REPO_ROOT/.github/workflows/release.yml" 'cargo install cargo-generate-rpm --version "$CARGO_GENERATE_RPM_VERSION" --locked'
assert_contains "$REPO_ROOT/.github/workflows/release.yml" "cargo generate-rpm -p crates/axis-daemon"
if grep -Fq "cargo generate-rpm -p crates/axis-daemon || true" "$REPO_ROOT/.github/workflows/release.yml"; then
    fail "rpm package build must not ignore failures"
fi
assert_contains "$REPO_ROOT/.github/workflows/release.yml" 'dpkg-deb -c "$deb" | grep -F "./usr/bin/lxc-exec"'
assert_contains "$REPO_ROOT/.github/workflows/release.yml" 'rpm -qpl "$rpm_path" | grep -F "/usr/bin/lxc-exec"'
assert_contains "$REPO_ROOT/.github/workflows/release.yml" "axis-netns-helper must not be installed by the base package"

assert_contains "$REPO_ROOT/crates/axis-sandbox/src/linux/mxc.rs" 'const MXC_EXECUTOR_DIRS: &[&str] = &["/usr/local/bin", "/usr/bin", "/bin"];'
assert_contains "$REPO_ROOT/crates/axis-sandbox/src/linux/mxc.rs" 'dir.join(AXIS_SECCOMP_LAUNCHER_NAME)'

assert_contains "$REPO_ROOT/rust-toolchain.toml" 'channel = "1.95.0"'
assert_contains "$REPO_ROOT/README.md" "docs/setup-and-install.md"
assert_contains "$REPO_ROOT/README.md" "docs/install-and-runtime-dependencies.md"
assert_contains "$REPO_ROOT/docs/linux-setup.md" "install-and-runtime-dependencies.md"
assert_contains "$REPO_ROOT/docs/linux-setup.md" "setup-and-install.md"
assert_contains "$INSTALL_DEPS_DOC" "Default Install Contract"
assert_contains "$INSTALL_DEPS_DOC" "Runtime Dependency Matrix"
assert_contains "$INSTALL_DEPS_DOC" "Test Dependency Classes"
assert_contains "$INSTALL_DEPS_DOC" "Safe Executor Discovery"
assert_contains "$INSTALL_DEPS_DOC" "Bubblewrap"
assert_contains "$INSTALL_DEPS_DOC" "LXC"
assert_contains "$INSTALL_DEPS_DOC" "WSL2"
assert_contains "$INSTALL_DEPS_DOC" "Windows Sandbox"
assert_contains "$INSTALL_DEPS_DOC" "WHP"
assert_contains "$INSTALL_DEPS_DOC" "KVM"
assert_contains "$INSTALL_DEPS_DOC" "Hyperlight"
assert_contains "$INSTALL_DEPS_DOC" "Xcode Command Line Tools"
assert_contains "$INSTALL_DEPS_DOC" "must not require root-installing a locally built AXIS artifact"
assert_contains "$SETUP_DOC" "cargo build --release -p axis-cli -p axis-daemon -p axis-sandbox --bins"
assert_contains "$SETUP_DOC" "MXC_REF=1736b48398c3fe4d1315b2311c0951cc893eb3ae"
assert_contains "$SETUP_DOC" "bubblewrap"
assert_contains "$SETUP_DOC" "cgroups v2"
assert_contains "$SETUP_DOC" "/dev/kvm"
assert_contains "$SETUP_DOC" "AXIS_RUN_MXC_MICROVM_E2E=1"
assert_contains "$SETUP_DOC" "AXIS_RUN_MXC_HYPERLIGHT_E2E=1"
assert_contains "$SETUP_DOC" "AXIS_RUN_PRIVILEGED_E2E=1"

echo "Linux MXC packaging checks passed"
