#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
    echo "usage: $0 <artifact-directory> <output-directory> <source-version> <mxc-checkout> <mxc-ref>" >&2
    exit 2
}

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ "$#" -eq 5 ] || usage
artifact_dir="$(realpath "$1")"
output_dir="$2"
source_version="$3"
mxc_dir="$(realpath "$4")"
mxc_ref="$5"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

command -v syft >/dev/null || fail "syft is required"
[[ "$source_version" =~ ^[0-9a-f]{40}$ ]] || fail "source version must be a Git commit SHA"
[[ "$mxc_ref" =~ ^[0-9a-f]{40}$ ]] || fail "MXC ref must be a Git commit SHA"
[ -d "$artifact_dir" ] || fail "artifact directory does not exist: $artifact_dir"
[ -f "$mxc_dir/src/Cargo.lock" ] || fail "MXC checkout is missing src/Cargo.lock"

mkdir -p "$output_dir"
if find "$output_dir" -mindepth 1 -print -quit | grep -q .; then
    fail "SBOM output directory must be empty: $output_dir"
fi
work_root="$(mktemp -d "${TMPDIR:-/tmp}/axis-sbom-XXXXXX")"
cleanup() {
    rm -rf "$work_root"
}
trap cleanup EXIT

declare -A seen_names=()
artifact_count=0
while IFS= read -r -d '' artifact; do
    name="$(basename "$artifact")"
    case "$name" in
        *.tar.gz|*.zip|*.deb|*.rpm) ;;
        *) fail "unsupported release artifact: $name" ;;
    esac
    [[ "$name" =~ ^[A-Za-z0-9._+-]+$ ]] || fail "unsafe artifact name: $name"
    [ -z "${seen_names[$name]:-}" ] || fail "duplicate artifact name: $name"
    seen_names[$name]=1
    artifact_count=$((artifact_count + 1))

    input="$work_root/input-$artifact_count"
    manifests="$input/manifests"
    mkdir -p "$manifests"
    cp "$artifact" "$input/$name"

    profile=""
    case "$name" in
        axis-desktop-linux-*) profile="gui-linux" ;;
        axis-desktop-macos-*) profile="gui-macos" ;;
        axis-desktop-windows-*) profile="gui-windows" ;;
        axis-linux-*|*.deb|*.rpm) profile="core-linux" ;;
        axis-macos-*) profile="core-macos" ;;
        axis-windows-*) profile="core-windows" ;;
        *) fail "unrecognized release artifact: $name" ;;
    esac

    if [[ "$profile" == core-* ]]; then
        mkdir -p "$manifests/axis"
        cp "$repo_root/Cargo.toml" "$repo_root/Cargo.lock" "$manifests/axis/"
    else
        mkdir -p "$manifests/npm"
        cp "$repo_root/gui/shared/package.json" \
            "$repo_root/gui/shared/package-lock.json" "$manifests/npm/"
    fi
    case "$profile" in
        core-linux)
            mkdir -p "$manifests/mxc"
            python3 "$repo_root/scripts/release_tools.py" stage-mxc-manifests \
                --mxc-dir "$mxc_dir" \
                --mxc-ref "$mxc_ref" \
                --output "$manifests/mxc"
            printf '%s\n' "$mxc_ref" >"$manifests/mxc/COMMIT"
            ;;
        gui-linux)
            mkdir -p "$manifests/gui-cargo"
            cp "$repo_root/gui/linux/Cargo.toml" \
                "$repo_root/gui/linux/Cargo.lock" "$manifests/gui-cargo/"
            ;;
        gui-windows)
            mkdir -p "$manifests/nuget"
            cp "$repo_root/gui/windows/AXIS/AXIS.csproj" \
                "$repo_root/gui/windows/AXIS/packages.lock.json" "$manifests/nuget/"
            ;;
    esac

    raw_one="$work_root/$name.one.raw.json"
    raw_two="$work_root/$name.two.raw.json"
    normalized_one="$work_root/$name.one.spdx.json"
    normalized_two="$work_root/$name.two.spdx.json"
    for raw in "$raw_one" "$raw_two"; do
        python3 "$repo_root/scripts/release_tools.py" run-syft \
            --syft "$(command -v syft)" \
            --input "$input" \
            --output "$raw" \
            --name "$name" \
            --version "$source_version"
    done

    finalize=(
        python3 "$repo_root/scripts/release_tools.py" finalize-sbom
        --repository-root "$repo_root"
        --artifact "$artifact"
        --source-version "$source_version"
        --profile "$profile"
    )
    if [ "$profile" = "core-linux" ]; then
        finalize+=(--mxc-dir "$mxc_dir" --mxc-ref "$mxc_ref")
    fi
    "${finalize[@]}" --raw "$raw_one" --output "$normalized_one"
    "${finalize[@]}" --raw "$raw_two" --output "$normalized_two"
    cmp --silent "$normalized_one" "$normalized_two" ||
        fail "normalized SPDX output is nondeterministic for $name"
    cp "$normalized_one" "$output_dir/$name.spdx.json"
done < <(find "$artifact_dir" -type f -print0)

[ "$artifact_count" -gt 0 ] || fail "no release artifacts found in $artifact_dir"
sbom_count="$(find "$output_dir" -maxdepth 1 -type f -name '*.spdx.json' | wc -l)"
[ "$sbom_count" -eq "$artifact_count" ] ||
    fail "generated $sbom_count SBOMs for $artifact_count artifacts"

echo "generated and verified $sbom_count normalized, dependency-complete SBOMs"
