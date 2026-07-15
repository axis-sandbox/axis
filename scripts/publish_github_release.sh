#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
    echo "usage: $0 <stable|nightly> <tag> <asset-directory> <title> [notes-file]" >&2
    exit 2
}

if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    usage
fi
release_type="$1"
tag="$2"
asset_dir="$(realpath "$3")"
title="$4"
notes_file="${5:-}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

command -v gh >/dev/null || {
    echo "ERROR: gh is required" >&2
    exit 1
}
[ -n "${GITHUB_SHA:-}" ] || {
    echo "ERROR: GITHUB_SHA is required" >&2
    exit 1
}
case "$release_type" in
    stable) [ -z "$notes_file" ] || usage ;;
    nightly)
        [ -n "$notes_file" ] || usage
        [ -f "$notes_file" ] || {
            echo "ERROR: notes file does not exist: $notes_file" >&2
            exit 1
        }
        ;;
    *) usage ;;
esac

"$repo_root/scripts/verify_release_assets.sh" "$release_type" "$asset_dir" "$GITHUB_SHA"
arguments=(
    python3 "$repo_root/scripts/release_tools.py" publish
    --repository-root "$repo_root"
    --release-type "$release_type"
    --tag "$tag"
    --asset-directory "$asset_dir"
    --title "$title"
)
if [ -n "$notes_file" ]; then
    arguments+=(--notes-file "$notes_file")
fi
exec "${arguments[@]}"
