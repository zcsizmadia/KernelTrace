#!/usr/bin/env bash
# gen-vmlinux.sh — Regenerate vmlinux.h from the running kernel's BTF.
#
# Usage:
#   ./native/scripts/gen-vmlinux.sh
#
# Output: native/probes/vmlinux.h
#
# Prerequisites:
#   - Linux kernel with CONFIG_DEBUG_INFO_BTF=y  (/sys/kernel/btf/vmlinux must exist)
#   - bpftool >= 5.13  (apt install linux-tools-common / dnf install bpftool)
#
# The generated file is kernel-version-specific. Regenerate when targeting a
# different kernel or after a major kernel upgrade.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT="${SCRIPT_DIR}/../probes/vmlinux.h"
BTF_SOURCE="/sys/kernel/btf/vmlinux"

if [[ ! -f "${BTF_SOURCE}" ]]; then
    echo "ERROR: ${BTF_SOURCE} not found." >&2
    echo "       Ensure the kernel was compiled with CONFIG_DEBUG_INFO_BTF=y." >&2
    exit 1
fi

if ! command -v bpftool &>/dev/null; then
    echo "ERROR: bpftool not found. Install with:" >&2
    echo "       apt install linux-tools-\$(uname -r) linux-tools-common" >&2
    echo "       dnf install bpftool" >&2
    exit 1
fi

KERNEL_VER="$(uname -r)"
echo "Generating vmlinux.h for kernel ${KERNEL_VER} ..."

bpftool btf dump file "${BTF_SOURCE}" format c > "${OUTPUT}"

echo "Written to ${OUTPUT}"
echo "Lines: $(wc -l < "${OUTPUT}")"
