#!/usr/bin/env bash
# build-and-install.sh — Build libkerneltrace.so and all eBPF probe objects,
# then install them into runtimes/<RID>/native/ so the .NET SDK and MSBuild
# pick them up automatically for both local builds and 'dotnet pack'.
#
# Usage:
#   bash native/scripts/build-and-install.sh
#
# Prerequisites:
#   clang >= 12, cmake >= 3.20, libbpf-dev, pkg-config, bpftool (optional)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
NATIVE_DIR="${REPO_ROOT}/native"
BUILD_DIR="${NATIVE_DIR}/build"

# ── Detect musl vs glibc → affects the .NET RID ──────────────────────────────

LIBC_SUFFIX=""
# /etc/alpine-release is the most reliable indicator for the Alpine Linux
# container used in CI.  Fall back to ldd --version for non-Alpine musl
# distros (Void Linux, OpenWRT, etc.).
if [[ -f /etc/alpine-release ]]; then
    LIBC_SUFFIX="-musl"
elif ldd --version 2>&1 | grep -qi musl; then
    LIBC_SUFFIX="-musl"
fi

# ── Detect architecture → .NET RID ───────────────────────────────────────────

ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64)  RID="linux${LIBC_SUFFIX}-x64"   ;;
    aarch64) RID="linux${LIBC_SUFFIX}-arm64" ;;
    armv7l)  RID="linux${LIBC_SUFFIX}-arm"   ;;
    *)
        echo "ERROR: Unsupported architecture '${ARCH}'." >&2
        exit 1
        ;;
esac

DEST_DIR="${REPO_ROOT}/runtimes/${RID}/native"

echo "KernelTrace — native build + install"
LIBC_DISPLAY="${LIBC_SUFFIX:+musl}"; LIBC_DISPLAY="${LIBC_DISPLAY:-glibc}"
echo "  Architecture : ${ARCH} (${LIBC_DISPLAY})  →  RID: ${RID}"
echo "  Build dir    : ${BUILD_DIR}"
echo "  Install dir  : ${DEST_DIR}"
echo

# ── CMake configure ───────────────────────────────────────────────────────────
# KERNELTRACE_INSTALL_PROBES=OFF — we copy probe objects ourselves below
# so cmake --install doesn't scatter them under share/kerneltrace/.

cmake \
    -S "${NATIVE_DIR}" \
    -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DKERNELTRACE_BUILD_PROBES=ON \
    -DKERNELTRACE_INSTALL_PROBES=OFF

# ── Build ─────────────────────────────────────────────────────────────────────

NPROC="$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 1)"
cmake --build "${BUILD_DIR}" --parallel "${NPROC}"

# ── Install into runtimes/<RID>/native/ ───────────────────────────────────────
#
# This is the folder the .NET SDK's NuGet runtime resolver and the repo's
# Directory.Build.targets both look at.  It maps to the nupkg path:
#   runtimes/linux-x64/native/libkerneltrace.so

mkdir -p "${DEST_DIR}"

# Native shim
SO_SRC="${BUILD_DIR}/libkerneltrace.so"
if [[ ! -f "${SO_SRC}" ]]; then
    echo "ERROR: Expected ${SO_SRC} — did the build succeed?" >&2
    exit 1
fi
cp -p "${SO_SRC}" "${DEST_DIR}/libkerneltrace.so"
echo "  ✔  libkerneltrace.so"

# eBPF probe objects compiled by clang
PROBE_COUNT=0
for OBJ in "${BUILD_DIR}"/*.bpf.o; do
    [[ -f "${OBJ}" ]] || continue
    cp -p "${OBJ}" "${DEST_DIR}/"
    echo "  ✔  $(basename "${OBJ}")"
    PROBE_COUNT=$(( PROBE_COUNT + 1 ))
done

# ── Summary ───────────────────────────────────────────────────────────────────

echo
echo "Installed to: ${DEST_DIR}"
echo "  libkerneltrace.so  $(du -h "${DEST_DIR}/libkerneltrace.so" | cut -f1)"
echo "  ${PROBE_COUNT} eBPF probe object(s)"
echo
echo "Next steps:"
echo "  dotnet build    — picks up the new native assets automatically"
echo "  dotnet pack     — includes the .so in runtimes/${RID}/native/ in the .nupkg"
