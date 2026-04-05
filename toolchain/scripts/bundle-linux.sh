#!/usr/bin/env bash
# ArmorComp — Linux self-contained bundler  (v0.26.0)
# ============================================================
#
# Copies clang-17 + all non-system .so dependencies into
# toolchain/bin/ and toolchain/vendor/, then patches RUNPATH
# so the binaries run without needing clang-17 installed.
#
# Requirements:
#   apt install clang-17 patchelf
#     OR
#   LLVM_PREFIX=/custom/llvm17  (if clang-17 is in a non-standard location)
#
# Usage:
#   bundle-linux.sh <clang17-prefix> <toolchain-dir>
#
# Example:
#   bundle-linux.sh /usr  /path/to/toolchain
#       (uses /usr/bin/clang-17 and /usr/lib/llvm-17/lib/)
#
# After running:
#   bin/clang17          ← RUNPATH patched to $ORIGIN/../vendor
#   bin/clang17++
#   vendor/              ← all non-system shared libs
# ============================================================

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <clang17-prefix> <toolchain-dir>" >&2
  exit 1
fi

LLVM_PREFIX="$1"
TC_DIR="$(cd "$2" && pwd)"
BIN_DIR="$TC_DIR/bin"
VENDOR_DIR="$TC_DIR/vendor"

mkdir -p "$VENDOR_DIR" "$BIN_DIR"

# Locate clang-17 binary
CLANG17=""
for candidate in \
  "$LLVM_PREFIX/bin/clang-17" \
  "$LLVM_PREFIX/bin/clang" \
  "/usr/lib/llvm-17/bin/clang" \
  "/usr/bin/clang-17"
do
  if [[ -x "$candidate" ]]; then
    CLANG17="$candidate"
    CLANGXX17="${candidate/clang/clang++}"
    [[ -x "$CLANGXX17" ]] || CLANGXX17="${CLANG17}++"
    break
  fi
done

if [[ -z "${CLANG17:-}" ]]; then
  echo "bundle-linux: clang-17 not found under $LLVM_PREFIX" >&2
  echo "  Install with: apt install clang-17" >&2
  exit 1
fi

# Check patchelf
if ! command -v patchelf &>/dev/null; then
  echo "bundle-linux: patchelf not found." >&2
  echo "  Install with: apt install patchelf" >&2
  exit 1
fi

echo "[bundle] clang-17   : $CLANG17"
echo "[bundle] Toolchain  : $TC_DIR"

# ── System lib filter: skip libs that are always present ─────────────────────
# These are part of the Linux ABI guarantee (glibc, libstdc++, libgcc_s, etc.)
is_system_lib() {
  local lib="$1"
  case "$(basename "$lib")" in
    libc.so*|libm.so*|libpthread.so*|libdl.so*|librt.so*|ld-linux*.so*)
      return 0;;
    libstdc++.so*|libgcc_s.so*|libgomp.so*)
      return 0;;
    linux-vdso*|libz.so.1*)  # libz.so.1 is ubiquitous on Ubuntu
      return 0;;
    *)
      return 1;;
  esac
}

# ── BFS: collect transitive non-system deps ────────────────────────────────────
VISITED_FILE="$(mktemp)"
trap 'rm -f "$VISITED_FILE"' EXIT

get_deps() {
  ldd "$1" 2>/dev/null \
    | awk '/=>/{print $3}' \
    | grep -v 'not found' \
    | grep '^/' \
    || true
}

# Seed
for src in "$CLANG17" "${CLANGXX17:-}"; do
  [[ -x "$src" ]] || continue
  while IFS= read -r dep; do
    is_system_lib "$dep" && continue
    echo "$dep"
  done < <(get_deps "$src")
done | sort -u > "$VISITED_FILE"

for _level in $(seq 1 6); do
  NEW_FILE="$(mktemp)"
  while IFS= read -r dep; do
    [[ -z "$dep" || ! -f "$dep" ]] && continue
    while IFS= read -r subdep; do
      is_system_lib "$subdep" && continue
      if ! grep -qxF "$subdep" "$VISITED_FILE"; then
        echo "$subdep"
      fi
    done < <(get_deps "$dep")
  done < "$VISITED_FILE" >> "$NEW_FILE" || true
  cat "$VISITED_FILE" "$NEW_FILE" | sort -u > "${VISITED_FILE}.tmp"
  mv "${VISITED_FILE}.tmp" "$VISITED_FILE"
  rm -f "$NEW_FILE"
done

DEP_COUNT=$(grep -c . "$VISITED_FILE" || echo 0)
echo "[bundle] Found $DEP_COUNT non-system lib(s) to vendor:"
while IFS= read -r dep; do
  echo "         $(basename "$dep")"
done < "$VISITED_FILE"

# ── Copy vendor libs ──────────────────────────────────────────────────────────
while IFS= read -r src; do
  [[ -z "$src" || ! -f "$src" ]] && continue
  dst="$VENDOR_DIR/$(basename "$src")"
  echo "[bundle] Copying $(basename "$src")"
  cp -f "$src" "$dst"
  chmod u+w "$dst"
done < "$VISITED_FILE"

# ── Copy clang binaries ────────────────────────────────────────────────────────
echo "[bundle] Copying clang17, clang17++"
cp -f "$CLANG17" "$BIN_DIR/clang17"
cp -f "${CLANGXX17:-$CLANG17}" "$BIN_DIR/clang17++"
chmod u+w "$BIN_DIR/clang17" "$BIN_DIR/clang17++"

# ── Patch RUNPATH via patchelf ─────────────────────────────────────────────────
echo "[bundle] Patching RUNPATH (patchelf)..."
patchelf --set-rpath '$ORIGIN/../vendor' "$BIN_DIR/clang17"
patchelf --set-rpath '$ORIGIN/../vendor' "$BIN_DIR/clang17++"

for lib in "$VENDOR_DIR"/*.so* "$VENDOR_DIR"/*.so; do
  [[ -f "$lib" ]] || continue
  # Dylibs in vendor search peer libs in the same dir ($ORIGIN)
  patchelf --set-rpath '$ORIGIN' "$lib" 2>/dev/null || true
done

echo "[bundle] Self-contained Linux toolchain ready."
echo "  bin/clang17, bin/clang17++  — no clang-17 system package required"
echo "  vendor/  — $DEP_COUNT lib(s)"
