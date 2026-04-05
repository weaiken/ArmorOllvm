#!/usr/bin/env bash
# ArmorComp — macOS self-contained bundler  (v0.26.0)
# ============================================================
#
# Copies brew clang@17 + LLVM dylibs into toolchain/bin/ and
# toolchain/vendor/, then patches rpath so the binaries run
# without any brew/system LLVM install on the customer's machine.
#
# Dependency structure (brew clang@17, arm64):
#   clang        → @rpath/libclang-cpp.dylib
#                → @rpath/libLLVM.dylib
#                  (rpath: @loader_path/../lib)
#   libclang-cpp → @rpath/libLLVM.dylib
#                  (rpath: @loader_path/../lib)
#   libLLVM      → /usr/lib/libffi.dylib      ← macOS system lib, always present
#                → /usr/lib/libedit.3.dylib    ← macOS system lib, always present
#
# Strategy:
#   1. Copy libLLVM.dylib + libclang-cpp.dylib → toolchain/vendor/
#   2. Copy clang + clang++ → toolchain/bin/clang17[++]
#   3. Add rpath @executable_path/../vendor to clang17 executables
#      → so @rpath/lib*.dylib is found in vendor/
#   4. Add rpath @loader_path to vendor dylibs
#      → libclang-cpp.dylib finds libLLVM.dylib in the same vendor/ dir
#   5. Codesign all modified binaries (ad-hoc signature)
#
# Usage:
#   bundle-macos.sh <brew-llvm17-prefix> <toolchain-dir>
# ============================================================

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <brew-llvm17-prefix> <toolchain-dir>" >&2
  exit 1
fi

BREW_PREFIX="$1"
TC_DIR="$(cd "$2" && pwd)"
BIN_DIR="$TC_DIR/bin"
VENDOR_DIR="$TC_DIR/vendor"

BREW_CLANG="$BREW_PREFIX/bin/clang"
BREW_CLANGXX="$BREW_PREFIX/bin/clang++"
BREW_LIBLLVM="$BREW_PREFIX/lib/libLLVM.dylib"
BREW_LIBCLANG_CPP="$BREW_PREFIX/lib/libclang-cpp.dylib"

# ── Sanity checks ──────────────────────────────────────────────────────────────
for f in "$BREW_CLANG" "$BREW_CLANGXX" "$BREW_LIBLLVM" "$BREW_LIBCLANG_CPP"; do
  if [[ ! -f "$f" ]]; then
    echo "bundle-macos: not found: $f" >&2
    exit 1
  fi
done

mkdir -p "$VENDOR_DIR" "$BIN_DIR"

echo "[bundle] LLVM prefix   : $BREW_PREFIX"
echo "[bundle] Toolchain dir : $TC_DIR"
echo ""
echo "[bundle] Dylibs to vendor:"
echo "         libLLVM.dylib       ($(du -sh "$BREW_LIBLLVM" | awk '{print $1}'))"
echo "         libclang-cpp.dylib  ($(du -sh "$BREW_LIBCLANG_CPP" | awk '{print $1}'))"

# ── Step 1: Copy dylibs → vendor/ ─────────────────────────────────────────────
echo ""
echo "[bundle] Copying dylibs..."
cp -f "$BREW_LIBLLVM"       "$VENDOR_DIR/libLLVM.dylib"
cp -f "$BREW_LIBCLANG_CPP"  "$VENDOR_DIR/libclang-cpp.dylib"
chmod u+w "$VENDOR_DIR/libLLVM.dylib" "$VENDOR_DIR/libclang-cpp.dylib"

# ── Step 2: Copy clang binaries → bin/ ────────────────────────────────────────
echo "[bundle] Copying clang17, clang17++..."
cp -f "$BREW_CLANG"   "$BIN_DIR/clang17"
cp -f "$BREW_CLANGXX" "$BIN_DIR/clang17++"
chmod u+w "$BIN_DIR/clang17" "$BIN_DIR/clang17++"

# ── Step 3: Patch clang executables ───────────────────────────────────────────
# Add @executable_path/../vendor as a new rpath search path.
# The existing rpath @loader_path/../lib (→ toolchain/lib/) doesn't have LLVM
# dylibs, but macOS searches ALL rpath entries before failing, so adding the
# new vendor entry is sufficient.
echo "[bundle] Patching rpath in clang17..."
install_name_tool \
  -add_rpath "@executable_path/../vendor" \
  "$BIN_DIR/clang17"

echo "[bundle] Patching rpath in clang17++..."
install_name_tool \
  -add_rpath "@executable_path/../vendor" \
  "$BIN_DIR/clang17++"

# ── Step 4: Patch vendor dylibs ───────────────────────────────────────────────
# libclang-cpp.dylib needs to find libLLVM.dylib from its own vendor/ dir.
# Its existing rpath is @loader_path/../lib (→ vendor/../lib = toolchain/lib/).
# Adding @loader_path means it also searches vendor/ itself, where libLLVM lives.
echo "[bundle] Patching rpath in libclang-cpp.dylib..."
install_name_tool \
  -add_rpath "@loader_path" \
  "$VENDOR_DIR/libclang-cpp.dylib"

# libLLVM.dylib: deps are all system libs (/usr/lib/), no rpath patching needed.

# ── Step 5: Ad-hoc re-sign ────────────────────────────────────────────────────
# macOS requires a valid (even ad-hoc) signature after LC_RPATH modifications.
echo "[bundle] Re-signing (ad-hoc)..."
for f in \
  "$BIN_DIR/clang17" \
  "$BIN_DIR/clang17++" \
  "$VENDOR_DIR/libLLVM.dylib" \
  "$VENDOR_DIR/libclang-cpp.dylib"
do
  codesign --force --sign - "$f" \
    && echo "[bundle]   signed  $(basename "$f")" \
    || echo "[bundle]   sign skipped: $(basename "$f") (may need Developer ID for distribution)"
done

# ── Step 6: Verify ────────────────────────────────────────────────────────────
echo ""
echo "[bundle] Verification:"

echo "  clang17 dylib refs:"
otool -L "$BIN_DIR/clang17" | grep -E "@rpath|libLLVM|libclang" || true

echo ""
echo "  clang17 rpath entries:"
otool -l "$BIN_DIR/clang17" \
  | awk '/cmd LC_RPATH/{getline; getline; print "    " $2}' || true

echo ""
echo "  libclang-cpp.dylib rpath entries:"
otool -l "$VENDOR_DIR/libclang-cpp.dylib" \
  | awk '/cmd LC_RPATH/{getline; getline; print "    " $2}' || true

echo ""
VENDOR_SIZE=$(du -sh "$VENDOR_DIR" | awk '{print $1}')
echo "[bundle] Done. Self-contained toolchain ready."
echo "  toolchain/bin/clang17[++]  — no brew llvm@17 required on delivery machine"
echo "  toolchain/vendor/          — ${VENDOR_SIZE} (libLLVM.dylib + libclang-cpp.dylib)"
