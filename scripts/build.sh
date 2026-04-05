#!/bin/bash
# scripts/build.sh — 一键构建 ArmorComp pass plugin 并验证加载
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$REPO_ROOT/build"

# ---- 检查 brew llvm@17 ----
BREW_LLVM=""
for PREFIX in "/opt/homebrew/opt/llvm@17" "/usr/local/opt/llvm@17"; do
  if [ -d "$PREFIX" ]; then
    BREW_LLVM="$PREFIX"
    break
  fi
done

if [ -z "$BREW_LLVM" ]; then
  echo "[ERROR] llvm@17 not found. Install with: brew install llvm@17"
  exit 1
fi

echo "[INFO] Using LLVM: $BREW_LLVM"
echo "[INFO] LLVM version: $($BREW_LLVM/bin/llvm-config --version)"

# ---- 找 NDK clang ----
NDK_CLANG=""
for NDK in ~/Library/Android/sdk/ndk/*/toolchains/llvm/prebuilt/darwin-x86_64/bin/clang; do
  NDK_CLANG="$NDK"
done

if [ ! -x "$NDK_CLANG" ]; then
  echo "[ERROR] NDK clang not found. Set ANDROID_NDK_ROOT or install NDK r26."
  exit 1
fi

echo "[INFO] NDK clang: $NDK_CLANG"
echo "[INFO] NDK clang version: $($NDK_CLANG --version | head -1)"

# ---- cmake 配置 ----
mkdir -p "$BUILD_DIR"
cmake -S "$REPO_ROOT" -B "$BUILD_DIR" \
  -DLLVM_DIR="$BREW_LLVM/lib/cmake/llvm" \
  -DCMAKE_BUILD_TYPE=Debug \
  -G Ninja

# ---- 编译 ----
cmake --build "$BUILD_DIR" --target ArmorComp

PLUGIN="$BUILD_DIR/libArmorComp.dylib"
echo ""
echo "[SUCCESS] Plugin built: $PLUGIN"
echo ""

# ---- 验证加载 ----
# 注意：NDK 的 standalone clang 静态链接 LLVM，dlopen 时不导出所有 LLVM 符号。
# 解决方案：用 brew clang（共享 LLVM dylib）+ NDK sysroot + NDK resource-dir。
# 这样 pass plugin 和 host clang 共享同一套 LLVM 17 符号，加载完全正常。
NDK_RESOURCE="$NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/lib/clang/17.0.2"
BREW_CLANG="$BREW_LLVM/bin/clang"

echo "=== 验证 pass plugin 加载 ==="
echo "  编译器: brew clang 17 + NDK sysroot + NDK resource-dir"
echo "  目标:   aarch64-linux-android21"
echo ""

"$BREW_CLANG" \
  -target aarch64-linux-android21 \
  --sysroot="$NDK_SYSROOT" \
  -resource-dir="$NDK_RESOURCE" \
  -fpass-plugin="$PLUGIN" \
  "$REPO_ROOT/test/hello.c" \
  -o "$BUILD_DIR/hello_aarch64" \
  2>&1

echo ""
echo "=== 验证结果 ==="
if [ -f "$BUILD_DIR/hello_aarch64" ]; then
  echo "[PASS] hello_aarch64 编译成功"
  file "$BUILD_DIR/hello_aarch64"
  echo ""
  echo "如果上面的 stderr 中看到 '[ArmorComp] function: ...' 行，环境验证通过。"
else
  echo "[FAIL] 编译失败，检查上面的错误信息。"
  exit 1
fi
