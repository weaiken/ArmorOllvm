# ArmorComp — Android NDK CMake toolchain  (v0.26.0)
# ============================================================
#
# USAGE — build.gradle (AGP 4+):
#
#   android {
#     defaultConfig {
#       externalNativeBuild {
#         cmake {
#           arguments "-DCMAKE_TOOLCHAIN_FILE=${rootDir}/armorcomp/toolchain/android.cmake"
#           abiFilters "arm64-v8a"             # 完整支持
#           # abiFilters "armeabi-v7a"         # 支持（AArch64-only pass 自动跳过：spo/rao/ntc/lro/fsig/dpoison）
#         }
#       }
#     }
#   }
#
# USAGE — plain CMake:
#
#   cmake -DCMAKE_TOOLCHAIN_FILE=/path/to/toolchain/android.cmake \
#         -DANDROID_ABI=arm64-v8a \         # 或 armeabi-v7a（arm32，AArch64-only pass 自动跳过）
#         -DANDROID_PLATFORM=android-21 \
#         -DANDROID_NDK=/path/to/ndk ..
#
# WHY THIS EXISTS:
#   NDK's bundled clang is statically linked against LLVM.  On macOS, dlopen()
#   of a pass plugin requires the host clang to export LLVM symbols — which NDK
#   clang does NOT do.  Solution: inject brew clang@17 (dynamic LLVM) via
#   CMAKE_C_COMPILER_LAUNCHER so NDK clang handles system detection while
#   brew clang@17 + -fpass-plugin handles actual compilation.
# ============================================================

cmake_minimum_required(VERSION 3.22)

# ── Step 1: Locate toolchain root ─────────────────────────────────────────────
get_filename_component(_AC_TOOLCHAIN_DIR "${CMAKE_CURRENT_LIST_FILE}" DIRECTORY)
get_filename_component(_AC_ROOT "${_AC_TOOLCHAIN_DIR}" DIRECTORY)

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
  execute_process(
    COMMAND uname -m
    OUTPUT_VARIABLE _AC_HOST_ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  set(_AC_LAUNCHER  "${_AC_TOOLCHAIN_DIR}/bin/armorcomp-launcher")
  set(_AC_PLUGIN    "${_AC_TOOLCHAIN_DIR}/lib/darwin-${_AC_HOST_ARCH}/libArmorComp.dylib")
elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
  set(_AC_LAUNCHER  "${_AC_TOOLCHAIN_DIR}/bin/armorcomp-launcher-linux")
  set(_AC_PLUGIN    "${_AC_TOOLCHAIN_DIR}/lib/linux-x86_64/libArmorComp.so")
else()
  message(FATAL_ERROR
    "[ArmorComp] Unsupported host OS: ${CMAKE_HOST_SYSTEM_NAME}\n"
    "  Supported: Darwin (macOS), Linux")
endif()

if(NOT EXISTS "${_AC_PLUGIN}")
  message(FATAL_ERROR
    "[ArmorComp] Plugin not found: ${_AC_PLUGIN}\n"
    "  Build it with:\n"
    "    cd ${_AC_ROOT}/build && cmake --build . --target ArmorComp")
endif()

# ── Step 2: Locate NDK ────────────────────────────────────────────────────────
if(NOT ANDROID_NDK)
  foreach(_env_var ANDROID_NDK_ROOT ANDROID_NDK_HOME NDK_ROOT)
    if(DEFINED ENV{${_env_var}})
      set(ANDROID_NDK "$ENV{${_env_var}}" CACHE PATH "Android NDK root")
      break()
    endif()
  endforeach()
endif()
if(NOT ANDROID_NDK)
  # Auto-detect from common SDK locations
  file(GLOB _ndk_candidates
    "$ENV{HOME}/Library/Android/sdk/ndk/*"
    "$ENV{ANDROID_HOME}/ndk/*"
    "/usr/local/lib/android/sdk/ndk/*")
  if(_ndk_candidates)
    list(SORT _ndk_candidates ORDER DESCENDING)
    list(GET _ndk_candidates 0 _ndk_latest)
    set(ANDROID_NDK "${_ndk_latest}" CACHE PATH "Android NDK root")
  endif()
endif()
if(NOT ANDROID_NDK OR NOT EXISTS "${ANDROID_NDK}")
  message(FATAL_ERROR
    "[ArmorComp] Android NDK not found.\n"
    "  Set ANDROID_NDK_ROOT environment variable, or pass:\n"
    "    -DANDROID_NDK=/path/to/ndk")
endif()

# ── Step 3: Include NDK toolchain ─────────────────────────────────────────────
# The NDK toolchain sets CMAKE_C_COMPILER to its own clang (statically linked
# LLVM) and configures sysroot, STL, linker, and Android ABI flags.
# We let NDK own the compiler for feature detection; the launcher (Step 4)
# intercepts the actual compilation and substitutes brew clang@17 + plugin.
set(_NDK_TC "${ANDROID_NDK}/build/cmake/android.toolchain.cmake")
if(NOT EXISTS "${_NDK_TC}")
  message(FATAL_ERROR "[ArmorComp] NDK toolchain not found: ${_NDK_TC}")
endif()
include("${_NDK_TC}")

# ── Step 4: Inject ArmorComp via CMAKE_C/CXX_COMPILER_LAUNCHER ───────────────
# Using a launcher avoids the NDK r26 FORCE override issue. CMake invokes:
#   ${LAUNCHER} ${NDK_CLANG} ${COMPILE_FLAGS}
# Our launcher (armorcomp-launcher) drops ${NDK_CLANG} and calls brew clang@17
# + -fpass-plugin with the same ${COMPILE_FLAGS} (--target, --sysroot, etc.).
set(CMAKE_C_COMPILER_LAUNCHER
  "${_AC_LAUNCHER}" CACHE FILEPATH "ArmorComp pass-plugin injector" FORCE)
set(CMAKE_CXX_COMPILER_LAUNCHER
  "${_AC_LAUNCHER}" CACHE FILEPATH "ArmorComp pass-plugin injector" FORCE)

# ── Expose for user CMakeLists ────────────────────────────────────────────────
set(ARMORCOMP_PLUGIN  "${_AC_PLUGIN}" CACHE FILEPATH "ArmorComp pass plugin path")
set(ARMORCOMP_ENABLED TRUE            CACHE BOOL     "ArmorComp pass plugin loaded")

message(STATUS "[ArmorComp] Plugin:   ${_AC_PLUGIN}")
message(STATUS "[ArmorComp] Launcher: ${_AC_LAUNCHER}")
message(STATUS "[ArmorComp] NDK:      ${ANDROID_NDK}")
