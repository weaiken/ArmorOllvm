# ArmorComp — iOS CMake toolchain  (v0.26.0)
# ============================================================
#
# USAGE — CMake (cross-compile iOS static library from macOS):
#
#   cmake -DCMAKE_TOOLCHAIN_FILE=/path/to/toolchain/ios.cmake \
#         -DIOS_PLATFORM=OS64 \      # OS64=device arm64, SIMULATOR64=x86_64 sim
#         -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 ..
#
# USAGE — Xcode project (via xcconfig):
#   See toolchain/ArmorComp.xcconfig for Xcode build settings integration.
#
# NOTE: This toolchain produces arm64-apple-ios Mach-O objects with
#       ArmorComp obfuscation applied.  Link with the normal Xcode
#       toolchain (ld from Xcode) — object file format is compatible.
# ============================================================

cmake_minimum_required(VERSION 3.22)

# ── Host checks ───────────────────────────────────────────────────────────────
if(NOT CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
  message(FATAL_ERROR "[ArmorComp iOS] iOS toolchain requires a macOS build host.")
endif()

get_filename_component(_AC_TOOLCHAIN_DIR "${CMAKE_CURRENT_LIST_FILE}" DIRECTORY)
get_filename_component(_AC_ROOT "${_AC_TOOLCHAIN_DIR}" DIRECTORY)

execute_process(
  COMMAND uname -m
  OUTPUT_VARIABLE _AC_HOST_ARCH
  OUTPUT_STRIP_TRAILING_WHITESPACE)

set(_AC_CLANG   "${_AC_TOOLCHAIN_DIR}/bin/armorcomp-clang")
set(_AC_CLANGXX "${_AC_TOOLCHAIN_DIR}/bin/armorcomp-clang++")
set(_AC_PLUGIN  "${_AC_TOOLCHAIN_DIR}/lib/darwin-${_AC_HOST_ARCH}/libArmorComp.dylib")

if(NOT EXISTS "${_AC_PLUGIN}")
  message(FATAL_ERROR
    "[ArmorComp] Plugin not found: ${_AC_PLUGIN}\n"
    "  Build: cd ${_AC_ROOT}/build && cmake --build . --target ArmorComp")
endif()

# ── Cross-compilation target ──────────────────────────────────────────────────
set(CMAKE_SYSTEM_NAME  "iOS")
set(CMAKE_SYSTEM_PROCESSOR "arm64")
set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "iOS architecture")

if(NOT CMAKE_OSX_DEPLOYMENT_TARGET)
  set(CMAKE_OSX_DEPLOYMENT_TARGET "15.0" CACHE STRING "iOS deployment target")
endif()

# Locate Xcode iOS SDK as sysroot
execute_process(
  COMMAND xcrun --sdk iphoneos --show-sdk-path
  OUTPUT_VARIABLE _IOS_SDK
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET)
if(NOT _IOS_SDK OR NOT EXISTS "${_IOS_SDK}")
  message(FATAL_ERROR
    "[ArmorComp iOS] Xcode iOS SDK not found.  Install Xcode from App Store.")
endif()
set(CMAKE_OSX_SYSROOT "${_IOS_SDK}" CACHE PATH "iOS sysroot")

# ── Compilers ─────────────────────────────────────────────────────────────────
set(CMAKE_C_COMPILER   "${_AC_CLANG}"   CACHE FILEPATH "" FORCE)
set(CMAKE_CXX_COMPILER "${_AC_CLANGXX}" CACHE FILEPATH "" FORCE)
set(CMAKE_C_COMPILER_FORCED   TRUE CACHE BOOL "" FORCE)
set(CMAKE_CXX_COMPILER_FORCED TRUE CACHE BOOL "" FORCE)
set(CMAKE_C_COMPILER_ID   "Clang" CACHE STRING "" FORCE)
set(CMAKE_CXX_COMPILER_ID "Clang" CACHE STRING "" FORCE)

# brew clang needs to know the iOS target triple explicitly
set(CMAKE_C_COMPILER_TARGET   "arm64-apple-ios${CMAKE_OSX_DEPLOYMENT_TARGET}")
set(CMAKE_CXX_COMPILER_TARGET "arm64-apple-ios${CMAKE_OSX_DEPLOYMENT_TARGET}")

# Xcode's ld for linking (Mach-O format compatible)
execute_process(
  COMMAND xcrun --find ld
  OUTPUT_VARIABLE CMAKE_LINKER
  OUTPUT_STRIP_TRAILING_WHITESPACE)

set(ARMORCOMP_PLUGIN  "${_AC_PLUGIN}" CACHE FILEPATH "ArmorComp pass plugin path")
set(ARMORCOMP_ENABLED TRUE            CACHE BOOL     "ArmorComp pass plugin loaded")

message(STATUS "[ArmorComp iOS] Plugin:  ${_AC_PLUGIN}")
message(STATUS "[ArmorComp iOS] Sysroot: ${_IOS_SDK}")
message(STATUS "[ArmorComp iOS] Target:  arm64-apple-ios${CMAKE_OSX_DEPLOYMENT_TARGET}")
