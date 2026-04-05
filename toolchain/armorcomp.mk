# ArmorComp — ndk-build integration  (v0.26.0)
# ============================================================
#
# Include this file from your Android.mk to enable ArmorComp.
#
# USAGE in Android.mk:
#
#   LOCAL_PATH := $(call my-dir)
#   include $(CLEAR_VARS)
#
#   LOCAL_MODULE    := mynativelib
#   LOCAL_SRC_FILES := src/native-lib.cpp src/secure_logic.c
#
#   # Include ArmorComp toolchain
#   include /path/to/armorcomp/toolchain/armorcomp.mk
#
#   include $(BUILD_SHARED_LIBRARY)
#
# USAGE in Application.mk:
#   APP_ABI       := arm64-v8a
#   APP_PLATFORM  := android-21
#
# ============================================================

_AC_TOOLCHAIN_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

ifeq ($(HOST_OS),darwin)
  _AC_PLUGIN   := $(_AC_TOOLCHAIN_DIR)lib/darwin-$(shell uname -m)/libArmorComp.dylib
  _AC_CLANG    := $(_AC_TOOLCHAIN_DIR)bin/armorcomp-clang
  _AC_CLANGXX  := $(_AC_TOOLCHAIN_DIR)bin/armorcomp-clang++
else
  _AC_PLUGIN   := $(_AC_TOOLCHAIN_DIR)lib/linux-x86_64/libArmorComp.so
  _AC_CLANG    := $(_AC_TOOLCHAIN_DIR)bin/armorcomp-clang-linux
  _AC_CLANGXX  := $(_AC_TOOLCHAIN_DIR)bin/armorcomp-clang++-linux
endif

# Override ndk-build compiler to brew clang wrapper
TARGET_CC  := $(_AC_CLANG)
TARGET_CXX := $(_AC_CLANGXX)

$(info [ArmorComp] Plugin:   $(_AC_PLUGIN))
$(info [ArmorComp] Compiler: $(_AC_CLANG))
