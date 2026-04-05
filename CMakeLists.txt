cmake_minimum_required(VERSION 3.20)
project(ArmorComp C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- Locate LLVM ----
# Priority order:
#   1. User-specified -DLLVM_DIR=...
#   2. brew llvm@17 on macOS
#   3. System LLVM

if(NOT DEFINED LLVM_DIR)
  # Auto-detect brew llvm@17 on Apple Silicon / Intel
  foreach(BREW_PREFIX
      "/opt/homebrew/opt/llvm@17/lib/cmake/llvm"   # Apple Silicon
      "/usr/local/opt/llvm@17/lib/cmake/llvm"      # Intel Mac
  )
    if(EXISTS "${BREW_PREFIX}/LLVMConfig.cmake")
      set(LLVM_DIR "${BREW_PREFIX}" CACHE PATH "LLVM cmake dir" FORCE)
      message(STATUS "Auto-detected LLVM_DIR: ${LLVM_DIR}")
      break()
    endif()
  endforeach()
endif()

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "  Include: ${LLVM_INCLUDE_DIRS}")
message(STATUS "  Lib:     ${LLVM_LIBRARY_DIRS}")

include_directories(${LLVM_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR}/include)
add_definitions(${LLVM_DEFINITIONS})

# ---- ArmorComp pass plugin ----
add_library(ArmorComp SHARED
  lib/HelloPass.cpp                  # Plugin entry point + HelloPass
  lib/ObfuscationConfig.cpp          # YAML config file parser + CL option
  lib/CFFPass.cpp                    # Control Flow Flattening pass
  lib/BCFPass.cpp                    # Bogus Control Flow pass
  lib/SubPass.cpp                    # Instruction Substitution pass
  lib/MBAPass.cpp                    # Mixed Boolean-Arithmetic pass
  lib/SplitPass.cpp                  # Basic Block Splitting pass
  lib/StrEncPass.cpp                 # String Encryption pass
  lib/IndirectCallPass.cpp           # Indirect Call Obfuscation pass
  lib/IndirectBranchPass.cpp         # Indirect Branch Obfuscation pass
  lib/IndirectGlobalVariablePass.cpp # Indirect Global Variable pass
  lib/SPOPass.cpp                    # Stack Pointer Obfuscation pass
  lib/ConstObfPass.cpp               # Integer Constant Obfuscation pass
  lib/FuncWrapPass.cpp               # Function Wrapper Obfuscation pass
  lib/RetAddrObfPass.cpp             # Return Address / Call-Frame Obfuscation pass
  lib/OpaquePredicatePass.cpp        # Opaque Predicate insertion pass
  lib/OutlinePass.cpp                # Basic Block Outlining pass
  lib/FlattenDataFlowPass.cpp        # Data Flow Flattening (stack pool merge) pass
  lib/GlobalEncPass.cpp              # Integer Global Variable Encryption pass
  lib/DataEncodingPass.cpp           # Integer Local Variable Memory Encoding pass
  lib/FuncSigObfPass.cpp             # Function Signature Obfuscation pass
  lib/DwarfPoisonPass.cpp            # DWARF CFI Table Poisoning pass
  lib/ConditionObfPass.cpp           # Comparison / ICmpInst Obfuscation pass
  lib/NeonTypeConfusionPass.cpp      # AArch64 NEON/FP type confusion pass
  lib/ReturnValueObfPass.cpp         # Return value XOR obfuscation pass
  lib/SwitchObfPass.cpp              # Switch statement obfuscation (dense jump-table + indirectbr)
  lib/LRObfPass.cpp                  # Link Register / Return Address Obfuscation pass
  lib/GEPObfPass.cpp                 # GEP Index Obfuscation pass (struct/array/vtable field obfuscation)
  lib/JunkCodePass.cpp               # Junk Code Injection pass (dead arithmetic chains per BB)
  lib/FakeAPICallPass.cpp            # Fake API Call injection (getpid/getpagesize sideeffect sinks)
  lib/PointerXorPass.cpp             # Pointer local-variable XOR encoding (complements DENC)
  lib/ArithmeticStatePass.cpp        # CFF state-variable XOR encoding (defeats d810/msynack)
  lib/GlobalPointerObfuscationPass.cpp # Function-pointer global encryption (ctor-decoded)
  lib/LoopObfuscationPass.cpp        # Loop obfuscation (preheader/header junk + fake invariant)
  lib/VMPLifter.cpp                  # VMP: LLVM IR → bytecode translator
  lib/VMPCodeGen.cpp                 # VMP: VM dispatcher LLVM IR generator
  lib/VMPPass.cpp                    # VMP: Virtual Machine Protection pass
)

# Pass plugins must NOT link against LLVM shared libs directly —
# the host clang already has LLVM loaded; we only need headers at build time.
# Use -undefined dynamic_lookup on macOS to defer symbol resolution.
if(APPLE)
  target_link_options(ArmorComp PRIVATE -undefined dynamic_lookup)
endif()

# Suppress RTTI warnings (LLVM is built without RTTI by default)
target_compile_options(ArmorComp PRIVATE -fno-rtti)

# ---- Package targets: copy plugin (and optionally bundle clang) into toolchain/ ----
#
# package-toolchain       — plugin only (requires brew/system clang@17 on customer machine)
# package-toolchain-full  — plugin + bundled clang17 + vendor dylibs (zero customer dependency)
#
# Usage:
#   cmake --build build --target package-toolchain        # minimal
#   cmake --build build --target package-toolchain-full   # self-contained delivery
if(APPLE)
  execute_process(COMMAND uname -m OUTPUT_VARIABLE _HOST_ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)
  set(_TC_LIB_DIR "${CMAKE_SOURCE_DIR}/toolchain/lib/darwin-${_HOST_ARCH}")
else()
  set(_TC_LIB_DIR "${CMAKE_SOURCE_DIR}/toolchain/lib/linux-x86_64")
endif()

# ── package-toolchain: plugin only ───────────────────────────────────────────
add_custom_target(package-toolchain
  DEPENDS ArmorComp
  COMMAND ${CMAKE_COMMAND} -E make_directory "${_TC_LIB_DIR}"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:ArmorComp>
    "${_TC_LIB_DIR}/$<TARGET_FILE_NAME:ArmorComp>"
  COMMENT "Packaging ArmorComp plugin → toolchain/lib/"
  VERBATIM)

# ── package-toolchain-full: plugin + bundled clang17 ─────────────────────────
# Self-contained delivery: customers need no pre-installed clang@17.
# On macOS: copies brew clang@17 + libLLVM-17.dylib + transitive deps into
#   toolchain/bin/clang17[++] and toolchain/vendor/.
# On Linux: copies clang-17 + non-system .so deps (requires patchelf).
if(APPLE)
  execute_process(
    COMMAND brew --prefix llvm@17
    OUTPUT_VARIABLE _BREW_LLVM17_PREFIX
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE _BREW_RESULT
    ERROR_QUIET)
  if(_BREW_RESULT EQUAL 0 AND _BREW_LLVM17_PREFIX AND EXISTS "${_BREW_LLVM17_PREFIX}/bin/clang")
    add_custom_target(package-toolchain-full
      DEPENDS ArmorComp
      # 1. Copy plugin
      COMMAND ${CMAKE_COMMAND} -E make_directory "${_TC_LIB_DIR}"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:ArmorComp>
        "${_TC_LIB_DIR}/$<TARGET_FILE_NAME:ArmorComp>"
      # 2. Bundle clang17 + vendor dylibs via helper script
      COMMAND bash
        "${CMAKE_SOURCE_DIR}/toolchain/scripts/bundle-macos.sh"
        "${_BREW_LLVM17_PREFIX}"
        "${CMAKE_SOURCE_DIR}/toolchain"
      COMMENT "Packaging self-contained ArmorComp toolchain (bundled clang17 + vendor dylibs)..."
      VERBATIM)
    message(STATUS "package-toolchain-full: brew llvm@17 found at ${_BREW_LLVM17_PREFIX}")
  else()
    add_custom_target(package-toolchain-full
      COMMAND ${CMAKE_COMMAND} -E echo
        "[ArmorComp] package-toolchain-full: brew llvm@17 not found. Run: brew install llvm@17"
      COMMENT "Skipping full package — brew llvm@17 not found")
    message(WARNING "package-toolchain-full: brew llvm@17 not found; target will be a no-op")
  endif()
elseif(UNIX)
  # Linux: use system clang-17 + patchelf
  find_program(_PATCHELF patchelf)
  find_program(_CLANG17 clang-17
    PATHS /usr/lib/llvm-17/bin /usr/bin /usr/local/bin)
  if(_CLANG17 AND _PATCHELF)
    get_filename_component(_CLANG17_BINDIR "${_CLANG17}" DIRECTORY)
    get_filename_component(_CLANG17_PREFIX "${_CLANG17_BINDIR}" DIRECTORY)
    add_custom_target(package-toolchain-full
      DEPENDS ArmorComp
      COMMAND ${CMAKE_COMMAND} -E make_directory "${_TC_LIB_DIR}"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:ArmorComp>
        "${_TC_LIB_DIR}/$<TARGET_FILE_NAME:ArmorComp>"
      COMMAND bash
        "${CMAKE_SOURCE_DIR}/toolchain/scripts/bundle-linux.sh"
        "${_CLANG17_PREFIX}"
        "${CMAKE_SOURCE_DIR}/toolchain"
      COMMENT "Packaging self-contained ArmorComp toolchain (bundled clang-17 + vendor libs)..."
      VERBATIM)
    message(STATUS "package-toolchain-full: clang-17 at ${_CLANG17}, patchelf at ${_PATCHELF}")
  else()
    add_custom_target(package-toolchain-full
      COMMAND ${CMAKE_COMMAND} -E echo
        "[ArmorComp] package-toolchain-full: clang-17 or patchelf not found. Run: apt install clang-17 patchelf"
      COMMENT "Skipping full package — clang-17 or patchelf not found")
    message(WARNING "package-toolchain-full: clang-17=${_CLANG17} patchelf=${_PATCHELF}; target will be a no-op")
  endif()
endif()

# ---- NDK convenience variables ----
set(NDK_ROOT "$ENV{ANDROID_NDK_ROOT}" CACHE PATH "Android NDK root")
if(NOT NDK_ROOT)
  # Try common location
  file(GLOB NDK_ROOT_GUESS "$ENV{HOME}/Library/Android/sdk/ndk/*")
  list(SORT NDK_ROOT_GUESS ORDER DESCENDING)
  list(GET NDK_ROOT_GUESS 0 NDK_ROOT)
endif()

if(NDK_ROOT)
  set(NDK_CLANG "${NDK_ROOT}/toolchains/llvm/prebuilt/darwin-x86_64/bin/clang")
  message(STATUS "NDK clang: ${NDK_CLANG}")
endif()

# ---- Test target: compile hello.c with the plugin ----
# NDK standalone clang static-links LLVM and doesn't export all symbols (macOS dlopen limitation).
# Workaround: use brew clang@17 (shared LLVM dylib) + NDK sysroot + NDK resource-dir.
set(BREW_CLANG "/opt/homebrew/opt/llvm@17/bin/clang")
set(NDK_SYSROOT "${NDK_ROOT}/toolchains/llvm/prebuilt/darwin-x86_64/sysroot")
set(NDK_RESOURCE_DIR "${NDK_ROOT}/toolchains/llvm/prebuilt/darwin-x86_64/lib/clang/17.0.2")

add_custom_target(test-hello
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    ${CMAKE_SOURCE_DIR}/test/hello.c
    -o ${CMAKE_BINARY_DIR}/hello_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/hello.c with ArmorComp plugin → ARM64 Android ELF"
)

# ---- Test target: CFG flattening pass validation ----
# CFFPass is registered at registerOptimizerLastEPCallback (annotation mode),
# so it auto-runs when the plugin is loaded with any optimization level.
# Only functions marked __attribute__((annotate("cff"))) are flattened.
#
# Expected stderr:
#   [ArmorComp] function: classify (N basic blocks)   ← HelloPass
#   [ArmorComp] function: sum_to_n (N basic blocks)
#   [ArmorComp] function: add (...)
#   [ArmorComp] function: main (...)
#   [ArmorComp][CFF] flattened: classify              ← CFFPass
#   [ArmorComp][CFF] flattened: sum_to_n
#
# Expected output (when run on device/emulator):
#   classify(-5) = -1
#   classify(0)  =  0
#   classify(3)  =  1
#   sum_to_n(10) = 55
#   add(3,4)     =  7
add_custom_target(test-cff
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O1
    ${CMAKE_SOURCE_DIR}/test/cff_test.c
    -o ${CMAKE_BINARY_DIR}/cff_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/cff_test.c with CFF pass (annotation mode) → ARM64 Android ELF"
)

# ---- Test target: BCF + combined BCF+CFF validation ----
# BCF auto-runs for annotate("bcf") functions.
# CFF auto-runs for annotate("cff") functions.
# protect_both() has both annotations → BCF first, then CFF.
#
# Expected stderr:
#   [ArmorComp][BCF] obfuscated: classify_bcf
#   [ArmorComp][BCF] obfuscated: protect_both
#   [ArmorComp][CFF] flattened:  protect_both
add_custom_target(test-bcf
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/bcf_test.c
    -o ${CMAKE_BINARY_DIR}/bcf_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/bcf_test.c with BCF+CFF passes → ARM64 Android ELF"
)

# ---- Test target: Instruction Substitution validation ----
# SubPass auto-runs for annotate("sub") functions.
# annotate("sub") only → pure instruction substitution (no CFG change)
# annotate("sub") + annotate("bcf") + annotate("cff") → full 3-layer protection
#
# Expected stderr:
#   [ArmorComp][SUB] substituted: calc_sub   (1 round default)
#   [ArmorComp][SUB] substituted: protect_all
#   [ArmorComp][BCF] obfuscated:  protect_all
#   [ArmorComp][CFF] flattened:   protect_all
#
# Expected output (when run on device/emulator):
#   add(3, 4)       = 7
#   mul_sub(5, 3)   = 2       (5-3)
#   and_or(0xF0,0x0F) = 0     (0xF0 & 0x0F)
#   xor_val(0xFF,0x0F) = 0xF0 (0xFF ^ 0x0F)
#   protect_all(10) = 55
add_custom_target(test-sub
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/sub_test.c
    -o ${CMAKE_BINARY_DIR}/sub_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/sub_test.c with SUB+BCF+CFF passes → ARM64 Android ELF"
)

# ---- Test target: String Encryption + Split + full 5-layer validation ----
# StrEncPass auto-runs for annotate("strenc") functions.
# SplitPass  auto-runs for annotate("split")  functions.
# Combined with SUB+BCF+CFF → 5 obfuscation layers in one binary.
#
# Expected stderr contains:
#   [ArmorComp][STRENC] encrypted: .str (the "SECRET_API_KEY" string)
#   [ArmorComp][STRENC] injected constructor: __armorcomp_str_init
#   [ArmorComp][SPLT]   split: secure_fn (N basic blocks after)
#   [ArmorComp][SUB]    substituted: secure_fn
#   [ArmorComp][BCF]    obfuscated: secure_fn
#   [ArmorComp][CFF]    flattened: secure_fn
#
# Expected output (when run on device/emulator):
#   key = SECRET_API_KEY
#   sum(5) = 15
add_custom_target(test-strenc
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/strenc_test.c
    -o ${CMAKE_BINARY_DIR}/strenc_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/strenc_test.c with all 5 ArmorComp passes → ARM64 Android ELF"
)

# ---- Test target: MBA obfuscation validation ----
# MBAPass auto-runs for annotate("mba") functions.
# Uses annotate("mba") alone to verify MBA expressions produce correct values.
# Also tests annotate("mba") + annotate("sub") stacked for maximum complexity.
#
# Expected stderr:
#   [ArmorComp][MBA] obfuscated: compute_mba   (1 round)
#   [ArmorComp][MBA] obfuscated: full_protect
#   [ArmorComp][SUB] substituted: full_protect
#   [ArmorComp][BCF] obfuscated:  full_protect
#   [ArmorComp][CFF] flattened:   full_protect
add_custom_target(test-mba
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/mba_test.c
    -o ${CMAKE_BINARY_DIR}/mba_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/mba_test.c with MBA pass → ARM64 Android ELF"
)

# ---- Test target: Indirect Call obfuscation validation ----
# IndirectCallPass auto-runs for annotate("icall") functions.
# After obfuscation, direct call instructions are replaced with:
#   load volatile @__armorcomp_icall_off → ptrtoint → add → inttoptr → call ptr
# Static analysis tools cannot resolve the callee statically.
#
# Expected stderr:
#   [ArmorComp][ICALL] indirected: secure_dispatch (N calls)
#
# Verification: objdump -d icall_test_aarch64 | grep -v "bl " shows no direct BL
add_custom_target(test-icall
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/icall_test.c
    -o ${CMAKE_BINARY_DIR}/icall_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/icall_test.c with IndirectCall pass → ARM64 Android ELF"
)

# ---- Test target: Indirect Branch obfuscation validation ----
# IndirectBranchPass auto-runs for annotate("ibr") functions.
# After obfuscation, direct branch instructions (BranchInst) are replaced by
# indirectbr whose target is a runtime-computed blockaddress.
#
# Expected stderr:
#   [ArmorComp][IBR] indirected: classify_ibr (N branches)
#
# Verification: llvm-objdump -d ibr_test_aarch64 | grep -A20 "<classify_ibr>"
#   → shows "br x8" / "blr" (indirect), NOT "b.lt", "b.gt" etc. (direct)
add_custom_target(test-ibr
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/ibr_test.c
    -o ${CMAKE_BINARY_DIR}/ibr_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/ibr_test.c with IndirectBranch pass → ARM64 Android ELF"
)

# ---- Test target: Indirect Global Variable obfuscation validation ----
# IndirectGlobalVariablePass auto-runs for annotate("igv") functions.
# After obfuscation, direct GV operands (load/store ptr @gv) are replaced by:
#   load volatile ptr, @__armorcomp_igv_gv → load/store via loaded ptr
#
# Expected stderr:
#   [ArmorComp][IGV] indirected: get_value_igv (N accesses, M globals)
#
# Verification: llvm-objdump -d igv_test_aarch64 | grep -A20 "<get_value_igv>"
#   → should load from __armorcomp_igv_* proxy, not directly from @g_counter/@g_value
add_custom_target(test-igv
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/igv_test.c
    -o ${CMAKE_BINARY_DIR}/igv_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/igv_test.c with IndirectGlobalVariable pass → ARM64 Android ELF"
)

# ---- Test target: YAML config file validation --------------------------------
# Demonstrates config-driven obfuscation without source annotations.
# The config file selects functions by name/pattern; no source changes needed.
#
# Expected stderr:
#   [ArmorComp][Config] loaded N rule(s) from "config_test.yaml"
#   [ArmorComp][CFF] flattened: config_classify
#   [ArmorComp][BCF] obfuscated: config_classify
#   [ArmorComp][IGV] indirected: config_classify
#   (no messages for config_plain — not selected by any rule)
#
# Expected stdout (when run on device/emulator):
#   config_classify(-5) = -1
#   config_classify(0)  =  0
#   config_classify(3)  =  1
#   ALL TESTS PASSED
add_custom_target(test-config
  COMMAND ${CMAKE_COMMAND} -E env
    ARMORCOMP_CONFIG=${CMAKE_SOURCE_DIR}/test/config_test.yaml
    ${BREW_CLANG}
      -target aarch64-linux-android21
      --sysroot=${NDK_SYSROOT}
      -resource-dir=${NDK_RESOURCE_DIR}
      -fpass-plugin=$<TARGET_FILE:ArmorComp>
      -O0
      ${CMAKE_SOURCE_DIR}/test/config_test.c
      -o ${CMAKE_BINARY_DIR}/config_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/config_test.c with YAML config → ARM64 Android ELF"
)

# ---- Test target: Stack Pointer Obfuscation validation ----------------------
# SPOPass injects "sub sp, sp, xN" at function entry and "add sp, sp, xN"
# before each ret.  xN is loaded from @__armorcomp_spo_zero (= 0 at runtime)
# via a volatile load, so the pair is a runtime no-op.
#
# IDA effect: Hex-Rays F5 sees sp_delta = UNKNOWN after the sub instruction
# and outputs "sp-analysis failed", refusing to decompile the annotated function.
#
# Expected stderr:
#   [ArmorComp][SPO] obfuscated: compute_spo (N ret(s))
#   (no message for compute_plain — not annotated)
#
# Expected stdout (when run on device/emulator):
#   compute_spo(3, 4) = 7
#   compute_spo(5, 7) = 35
#   compute_spo(2, 3) = 5
#   ALL TESTS PASSED
#
# Verification: llvm-objdump -d spo_test_aarch64 | grep -A30 "<compute_spo>"
#   → should show "sub sp, sp, x<N>" immediately after function prologue
add_custom_target(test-spo
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/spo_test.c
    -o ${CMAKE_BINARY_DIR}/spo_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/spo_test.c with SPO pass → ARM64 Android ELF"
)

# ---- Test target: Integer Constant Obfuscation validation -------------------
# ConstObfPass replaces each ConstantInt operand in BinaryOperator / ICmpInst
# with: xor iN (C^K), (or i64 volatile_zero, K64_trunc_to_N)
# where K is a compile-time random key.
#
# IDA effect: every numeric literal in the annotated function becomes a complex
# expression in the decompiler output.  No bare immediates are visible.
#
# Expected stderr:
#   [ArmorComp][CO] obfuscated: compute_co (N constant(s))
#   (no message for compute_plain — not annotated)
#
# Expected stdout (when run on device/emulator):
#   compute_co(3)  = 255
#   compute_co(7)  = 249
#   compute_co(10) = 241
#   ALL TESTS PASSED
#
# Verification: llvm-objdump -d co_test_aarch64 | grep -A40 "<compute_co>"
#   → should NOT contain plain "mov w8, #42" etc. (constants are hidden)
#   → should show xor/or sequences instead
add_custom_target(test-co
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/co_test.c
    -o ${CMAKE_BINARY_DIR}/co_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/co_test.c with ConstObf pass → ARM64 Android ELF"
)

# ---- Test target: Function Wrapper obfuscation validation -------------------
# FuncWrapPass replaces each direct call in an annotated function with a call
# to an internal wrapper @__armorcomp_fw_N that forwards arguments and the
# return value.  Multiple call sites to the same callee reuse one wrapper.
#
# IDA effect: xref "Who calls helper_add?" shows __armorcomp_fw_N, not the
# annotated function itself; analysts must trace one more indirection level.
# The wrapper contains a volatile load noise instruction so it is not trivially
# recognised as a passthrough.
#
# Expected stderr:
#   [ArmorComp][FW] wrapped: secure_dispatch (4 calls, 3 wrappers)
#   (no message for plain_dispatch — not annotated)
#
# Expected stdout (when run on device/emulator):
#   secure_dispatch(3, 4)  = 15
#   secure_dispatch(5, 6)  = 35
#   plain_dispatch(3, 4)   = 15
#   ALL TESTS PASSED
#
# Verification: llvm-objdump --syms fw_test_aarch64 | grep __armorcomp_fw_
#   → 3 wrapper symbols (helper_add, helper_mul, helper_cmp each get one)
#
# llvm-objdump -d fw_test_aarch64 | awk '/<secure_dispatch>/{p=1}p{print;if(/ret/)exit}'
#   → bl targets are __armorcomp_fw_N, NOT helper_add/helper_mul/helper_cmp
add_custom_target(test-fw
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/fw_test.c
    -o ${CMAKE_BINARY_DIR}/fw_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/fw_test.c with FuncWrap pass → ARM64 Android ELF"
)

# ---- Test target: Return Address / Call-Frame Obfuscation validation --------
# RetAddrObfPass inserts "sub sp, sp, xN" before each call and
# "add sp, sp, xN" after each call.  xN = volatile load of
# @__armorcomp_rao_zero (= 0) — no-op at runtime, UNKNOWN to IDA.
#
# IDA effect: every call site shows UNKNOWN sp_delta → Hex-Rays F5 fails.
# Combined with SPOPass (entry/exit sub/add), the function is completely
# opaque to static stack-frame analysis.
#
# Expected stderr:
#   [ArmorComp][RAO] obfuscated: secure_calls (4 calls)
#   (no message for plain_calls — not annotated)
#
# Expected stdout (when run on device/emulator):
#   secure_calls(3, 4)  = 14
#   secure_calls(5, 6)  = 22
#   plain_calls(3, 4)   = 14
#   ALL TESTS PASSED
#
# Verification: llvm-objdump -d rao_test_aarch64 | grep -A60 "<secure_calls>"
#   → should show ldr+sub before each bl, ldr+add after each bl
add_custom_target(test-rao
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/rao_test.c
    -o ${CMAKE_BINARY_DIR}/rao_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/rao_test.c with RetAddrObf pass → ARM64 Android ELF"
)

# ---- Test target: Opaque Predicate insertion validation ---------------------
# OpaquePredicatePass splits each non-entry BB into head + tail.  The head
# evaluates one of 6 opaque predicate formulas (3 always-true, 3 always-false)
# and branches to the real tail or a dead-end block that contains junk ops +
# a ret null-value.  The predicate formulas use @__armorcomp_op_zero (volatile
# global = 0) so they are opaque to the optimizer.
#
# IDA effect: the CFG appears to have multiple additional paths (dead-end BBs).
# After CFF, the dead BBs become additional (never-taken) cases in the dispatch
# switch, inflating complexity beyond BCF alone.
#
# Expected stderr:
#   [ArmorComp][OP] obfuscated: secure_classify (N predicates)
#   [ArmorComp][OP] obfuscated: secure_arith (N predicates)
#   (no message for plain_classify / plain_arith — not annotated)
#
# Expected stdout (when run on device/emulator):
#   secure_classify(-5)  = -1
#   secure_classify(0)   =  0
#   secure_classify(5)   =  1
#   secure_classify(50)  =  2
#   secure_classify(100) =  3
#   plain_classify(-5)   = -1
#   ALL TESTS PASSED
#
# Verification: llvm-objdump -d op_test_aarch64 | grep -A80 "<secure_classify>"
#   → Should show multiple dead-end "op.dead" blocks containing 0x4f50 marker
#   → Real logic path still produces correct results
add_custom_target(test-op
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/op_test.c
    -o ${CMAKE_BINARY_DIR}/op_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/op_test.c with OpaquePredicate pass → ARM64 Android ELF"
)

# ---- Test target: Basic Block Outlining validation --------------------------
# OutlinePass extracts each non-entry BB into an independent internal function
# named __armorcomp_outline_N with noinline + optnone attributes.
# The original function is replaced by a chain of calls to the outlined helpers.
#
# This makes reverse engineering much harder: instead of one function body,
# analysts must trace through N small helper functions to reconstruct logic.
# Combined with BCF/CFF, the outlined helpers also receive CFG obfuscation.
#
# Prerequisite: SSA demotion (DemotePHIToStack + DemoteRegToStack) is applied
# before extraction so CodeExtractor can handle all cross-block live values.
#
# Expected stderr:
#   [ArmorComp][OUTLINE] outlined: secure_compute (N blocks)
#   (no message for plain_compute — not annotated)
#
# Expected stdout (when run on device/emulator):
#   secure_compute(3, 4)  = 14
#   secure_compute(5, 10) = 35
#   plain_compute(3, 4)   = 14
#   ALL TESTS PASSED
#
# Verification: llvm-objdump --syms outline_test_aarch64 | grep __armorcomp_outline_
#   → multiple __armorcomp_outline_N symbols should appear
#
# llvm-objdump -d outline_test_aarch64 | awk '/<secure_compute>/{p=1}p{print;if(/ret$/)exit}'
#   → should show bl __armorcomp_outline_N calls instead of inline BB code
add_custom_target(test-outline
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/outline_test.c
    -o ${CMAKE_BINARY_DIR}/outline_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/outline_test.c with Outline pass → ARM64 Android ELF"
)

# ---- Test target: Data Flow Flattening validation ---------------------------
# FlattenDataFlowPass merges all statically-sized alloca instructions in a
# function's entry block into a single byte pool alloca [N x i8].
# Each original alloca at byte offset O is accessed via an obfuscated GEP:
#
#   idx = xor i64 (O ^ KEY), (or i64 volatile_zero, KEY)   ; = O at runtime
#   ptr = gep i8, ptr pool, i64 idx
#
# where KEY = xorshift64(hash(function_name)).
#
# IDA/Ghidra effect: variable recovery fails — analysts see all locals as
# pointer arithmetic into an opaque byte array; type recovery is impossible
# without resolving the volatile GEP index at runtime.
#
# Expected stderr:
#   [ArmorComp][DF] flattened: secure_compute (N alloca(s), M bytes)
#   [ArmorComp][DF] flattened: secure_mixed   (N alloca(s), M bytes)
#   (no message for plain_compute / plain_mixed — not annotated)
#
# Expected stdout (when run on device/emulator):
#   secure_compute(3, 4)   = 6
#   secure_compute(5, 3)   = 42
#   plain_compute(3, 4)    = 6
#   secure_mixed(3, 4)     = 42
#   ALL TESTS PASSED
#
# Verification: llvm-objdump -d df_test_aarch64 | grep -A60 "<secure_compute>"
#   → should show "armorcomp.df.pool" alloca at function entry and GEP-based
#     pointer loads using eor/orr sequences (no plain [sp, #-N] offsets)
add_custom_target(test-df
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/df_test.c
    -o ${CMAKE_BINARY_DIR}/df_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/df_test.c with FlattenDataFlow pass → ARM64 Android ELF"
)

# ---- Test target: Integer Global Variable Encryption validation ---------------
# GlobalEncPass XOR-encrypts the ConstantInt initializer of each integer global
# (@g_key, @g_magic, @g_flags …) used by annotate("genc") functions.
# A generated __armorcomp_genc_init ctor decrypts them at startup.
#
# IDA/Ghidra effect:
#   - .data section shows only XOR-scrambled ciphertext values.
#   - IDA displays wrong values for the annotated globals; the analyst must
#     trace the ctor (showing only the XOR key) to recover the real constants.
#   - Paired with StrEncPass and ConstObfPass this hides ALL static constants.
#
# Expected stderr:
#   [ArmorComp][GENC] encrypted: g_key   (i32, key=0x...)
#   [ArmorComp][GENC] encrypted: g_magic (i64, key=0x...)
#   [ArmorComp][GENC] injected constructor: __armorcomp_genc_init (2 global(s))
#   (no message for g_plain — not used by any annotate("genc") function)
#
# Expected stdout (when run on device/emulator):
#   verify_key(1000) = 1
#   verify_key(9999) = 0
#   read_magic()     = 3735928559
#   ALL TESTS PASSED
#
# Verification: llvm-objdump -d genc_test_aarch64 | grep -A20 "<__armorcomp_genc_init>"
#   → should show volatile ldr + eor + str pattern for each encrypted GV
#   (the eor immediate is the XOR key, not the original plaintext value)
#
# llvm-objdump -s --section=.data genc_test_aarch64
#   → .data bytes for g_key and g_magic should differ from the C source values
add_custom_target(test-genc
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/genc_test.c
    -o ${CMAKE_BINARY_DIR}/genc_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/genc_test.c with GlobalEnc pass → ARM64 Android ELF"
)

# ---- Test target: Integer Local Variable Memory Encoding validation -----------
# DataEncodingPass wraps every load/store to eligible integer allocas with
# XOR encode/decode pairs:
#   store side: %de.enc = xor iN val, K  →  store %de.enc
#   load  side: %raw = load iN          →  %de.dec = xor %raw, K  (replaces uses)
# KEY = xorshift64(FNV1a(fn_name + "_denc_" + alloca_index)) — per-alloca, deterministic.
#
# IDA/Ghidra effect:
#   - Stack memory always contains XOR-encoded (ciphertext) values.
#   - Decompiler shows eor around every ldr/str instead of plain variables;
#     variable type recovery and value propagation are hindered.
#   - Composable with FlattenDataFlowPass (runs after DENC): DF merges allocas
#     into a pool, combining address obfuscation with value obfuscation.
#   - Composable with ConstObfPass (runs after DENC): CO hides DENC's XOR keys.
#
# Expected stderr:
#   [ArmorComp][DENC] encoded: secure_compute (N alloca(s))
#   [ArmorComp][DENC] encoded: secure_mixed   (N alloca(s))
#   (no message for plain_compute / plain_mixed — not annotated)
#
# Expected stdout (when run on device/emulator):
#   secure_compute(3, 4)   = 14
#   secure_compute(5, 7)   = 60
#   plain_compute(3, 4)    = 14
#   secure_mixed(3, 4)     = 7
#   ALL TESTS PASSED
#
# Verification: llvm-objdump -d denc_test_aarch64 | grep -A50 "<secure_compute>"
#   → should show eor instructions immediately before str and after ldr
#     for every local variable access (no plain str/ldr without surrounding eor)
add_custom_target(test-denc
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/denc_test.c
    -o ${CMAKE_BINARY_DIR}/denc_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/denc_test.c with DataEncoding pass → ARM64 Android ELF"
)

# ---- Test target: Function Signature Obfuscation validation -----------------
# FuncSigObfPass injects two classes of AArch64 inline asm at function
# boundaries to poison IDA Hex-Rays register-liveness analysis:
#
#  ENTRY (fake extra-argument reads):
#    mov <tmp>, x1 ; mov <tmp>, x2 ; mov <tmp>, x3  → or-chain → volatile str
#    IDA liveness: x1/x2/x3 are READ before any WRITE → inferred as arguments.
#    IDA Function prototype: "int secure_add(int, int, int, int)" instead of
#    "int secure_add(int, int)".
#
#  EXIT (fake return-value writes):
#    mov x1, <zero>  ;  mov x2, <zero>  (before every ret)
#    IDA return-type analysis: x1/x2 written before ret → multi-register return
#    or struct return.  Hex-Rays generates wrong prototype for annotated fns.
#
# Runtime correctness:
#   x1–x3 are caller-saved AArch64 argument registers.  Reading them (entry)
#   is a side-effect-free observe; writing 0 to x1/x2 (exit) does not break
#   the ABI because callers may not rely on x1/x2 being preserved.
#
# Expected stderr:
#   [ArmorComp][FSIG] obfuscated: secure_add   (3 fake arg-reads at entry, 1 ret(s) ...)
#   [ArmorComp][FSIG] obfuscated: secure_abs   (3 fake arg-reads at entry, 2 ret(s) ...)
#   [ArmorComp][FSIG] obfuscated: secure_sum   (3 fake arg-reads at entry, 1 ret(s) ...)
#   (no message for plain_add / plain_abs / plain_sum — not annotated)
#
# Expected stdout (when run on device/emulator):
#   secure_add(3, 4)   = 7
#   secure_add(-5, 2)  = -3
#   plain_add(3, 4)    = 7
#   secure_abs(-7)     = 7
#   secure_abs(5)      = 5
#   secure_sum(1, 10)  = 55
#   ALL TESTS PASSED
#
# Verification: llvm-objdump -d fsig_test_aarch64 | grep -A40 "<secure_add>"
#   → near entry: "mov  x9, x1" / "mov x10, x2" / "mov x11, x3" reads + volatile store
#   → near each ret: "mov x1, <zero_reg>" / "mov x2, <zero_reg>" immediately before ret
add_custom_target(test-fsig
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/fsig_test.c
    -o ${CMAKE_BINARY_DIR}/fsig_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/fsig_test.c with FuncSigObf pass → ARM64 Android ELF"
)

# ---- Test target: DWARF CFI Table Poisoning validation ----------------------
# DwarfPoisonPass injects self-contained .cfi_remember_state / fake CFI /
# .cfi_restore_state inline-asm blocks at:
#   - Entry block (2× after allocas): establishes immediate CFA confusion
#   - Each non-entry BB (1× before terminator): spreads poison through body
#   - Before each ReturnInst (1× extra): maximum noise at function exit
#
# Each block emits a DWARF CFI row such as:
#   DW_CFA_def_cfa: sp+524288   (impossible stack size)
#   DW_CFA_undefined: r30       (LR "lost" → IDA can't trace return addr)
#   DW_CFA_undefined: r29       (FP "lost" → frame-pointer chain broken)
# followed immediately by .cfi_restore_state to preserve runtime correctness.
#
# IDA Pro effect:
#   - sp_delta UNKNOWN throughout annotated functions
#   - Hex-Rays: "stack analysis failed" / wrong local-variable addresses
#   - Stack view shows impossible frame sizes (e.g., 524288 bytes)
#   - IDA warns "sp is not balanced" on every basic block
#
# Runtime correctness:
#   .cfi_restore_state restores the correct CFA for all PCs except the single
#   injected nop.  Backtraces and C++ exception unwinding are unaffected.
#
# This pass is orthogonal to SPOPass (which targets runtime SP tracking) —
# DwarfPoisonPass targets IDA's DWARF-table-based analysis path instead.
#
# Expected stderr:
#   [ArmorComp][DPOISON] obfuscated: secure_compute   (N CFI poison injection(s), 1 ret(s))
#   [ArmorComp][DPOISON] obfuscated: secure_branch     (N CFI poison injection(s), 2 ret(s))
#   [ArmorComp][DPOISON] obfuscated: secure_loop       (N CFI poison injection(s), 1 ret(s))
#   (no message for plain_compute / plain_branch / plain_loop — not annotated)
#
# Expected stdout (when run on device/emulator):
#   secure_compute(3, 4)   = 14
#   secure_compute(2, 3)   = 7
#   plain_compute(3, 4)    = 14
#   secure_branch(-7)      = 7
#   secure_branch(5)       = 5
#   secure_loop(1, 10)     = 55
#   ALL TESTS PASSED
#
# Verification (host, requires readelf or llvm-dwarfdump):
#   readelf --debug-dump=frames dpoison_test_aarch64 | grep -A30 "FDE.*secure_compute"
#   → should contain DW_CFA_def_cfa rows with huge offsets (sp+524288, sp+131072, etc.)
#     and DW_CFA_undefined entries for r30 (LR) and/or r29 (FP)
#
#   llvm-dwarfdump --eh-frame dpoison_test_aarch64 | grep -A40 "secure_compute"
#   → should show CFA= alternating between correct (sp+16 or x29+16) and
#     enormous fake values, confirming .cfi_remember_state/restore_state pairs
add_custom_target(test-dpoison
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/dpoison_test.c
    -o ${CMAKE_BINARY_DIR}/dpoison_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/dpoison_test.c with DwarfPoison pass → ARM64 Android ELF"
)

# ---- Test target: Condition Obfuscation (ICmpInst noise injection) -----------
# ConditionObfPass adds opaque noise to both operands of every ICmpInst in
# annotate("cob") functions:
#   icmp pred A, B  →  icmp pred (A+noise_A), (B+noise_B)
# where noise = trunc(mul(volatile_zero_global, K)) = 0 at runtime.
#
# Neither SubPass nor MBAPass transform ICmpInst — they only target
# BinaryOperator (ADD/SUB/AND/OR/XOR).  ConditionObfPass closes this gap so
# that condition expressions in IDA Hex-Rays F5 decompiler output become
# unresolvable:
#   Real code:      if ( x < 0 )
#   IDA F5 output:  if ( (v4 + v2) < v3 )
# where v2, v3 are the noise terms loaded from the volatile zero global.
#
# IDA effect: every if/while/for condition in annotated functions becomes an
# unresolvable expression involving noise variables.  The analyst must trace
# the volatile-zero provenance chain to recover the original comparison.
#
# Expected stderr:
#   [ArmorComp][COB] obfuscated: secure_classify (N icmp(s))
#   [ArmorComp][COB] obfuscated: secure_max      (N icmp(s))
#   [ArmorComp][COB] obfuscated: secure_between  (N icmp(s))
#   [ArmorComp][COB] obfuscated: secure_mix      (N icmp(s))
#   (no message for plain_* — not annotated)
#
# Expected stdout (when run on device/emulator):
#   secure_classify(-5)      = -1
#   secure_classify(0)       =  0
#   secure_classify(5)       =  1
#   secure_classify(101)     =  2
#   plain_classify(-5)       = -1
#   secure_max(3, 7)         =  7
#   secure_max(5, 3)         =  5
#   plain_max(3, 7)          =  7
#   secure_between(5,1,10)   =  1
#   secure_between(0,1,10)   =  0
#   plain_between(5,1,10)    =  1
#   secure_mix(-3, 7, -1)    = 10
#   ALL TESTS PASSED
#
# Verification: llvm-objdump -d cob_test_aarch64 | grep -A40 "<secure_classify>"
#   → should show add+mul noise sequences (e.g. "mul x8, x9, x10") before each
#     cmp instruction instead of bare "cmp w0, #0" seen in plain_classify
add_custom_target(test-cob
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/cob_test.c
    -o ${CMAKE_BINARY_DIR}/cob_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/cob_test.c with ConditionObf pass → ARM64 Android ELF"
)

# ---- Test target: NEON/FP Type Confusion validation -------------------------
# NeonTypeConfusionPass injects fmov GPR↔SIMD roundtrips at function entry
# (Block A: fmov s16/$0 + fmov w9/s16, Block B: fmov s17/$0 + fmov w10/s17)
# and before each ReturnInst (Block C: fmov s18-s19/$0 + fmov w11-w12/sN).
# Source operand = volatile i32 load of @__armorcomp_ntc_zero (= 0 at runtime).
#
# IDA Hex-Rays type inference uses register class to annotate variable types.
# When it sees integer values routed through s16-s19 (32-bit FP registers),
# it infers float/double types for those values.  Consequently:
#   - Integer parameters are annotated as float in the Hex-Rays prototype
#   - Local variables near SIMD roundtrips get float/double types
#   - F5 decompiler output shows wrong type declarations
# Combined with FuncSigObfPass: IDA prototype analysis fails from both
# the liveness side (FSIG) and the type-inference side (NTC).
#
# AArch64-only: pass is a no-op on non-AArch64 targets (triple check guard).
#
# Expected stderr:
#   [ArmorComp][NTC] obfuscated: secure_add      (2 injection(s), 1 ret(s))
#   [ArmorComp][NTC] obfuscated: secure_abs      (2 injection(s), 2 ret(s))
#   [ArmorComp][NTC] obfuscated: secure_classify (2 injection(s), 4 ret(s))
#   [ArmorComp][NTC] obfuscated: secure_sum      (2 injection(s), 1 ret(s))
#   (no message for plain_* — not annotated)
#
# Expected stdout (when run on device/emulator):
#   secure_add(3, 4)         =  7
#   secure_add(-5, 2)        = -3
#   plain_add(3, 4)          =  7
#   secure_abs(-7)           =  7
#   secure_abs(5)            =  5
#   plain_abs(-7)            =  7
#   secure_classify(-5)      = -1
#   secure_classify(0)       =  0
#   secure_classify(5)       =  1
#   secure_classify(101)     =  2
#   plain_classify(-5)       = -1
#   secure_sum(1, 10)        = 55
#   plain_sum(1, 10)         = 55
#   ALL TESTS PASSED
#
# Verification: llvm-objdump -d ntc_test_aarch64 | grep -A20 "<secure_add>"
#   → should show fmov s16/s17 instructions at function entry immediately
#     after the volatile ldr from __armorcomp_ntc_zero
#   → plain_add should contain NO fmov instructions (bare arithmetic only)
#
# llvm-objdump -d ntc_test_aarch64 | grep -A20 "<secure_abs>"
#   → should show fmov s18/s19 instructions before each ret instruction
#     (two distinct ret sites → two Block C injections)
add_custom_target(test-ntc
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/ntc_test.c
    -o ${CMAKE_BINARY_DIR}/ntc_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/ntc_test.c with NeonTypeConfusion pass → ARM64 Android ELF"
)

# ---- Test target: Return Value Obfuscation validation -----------------------
# ReturnValueObfPass XOR-encodes the return value of each integer/pointer-
# returning function annotated with annotate("rvo"):
#
#   rvo.zero = load volatile iN, @__armorcomp_rvo_zero   ; = 0 at runtime
#   rvo.xor  = <original_retval> xor rvo.zero             ; no-op at runtime
#   ret rvo.xor
#
# AArch64 disassembly (i32 return):
#   ldr  w8, [__armorcomp_rvo_zero]   ; volatile zero load
#   eor  w0, w0, w8                   ; w0 ^= 0 (IDA cannot prove this)
#   ret
#
# IDA Hex-Rays effect:
#   - Return type inference fails: the EOR makes x0 appear as a computed
#     value based on a runtime memory load.  IDA marks return type as
#     __int64 / void* / _UNKNOWN (depending on its heuristic).
#   - Return-value propagation across callers: call sites that capture
#     the return value track an unresolvable XOR expression.
#   - Combined with FuncSigObfPass (fake arg reads / x1,x2 writes) and
#     NeonTypeConfusionPass (fmov GPR↔SIMD at entry/exit): the function's
#     complete prototype — parameter types, count, AND return type — is
#     unrecoverable from static analysis alone.
#
# Target-independent: uses pure LLVM IR (load + xor), no AArch64 inline asm.
# Works on all LLVM targets; most effective against AArch64/x86_64 Hex-Rays.
#
# Expected stderr:
#   [ArmorComp][RVO] obfuscated: secure_add    (1 ret(s), 32-bit)
#   [ArmorComp][RVO] obfuscated: secure_abs    (1 ret(s), 32-bit)
#   [ArmorComp][RVO] obfuscated: secure_classify (1 ret(s), 32-bit)
#   [ArmorComp][RVO] obfuscated: secure_sum    (1 ret(s), 32-bit)
#   [ArmorComp][RVO] obfuscated: secure_id64   (1 ret(s), 64-bit)
#   [ArmorComp][RVO] obfuscated: secure_ptr    (1 ret(s), ptr)
#   (no message for plain_* — not annotated)
#
# Expected stdout (when run on device/emulator):
#   secure_add(3, 4)         =  7
#   secure_add(-5, 2)        = -3
#   plain_add(3, 4)          =  7
#   secure_abs(-7)           =  7
#   secure_abs(5)            =  5
#   plain_abs(-7)            =  7
#   secure_classify(-5)      = -1
#   secure_classify(0)       =  0
#   secure_classify(5)       =  1
#   secure_classify(101)     =  2
#   plain_classify(-5)       = -1
#   secure_sum(1, 10)        = 55
#   plain_sum(1, 10)         = 55
#   secure_id64(42)          = 42
#   plain_id64(42)           = 42
#   secure_ptr(ok)           = ok
#   ALL TESTS PASSED
#
# Verification: llvm-objdump -d rvo_test_aarch64 | grep -A15 "<secure_add>"
#   → near each ret: "ldr w8, [__armorcomp_rvo_zero]" then "eor w0, w0, w8"
#   → plain_add should NOT have any eor on w0 before ret
#
# llvm-objdump -d rvo_test_aarch64 | grep -A15 "<secure_id64>"
#   → near ret: "ldr x8, [__armorcomp_rvo_zero]" then "eor x0, x0, x8"
#     (64-bit variant: eor x0 instead of eor w0)
#
# llvm-objdump -d rvo_test_aarch64 | grep -A15 "<secure_ptr>"
#   → near ret: volatile load + "eor x0, x0, x8" (ptr via ptrtoint/xor/inttoptr)
add_custom_target(test-rvo
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/rvo_test.c
    -o ${CMAKE_BINARY_DIR}/rvo_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/rvo_test.c with ReturnValueObf pass → ARM64 Android ELF"
)

# ---- Test target: RVO arm32 validation (ptrtoint width verification) ---------
# Emits LLVM IR (-S -emit-llvm) so the ptrtoint/xor/inttoptr types can be
# inspected without a device.  Expected in rvo_test_arm32.ll:
#
#   secure_ptr:
#     %N = ptrtoint ptr %M to i32     ← i32, NOT i64
#     %P = xor i32 %N, %trunc         ← all-i32 chain
#     %Q = inttoptr i32 %P to ptr
#
#   secure_id64:
#     %N = load volatile i64, ...     ← i64 unchanged (integer, not ptr)
#     %P = xor i64 %M, %N
#
# Verification:
#   grep "ptrtoint\|inttoptr" ${CMAKE_BINARY_DIR}/rvo_test_arm32.ll
#   → should show "to i32" for secure_ptr, "to i64" for none (ptr only)
add_custom_target(test-rvo-arm32
  COMMAND ${BREW_CLANG}
    -target armv7a-linux-androideabi21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0 -S -emit-llvm
    ${CMAKE_SOURCE_DIR}/test/rvo_test.c
    -o ${CMAKE_BINARY_DIR}/rvo_test_arm32.ll
  DEPENDS ArmorComp
  COMMENT "Compiling test/rvo_test.c with ReturnValueObf pass → ARM32 LLVM IR (ptrtoint width check)"
)

# ---- Test target: Switch Obfuscation validation -----------------------------
# SwitchObfPass replaces every SwitchInst in annotate("sob") functions with a
# dense jump-table lookup + indirectbr.  The table entry is loaded as a volatile
# ptr; the loaded address is then ptrtoint'd, XOR'd with a volatile-zero i64,
# then inttoptr'd before branching.  IDA Pro's switch pattern matcher sees:
#   ldr x8, [sob_table_N, x0, lsl #3]   ; volatile table load
#   ldr x9, [__armorcomp_sob_zero]        ; volatile zero
#   eor x8, x8, x9                        ; XOR mask — IDA cannot fold away
#   br  x8                                ; indirect jump
# and fails to reconstruct the original switch: all case paths show JUMPOUT().
#
# Notes on the dense table algorithm:
#   - Sparsity guard: if (maxCase - minCase) > 1023 the switch is left intact.
#   - Table entries: indices [0..maxCase-minCase] map to case BBs (or default if
#     no case at that value); index [maxCase-minCase+1] is the explicit default
#     for out-of-range access (after a select clamps the index).
#   - Orthogonal to IndirectBranchPass: IBR only handles BranchInst; SOB only
#     handles SwitchInst.  No overlap.
#
# Expected stderr (ArmorComp log):
#   [ArmorComp][SOB] obfuscated: classify_dir   (1 switch)
#   [ArmorComp][SOB] obfuscated: classify_neg   (1 switch)
#   [ArmorComp][SOB] obfuscated: classify_gap   (1 switch)
#   [ArmorComp][SOB] obfuscated: grade           (1 switch)
#   [ArmorComp][SOB] obfuscated: multi_switch    (2 switches)
#   (no message for plain_* — not annotated)
#
# Expected stdout (when run on device/emulator):
#   classify_dir(0)    = zero
#   classify_dir(1)    = one
#   classify_dir(2)    = two
#   classify_dir(99)   = other
#   classify_neg(-1)   = minus_one
#   classify_neg(0)    = zero
#   classify_neg(1)    = plus_one
#   classify_neg(99)   = far_positive
#   grade(90)          = A
#   grade(80)          = B
#   grade(70)          = C
#   grade(60)          = D
#   grade(50)          = F
#   multi_switch(1,0)  = (1+0)=1
#   multi_switch(2,3)  = (2*3)=6
#   ALL TESTS PASSED
#
# Verification: llvm-objdump -d sob_test_aarch64 | grep -A30 "<classify_dir>"
#   → should show: ldr (table load) + ldr (__armorcomp_sob_zero) + eor + br x8
#   → plain_classify_dir should show: adrp + add + ldr offset table + br (direct switch)
add_custom_target(test-sob
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/sob_test.c
    -o ${CMAKE_BINARY_DIR}/sob_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/sob_test.c with SwitchObf pass → ARM64 Android ELF"
)

# ---- Test target: LRObfPass (link register / return address obfuscation) ----
# LRObfPass injects inline asm "eor x30, x30, <volatile_zero>" before every
# ReturnInst in annotate("lro") functions.  At runtime x30 ^ 0 == x30 so the
# return address is unaffected; IDA Pro cannot resolve the return target
# statically → all caller xrefs become JUMPOUT() / "sp-analysis failed".
#
# AArch64-only: the x30 register is the AArch64 link register.  The pass is a
# no-op on all other targets (Triple::isAArch64() guard inside the pass).
#
# Expected stderr (one line per obfuscated function):
#   [ArmorComp][LRO] obfuscated: secure_add     (1 ret(s))
#   [ArmorComp][LRO] obfuscated: secure_classify (1 ret(s))
#   [ArmorComp][LRO] obfuscated: secure_sum     (1 ret(s))
#   [ArmorComp][LRO] obfuscated: secure_id64    (1 ret(s))
#   [ArmorComp][LRO] obfuscated: secure_ptr     (1 ret(s))
#   [ArmorComp][LRO] obfuscated: multi_ret      (3 ret(s))
#
# Disassembly verification:
#   llvm-objdump -d lro_test_aarch64 | grep -A15 "<secure_add>"
#   → should show:
#       ldr  x9, [__armorcomp_lro_zero]
#       eor  x30, x30, x9
#       ret
#   plain_add should NOT contain any eor on x30 before ret.
#
# Run on device/emulator; expected stdout ends with "ALL TESTS PASSED".
add_custom_target(test-lro
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/lro_test.c
    -o ${CMAKE_BINARY_DIR}/lro_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/lro_test.c with LROObf pass → ARM64 Android ELF"
)

# ---- Test target: GEPObfPass (GEP index obfuscation) ----
# GEPObfPass replaces non-zero ConstantInt GEP index operands with:
#   %gepo.zero = load volatile i64, @__armorcomp_gepo_zero
#   %gepo.idx  = xor iN K, trunc(%gepo.zero, iN)
#   getelementptr T, ptr base, ..., iN %gepo.idx, ...
#
# IDA Pro effect:
#   Before: ldr  w0, [x0, #8]                 → struct field at offset 8 (visible)
#   After:  ldr  x9, [__armorcomp_gepo_zero]
#           eor  w9, w9, #8
#           ldr  w0, [x0, w9, sxtw]            → unknown offset → struct recovery fails
#
# Orthogonal to ConstObfPass (CO): CO transforms BinaryOperator/ICmpInst constants;
# GEPO transforms GetElementPtrInst index constants.  Together they hide all integer
# constants appearing in the binary.
#
# Expected stderr (one line per obfuscated function):
#   [ArmorComp][GEPO] obfuscated: get_field_b  (N GEP index(es))
#   [ArmorComp][GEPO] obfuscated: get_nested   (N GEP index(es))
#   [ArmorComp][GEPO] obfuscated: array_elem   (N GEP index(es))
#   [ArmorComp][GEPO] obfuscated: multi_field  (N GEP index(es))
#   [ArmorComp][GEPO] obfuscated: mixed_access (N GEP index(es))
#
# Disassembly verification:
#   llvm-objdump -d gepo_test_aarch64 | grep -A20 "<get_field_b>"
#   → should show  eor w9, w9, #N  before struct load (IDA unknown offset)
#   plain_get_field_b should show bare  ldr w0, [x0, #8]  (constant visible)
#
# Run on device/emulator; expected stdout ends with "ALL TESTS PASSED".
add_custom_target(test-gepo
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/gepo_test.c
    -o ${CMAKE_BINARY_DIR}/gepo_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/gepo_test.c with GEPObf pass → ARM64 Android ELF"
)

# ---- Test target: JunkCodePass (JCI — junk code injection) ------------------
# JunkCodePass inserts dead arithmetic computation chains into each BB of
# annotate("jci") functions.  Each chain:
#   1. volatile load @__armorcomp_jci_zero (= 0 at runtime)
#   2. 4–7 xor/or/and/shl/lshr/mul/add/sub ops with PRNG constants
#   3. empty asm sideeffect "r,~{dirflag},~{fpsr},~{flags}" sink (no output)
#
# Runtime: the entire chain evaluates to 0 and is consumed by the asm sink
# with zero actual instructions generated.  Correctness is preserved.
#
# IDA Hex-Rays F5 effect (annotated vs plain):
#   Annotated: every BB has N extra local variables (jci.base, jci.xor, ...)
#   Plain:     clean output, no dead variable chains
#
# PRNG determinism: seed = FNV-1a(fnName + "_jci_" + bbIdx) → xorshift64.
# Same source code compiles to the same obfuscated binary every time.
#
# Expected stderr:
#   [ArmorComp][JCI] injected: jci_add          (N junk instr(s), M BB(s))
#   [ArmorComp][JCI] injected: jci_add_multi    (N junk instr(s), M BB(s))
#   [ArmorComp][JCI] injected: jci_classify     (N junk instr(s), M BB(s))
#   [ArmorComp][JCI] injected: jci_loop         (N junk instr(s), M BB(s))
#   [ArmorComp][JCI] injected: jci_branch       (N junk instr(s), M BB(s))
#   (no message for plain_* — not annotated)
#
# Expected stdout (when run on device/emulator):
#   jci_add(3, 4)     = 7
#   plain_add(3, 4)   = 7
#   jci_classify(-5)  = -1
#   ...
#   ALL TESTS PASSED
#
# Verification: llvm-objdump -d jci_test_aarch64 | grep -A30 "<jci_classify>"
#   → each BB should show a chain of  eor/orr/and/mul/add/sub  register ops
#     before the BB terminator, followed by no visible asm sink output
#   → plain_classify should show none of these dead chains
add_custom_target(test-jci
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/jci_test.c
    -o ${CMAKE_BINARY_DIR}/jci_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/jci_test.c with JunkCode pass → ARM64 Android ELF"
)

# ---- Test target: VMPPass (VMP — Virtual Machine Protection) -----------------
# VMPPass lifts annotate("vmp") functions to custom VMP bytecode and replaces
# each function body with a fetch-decode-execute VM interpreter loop in LLVM IR.
#
# Architecture:
#   annotate("vmp") fn → VMPLifter → [N x i8] bytecode global
#                      → VMPCodeGen → __armorcomp_vmp_dispatch_<fn> loop
#   original fn body  → thunk: tail-call to dispatcher
#
# ISA: register-based VM, 64 virtual registers (i64 each), ~48 opcodes.
# See include/ArmorComp/VMPOpcodes.h for full ISA documentation.
#
# Limitations (initial implementation):
#   - Direct function calls inside virtualized functions → function skipped
#   - Conditional branches with PHI nodes on both edges → function skipped
#   - Floating-point and SIMD instructions → function skipped
#
# Expected stderr (successful virtualization):
#   [ArmorComp][VMP] virtualized: vmp_add    (N bytecode bytes, M virtual instrs)
#   [ArmorComp][VMP] virtualized: vmp_classify (N bytecode bytes, M virtual instrs)
#   [ArmorComp][VMP] virtualized: vmp_loop   (N bytecode bytes, M virtual instrs)
#
# Expected stdout (when run on device/emulator):
#   vmp_add(3, 4) = 7
#   ...
#   ALL TESTS PASSED
add_custom_target(test-vmp
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/vmp_test.c
    -o ${CMAKE_BINARY_DIR}/vmp_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/vmp_test.c with VMP pass → ARM64 Android ELF"
)

# ---- Test target: FakeAPICallPass (FAPI) validation ----
# Injects real libc calls (getpid / getpagesize) before each BB terminator.
# Results are consumed by asm sideeffect sinks; cannot be DCE'd.
#
# Expected stderr:
#   [ArmorComp][FAPI] injected: secure_compute (N API call(s))
#   [ArmorComp][FAPI] injected: secure_mixed   (N API call(s))
#
# Expected stdout: ALL TESTS PASSED
add_custom_target(test-fapi
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/fapi_test.c
    -o ${CMAKE_BINARY_DIR}/fapi_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/fapi_test.c with FAPI pass → ARM64 Android ELF"
)

# ---- Test target: PointerXorPass (PXOR) validation ----
# XOR-encodes pointer-typed alloca slots (complements DENC for integer slots).
# Stack memory always holds (real_ptr ^ K) instead of real_ptr.
#
# Expected stderr:
#   [ArmorComp][PXOR] encoded: secure_ptr_ops (N pointer alloca(s))
#   [ArmorComp][PXOR] encoded: secure_ptr_swap (N pointer alloca(s))
#
# Expected stdout: ALL TESTS PASSED
add_custom_target(test-pxor
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/pxor_test.c
    -o ${CMAKE_BINARY_DIR}/pxor_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/pxor_test.c with PXOR pass → ARM64 Android ELF"
)

# ---- Test target: ArithmeticStatePass (ASP) validation ----
# Runs after CFF and XOR-encodes the CFF state variable constants.
# All store/case constants are encoded with the same key → correct dispatch.
# Defeats d810/msynack which trace constant state values.
#
# Expected stderr:
#   [ArmorComp][CFF] flattened: secure_classify
#   [ArmorComp][ASP] encoded: secure_classify (N state var(s), M constant(s))
#
# Expected stdout: ALL TESTS PASSED
add_custom_target(test-asp
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/asp_test.c
    -o ${CMAKE_BINARY_DIR}/asp_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/asp_test.c with CFF+ASP passes → ARM64 Android ELF"
)

# ---- Test target: GlobalPointerObfuscationPass (GPO) validation ----
# Encrypts function-pointer globals; decoder ctor runs before main().
# In binary: @fn_ptr_global lands as null; real address stored XOR-encoded.
#
# Expected stderr:
#   [ArmorComp][GPO] encrypted: N function pointer global(s)
#
# Expected stdout: ALL TESTS PASSED
add_custom_target(test-gpo
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/gpo_test.c
    -o ${CMAKE_BINARY_DIR}/gpo_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/gpo_test.c with GPO pass → ARM64 Android ELF"
)

# ---- Test target: LoopObfuscationPass (LOB) validation ----
# Uses LoopAnalysis to find natural loops and injects preheader/header junk.
# Must run BEFORE BCF/CFF (step 7.5 in pipeline, after MBA).
#
# Expected stderr:
#   [ArmorComp][LOB] obfuscated: secure_sum    (N loop(s))
#   [ArmorComp][LOB] obfuscated: secure_matrix (N loop(s))
#
# Expected stdout: ALL TESTS PASSED
add_custom_target(test-lob
  COMMAND ${BREW_CLANG}
    -target aarch64-linux-android21
    --sysroot=${NDK_SYSROOT}
    -resource-dir=${NDK_RESOURCE_DIR}
    -fpass-plugin=$<TARGET_FILE:ArmorComp>
    -O0
    ${CMAKE_SOURCE_DIR}/test/lob_test.c
    -o ${CMAKE_BINARY_DIR}/lob_test_aarch64
  DEPENDS ArmorComp
  COMMENT "Compiling test/lob_test.c with LOB pass → ARM64 Android ELF"
)
