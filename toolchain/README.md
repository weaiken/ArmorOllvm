# ArmorComp Toolchain — Integration Guide  (v0.27.0)

**33 obfuscation passes** — LLVM 17 out-of-tree plugin for Android NDK & iOS.
Supports arm64-v8a (full, 33 passes) and armeabi-v7a (IR-level passes; 6 AArch64-only auto-skipped).

This directory is the self-contained delivery package.
Copy the entire `toolchain/` folder into your project and follow the instructions below.

## Directory Layout

```
toolchain/
├── bin/
│   ├── armorcomp-clang          # macOS C compiler wrapper
│   ├── armorcomp-clang++        # macOS C++ compiler wrapper
│   ├── armorcomp-clang-linux    # Linux C compiler wrapper
│   └── armorcomp-clang++-linux  # Linux C++ compiler wrapper
├── lib/
│   ├── darwin-arm64/libArmorComp.dylib   # macOS Apple Silicon plugin
│   ├── darwin-x86_64/libArmorComp.dylib  # macOS Intel plugin
│   └── linux-x86_64/libArmorComp.so      # Linux plugin
├── android.cmake       # Android NDK CMake toolchain file
├── ios.cmake           # iOS CMake toolchain file
├── ArmorComp.xcconfig  # Xcode build settings
├── armorcomp.mk        # ndk-build Android.mk integration
└── README.md           # this file
```

## Requirements

| Host OS | Required tool |
|---------|--------------|
| macOS   | `brew install llvm@17` |
| Linux   | `apt install clang-17` or equivalent |

The plugin **must** be loaded via brew/system clang@17 (dynamic LLVM).
NDK's bundled clang is statically linked and cannot `dlopen` a pass plugin.

---

## Android — CMake / Gradle (recommended)

### 1. build.gradle (AGP 4+)

```groovy
android {
    defaultConfig {
        externalNativeBuild {
            cmake {
                arguments "-DCMAKE_TOOLCHAIN_FILE=${rootDir}/armorcomp/toolchain/android.cmake"
                abiFilters "arm64-v8a"     // ArmorComp supports AArch64 only
            }
        }
    }
}
```

### 2. Plain CMake

```bash
cmake -DCMAKE_TOOLCHAIN_FILE=/path/to/toolchain/android.cmake \
      -DANDROID_ABI=arm64-v8a          \
      -DANDROID_PLATFORM=android-21    \
      -DANDROID_NDK=/path/to/ndk       \
      ..
```

`ANDROID_NDK` is auto-detected from `ANDROID_NDK_ROOT`, `ANDROID_HOME`, or common SDK paths
if not set explicitly.

---

## Android — ndk-build

In your `Android.mk`:

```makefile
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE    := mynativelib
LOCAL_SRC_FILES := src/native-lib.cpp

# Include ArmorComp toolchain
include /path/to/armorcomp/toolchain/armorcomp.mk

include $(BUILD_SHARED_LIBRARY)
```

In your `Application.mk`:

```makefile
APP_ABI      := arm64-v8a
APP_PLATFORM := android-21
```

---

## iOS — CMake

```bash
cmake -DCMAKE_TOOLCHAIN_FILE=/path/to/toolchain/ios.cmake \
      -DIOS_PLATFORM=OS64                      \
      -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0       \
      ..
```

Produced object files are standard arm64 Mach-O — link with Xcode's `ld` as normal.

---

## iOS — Xcode (.xcconfig)

1. **Add** `ArmorComp.xcconfig` to your Xcode project (`File → Add Files to Project`).
2. In the target's **Info** tab → **Configurations** → add this `.xcconfig`, or
   in **Build Settings** → **Based on**: choose `ArmorComp`.
3. Set `ARMORCOMP_TOOLCHAIN_DIR` to the absolute path of this `toolchain/` folder:

   ```
   ARMORCOMP_TOOLCHAIN_DIR = /absolute/path/to/toolchain
   ```

   Or pass it via xcodebuild:

   ```bash
   xcodebuild -DARMORCOMP_TOOLCHAIN_DIR=/absolute/path/to/toolchain
   ```

---

## Annotating Functions

Add `__attribute__((annotate("PASS")))` to any C/C++ function to enable a specific pass:

```c
// Enable CFG Flattening
__attribute__((annotate("cff")))
int secure_decrypt(const uint8_t *buf, int len) { ... }

// Enable multiple passes (comma-separate in separate attributes or stack them)
__attribute__((annotate("cff")))
__attribute__((annotate("bcf")))
__attribute__((annotate("sub")))
int ultra_protect(int x) { ... }
```

### Available Pass Annotations

| Annotation | Pass |
|------------|------|
| `cff`    | CFG Flattening |
| `bcf`    | Bogus Control Flow |
| `op`     | Opaque Predicates |
| `sub`    | Instruction Substitution |
| `split`  | Basic Block Splitting |
| `strenc` | String Encryption |
| `genc`   | Global Integer Encryption |
| `mba`    | Mixed Boolean-Arithmetic |
| `denc`   | Local Variable Encoding |
| `icall`  | Indirect Call Obfuscation |
| `ibr`    | Indirect Branch Obfuscation |
| `igv`    | Indirect Global Variable Access |
| `spo`    | Stack Pointer Obfuscation |
| `co`     | Constant Obfuscation |
| `fw`     | Function Wrapper Obfuscation |
| `rao`    | Return Address / Call-Frame Obfuscation |
| `outline`| Basic Block Outlining |
| `df`     | Data Flow Flattening |
| `fsig`   | Function Signature Obfuscation |
| `dpoison`| DWARF CFI Table Poisoning |
| `cob`    | Comparison Obfuscation |
| `ntc`    | NEON/FP Type Confusion (AArch64) |
| `rvo`    | Return Value XOR Obfuscation |
| `lro`    | Link Register XOR Obfuscation (AArch64) |
| `gepo`   | GEP Index / Struct Field Obfuscation |
| `sob`    | Switch Statement Obfuscation |
| `jci`    | Junk Code Injection |
| `asp`    | Arithmetic State Encoding |
| `pxor`   | Pointer XOR Obfuscation |
| `fapi`   | Fake API Call Injection |
| `gpo`    | Global Pointer Obfuscation |
| `lob`    | Loop Obfuscation |
| `vmp`    | Virtual Machine Protection (128-reg VM, XTEA-CTR encryption, opcode scramble, integrity check, dead handlers, handler polymorphism, super-instructions, vararg support) |

---

## YAML Config (apply passes without source changes)

Set `ARMORCOMP_CONFIG=/path/to/armorcomp.yaml` before building:

```bash
export ARMORCOMP_CONFIG="$(pwd)/armorcomp.yaml"
```

`armorcomp.yaml` example:

```yaml
functions:
  - name: "Java_com_example_Crypto_decrypt"
    passes: [cff, bcf, icall, ibr, vmp]

  - pattern: "^Java_"
    passes: [cff, sub, co]

  - pattern: "^secure_"
    passes: [cff, bcf, op, mba, spo]
```

Config is **additive** with `annotate()` — both can be used simultaneously.

---

## VMP — Virtual Machine Protection

VMPPass is the strongest protection tier. It converts an entire function body into a custom bytecode VM interpreter:

```
Source Code → LLVM IR → VMPLifter (bytecode) → Opcode Scramble → XTEA-CTR Encrypt → VMPCodeGen (dispatcher)
```

**Protection layers:**
- **XTEA-CTR encryption** — 32-round block cipher (per-function key), replaces simple XOR
- **Per-function opcode scramble** — Fisher-Yates permutation, each function has unique encoding
- **FNV-1a integrity check** — runtime tamper detection, triggers `trap` on mismatch
- **16 dead handler BBs** — fake handlers (4 templates) indistinguishable from real ones in IDA
- **Handler polymorphism** — 6 high-frequency handlers use randomized MBA-equivalent expressions
- **Super-instructions** — ADD_I32/SUB_I32 fused opcodes reduce dispatch overhead
- **VarArg support** — wrapper shims for printf/snprintf/etc.
- **Built-in disassembler** — `ARMORCOMP_VMP_DISASM=1` dumps human-readable bytecode

**VM ISA**: ~50 opcodes, 128 virtual registers (64-bit), integer + float + pointer + atomic operations, direct & indirect calls with float/double ABI.

---

## Recommended Combinations (Anti-F5)

| Goal | Passes | Effect |
|------|--------|--------|
| Break IDA F5 | `spo + rao + dpoison` | sp_delta = UNKNOWN |
| F5 output unreadable | `cff + bcf + mba` | State machine maze |
| Strongest | `vmp + spo + dpoison` | Algorithm in VM + sp broken |
| Full stack | `spo + rao + cff + bcf + mba + dpoison` | All layers |

> VMP + CFF should NOT be combined (musttail conflict).

---

## Building the Plugin from Source

If you need to rebuild the plugin (e.g., after updating the source):

```bash
cd /path/to/ArmorComp
mkdir -p build && cd build
cmake -G Ninja ..
cmake --build . --target package-toolchain
```

The `package-toolchain` target builds `libArmorComp.dylib` / `.so` and copies it into
the appropriate `toolchain/lib/` subdirectory automatically.
