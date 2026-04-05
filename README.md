# ArmorComp

OLLVM-style obfuscation as an out-of-tree LLVM 17 pass plugin targeting Android NDK (aarch64).
No LLVM source-tree modifications required — just build and load with `-fpass-plugin`.

## Passes

| Pass | Annotation | -passes= name | Description |
|------|-----------|---------------|-------------|
| CFFPass | `annotate("cff")` | `armorcomp-cff` | CFG flattening — dispatch-switch loop |
| BCFPass | `annotate("bcf")` | `armorcomp-bcf` | Bogus control flow — opaque-predicate dead branches |
| OpaquePredicatePass | `annotate("op")` | `armorcomp-op` | Opaque predicates — 6-formula variety (P0–P2 always-true, P3–P5 always-false) dead-end branches |
| SubPass | `annotate("sub")` | `armorcomp-sub` | Instruction substitution (13 ADD/SUB/AND/OR/XOR patterns) |
| MBAPass | `annotate("mba")` | `armorcomp-mba` | Mixed Boolean-Arithmetic rewrite (10 formulas) |
| SplitPass | `annotate("split")` | `armorcomp-split` | Basic block splitting — inflates CFG before BCF/CFF |
| StrEncPass | `annotate("strenc")` | `armorcomp-strenc` | String encryption — XOR ciphertext + ctor decryptor |
| GlobalEncPass | `annotate("genc")` (on using fn) | `armorcomp-genc` | Integer global encryption — XOR-encrypts `i8/i16/i32/i64` initializers, injects ctor decryptor |
| IndirectCallPass | `annotate("icall")` | `armorcomp-icall` | Indirect call — opaque ptr hides call target |
| IndirectBranchPass | `annotate("ibr")` | `armorcomp-ibr` | Indirect branch — `indirectbr` hides branch targets |
| IndirectGlobalVariablePass | `annotate("igv")` | `armorcomp-igv` | Indirect global variable — proxy-ptr hides GV xrefs |
| SPOPass | `annotate("spo")` | `armorcomp-spo` | Stack pointer obfuscation — volatile sub/add SP defeats IDA sp_delta analysis |
| ConstObfPass | `annotate("co")` | `armorcomp-co` | Integer constant obfuscation — XOR-key split hides all numeric literals |
| FuncWrapPass | `annotate("fw")` | `armorcomp-fw` | Function wrapper obfuscation — internal forwarder functions hide true callers |
| RetAddrObfPass | `annotate("rao")` | `armorcomp-rao` | Return address / call-frame obfuscation — volatile sub/add SP around every call |
| OutlinePass | `annotate("outline")` | `armorcomp-outline` | Basic block outlining — each non-entry BB extracted to `__armorcomp_outline_N` (noinline + optnone) |
| FlattenDataFlowPass | `annotate("df")` | `armorcomp-df` | Data flow flattening — merges all allocas into a single `[N x i8]` pool with obfuscated GEP indices, defeating IDA/Ghidra variable recovery |
| DataEncodingPass | `annotate("denc")` | `armorcomp-denc` | Local variable memory encoding — XOR encode/decode around every integer alloca store/load; stack always contains ciphertext |
| FuncSigObfPass | `annotate("fsig")` | `armorcomp-fsig` | Function signature obfuscation — fake arg reads (x1/x2/x3) at entry + fake ret-val writes (x1/x2) at exit; poisons IDA Hex-Rays prototype analysis |
| DwarfPoisonPass | `annotate("dpoison")` | `armorcomp-dpoison` | DWARF CFI table poisoning — `.cfi_remember_state` / fake `def_cfa` (sp+524288, x15, x16) + undef LR/FP / `.cfi_restore_state` at entry, each BB, and each ret; defeats IDA's `.eh_frame`-based sp_delta analysis |
| ConditionObfPass | `annotate("cob")` | `armorcomp-cob` | Comparison obfuscation — adds opaque noise `mul(volatile_zero, K)` to both `ICmpInst` operands; IDA Hex-Rays cannot resolve condition expressions |
| NeonTypeConfusionPass | `annotate("ntc")` | `armorcomp-ntc` | AArch64 NEON/FP type confusion — `fmov` GPR↔SIMD roundtrips at entry/exit; IDA type inference annotates integer parameters as `float`/`double` |
| ReturnValueObfPass | `annotate("rvo")` | `armorcomp-rvo` | Return value obfuscation — `eor x0/w0, x0/w0, volatile_zero` before `ret`; IDA cannot determine return type or value statically; target-independent pure IR |
| LRObfPass | `annotate("lro")` | `armorcomp-lro` | Link register obfuscation — `eor x30, x30, volatile_zero` before `ret`; IDA cannot resolve return address → caller xrefs become JUMPOUT(); AArch64-only |
| GEPObfPass | `annotate("gepo")` | `armorcomp-gepo` | GEP index obfuscation — folds GEP indices into a single XOR-obfuscated byte offset via `getelementptr i8`; defeats IDA struct field recognition, array subscript analysis, and vtable dispatch identification |
| SwitchObfPass | `annotate("sob")` | `armorcomp-sob` | Switch statement obfuscation — replaces `SwitchInst` with dense jump-table + `indirectbr`; volatile XOR between table load and `br` defeats IDA switch pattern matcher |
| JunkCodePass | `annotate("jci")` | `armorcomp-jci` | Junk code injection — dead arithmetic chain (4–7 xor/or/and/shl/lshr/mul/add/sub ops, volatile-zero base, `asm sideeffect` sink) per BB; defeats IDA Hex-Rays decompiler clean output |
| VMPPass | `annotate("vmp")` | `armorcomp-vmp` | Virtual Machine Protection — lifts IR to 64-register custom bytecode VM; original function replaced by fetch-decode-execute dispatcher; algorithm fully hidden from static analysis |

Auto-run order (annotation mode, optimizer-last EP):
`STRENC → GENC → VMP → SOB → SPLIT → SUB → MBA → COB → DENC → JCI → CO → GEPO → DF → OUTLINE → BCF → OP → CFF → RAO → ICALL → IBR → IGV → FW → FSIG → SPO → NTC → RVO → LRO → DPOISON`

Each pass also has an `-all` variant (e.g. `armorcomp-cff-all`) that applies to every function without requiring annotations.

---

## Build

Requirements: LLVM 17 (Homebrew `llvm@17`), Android NDK, CMake ≥ 3.20, Ninja.

```bash
git clone <repo>
cd ArmorComp
cmake -B build -G Ninja
cmake --build build --target ArmorComp
# → build/libArmorComp.dylib
```

---

## Usage

### Method 1 — Source Annotations

Mark individual functions with `__attribute__((annotate("...")))`.
No build-system changes needed.

```c
// Apply CFF + BCF + IGV to this function
__attribute__((annotate("cff")))
__attribute__((annotate("bcf")))
__attribute__((annotate("igv")))
int verify_license(const char *key) {
    /* ... */
}

// String encryption on functions using string literals
__attribute__((annotate("strenc")))
void init_keys(void) {
    const char *api = "SECRET_API_KEY";   // → encrypted in binary
    /* ... */
}
```

Compile:

```bash
clang -fpass-plugin=build/libArmorComp.dylib \
      -target aarch64-linux-android21 \
      --sysroot=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot \
      -O0 source.c -o output
```

---

### Method 2 — YAML Config File (no source changes)

Select functions and passes through a YAML config file. No `__attribute__` needed.
Useful for protecting third-party code or when you cannot modify source files.

#### Activation

Set the `ARMORCOMP_CONFIG` environment variable before running clang:

```bash
export ARMORCOMP_CONFIG=/path/to/armorcomp.yaml

clang -fpass-plugin=build/libArmorComp.dylib \
      -target aarch64-linux-android21 \
      --sysroot=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot \
      -O0 source.c -o output
```

> **Why an env var and not `-mllvm -armorcomp-config=...`?**
> clang loads `-fpass-plugin` DSOs during LLVM backend initialisation, which happens
> *after* `cl::ParseCommandLineOptions()` has already run.  The `cl::opt` registered
> by the plugin therefore cannot receive values from `-mllvm` flags.
> The environment variable is read at the first pass invocation, which is well after
> DSO loading — no ordering issue.

Auto-discovery: if `ARMORCOMP_CONFIG` is not set, ArmorComp looks for
`armorcomp.yaml` in the current working directory.

#### Config file format

```yaml
# armorcomp.yaml

functions:
  # Rule 1 — exact function name
  - name: "verify_license"
    passes: [cff, bcf, sub, mba, icall, ibr, igv, rao, fw, spo]

  # Rule 2 — POSIX ERE pattern (anchored recommended)
  - pattern: "^Java_"
    passes: [cff, bcf, icall, ibr]

  # Rule 3 — protect anything whose name contains "secret"
  - pattern: "secret"
    passes: [strenc, split, sub, cff]
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Exact function name. Mutually exclusive with `pattern`. |
| `pattern` | string | POSIX ERE matched against the function name. Mutually exclusive with `name`. |
| `passes` | list | Pass names to apply. Valid values: `cff bcf op sub mba cob split strenc genc denc jci icall ibr igv spo co gepo fw rao outline df fsig dpoison ntc rvo lro sob vmp` |

**Evaluation rules:**

- Rules are evaluated **top-to-bottom**; the **first matching rule wins**.
- Config is **additive** with `__attribute__((annotate(...)))`: a function is
  transformed if *either* the annotation *or* a config rule selects the pass.
- If no rule matches and there is no annotation, the function is untouched.

#### Verifying config selection

The plugin prints a summary to stderr when a config is loaded:

```
[ArmorComp][Config] loaded 3 rule(s) from "/path/to/armorcomp.yaml"
[ArmorComp][BCF] obfuscated: verify_license
[ArmorComp][CFF] flattened:  verify_license
[ArmorComp][IGV] indirected: verify_license (4 accesses, 2 globals)
[ArmorComp][RAO] obfuscated: verify_license (N calls)
[ArmorComp][FW]  wrapped:    verify_license (N calls, M wrappers)
[ArmorComp][SPO] obfuscated: verify_license (1 ret(s))
```

Functions *not* matched by any rule produce no obfuscation log lines.

---

## Test Targets

```bash
cmake --build build --target test-cff      # CFG flattening
cmake --build build --target test-bcf      # Bogus control flow
cmake --build build --target test-op       # Opaque predicate insertion
cmake --build build --target test-sub      # Instruction substitution
cmake --build build --target test-mba      # Mixed Boolean-Arithmetic
cmake --build build --target test-strenc   # String encryption
cmake --build build --target test-icall    # Indirect call
cmake --build build --target test-ibr      # Indirect branch
cmake --build build --target test-igv      # Indirect global variable
cmake --build build --target test-spo      # Stack pointer obfuscation (IDA sp-analysis failed)
cmake --build build --target test-co       # Integer constant obfuscation (no bare immediates)
cmake --build build --target test-fw       # Function wrapper obfuscation (call graph indirection)
cmake --build build --target test-rao      # Return addr / call-frame obfuscation (sp_delta UNKNOWN at every call)
cmake --build build --target test-outline  # Basic block outlining (__armorcomp_outline_N helpers)
cmake --build build --target test-df       # Data flow flattening (stack pool merge)
cmake --build build --target test-genc     # Integer global variable encryption (ctor decryptor)
cmake --build build --target test-denc     # Integer local variable memory encoding (store/load XOR wrappers)
cmake --build build --target test-fsig     # Function signature obfuscation (IDA prototype analysis failure)
cmake --build build --target test-dpoison  # DWARF CFI table poisoning (sp_delta UNKNOWN via .eh_frame)
cmake --build build --target test-cob      # Comparison obfuscation (ICmpInst noise, IDA condition unresolvable)
cmake --build build --target test-ntc      # NEON/FP type confusion (fmov GPR↔SIMD, IDA float type annotation)
cmake --build build --target test-rvo      # Return value obfuscation (eor x0/w0, IDA return type unknown)
cmake --build build --target test-lro      # Link register obfuscation (eor x30, IDA caller xrefs broken, AArch64)
cmake --build build --target test-gepo     # GEP index obfuscation (byte-offset XOR, IDA struct/array layout unrecoverable)
cmake --build build --target test-sob      # Switch obfuscation (dense jump-table + indirectbr, IDA JUMPOUT)
cmake --build build --target test-jci      # Junk code injection (dead arithmetic chains per BB, extra Hex-Rays variables)
cmake --build build --target test-vmp      # Virtual Machine Protection (64-reg bytecode VM, dispatcher hides algorithm)
cmake --build build --target test-config   # YAML config file (no annotations)
```

Each target compiles the corresponding `test/*.c` file to an ARM64 Android ELF.
Run on device/emulator; expected output for every test ends with `ALL TESTS PASSED`.

The `test-config` target uses `ARMORCOMP_CONFIG=test/config_test.yaml` and
`test/config_test.c` which has **zero** `__attribute__((annotate(...)))` — all
obfuscation is driven purely by the YAML config.

---

## Combining Both Methods

Annotations and config rules work together. Example: the config protects all
`Java_*` exports project-wide; individual functions add extra layers via annotations.

```yaml
# armorcomp.yaml — project-wide baseline
functions:
  - pattern: "^Java_"
    passes: [cff, bcf, icall]
```

```c
// Extra layers on top of config baseline
__attribute__((annotate("igv")))   // IGV not in config → added by annotation
__attribute__((annotate("sub")))
JNIEXPORT jint JNICALL Java_com_example_App_verify(JNIEnv *env, jobject obj) {
    /* cff+bcf+icall from config, igv+sub from annotation */
}
```
