//===-- ArmorComp/DwarfPoisonPass.h ----------------------------*- C++ -*-===//
// ArmorComp — DwarfPoisonPass (DWARF CFI Table Poisoning)
//
// Annotation : __attribute__((annotate("dpoison")))
// -passes=   : armorcomp-dpoison      (annotation mode)
//            : armorcomp-dpoison-all   (all AArch64 functions)
//
// Strategy
// ────────
// At each injection point, emit a self-contained inline-asm block:
//
//   .cfi_remember_state           ; save current (correct) CFI state
//   .cfi_def_cfa <fake_reg,ofs>   ; replace CFA with huge / unexpected value
//   .cfi_undefined x30            ; claim LR is unrecoverable (optional per pattern)
//   .cfi_undefined x29            ; claim FP is unrecoverable (optional per pattern)
//   nop                           ; single real instruction → DWARF row written here
//   .cfi_restore_state            ; restore saved (correct) CFI state
//
// DWARF table produced:
//   At PC(nop):  CFA = <fake>,  x30 = undefined → IDA sp-delta: UNKNOWN
//   At PC(next): CFA = <real>,  x30 = [CFA-8]   → runtime unwinder sees correct state
//
// IDA Pro effect:
//   - sp_delta marked UNKNOWN throughout annotated functions
//   - Hex-Rays decompiler: "stack analysis failed" / wrong local-variable addresses
//   - Stack view shows inconsistent frame sizes across the function body
//   - Call-stack window may display incorrect frames for annotated functions
//
// Runtime safety:
//   .cfi_restore_state reinstates the correct CFA record for all PCs except the
//   single injected nop.  The GNU/LLVM unwinder (libunwind / libgcc_s) can still
//   unwind through the function.  The only runtime cost is one extra nop per
//   injection point.
//
// Orthogonality with other passes:
//   - SPOPass targets IDA's runtime-trace-based SP analysis (sub/add volatile)
//   - DwarfPoisonPass targets IDA's DWARF-table-based analysis (.eh_frame rows)
//   Running both provides two independent, mutually-reinforcing sp_delta attacks.
//===----------------------------------------------------------------------===//

#pragma once
#include "llvm/IR/PassManager.h"

namespace llvm {

/// DwarfPoisonPass — inject CFI-poison inline-asm blocks at function boundaries.
///
/// Injection points (per function):
///   1. Entry basic block: 2 blocks after the last alloca instruction
///   2. Each non-entry basic block: 1 block before the terminator
///   3. Before each ReturnInst: 1 additional block (extra noise at exit)
///
/// Pattern selection (6 patterns, keyed by FNV-hash(fn_name) XOR seqNo):
///   A) CFA=sp+524288,  LR+FP undefined — 0.5 MB fake stack, both critical regs lost
///   B) CFA=sp+131072,  LR undefined    — 128 KB fake stack, LR lost
///   C) CFA=x15+16,     FP undefined    — scratch reg as CFA base, FP lost
///   D) CFA=sp+65536,   LR+FP undefined — 64 KB fake stack, both lost
///   E) CFA=x16+0,      LR undefined    — linker scratch reg as CFA, LR lost
///   F) CFA=sp+32767,   FP undefined    — near-max i16 offset, FP lost
struct DwarfPoisonPass : PassInfoMixin<DwarfPoisonPass> {
  bool annotateOnly;

  explicit DwarfPoisonPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);

  /// Must run even on optnone functions — obfuscation must survive -O0.
  static bool isRequired() { return true; }
};

} // namespace llvm
