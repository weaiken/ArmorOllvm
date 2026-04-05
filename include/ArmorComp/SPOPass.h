//===----------------------------------------------------------------------===//
// ArmorComp — SPOPass (Stack Pointer Obfuscation)
//
// Defeats IDA Hex-Rays F5 by making sp_delta UNKNOWN at compile time.
//
// Technique: volatile zero-load → inline asm sub/add SP
// ──────────────────────────────────────────────────────
// A process-wide global @__armorcomp_spo_zero (= 0, weak linkage) is loaded
// with a volatile load into a register xN.  The function entry block gets:
//
//   %spo.v = load volatile i64, ptr @__armorcomp_spo_zero
//   call void asm "sub sp, sp, $0", "r"(%spo.v)   ; runtime NOP
//
// Every return block gets the paired restore:
//
//   %spo.r = load volatile i64, ptr @__armorcomp_spo_zero
//   call void asm "add sp, sp, $0", "r"(%spo.r)   ; runtime NOP
//
// Why IDA fails:
//   IDA tracks sp_delta = SP − SP_entry at each instruction.  When it
//   encounters "sub sp, sp, xN" with xN unknown at analysis time, it
//   marks sp_delta = UNKNOWN and Hex-Rays refuses to decompile the function.
//
// Why the program still runs correctly:
//   @__armorcomp_spo_zero is always 0 at runtime, so sub/add are no-ops.
//   At -O0, AArch64 uses x29 (fp) for all local-variable addressing, so
//   the transient SP change (zero) cannot corrupt any variable accesses.
//
// AArch64 only — silently skipped on other targets.
//
// Usage:
//   -passes=armorcomp-spo        (annotation mode)
//   -passes=armorcomp-spo-all    (all functions)
//
// Source annotation:
//   __attribute__((annotate("spo"))) int my_fn(...) { ... }
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

struct SPOPass : llvm::PassInfoMixin<SPOPass> {
  bool annotateOnly;

  explicit SPOPass(bool annotateOnly = true) : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
