//===----------------------------------------------------------------------===//
// ArmorComp — IndirectGlobalVariablePass (Indirect Global Variable Access)
//
// Replaces direct global variable references in annotated functions with
// indirect accesses through volatile proxy pointer globals, hiding data-flow
// from static cross-reference analysis.
//
// Technique: volatile proxy pointer table
// ────────────────────────────────────────
// For each global variable @gv directly used in an annotated function:
//
//   @__armorcomp_igv_gv = weak volatile ptr @gv   ; proxy pointer global
//
//   Before:  %x = load i32, ptr @gv
//   After:   %igv.ptr = load volatile ptr, ptr @__armorcomp_igv_gv
//            %x = load i32, ptr %igv.ptr
//
//   Before:  store i32 %v, ptr @gv
//   After:   %igv.ptr = load volatile ptr, ptr @__armorcomp_igv_gv
//            store i32 %v, ptr %igv.ptr
//
//   Before:  %p = getelementptr %T, ptr @gv, i32 0, i32 1
//   After:   %igv.ptr = load volatile ptr, ptr @__armorcomp_igv_gv
//            %p = getelementptr %T, ptr %igv.ptr, i32 0, i32 1
//
// Why this defeats static analysis:
//   - IDA/Ghidra build cross-reference (xref) tables by following GV operands
//     statically. After transformation, the actual GV address appears only as
//     a constant in the proxy global's initializer — not as a direct operand
//     in any instruction.
//   - The volatile qualifier on the proxy load prevents the optimizer from
//     caching the pointer value and re-using it across calls (each access
//     re-loads from the proxy global, so the decompiler sees independent
//     pointer loads rather than a resolved GV address).
//
// Skips (per instruction operand):
//   - PHI node operands — insertion point ambiguous (predecessor block needed)
//   - ConstantExpr operands — can't insert a load inside a constant expression
//   - Functions (GlobalFunction) — use IndirectCallPass for those
//   - Globals with "llvm." prefix (LLVM intrinsic infrastructure)
//   - Globals with "__armorcomp_" prefix (ArmorComp's own globals)
//   - Non-pointer-typed operands (safety guard)
//
// Usage in pipeline:
//   -passes=armorcomp-igv        (annotation mode)
//   -passes=armorcomp-igv-all    (all functions)
//
// Source annotation:
//   __attribute__((annotate("igv"))) int my_fn(...) { ... }
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

struct IndirectGlobalVariablePass
    : llvm::PassInfoMixin<IndirectGlobalVariablePass> {
  bool annotateOnly;

  explicit IndirectGlobalVariablePass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
