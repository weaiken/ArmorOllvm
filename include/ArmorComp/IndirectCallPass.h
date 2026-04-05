//===----------------------------------------------------------------------===//
// ArmorComp — IndirectCallPass (Indirect Call Obfuscation) public interface
//
// Replaces direct function calls with indirect calls through a runtime-
// computed pointer, breaking static call-graph analysis.
//
// Technique: opaque-zero-offset pointer computation
// ─────────────────────────────────────────────────
// For each direct call  call @foo(args...)  in an annotated function:
//
//   %off  = load volatile i64, ptr @__armorcomp_icall_off  ; always 0, volatile
//   %base = ptrtoint ptr @foo to i64
//   %addr = add  i64 %base, %off                           ; == @foo at runtime
//   %fp   = inttoptr i64 %addr to ptr
//   call ptr %fp(args...)                                  ; indirect call
//
// Why this defeats static analysis:
//   - Ghidra / IDA / BinaryNinja's call graph relies on the callee being
//     statically known (direct call or constant in plt/got).
//   - After this transformation the callee is a runtime-computed pointer;
//     the tool cannot resolve it without executing the program.
//   - The volatile load of the zero offset prevents the optimizer from
//     constant-folding %addr back to @foo (volatile = "may change at any time"
//     as far as the compiler knows).
//
// Limitations:
//   - Intrinsics (llvm.*) are skipped — they MUST remain direct calls.
//   - Calls to declarations only (external functions) are processed;
//     calls to locally-defined functions can also be processed.
//
// Usage in pipeline:
//   -passes=armorcomp-icall        (annotation mode)
//   -passes=armorcomp-icall-all    (all functions)
//
// Source annotation:
//   __attribute__((annotate("icall"))) int my_fn(...) { ... }
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

struct IndirectCallPass : llvm::PassInfoMixin<IndirectCallPass> {
  bool annotateOnly;

  explicit IndirectCallPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
