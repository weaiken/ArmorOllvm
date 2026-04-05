//===----------------------------------------------------------------------===//
// ArmorComp — FuncWrapPass (Function Wrapper Obfuscation)
//
// For each direct call in an annotated function, creates an opaque wrapper
// function and replaces the call site with a call to the wrapper.
//
// Technique: call graph indirection via internal wrapper functions
// ────────────────────────────────────────────────────────────────
// For every direct CallInst in an annotated function calling a known Function:
//
//   Before:
//     %r = call i32 @target(arg0, arg1)
//
//   After (in the annotated function):
//     %r = call i32 @__armorcomp_fw_N(arg0, arg1)
//
//   Wrapper function __armorcomp_fw_N (emitted once per unique callee):
//     define internal i32 @__armorcomp_fw_N(i32 %a0, i32 %a1) noinline {
//       %fw.z = load volatile i64, ptr @__armorcomp_fw_zero  ; noise
//       %r    = call i32 @target(%a0, %a1)
//       ret i32 %r
//     }
//
// Effect on IDA cross-reference analysis:
//   - "Who calls target?" → shows __armorcomp_fw_N, not the annotated function
//   - The annotated function's call graph shows __armorcomp_fw_N nodes instead
//     of their real targets, requiring the analyst to trace one more level
//   - The volatile load in the wrapper adds noise to the wrapper's decompiled
//     output so it is not trivially recognised as a passthrough
//
// Skips:
//   - Indirect calls (callee not a Function*)
//   - Intrinsics (llvm.*)
//   - Vararg callees (cannot create a type-safe wrapper)
//   - __armorcomp_* callees (ArmorComp's own injected functions)
//   - Declarations with no available body (external symbols are fine to wrap)
//
// Wrappers are noinline + optnone to prevent the optimizer from collapsing
// them back into the call site at -O1+.
//
// Usage:
//   -passes=armorcomp-fw       (annotation mode)
//   -passes=armorcomp-fw-all   (all functions)
//
// Source annotation:
//   __attribute__((annotate("fw"))) int my_fn(...) { ... }
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

struct FuncWrapPass : llvm::PassInfoMixin<FuncWrapPass> {
  bool annotateOnly;

  explicit FuncWrapPass(bool annotateOnly = true) : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
