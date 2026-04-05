//===----------------------------------------------------------------------===//
// ArmorComp — RetAddrObfPass (Return Address / Call-Frame Obfuscation)
//
// For each direct or indirect call in an annotated function, inserts a pair
// of inline-asm SP adjustments that are no-ops at runtime but defeat IDA's
// sp_delta tracker at every call site:
//
//   Before:
//     %r = call i32 @target(arg0, arg1)
//
//   After:
//     %rao.pre = load volatile i64, ptr @__armorcomp_rao_zero   ; = 0
//     call void asm "sub sp, sp, $0", "r"(%rao.pre)             ; nop
//     %r       = call i32 @target(arg0, arg1)
//     %rao.post = load volatile i64, ptr @__armorcomp_rao_zero  ; = 0
//     call void asm "add sp, sp, $0", "r"(%rao.post)            ; nop
//
// Effect on IDA sp_delta analysis:
//   - Before each call: "sub sp, sp, xN" where xN is volatile-loaded →
//     sp_delta = UNKNOWN at the call site
//   - After each call:  "add sp, sp, xN" similarly unknown
//   - Cascades across all calls in the function → "sp-analysis failed"
//   - Combined with SPOPass (entry/exit sub/add), the entire function is
//     impervious to Hex-Rays F5 decompilation
//
// Skips:
//   - Intrinsics (llvm.*)
//   - Calls that are already inline asm
//   - __armorcomp_* callees (own injected wrappers)
//   - AArch64 only (triple guard)
//
// Pipeline position: before IndirectCallPass
//   — ICALL converts direct calls to indirect calls (calledFunction() = null);
//     RAO must run first to see and instrument them.
//
// Usage:
//   -passes=armorcomp-rao       (annotation mode)
//   -passes=armorcomp-rao-all   (all functions)
//
// Source annotation:
//   __attribute__((annotate("rao"))) int my_fn(...) { ... }
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

struct RetAddrObfPass : llvm::PassInfoMixin<RetAddrObfPass> {
  bool annotateOnly;

  explicit RetAddrObfPass(bool annotateOnly = true) : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
