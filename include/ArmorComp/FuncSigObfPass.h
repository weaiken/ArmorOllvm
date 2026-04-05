#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — FuncSigObfPass (Function Signature Obfuscation)
//
// Confuses IDA Hex-Rays function-prototype analysis via two techniques:
//
//  1. Entry: fake extra-argument reads  (x1, x2, x3)
//     Inline asm reads x1–x3 at function entry regardless of actual arity;
//     the values are OR-combined with a volatile-loaded zero and stored to a
//     volatile global sink.  IDA's register-liveness analysis sees x1–x3 live
//     at function entry and concludes the function accepts 4+ arguments.
//
//  2. Exit: fake return-value writes  (x1, x2)
//     Before each ret, inline asm writes 0 (from a volatile global) into x1
//     and x2.  IDA's return-value analysis sees x1 and x2 written before
//     every return and may infer a multi-register or struct return type.
//     Hex-Rays generates a wrong function prototype for annotated functions.
//
// AArch64 only; x1–x3 are caller-saved argument registers.
// Runtime correctness is preserved: all injected operations are no-ops
// (volatile load of 0, OR/store into a write-only sink, write-before-ret
//  into caller-saved registers that callers never read after the call).
//
// Annotation : __attribute__((annotate("fsig")))
// -passes= name : armorcomp-fsig  /  armorcomp-fsig-all
//===----------------------------------------------------------------------===//

#include "llvm/IR/PassManager.h"

namespace llvm {

struct FuncSigObfPass : PassInfoMixin<FuncSigObfPass> {
  bool annotateOnly;

  explicit FuncSigObfPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);

  // Must run even on optnone functions
  static bool isRequired() { return true; }
};

} // namespace llvm
