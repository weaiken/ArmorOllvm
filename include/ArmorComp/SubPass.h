//===----------------------------------------------------------------------===//
// ArmorComp — SubPass (Instruction Substitution) public interface
//
// Replaces arithmetic and bitwise instructions with semantically equivalent
// but structurally different sequences that confuse decompilers and pattern
// matchers.
//
// Substitution table (all verified in Z/2^n):
//
//   ADD   (a+b):   3 variants
//   SUB   (a-b):   3 variants
//   AND   (a&b):   2 variants  (one parameterized with random constant)
//   OR    (a|b):   2 variants
//   XOR   (a^b):   3 variants
//
// Usage in pipeline:
//   -passes=armorcomp-sub          (annotation mode: annotate("sub") fns)
//   -passes=armorcomp-sub-all      (all mode: every function)
//
// Source annotation:
//   __attribute__((annotate("sub"))) int my_fn(...) { ... }
//
// For maximum protection stack passes:
//   -passes=armorcomp-sub,armorcomp-bcf,armorcomp-cff
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

struct SubPass : llvm::PassInfoMixin<SubPass> {
  bool annotateOnly;
  int  numRounds;   ///< How many substitution rounds (default 2, max 5)

  explicit SubPass(bool annotateOnly = true, int numRounds = 2)
      : annotateOnly(annotateOnly), numRounds(numRounds) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
