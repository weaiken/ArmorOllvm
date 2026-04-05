//===----------------------------------------------------------------------===//
// ArmorComp — MBAPass (Mixed Boolean-Arithmetic Obfuscation) public interface
//
// Replaces arithmetic and bitwise instructions with Mixed Boolean-Arithmetic
// (MBA) expressions — equivalences that cross the boolean/arithmetic boundary
// simultaneously.  Unlike SubPass which uses either pure bitwise algebra or
// pure arithmetic identities, MBA expressions fuse both domains in a single
// rewrite, making symbolic simplification significantly harder.
//
// How MBA differs from instruction substitution (SubPass):
//   SubPass:  a+b  →  (a|b)+(a&b)         (stays in arithmetic+bitwise)
//   MBAPass:  a+b  →  2*(a|b)-(a^b)       (arithmetic *2 mixed with bitwise |^)
//
// Why MBA resists decompiler recovery:
//   Tools like Ghidra/IDA use pattern-matching and algebraic simplification
//   rules specialized to either arithmetic OR boolean domains.  Expressions
//   that interleave multiplication/subtraction with &/|/^ simultaneously
//   violate these domain assumptions, causing the tool to give up and leave
//   the expression in its raw low-level form.
//
// Substitution table (all verified in Z/2^n wrapping integer arithmetic):
//
//   ADD  (a+b):   2 MBA variants
//   SUB  (a-b):   2 MBA variants
//   AND  (a&b):   2 MBA variants  (one uses arithmetic right-shift)
//   OR   (a|b):   2 MBA variants
//   XOR  (a^b):   2 MBA variants
//
// Usage in pipeline:
//   -passes=armorcomp-mba          (annotation mode)
//   -passes=armorcomp-mba-all      (all functions)
//
//   For maximum protection, stack with SubPass:
//   annotate("mba"), annotate("sub"), annotate("bcf"), annotate("cff")
//
// Source annotation:
//   __attribute__((annotate("mba"))) int my_fn(...) { ... }
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

struct MBAPass : llvm::PassInfoMixin<MBAPass> {
  bool annotateOnly;
  int  numRounds;  ///< Substitution rounds (default 1; each round expands ~3x)

  explicit MBAPass(bool annotateOnly = true, int numRounds = 1)
      : annotateOnly(annotateOnly), numRounds(numRounds) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
