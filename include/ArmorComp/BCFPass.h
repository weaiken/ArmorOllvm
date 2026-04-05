//===----------------------------------------------------------------------===//
// ArmorComp — BCFPass public interface
//
// Bogus Control Flow pass declaration.
// Implementation: lib/BCFPass.cpp
//
// Algorithm: for each targeted basic block, insert an always-true opaque
// predicate that dispatches to the real block or a structurally-identical
// bogus clone. The bogus clone loops back, creating an unreachable infinite
// loop that confuses static analysis and decompilation.
//
// Usage in pipeline:
//   -passes=armorcomp-bcf          (annotation mode: only bcf-annotated fns)
//   -passes=armorcomp-bcf-all      (all mode: every function with >1 BB)
//
// Source annotation:
//   __attribute__((annotate("bcf"))) int my_fn(...) { ... }
//
// For maximum protection, apply BCF before CFF:
//   -passes=armorcomp-bcf,armorcomp-cff
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

struct BCFPass : llvm::PassInfoMixin<BCFPass> {
  bool annotateOnly;

  explicit BCFPass(bool annotateOnly = true) : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
