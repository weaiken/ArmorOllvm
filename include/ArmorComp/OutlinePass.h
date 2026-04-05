//===----------------------------------------------------------------------===//
// ArmorComp — OutlinePass public interface
//
// Basic block outlining pass declaration.
// Implementation: lib/OutlinePass.cpp
//
// Algorithm: for each non-entry basic block in a targeted function, extract
// the block into an independent internal function using LLVM's CodeExtractor.
// The original basic block is replaced by a single call to the outlined
// function, turning the annotated function into a chain of calls to small
// internal helper functions.
//
// LLVM's CodeExtractor automatically handles:
//   - Live-in analysis: values defined outside the BB and used inside become
//     function arguments.
//   - Live-out analysis: values defined inside the BB and used outside become
//     output arguments (via pointer or struct return).
//
// The outlined functions receive the suffix ".armorcomp_outline" and are
// renamed to "__armorcomp_outline_N" with noinline + optnone attributes to
// prevent the optimizer from re-merging them.
//
// Usage in pipeline:
//   -passes=armorcomp-outline       (annotation mode: only outline-annotated fns)
//   -passes=armorcomp-outline-all   (all mode: every eligible function)
//
// Source annotation:
//   __attribute__((annotate("outline"))) int my_fn(...) { ... }
//
// Recommended pipeline position: after CO, before BCF.
//   SUB → MBA → CO → OUTLINE → BCF → OP → CFF
// Outlined blocks contain the constant-obfuscated instructions; BCF/CFF can
// further obfuscate the dispatch-call structure left in the original function.
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

struct OutlinePass : llvm::PassInfoMixin<OutlinePass> {
  bool annotateOnly;

  explicit OutlinePass(bool annotateOnly = true) : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
