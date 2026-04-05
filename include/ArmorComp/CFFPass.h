//===----------------------------------------------------------------------===//
// ArmorComp — CFFPass public interface
//
// Control Flow Flattening pass declaration.
// Implementation: lib/CFFPass.cpp
//
// Usage in pipeline:
//   -passes=armorcomp-cff          (annotation mode: only cff-annotated fns)
//   -passes=armorcomp-cff-all      (all mode: every function with >1 BB)
//
// Source annotation:
//   __attribute__((annotate("cff"))) int my_fn(...) { ... }
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

/// Control Flow Flattening pass.
///
/// Converts each function's control flow into a single-level dispatch loop:
///   entry → dispatch ─┬─ case A ─┐
///                     ├─ case B ─┤ → dispatch
///                     └─ case C ─┘
///
/// This makes static analysis and decompilation significantly harder.
struct CFFPass : llvm::PassInfoMixin<CFFPass> {
  /// If true, only flatten functions annotated with __attribute__((annotate("cff"))).
  /// If false, flatten every function that has more than one basic block.
  bool annotateOnly;

  explicit CFFPass(bool annotateOnly = true) : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  /// Must run even on functions marked optnone (e.g. debug builds).
  static bool isRequired() { return true; }
};
