//===----------------------------------------------------------------------===//
// ArmorComp — SplitPass (Basic Block Splitting) public interface
//
// Splits each basic block at a random point into two sub-blocks connected
// by an unconditional branch.  This artificially inflates the BB count before
// BCF/CFF apply, making the resulting switch dispatch significantly larger and
// the CFG harder to reconstruct.
//
// Example (numSplits=2, i.e. split into 2 parts):
//
//   Before:  [i1, i2, i3, i4, ret]
//   After:   [i1, i2, br .splt] → [i3, i4, ret]
//
// Synergy with other passes:
//   SPLT → BCF:  BCF's opaque predicate is inserted in front of each BB;
//                more BBs = more bogus branches.
//   SPLT → CFF:  Each sub-block becomes a case in the dispatch switch;
//                doubling BB count nearly doubles switch complexity.
//   SPLT → SUB → BCF → CFF:  Maximum obfuscation surface.
//
// Usage:
//   -passes=armorcomp-split       (annotation mode)
//   -passes=armorcomp-split-all   (all functions)
//
// Source annotation:
//   __attribute__((annotate("split"))) int my_fn(...) { ... }
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

struct SplitPass : llvm::PassInfoMixin<SplitPass> {
  bool annotateOnly;
  int  numSplits;  ///< Target sub-blocks per BB after splitting (default 2)

  explicit SplitPass(bool annotateOnly = true, int numSplits = 2)
      : annotateOnly(annotateOnly), numSplits(numSplits) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
