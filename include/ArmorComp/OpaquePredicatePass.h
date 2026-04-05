//===----------------------------------------------------------------------===//
// ArmorComp — OpaquePredicatePass public interface
//
// Opaque predicate insertion pass declaration.
// Implementation: lib/OpaquePredicatePass.cpp
//
// Algorithm: for each non-entry basic block in a targeted function, split the
// block into a head and a tail.  The head evaluates one of 6 opaque predicate
// formulas that is mathematically always-true (or always-false), then branches
// to either the real tail or a dead-end block.  The dead-end block contains
// junk volatile loads/arithmetic and a ret of the function's null value.
//
// 6 predicate formulas (cycling via xorshift64):
//   P0 (always-true):  (z*(z+1)) & 1 == 0     — product of consecutive ints is even
//   P1 (always-true):  (z | ~z)  == -1         — OR-with-complement is all-ones
//   P2 (always-true):  (z & ~z)  == 0          — AND-with-complement is zero
//   P3 (always-false): (z & ~z)  != 0          — complement of P2
//   P4 (always-false): (z * 2)   & 1 != 0      — double is always even
//   P5 (always-false): (z*z + 1) & 3 == 0      — z^2 mod 4 ∈ {0,1} → z^2+1 mod 4 ∈ {1,2}
//
// z is a volatile load from @__armorcomp_op_zero (= 0), preventing optimizer
// constant-folding while remaining always-zero at runtime.
//
// Usage in pipeline:
//   -passes=armorcomp-op            (annotation mode: only op-annotated fns)
//   -passes=armorcomp-op-all        (all mode: every eligible function)
//
// Source annotation:
//   __attribute__((annotate("op"))) int my_fn(...) { ... }
//
// Recommended pipeline position: after BCF, before CFF.
//   BCF → OP → CFF
// OPP's dead BBs become additional (never-taken) cases in CFF's switch dispatch.
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

struct OpaquePredicatePass : llvm::PassInfoMixin<OpaquePredicatePass> {
  bool annotateOnly;

  explicit OpaquePredicatePass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
