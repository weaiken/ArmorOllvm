#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — VMPPass (VMP — Virtual Machine Protection)
//
// Virtualizes targeted functions: translates them from LLVM IR to VMP
// bytecode (via VMPLifter), injects the bytecode as a module global, and
// replaces the function body with an interpreter dispatch loop (via
// VMPCodeGen).
//
// ── Effect on Binary Analysis ─────────────────────────────────────────────
//   Without VMP:
//     IDA / Ghidra F5 produces readable pseudocode of the original function.
//
//   With VMP:
//     The original function is a one-instruction tail-call thunk:
//       __armorcomp_vmp_dispatch_<fname>(args...)
//     The dispatcher is a large switch-based interpreter loop with ~50 BBs.
//     The "real" computation is encoded in a [N x i8] bytecode global with
//     no symbol or debug info.
//     IDA cannot reconstruct the original algorithm — the analyst must
//     first reverse-engineer the custom ISA and then trace execution through
//     the bytecode.
//
// ── Limitations (initial implementation) ─────────────────────────────────
//   - Direct function calls inside virtualized functions are not supported.
//     (The lifter returns nullopt for CallInst; such functions are skipped.)
//   - Conditional branches whose successor BBs have PHI nodes are not
//     supported (the lifter returns nullopt).
//   - Floating-point instructions are not supported.
//   - SIMD / vector instructions are not supported.
//
// ── Annotation ────────────────────────────────────────────────────────────
//   __attribute__((annotate("vmp")))
//   -passes= : armorcomp-vmp  /  armorcomp-vmp-all
//
// ── Pipeline position ─────────────────────────────────────────────────────
//   After GENC (step 2), before SOB (step 3).
//   Runs early so that all downstream passes (SOB, SPLIT, SUB, MBA, COB,
//   DENC, JCI, CO, ...) operate on the generated dispatcher stub rather
//   than the original function body.  This applies multiple obfuscation
//   layers on top of the already-opaque VM loop.
//
//===----------------------------------------------------------------------===//

#include "llvm/IR/PassManager.h"

namespace llvm {

struct VMPPass : PassInfoMixin<VMPPass> {
  bool annotateOnly;

  explicit VMPPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};

} // namespace llvm
