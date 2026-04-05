//===----------------------------------------------------------------------===//
// ArmorComp — ArithmeticStatePass public interface
//
// CFF state-variable XOR encoding pass declaration.
// Implementation: lib/ArithmeticStatePass.cpp
//
// Algorithm (function-level pass):
//   Runs AFTER CFFPass to defeat automated CFF deobfuscation tools (d810,
//   msynack) that work by detecting the state-variable/switch-dispatcher
//   pattern and tracing constant state transitions.
//
//   Detection:
//     A "state variable" alloca is an i32/i64 alloca where:
//       - ALL stores are from ConstantInt values (explicit state assignments)
//       - ALL loads feed directly into SwitchInst discriminants
//
//   Transformation:
//     1. Derive a per-alloca XOR key: K = xorshift64(FNV1a(fn_name + "_asp_" + idx))
//     2. Replace every StoreInst: store i32 CONST → store i32 (CONST XOR K)
//     3. Replace every SwitchInst case constant: case i32 C → case i32 (C XOR K)
//
//   Correctness guarantee:
//     The stored value and all case constants are consistently XOR-encoded with
//     the same key K. Since load→switch sees encoded value vs encoded cases,
//     the dispatch logic is exactly preserved. No runtime overhead.
//
// Effect on deobfuscation tools:
//   - d810: "collect all constant stores to state_var" step fails — stores are
//     now (CONST XOR K) not CONST, but K is not recoverable without symbolic exec.
//   - msynack: state transition graph extraction fails for the same reason.
//   - IDA Hex-Rays: switch discriminant still matches case values, so decompiler
//     output is correct; but automated analysis tools that assume bare constants
//     fail to reconstruct the original CFG.
//
// Pipeline position:
//   Immediately after CFF: ... → CFF → ASP → RAO → ICALL → ...
//
// Annotation: __attribute__((annotate("asp")))
// Usage:
//   -passes=armorcomp-asp       (annotation mode)
//   -passes=armorcomp-asp-all   (all functions)
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"

struct ArithmeticStatePass : llvm::PassInfoMixin<ArithmeticStatePass> {
  bool annotateOnly;

  explicit ArithmeticStatePass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
