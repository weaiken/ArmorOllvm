//===----------------------------------------------------------------------===//
// ArmorComp — LoopObfuscationPass public interface
//
// Loop structure obfuscation pass declaration.
// Implementation: lib/LoopObfuscationPass.cpp
//
// Algorithm (function-level pass):
//   Uses LoopAnalysis (LLVM new PM) to find all natural loops in annotate("lob")
//   functions, then applies three orthogonal obfuscations:
//
//   1. Loop preheader junk injection:
//      For each loop that has a single preheader block, insert before its
//      terminator an opaque dead arithmetic chain:
//        %z  = load volatile i64, @__armorcomp_lob_zero   ; = 0 at runtime
//        %s0 = mul i64 %z, CONST_A
//        %s1 = add i64 %s0, CONST_B
//        %s2 = xor i64 %s1, CONST_C
//        call void asm sideeffect "", "r,~{memory}"(i64 %s2)
//      Effect: loop preheader now contains an opaque expression that IDA/Ghidra
//      cannot prove is dead; loop bound detection tools see extra complexity.
//
//   2. Loop header noise:
//      For each loop header, insert a volatile zero load + opaque add before
//      the first non-PHI instruction:
//        %n  = load volatile i64, @__armorcomp_lob_zero
//        %nb = add i64 %n, 0         ; = 0, but opaque
//      The result is fed into an asm sideeffect sink.
//      Effect: loop condition block has an extra opaque value; automatic
//      loop-trip-count analysis fails because the header looks more complex.
//
//   3. Fake loop invariant:
//      After the preheader junk, insert a 4-instruction chain that computes
//      `(volatile_zero * PRIME) & 0 = 0` and stores into a temp alloca.
//      IDA Hex-Rays sees a local variable that appears to be set in the
//      preheader, making loop invariant motion analysis unreliable.
//
// Effect on static analysis:
//   - Loop unrolling tools (IDA / Binary Ninja) fail to determine trip count.
//   - Symbolic execution (angr, Triton) must track more state through preheader.
//   - Decompiler output shows extra "dead" expressions that confuse analysts.
//
// Pipeline position:
//   After MBA (arithmetic obfuscation) and before BCF (bogus control flow).
//   Loops must be visible in the IR at this point — CFF destroys loop structure.
//   MBA → LOB → COB → DENC → PXOR → JCI → FAPI → CO → ... → BCF → CFF
//
// Analysis requirement:
//   Requests LoopAnalysis from FunctionAnalysisManager.
//   Invalidates loop analysis after modification.
//
// Annotation: __attribute__((annotate("lob")))
// Usage:
//   -passes=armorcomp-lob       (annotation mode)
//   -passes=armorcomp-lob-all   (all functions)
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"

struct LoopObfuscationPass : llvm::PassInfoMixin<LoopObfuscationPass> {
  bool annotateOnly;

  explicit LoopObfuscationPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
