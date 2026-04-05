#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — JunkCodePass (JCI — Junk Code Injection)
//
// Strategy: inject dead arithmetic computation chains into each targeted
// basic block.  Each chain:
//   1. Loads a volatile i64 from @__armorcomp_jci_zero (= 0 at runtime)
//   2. Applies 4–7 arithmetic/logic operations using deterministic PRNG-derived
//      constants (xorshift64 seeded with FNV-1a hash of function+BB index)
//   3. Feeds the final result into an empty "asm sideeffect" with "r" input
//      constraint — this forces register allocation of the junk value and
//      prevents DCE of the entire chain
//
// Runtime behaviour: the volatile load always returns 0; every op on 0
// produces 0.  The asm sink generates zero actual instructions.
// Net effect: the chain is a provable no-op at runtime while appearing
// non-trivial to both the LLVM optimiser and IDA Pro.
//
// IDA Pro analysis effect:
//   Without JCI:  Hex-Rays F5 shows the real function logic.
//   With JCI:     each basic block gets N extra local variables (jci.base,
//                 jci.xor, jci.add, ...) that Hex-Rays cannot eliminate
//                 because the volatile load defeats constant propagation.
//                 The analyst must first identify and strip the dead chain
//                 from each BB before reading the actual algorithm.
//
// WHY asm sideeffect sink?
// ─────────────────────────────────────────────────────────────────────────────
// A plain `store volatile, junk_val` would leave a memory write footprint.
// An `asm volatile("" : : "r"(v))` generates zero instructions in the binary
// while still telling LLVM "this value is used — do not eliminate it."
// The "r" input constraint means the compiler MUST materialise the value in
// a register before the asm boundary — effectively a use without a def.
//
// DCE survival:
//   LoadInst(volatile)    → marked as having side effects; never DCE'd
//   BinaryOperator chain  → each result feeds the next, transitively used
//   InlineAsm(sideeffect) → marked as a use; prevents elimination of the arg
//
// AArch64 disassembly (3-op chain example, entry block of a simple function):
//   ldr  x8, [__armorcomp_jci_zero]   ; volatile load, = 0 at runtime
//   eor  x8, x8, #0xdeadbeef01234567  ; jci.xor
//   orr  x8, x8, #0x123456789abcdef0  ; jci.or
//   mul  x8, x8, #0xfedcba9876543210  ; jci.mul  (IDA: mystery register chain)
//   ; no instructions generated for the asm sink — value in x8 is "live"
//   ; but the asm produces no output; the register is freed at asm boundary
//
// DETERMINISM
// ────────────
// Seed = FNV-1a(fnName + "_jci_" + bbIndex).
// Same source code → same obfuscated binary, regardless of invocation order.
// No random_device, no timestamp.
// Different BBs and different functions each get distinct chains.
//
// PIPELINE POSITION
// ─────────────────
// Step 9 in the auto-run order:
//   Runs after DENC (step 8) so junk chains are inserted after the data-encoding
//   store/load wrappers.  The JCI constants and the DENC keys coexist in the
//   same BB but are independent.
//   Runs before CO (step 10) so CO's XOR-key split additionally obfuscates
//   JCI's own arithmetic constants — two-layer obfuscation of junk constants.
//   Does not use or produce GEPs, so orthogonal to GEPO (step 11) and DF (step 12).
//
// New auto-run order (26+1 passes):
//   STRENC → GENC → SOB → SPLIT → SUB → MBA → COB → DENC → JCI → CO
//   → GEPO → DF → OUTLINE → BCF → OP → CFF → RAO → ICALL → IBR → IGV
//   → FW → FSIG → SPO → NTC → RVO → LRO → DPOISON
//
// Annotation : __attribute__((annotate("jci")))
// -passes= name : armorcomp-jci  /  armorcomp-jci-all
//===----------------------------------------------------------------------===//

#include "llvm/IR/PassManager.h"

namespace llvm {

struct JunkCodePass : PassInfoMixin<JunkCodePass> {
  bool annotateOnly;

  explicit JunkCodePass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};

} // namespace llvm
