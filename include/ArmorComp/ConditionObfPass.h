//===----------------------------------------------------------------------===//
// ArmorComp — ConditionObfPass (Comparison / ICmpInst Obfuscation)
//
// Attack target: IDA Hex-Rays F5 condition-expression analysis.
// All other passes (MBAPass, SubPass) operate exclusively on BinaryOperator
// instructions (ADD/SUB/AND/OR/XOR) and never touch ICmpInst (comparison).
// ConditionObfPass fills this gap: it transforms every ICmpInst operand pair
// so that IDA cannot statically resolve the comparison condition.
//
// MECHANISM
// ─────────
// For each  icmp pred A, B  in an annotated function:
//
//   1. Load a volatile zero from @__armorcomp_cob_zero (i64, init = 0):
//        zero = load volatile i64, @__armorcomp_cob_zero   ; = 0 at runtime
//
//   2. Derive per-ICmp opaque noise terms using FNV(fn_name) × LCG mixing:
//        Na_wide = mul i64 zero, Ka    ; = 0 at runtime  (Ka ≠ 0: LCG mix)
//        Nb_wide = mul i64 zero, Kb    ; = 0 at runtime  (Kb ≠ Ka)
//        Na      = trunc Na_wide to iN ; iN = operand bit-width
//        Nb      = trunc Nb_wide to iN
//
//   3. Add noise to both operands:
//        A' = add iN A, Na             ; = A at runtime
//        B' = add iN B, Nb             ; = B at runtime
//
//   4. Replace original comparison:
//        icmp pred A', B'              ; identical result to icmp pred A, B ✓
//
// CORRECTNESS
// ───────────
// Because Na = 0 and Nb = 0 at runtime for all comparison predicates:
//   A' = A + 0 = A,  B' = B + 0 = B
//   icmp pred A', B'  ≡  icmp pred A, B   for ALL ICmpInst predicates
// (signed: slt/sgt/sle/sge; unsigned: ult/ugt/ule/uge; equality: eq/ne)
//
// Note: XOR-based noise would be unsafe for signed ordered predicates
// because XOR can flip the sign bit.  ADD 0 is safe for every predicate.
//
// IDA F5 EFFECT
// ─────────────
// IDA's decompiler sees:
//   icmp slt (add x, trunc(mul(volatile_i64, Ka))),
//            (add 0, trunc(mul(volatile_i64, Kb)))
// It cannot prove trunc(mul(volatile_i64, K)) = 0 (volatile load blocks
// value propagation).  Hex-Rays emits wrong or unresolvable condition
// expressions such as:  if ( v4 + v2 < v3 )   instead of  if ( x < 0 ).
// Analysts must manually trace the volatile-zero chain to recover the
// original comparison predicate and constants.
//
// SKIPPED OPERAND TYPES
// ─────────────────────
//   i1     : single-bit booleans (results of comparisons themselves)
//   > i64  : integer types wider than 64 bits (i128, iN etc.) — rare in C
//   pointer: pointer comparisons (null checks) — no integer add semantics
//
// PIPELINE POSITION
// ─────────────────
//   STRENC → GENC → SPLIT → SUB → MBA → COB → DENC → CO → DF → …
//
//   Runs after MBA so condition noise wraps already MBA-obfuscated operands.
//   Runs before DENC/CO so DENC's encoding keys and CO's constant splits
//   also cover the noise constants Ka/Kb introduced by COB.
//
// USAGE
// ─────
//   Source annotation:  __attribute__((annotate("cob")))
//   -passes= name:      armorcomp-cob          (annotation mode)
//                       armorcomp-cob-all      (all functions)
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

struct ConditionObfPass : llvm::PassInfoMixin<ConditionObfPass> {
  bool annotateOnly;

  explicit ConditionObfPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
