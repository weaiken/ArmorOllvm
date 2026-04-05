#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — LRObfPass (Link Register / Return Address Obfuscation)
//
// Strategy: before every ReturnInst in a targeted function, inject a no-op
// XOR on the link register (x30) via inline asm:
//
//     ldr  x9, [__armorcomp_lro_zero]   ; volatile load — always 0 at runtime
//     eor  x30, x30, x9                 ; x30 ^= 0  (no-op at runtime)
//     ret                               ; branches to x30 = correct return addr
//
// IDA Pro observes "eor x30, x30, x9" where x9 comes from a volatile memory
// load.  It cannot prove x9 == 0 statically, so it cannot determine where the
// function returns.  All caller xrefs from the annotated function become
// JUMPOUT() or "sp-analysis failed" rather than proper cross-references.
//
// ORTHOGONALITY
// ─────────────
// ReturnValueObfPass (RVO)  : XORs the return VALUE register (x0/w0).
// LRObfPass         (LRO)  : XORs the return ADDRESS register (x30 = lr).
// Together they defeat two complementary IDA analysis paths:
//   - RVO: "what does this function return?"   → _UNKNOWN / unresolvable
//   - LRO: "where does this function return?"  → JUMPOUT / no xref
//
// SPOPass / RetAddrObfPass : corrupt SP (stack-pointer delta analysis).
// LRObfPass                : corrupts LR (return-address / xref analysis).
// DwarfPoisonPass          : corrupts .eh_frame CFA rows.
// All three attack distinct IDA analysis engines; maximally independent.
//
// IDA HEX-RAYS EFFECT
// ───────────────────
// 1. Caller cross-reference: IDA builds "XREF FROM func+N" by tracking which
//    instruction in the caller follows each `BL func` instruction.  After LRO,
//    IDA sees `eor x30, x30, x9; ret` and cannot resolve the return target,
//    so the BL instruction in the caller loses its XREF to the callee — the
//    link is broken in BOTH directions.
// 2. Stack unwinding: .eh_frame CFA tables reference `ret` as the unwinding
//    anchor.  With x30 XOR'd through a volatile operand, IDA's unwind-based
//    sp_delta calculation at the ret site becomes UNKNOWN.
// 3. Function boundary detection: IDA detects function ends by finding `ret`
//    reachable from the function entry.  The XOR of x30 makes the control flow
//    look like an indirect branch to an unknown target rather than a plain
//    return — IDA may not recognise the function boundary at all.
//
// AArch64-ONLY
// ────────────
// The x30 (lr) register is AArch64-specific.  This pass is a no-op on all
// other targets (Triple::isAArch64() guard).
//
// PIPELINE POSITION
// ─────────────────
// Runs after RVO (return value XOR is already in place) and before DPOISON
// (DWARF rows should reflect the fully-transformed IR including LRO).
// New auto-run order:
//   STRENC → GENC → SOB → SPLIT → SUB → MBA → COB → DENC → CO → DF → OUTLINE
//   → BCF → OP → CFF → RAO → ICALL → IBR → IGV → FW → FSIG → SPO → NTC → RVO
//   → LRO → DPOISON
//
// Annotation : __attribute__((annotate("lro")))
// -passes= name : armorcomp-lro  /  armorcomp-lro-all
//===----------------------------------------------------------------------===//

#include "llvm/IR/PassManager.h"

namespace llvm {

struct LRObfPass : PassInfoMixin<LRObfPass> {
  bool annotateOnly;

  explicit LRObfPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};

} // namespace llvm
