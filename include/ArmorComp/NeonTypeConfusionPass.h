//===----------------------------------------------------------------------===//
// ArmorComp — NeonTypeConfusionPass (NTC)
//
// AArch64-only pass: injects fmov GPR↔SIMD instructions at function entry
// and before each ReturnInst to route integer values through NEON/FP registers.
// IDA Hex-Rays type inference annotates values that flow through FP registers
// as float/double, producing incorrect type declarations in F5 output.
//
// MECHANISM
// ─────────
// Two GPR→SIMD→GPR roundtrips at entry (after first insertion point):
//   load volatile i32 @__armorcomp_ntc_zero      → ZeroI32 = 0 at runtime
//   Block A: fmov s16, w<ZeroI32> ; fmov w9,  s16   → clobbers s16, x9
//   Block B: fmov s17, w<ZeroI32> ; fmov w10, s17   → clobbers s17, x10
//
// One additional roundtrip before each ReturnInst:
//   load volatile i32 @__armorcomp_ntc_zero
//   Block C: fmov s18, w<ZeroI32> ; fmov s19, w<ZeroI32>
//            fmov w11, s18        ; fmov w12, s19
//            → clobbers s18, s19, x11, x12
//
// REGISTER SELECTION
// ──────────────────
//   s16-s31: caller-saved scratch SIMD/FP registers (AArch64 AAPCS64 §6.1.2)
//   w9-w15 / x9-x15: caller-saved scratch GPR registers
//   Neither group requires save/restore — zero ABI impact.
//   s0-s7 (FP argument/result regs) and s8-s15 (callee-saved) are NOT used.
//
// IDA HEX-RAYS EFFECT
// ───────────────────
//   Values flowing through s16-s19 (32-bit FP registers) are annotated as
//   float.  Hex-Rays generates incorrect parameter/return type declarations
//   for integer functions.  Variable liveness analysis is confused by the
//   unexpected GPR←→SIMD data movement at entry and exit boundaries.
//
// PIPELINE POSITION
// ─────────────────
//   Runs after SPOPass (volatile SP sub/add) and before DwarfPoisonPass
//   (.eh_frame CFA poisoning).  Together the three passes attack all IDA
//   F5 analysis paths:
//     SPO     → defeats runtime SP tracking
//     NTC     → defeats type inference on parameters/return values
//     DPOISON → defeats DWARF .eh_frame CFA reader
//
// ANNOTATION / CONFIG
// ───────────────────
//   Annotation: __attribute__((annotate("ntc")))
//   -passes= name: armorcomp-ntc  (annotation mode)
//                  armorcomp-ntc-all (all AArch64 functions)
//   YAML config:  passes: [ntc]
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

struct NeonTypeConfusionPass : llvm::PassInfoMixin<NeonTypeConfusionPass> {
  bool annotateOnly;
  explicit NeonTypeConfusionPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}
  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &AM);
  static bool isRequired() { return true; }
};
