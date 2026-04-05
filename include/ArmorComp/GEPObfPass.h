#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — GEPObfPass (GEP Index Obfuscation)
//
// Strategy: for every GetElementPtrInst in a targeted function, compute the
// total constant byte offset using DataLayout, then replace the entire GEP
// with a raw i8-pointer GEP using an XOR-obfuscated byte offset:
//
//   Original (struct field):
//     getelementptr %T, ptr base, i64 0, i32 K
//     (byte offset = DataLayout::getOffset(field K in %T))
//
//   Original (pointer arithmetic):
//     getelementptr i32, ptr base, i64 N
//     (byte offset = N * sizeof(i32))
//
//   Replaced:
//     %gepo.zero = load volatile i64, @__armorcomp_gepo_zero  ; = 0 at runtime
//     %gepo.off  = xor i64 <ByteOffset>, %gepo.zero           ; = ByteOffset
//     %gepo.ptr  = getelementptr i8, ptr base, i64 %gepo.off  ; legal i8 GEP
//
// WHY BYTE-OFFSET GEP (not per-index XOR)?
// ──────────────────────────────────────────
// LLVM IR requires struct field indices to be ConstantInt — the backend
// IRTranslator enforces this and crashes on non-constant struct indices.
// Converting to a single i8 GEP with a runtime byte offset sidesteps the
// constraint entirely: i8 GEP index is just pointer arithmetic (no struct
// layout constraint).  For non-struct GEPs (arrays, pointers), the same
// approach uniformly folds stride*index into one byte offset.
//
// IDA PRO EFFECT
// ──────────────
// 1. Structure field recognition: IDA matches `[x0 + 8]` → field at byte 8.
//    After GEPO, `[x0, x9]` where x9 = 8 XOR volatile_zero — IDA cannot
//    determine the field offset statically → struct layout unrecoverable.
//
// 2. Array subscript recovery: IDA detects `stride * induction_var`.
//    GEPO folds stride*index into a volatile XOR expression → unresolvable.
//
// 3. C++ vtable dispatch: vtable slot indices become opaque XOR results;
//    IDA cannot identify which virtual method is being called.
//
// ORTHOGONALITY WITH ConstObfPass (CO)
// ─────────────────────────────────────
// ConstObfPass transforms constant operands of BinaryOperator and ICmpInst;
// it explicitly skips GetElementPtrInst (GEP struct indices must be constant).
// GEPObfPass exclusively targets GEPs using the byte-offset conversion approach.
// Running CO before GEPO ensures CO's own XOR-key constants are not re-processed.
//
// ZERO-OFFSET SKIP
// ─────────────────
// GEPs with a total byte offset of zero are skipped.  Field 0 of any struct
// sits at the base pointer; XOR(0, volatile_zero) = volatile_zero (= 0 at
// runtime), but IDA could still determine the access is to offset 0 via the
// load pattern.  More importantly, zero-byte GEPs produce no useful entropy.
//
// GEPs with non-constant indices (dynamic array subscripts) are skipped;
// they are already non-resolvable at compile time.
//
// AArch64 DISASSEMBLY
// ───────────────────
// Before GEPO (struct field access, field at byte offset 4):
//   ldr  w0, [x0, #4]                ; constant immediate #4 visible to IDA
//
// After GEPO:
//   ldr  x9, [__armorcomp_gepo_zero] ; volatile load of zero
//   eor  x9, x9, #4                  ; x9 = 4 XOR 0 = 4 at runtime
//                                    ; IDA cannot constant-fold → offset unknown
//   ldr  w0, [x0, x9]                ; struct member access with unknown offset
//
// PIPELINE POSITION
// ─────────────────
// Runs after CO (step 9) so CO does not further obfuscate GEPO's own XOR-key
// constants; before DF (step 11) so the data flow flattening pool GEPs (which
// already have their own obfuscated indices) are not double-processed.
//
// New auto-run order:
//   STRENC → GENC → SOB → SPLIT → SUB → MBA → COB → DENC → CO → GEPO → DF
//   → OUTLINE → BCF → OP → CFF → RAO → ICALL → IBR → IGV → FW → FSIG
//   → SPO → NTC → RVO → LRO → DPOISON
//
// Annotation : __attribute__((annotate("gepo")))
// -passes= name : armorcomp-gepo  /  armorcomp-gepo-all
//===----------------------------------------------------------------------===//

#include "llvm/IR/PassManager.h"

namespace llvm {

struct GEPObfPass : PassInfoMixin<GEPObfPass> {
  bool annotateOnly;

  explicit GEPObfPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};

} // namespace llvm
