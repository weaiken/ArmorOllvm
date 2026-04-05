#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — SwitchObfPass (Switch Statement Obfuscation)
//
// Strategy: replace each SwitchInst with a dense jump-table lookup and
// indirectbr, with volatile-zero XOR applied to the target pointer before
// branching.  IDA's switch pattern matcher cannot reconstruct the original
// switch structure.
//
// INJECTION PATTERN
// ─────────────────
// Original LLVM IR (after Clang lowering a C switch):
//
//   switch i32 %x, label %default [
//     i32 0, label %case0
//     i32 1, label %case1
//     i32 2, label %case2
//   ]
//
// After SwitchObfPass:
//
//   ; (module-level constant table, created once per switch)
//   @sob_table_N = private constant [4 x ptr]
//       [ptr blockaddress(@fn, %case0), ptr blockaddress(@fn, %case1),
//        ptr blockaddress(@fn, %case2), ptr blockaddress(@fn, %default)]
//
//   ; (at switch site — in the switch BB)
//   %sob.idx.raw  = sub i32 %x, <min_case>           ; normalize to 0-based
//   %sob.inrange  = icmp ule i32 %sob.idx.raw, <max-min>  ; bounds check
//   %sob.idx      = select %sob.inrange, %sob.idx.raw, <default_slot>
//   %sob.idx64    = sext i32 %sob.idx to i64
//   %sob.gep      = getelementptr [N x ptr], @sob_table_N, i64 0, i64 %sob.idx64
//   %sob.raw_ptr  = load volatile ptr, %sob.gep       ; volatile load (prevents folding)
//   %sob.zero     = load volatile i64, @__armorcomp_sob_zero
//   %sob.tgt_int  = ptrtoint ptr %sob.raw_ptr to i64
//   %sob.xor_int  = xor i64 %sob.tgt_int, %sob.zero  ; = raw_ptr (no-op at runtime)
//   %sob.target   = inttoptr i64 %sob.xor_int to ptr
//   indirectbr ptr %sob.target, [label %case0, label %case1, label %case2, label %default]
//
// WHY VOLATILE LOAD OF TABLE
// ─────────────────────────
// Loading the table entry as `load volatile ptr` prevents LLVM from
// constant-folding the load back to the literal blockaddress constant.
// Without this, the optimizer can see through the table and reconstruct
// the original switch.  The volatile semantics ensure the load is visible
// in the final binary with a non-constant source.
//
// WHY XOR BEFORE BRANCH
// ─────────────────────
// IDA's switch pattern matcher (IDAPro/Hex-Rays) specifically looks for
// the sequence: [normalize index] + [bounds check] + [table load] + [br].
// The ptrtoint → XOR → inttoptr sequence between the table load and
// indirectbr breaks this pattern:
//   - IDA sees: `ldr x8, [table_base, x0, lsl #3]` + `ldr x9, [sob_zero]`
//               + `eor x8, x8, x9` + `br x8`
//   - The EOR with a runtime-loaded operand prevents IDA from statically
//     determining the branch target → switch reconstruction fails
//   - IDA decompiler falls back to JUMPOUT() for all case paths
//
// DENSE TABLE CONSTRUCTION
// ────────────────────────
// - Collect all case values; find min = minCase, max = maxCase.
// - If (maxCase - minCase) > 1023, skip the switch (too sparse; fall back to
//   the existing SwitchInst which is already IR-level obfuscated by COB/BCF).
// - Build table of size (maxCase - minCase + 2):
//     entries [0 .. maxCase-minCase] : case dest (or default if gap in range)
//     entry  [maxCase-minCase+1]     : default dest  (out-of-range fallback)
// - Out-of-range index is redirected to the default slot using a select.
//
// ORTHOGONALITY WITH IBR
// ──────────────────────
// IndirectBranchPass targets BranchInst (conditional/unconditional).
// SwitchInst is a different LLVM IR instruction class — IBR never touches it.
// SOB specifically targets SwitchInst, filling the gap.
//
// PIPELINE POSITION
// ─────────────────
// Runs after the two module passes (STRENC, GENC) and before SPLIT.
// The bounds-check ICmpInst SOB creates is later noised by COB.
// The indirectbr SOB creates is later flattened by CFF (as a switch case).
// This creates a two-level dispatch: SOB's indirectbr inside CFF's switch.
//
// Annotation : __attribute__((annotate("sob")))
// -passes= name : armorcomp-sob  /  armorcomp-sob-all
//===----------------------------------------------------------------------===//

#include "llvm/IR/PassManager.h"

namespace llvm {

struct SwitchObfPass : PassInfoMixin<SwitchObfPass> {
  bool annotateOnly;

  explicit SwitchObfPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};

} // namespace llvm
