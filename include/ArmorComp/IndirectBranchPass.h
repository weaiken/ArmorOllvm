//===----------------------------------------------------------------------===//
// ArmorComp — IndirectBranchPass (Indirect Branch Obfuscation) public interface
//
// Replaces direct branch instructions with indirect branches through a
// runtime-computed block address, breaking static control-flow graph
// reconstruction.
//
// Technique: opaque-zero-offset blockaddress computation
// ──────────────────────────────────────────────────────
// For each BranchInst in an annotated function:
//
// Unconditional:
//   Before:  br label %target
//   After:   %off  = load volatile i64, @__armorcomp_ibr_off  ; always 0
//            %base = ptrtoint blockaddress(@fn, %target) to i64
//            %addr = add i64 %base, %off
//            %ptr  = inttoptr i64 %addr to ptr
//            indirectbr ptr %ptr, [label %target]
//
// Conditional:
//   Before:  br i1 %cond, label %T, label %F
//   After:   %off    = load volatile i64, @__armorcomp_ibr_off
//            %base_t = ptrtoint blockaddress(@fn, %T) to i64
//            %base_f = ptrtoint blockaddress(@fn, %F) to i64
//            %addr_t = add i64 %base_t, %off
//            %addr_f = add i64 %base_f, %off
//            %ptr_t  = inttoptr i64 %addr_t to ptr
//            %ptr_f  = inttoptr i64 %addr_f to ptr
//            %ptr    = select i1 %cond, ptr %ptr_t, ptr %ptr_f
//            indirectbr ptr %ptr, [label %T, label %F]
//
// Why this defeats static analysis:
//   - Disassemblers reconstruct CFG by following branch targets. After this
//     transformation all branch targets are runtime-computed registers (AArch64:
//     BR Xn, x86: JMP *%rax), which CFG tools cannot resolve statically.
//   - The volatile zero load prevents the optimizer constant-folding the
//     address computation back to a literal label.
//   - Combined with CFFPass the dispatch block becomes doubly unreachable:
//     its switch cases are already opaque, and now each case's back-branch
//     to dispatch is also indirect.
//
// Skips:
//   - SwitchInst (complex; CFF handles switches)
//   - Branches whose successor IS the function entry block
//     (taking blockaddress of the entry block is illegal in LLVM IR)
//   - Functions with personality / landing pads (exception handling)
//   - Function entry block itself as the branch source (conservative)
//
// Usage in pipeline:
//   -passes=armorcomp-ibr        (annotation mode)
//   -passes=armorcomp-ibr-all    (all functions)
//
// Source annotation:
//   __attribute__((annotate("ibr"))) int my_fn(...) { ... }
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

struct IndirectBranchPass : llvm::PassInfoMixin<IndirectBranchPass> {
  bool annotateOnly;

  explicit IndirectBranchPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
