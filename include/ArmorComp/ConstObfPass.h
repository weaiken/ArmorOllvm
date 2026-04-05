//===----------------------------------------------------------------------===//
// ArmorComp — ConstObfPass (Integer Constant Obfuscation)
//
// Replaces integer constants in annotated functions with equivalent
// XOR-based expressions that reference a volatile global, defeating
// IDA/Ghidra constant propagation and making decompiler output unreadable.
//
// Technique: XOR key split through volatile zero
// ──────────────────────────────────────────────
// For each integer constant C of width N in qualifying instructions:
//
//   K   = random N-bit compile-time key
//   C'  = C ^ K  (stored as an immediate in the IR)
//
//   Emitted IR:
//     %co.z   = load volatile i64, ptr @__armorcomp_co_zero    ; = 0
//     %co.k64 = or i64 %co.z, K64_const                       ; = K64 (but
//                                                              ;   IDA sees
//                                                              ;   volatile | K)
//     %co.k   = trunc i64 %co.k64 to iN   (or identity if N=64)
//     %co.v   = xor iN C'_const, %co.k    ; = C at runtime
//
//   The original constant operand is replaced with %co.v.
//
// IDA decompiler output (approximate):
//   x * (int)((*(volatile __int64 *)co_zero | 5LL) & 0xFFFFFFFF) ^ 0x3FF ^ C')
//   → Every constant appears as a complex expression; no bare immediates.
//
// Qualifying instructions (safe to replace constant operands):
//   BinaryOperator (add/sub/mul/and/or/xor/shl/lshr/ashr)
//   ICmpInst (all integer comparisons)
//
// Skipped instructions (constant operands must remain constants):
//   AllocaInst, GetElementPtrInst, PHINode, BranchInst, SwitchInst,
//   ReturnInst, IntrinsicInst, CallInst callee (operand 0)
//
// Skipped constant widths: i1 (boolean), >64 bits (i128, wide vectors)
//
// Usage:
//   -passes=armorcomp-co        (annotation mode)
//   -passes=armorcomp-co-all    (all functions)
//
// Source annotation:
//   __attribute__((annotate("co"))) int my_fn(...) { ... }
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

struct ConstObfPass : llvm::PassInfoMixin<ConstObfPass> {
  bool annotateOnly;

  explicit ConstObfPass(bool annotateOnly = true) : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
