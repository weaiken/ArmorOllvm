#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — ReturnValueObfPass (Return Value Obfuscation)
//
// Strategy: XOR every integer return value with a volatile-zero before ret.
//
// MECHANISM
// ─────────
// For each ReturnInst that returns i8/i16/i32/i64 or a pointer type,
// inject immediately before the ret:
//
//   rvo_zero = load volatile iN, @__armorcomp_rvo_zero    ; = 0 at runtime
//   retval_xor = <return_value> XOR rvo_zero              ; = return_value (no-op)
//   ret retval_xor                                         ; replaces original ret
//
// At runtime the XOR is a mathematical identity (x ^ 0 == x).
// The volatile load prevents the optimizer from constant-folding rvo_zero to 0.
//
// IDA HEX-RAYS EFFECT
// ───────────────────
// IDA observes:
//   ldr  x8, [__armorcomp_rvo_zero]   ; runtime load from global
//   eor  x0, x0, x8                   ; x0 = retval ^ mem[addr]
//   ret
// Because the load is from a non-constant memory location (from IDA's static
// perspective), Hex-Rays cannot determine the return value at compile time.
// Specifically:
//   - Return type inference fails: IDA marks return type as __int64 / void* /
//     _UNKNOWN depending on the callee-signature heuristic in use.
//   - Return-value propagation across callers breaks: call sites that capture
//     the return value in a register now track an XOR expression that Hex-Rays
//     cannot simplify → incorrect data-flow in the decompiled output.
//   - Combined with FuncSigObfPass (fake arg reads / fake x1,x2 writes at exit)
//     and NeonTypeConfusionPass (fmov GPR↔SIMD on entry and before ret):
//     the function's complete prototype — parameter types AND return type —
//     is unrecoverable by static analysis.
//
// TARGET-INDEPENDENT
// ──────────────────
// Unlike NTC (AArch64-specific fmov) or DPOISON (AArch64 .cfi directives),
// RVO uses only standard LLVM IR (load + xor).  It compiles and runs correctly
// on any LLVM-supported architecture.  The confusing register pattern it
// produces is most effective against Hex-Rays on AArch64 / x86_64 targets.
//
// VOLATILE SEMANTICS
// ──────────────────
// @__armorcomp_rvo_zero is a WeakAny i64 global initialized to 0.
// Volatile loads of this global cannot be removed, reordered, or constant-
// folded by LLVM — the generated eor instruction is always present in the
// final binary.  For 32-bit returns, a volatile i32 load is used and the
// XOR operates on i32 (eor w0, w0, w8 in AArch64 disassembly).
//
// POINTER RETURNS
// ───────────────
// For pointer-typed returns, inject ptrtoint → XOR → inttoptr (using i64
// on 64-bit targets).  IDA sees the same pattern: a pointer value flowing
// through an arithmetic operation with a runtime-loaded operand.
//
// Annotation : __attribute__((annotate("rvo")))
// -passes= name : armorcomp-rvo  /  armorcomp-rvo-all
// Pipeline position : after NeonTypeConfusionPass, before DwarfPoisonPass
//===----------------------------------------------------------------------===//

#include "llvm/IR/PassManager.h"

namespace llvm {

struct ReturnValueObfPass : PassInfoMixin<ReturnValueObfPass> {
  bool annotateOnly;

  explicit ReturnValueObfPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};

} // namespace llvm
