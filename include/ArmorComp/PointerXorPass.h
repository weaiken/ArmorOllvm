//===----------------------------------------------------------------------===//
// ArmorComp — PointerXorPass public interface
//
// Pointer local-variable XOR encryption pass declaration.
// Implementation: lib/PointerXorPass.cpp
//
// Algorithm (function-level pass):
//   For each pointer-typed alloca (ptr) in the entry block of annotate("pxor")
//   functions that is accessed exclusively via direct loads, stores, and LLVM
//   lifetime/debug intrinsics:
//
//     STORE side:
//       Before: store ptr val, ptr %x
//       After:  %px.raw = ptrtoint ptr val to i64
//               %px.enc = xor i64 %px.raw, K
//               %px.ptr = inttoptr i64 %px.enc to ptr
//               store ptr %px.ptr, ptr %x
//
//     LOAD side:
//       Before: %v = load ptr, ptr %x
//       After:  %raw = load ptr, ptr %x
//               %px.ri  = ptrtoint ptr %raw to i64
//               %px.dec = xor i64 %px.ri, K
//               %v      = inttoptr i64 %px.dec to ptr
//               ; all prior uses of %raw replaced with %v
//
//   K = xorshift64(FNV1a(fn_name + "_pxor_" + alloca_index))
//   K is 64-bit on 64-bit targets (AArch64); 32-bit on 32-bit targets.
//
// Effect on static analysis:
//   - Complements DataEncodingPass which only handles integer allocas.
//     PXOR fills the gap: pointer locals stored on-stack are XOR-scrambled.
//   - Stack memory always holds scrambled pointer values.
//   - IDA decompiler sees ptrtoint/xor/inttoptr sequences around every
//     pointer load/store; pointer type recovery is hindered.
//   - Pointer equality checks, NULL checks, and vtable-pointer analysis
//     become unreliable in static analysis tools.
//
// Eligibility:
//   - Alloca must be in the entry block (statically-sized)
//   - Allocated type must be ptr (pointer type)
//   - All users must be direct loads, direct stores, or LLVM intrinsics
//     (lifetime.start/end, dbg.declare, dbg.value) — no GEPs, no calls
//
// Pipeline position:
//   Right after DENC (integer variable encoding), before JCI:
//   MBA → COB → DENC → PXOR → JCI → CO → ...
//
// Annotation: __attribute__((annotate("pxor")))
// Usage:
//   -passes=armorcomp-pxor       (annotation mode)
//   -passes=armorcomp-pxor-all   (all functions)
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"

struct PointerXorPass : llvm::PassInfoMixin<PointerXorPass> {
  bool annotateOnly;

  explicit PointerXorPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
