//===----------------------------------------------------------------------===//
// ArmorComp — DataEncodingPass public interface
//
// Integer local-variable memory encoding pass declaration.
// Implementation: lib/DataEncodingPass.cpp
//
// Algorithm (function-level pass):
//   For each integer alloca (i8/i16/i32/i64) in annotate("denc") functions
//   that is accessed exclusively via direct loads and stores:
//
//     STORE side:
//       Before: store iN val, ptr %x
//       After:  %de.enc = xor iN val, K
//               store iN %de.enc, ptr %x
//
//     LOAD side:
//       Before: %v = load iN, ptr %x
//       After:  %raw = load iN, ptr %x
//               %de.dec = xor iN %raw, K
//               ; all prior uses of %v replaced with %de.dec
//
//   K = xorshift64(FNV1a(fn_name + "_" + alloca_index))
//   Different key per alloca, deterministic across compilations.
//
// Effect on static analysis:
//   - Stack memory always contains encoded (XOR-scrambled) values.
//   - IDA/Ghidra decompiler shows XOR arithmetic around every load/store
//     instead of plain variable reads/writes; type recovery is hindered.
//   - With FlattenDataFlowPass (runs after DENC): the pool GEP obfuscates
//     which slot is accessed, while DENC obfuscates the stored value.
//   - With ConstObfPass (runs after DENC): the XOR keys K are themselves
//     hidden behind a secondary XOR-key split expression.
//
// Eligibility:
//   - Alloca must be in the entry block (statically-sized)
//   - Allocated type must be i8 / i16 / i32 / i64
//   - All users must be direct loads, direct stores, or LLVM intrinsics
//     (lifetime.start/end, dbg.declare, dbg.value) — no GEPs, no calls
//
// Usage in pipeline:
//   -passes=armorcomp-denc       (annotation mode)
//   -passes=armorcomp-denc-all   (all functions)
//
// Recommended pipeline position: after MBA, before CO
//   SUB → MBA → DENC → CO → DF → OUTLINE → BCF → ...
//   DENC runs after SUB/MBA so encoding wraps already-substituted ops;
//   CO then hides DENC's XOR keys; DF then merges the still-existing
//   allocas into a pool (the two transforms compose cleanly).
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"

struct DataEncodingPass : llvm::PassInfoMixin<DataEncodingPass> {
  bool annotateOnly;

  explicit DataEncodingPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
