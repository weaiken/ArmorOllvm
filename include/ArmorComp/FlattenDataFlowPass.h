//===----------------------------------------------------------------------===//
// ArmorComp — FlattenDataFlowPass public interface
//
// Stack variable pool merging pass declaration.
// Implementation: lib/FlattenDataFlowPass.cpp
//
// Algorithm: merges all statically-sized alloca instructions in a function's
// entry block into a single byte pool: alloca [N x i8].  Each original alloca
// at byte offset O is replaced by a GEP with an obfuscated index:
//
//   pool  = alloca [N x i8]
//   z     = load volatile i64 @__armorcomp_df_zero    ; always 0 at runtime
//   idx   = xor i64 (O ^ KEY), (or i64 z, KEY)        ; always = O at runtime
//   ptr   = gep i8, ptr pool, i64 idx
//
// KEY is derived from xorshift64(hash(function_name)) — different per
// function, stable across compilations.
//
// Effect on static analysis:
//   - IDA/Ghidra variable recovery fails: instead of named locals at fixed
//     stack offsets, analysts see pointer arithmetic into an opaque byte array.
//   - Stack layout cannot be reconstructed without resolving the volatile load.
//   - All local variables appear to share the same base pointer with opaque
//     byte offsets — making type recovery and alias analysis much harder.
//
// Usage in pipeline:
//   -passes=armorcomp-df       (annotation mode: only df-annotated fns)
//   -passes=armorcomp-df-all   (all mode: every eligible function)
//
// Source annotation:
//   __attribute__((annotate("df"))) int my_fn(...) { ... }
//
// Recommended pipeline position: after CO, before OUTLINE.
//   SUB → MBA → CO → DF → OUTLINE → BCF → OP → CFF
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

struct FlattenDataFlowPass : llvm::PassInfoMixin<FlattenDataFlowPass> {
  bool annotateOnly;

  explicit FlattenDataFlowPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
