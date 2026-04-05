//===----------------------------------------------------------------------===//
// ArmorComp — GlobalEncPass public interface
//
// Integer global variable encryption pass declaration.
// Implementation: lib/GlobalEncPass.cpp
//
// Algorithm (module-level pass, analogous to StrEncPass):
//   For each integer global @gv = global iN X used by an annotate("genc")
//   function:
//     1. Replace the initializer with the ciphertext: (X ^ K)
//     2. setConstant(false) — ensures the symbol lives in writable .data
//     3. Inject __armorcomp_genc_init ctor to XOR-decrypt at startup:
//          %ct = load volatile iN, ptr @gv
//          %pt = xor  iN %ct, K
//          store iN %pt, ptr @gv
//
//   K = xorshift64(FNV1a(global_name)) — deterministic per global,
//   different for every global, stable across compilations.
//
// Effect on static analysis:
//   - String-search tools that scan .data for magic constants find only
//     scrambled ciphertext values.
//   - IDA/Ghidra display wrong values for annotated globals; the analyst
//     must trace the ctor to understand the actual runtime value.
//   - The ctor itself only shows XOR constants (keys), not plaintext.
//
// Eligible globals:
//   - Defined in this module (not declarations)
//   - Integer type: i8 / i16 / i32 / i64
//   - Non-zero ConstantInt initializer
//   - Not llvm.* or __armorcomp_* namespace
//
// Usage in pipeline:
//   -passes=armorcomp-genc       (annotation mode: globals used by genc fns)
//   -passes=armorcomp-genc-all   (all mode: every eligible global)
//
// Source annotation (on the using function, not the global):
//   __attribute__((annotate("genc"))) int my_fn(...) { /* uses g_key */ }
//
// Recommended pipeline position: right after STRENC (both are data-section
// encryption passes), before function-level transforms.
//   STRENC → GENC → SPLIT → SUB → MBA → CO → DF → OUTLINE → BCF → ...
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"

struct GlobalEncPass : llvm::PassInfoMixin<GlobalEncPass> {
  bool annotateOnly;

  explicit GlobalEncPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Module &M,
                              llvm::ModuleAnalysisManager &AM);

  static bool isRequired() { return true; }
};
