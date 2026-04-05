//===----------------------------------------------------------------------===//
// ArmorComp — GlobalPointerObfuscationPass public interface
//
// Function-pointer global variable encryption pass declaration.
// Implementation: lib/GlobalPointerObfuscationPass.cpp
//
// Algorithm (module-level pass):
//   1. Find all globally-defined pointer-typed variables with non-null
//      function-pointer initializers in annotate("gpo")-using modules.
//   2. For each eligible global @gp with initializer @fn:
//      a. Compute K = xorshift64(FNV1a(gv_name)); K is an i64 key.
//      b. Create companion: @__armorcomp_gpo_enc_N = global i64 (ptrtoint(@fn) XOR K)
//      c. Set original @gp initializer to null (zeroinitializer).
//      d. Generate ctor decode body:
//           %enc = load volatile i64, @__armorcomp_gpo_enc_N
//           %pt  = xor i64 %enc, K
//           %ptr = inttoptr i64 %pt to ptr
//           store ptr %ptr, @gp
//   3. Generate a single module ctor __armorcomp_gpo_init that decodes all
//      encrypted globals and register it via appendToGlobalCtors(priority=10).
//
// Effect on static analysis:
//   - Function pointer globals appear null in .data at rest (in the binary).
//   - IDA / Ghidra cannot resolve vtable pointers, callback arrays, or jump
//     tables at analysis time — xrefs from the global to target functions are
//     missing.
//   - The decrypt-ctor performs a XOR on a runtime-loaded i64; tools that
//     trace ctor logic see a XOR with a compile-time constant, but the
//     original function address is not present in the binary.
//
// Eligibility:
//   - Global must be defined (not a declaration)
//   - Global type must be pointer (ptr)
//   - Initializer must be a non-null Function* (function pointer) or
//     a ConstantExpr (bitcast/ptrtoint of function)
//   - Global must NOT already be an __armorcomp_* symbol
//
// Pipeline position:
//   Module pass, runs right after GlobalEncPass (integer GV encryption):
//   STRENC → GENC → GPO → VMP → ...
//
// Annotation:
//   Applied to any function that uses the global (like GENC):
//   __attribute__((annotate("gpo"))) on the using function.
//   Or use armorcomp.yaml config to target specific globals by name.
//
// Usage:
//   -passes=armorcomp-gpo       (annotation mode)
//   -passes=armorcomp-gpo-all   (all eligible function pointer globals)
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"

struct GlobalPointerObfuscationPass
    : llvm::PassInfoMixin<GlobalPointerObfuscationPass> {
  bool annotateOnly;

  explicit GlobalPointerObfuscationPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Module &M,
                              llvm::ModuleAnalysisManager &AM);

  static bool isRequired() { return true; }
};
