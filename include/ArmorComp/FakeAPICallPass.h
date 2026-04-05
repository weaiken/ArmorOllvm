//===----------------------------------------------------------------------===//
// ArmorComp — FakeAPICallPass public interface
//
// Real libc API call injection pass declaration.
// Implementation: lib/FakeAPICallPass.cpp
//
// Algorithm (function-level pass):
//   For each basic block in annotate("fapi") functions (except entry block),
//   insert before the terminator:
//
//     %r0 = call i32 @getpid()           — or @getpagesize()
//     call void asm sideeffect "", "r"(i32 %r0)   — DCE sink
//
//   The asm sideeffect forces the compiler to retain the call result in a
//   register, preventing dead-code-elimination of the API call.
//
// Effect on static analysis:
//   - Unlike JunkCodePass (which uses arithmetic on dead variables), FAPI
//     injects real libc calls with genuine side effects.
//   - IDA/Ghidra cannot prove getpid()/getpagesize() are pure, so the call
//     instruction is never removed; the BB layout in the decompiler shows
//     seemingly-important system calls between actual logic.
//   - Hexdump / xrefs analysis is cluttered with libc entries.
//   - Anti-emulation bonus: getpid() returns different values in emulators
//     vs real devices; injecting it creates plausible anti-debug checks.
//
// Pipeline position:
//   After JCI (dead arithmetic chains), before CO (key hiding).
//   Position: DENC → JCI → FAPI → CO → GEPO → DF → ...
//
// Annotation: __attribute__((annotate("fapi")))
// Usage:
//   -passes=armorcomp-fapi       (annotation mode)
//   -passes=armorcomp-fapi-all   (all functions)
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"

struct FakeAPICallPass : llvm::PassInfoMixin<FakeAPICallPass> {
  bool annotateOnly;

  explicit FakeAPICallPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};
