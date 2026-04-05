//===----------------------------------------------------------------------===//
// ArmorComp — StrEncPass (String Encryption) public interface
//
// Module-level pass that XOR-encrypts all string literal globals that are
// exclusively referenced by annotated functions, then injects a module
// constructor (__armorcomp_str_init) that decrypts them in-place at startup.
//
// Effect:
//   - "strings" / grep analysis on the binary finds only ciphertext.
//   - Ghidra / IDA string cross-references point to unreadable data.
//   - At runtime the constructor decrypts everything before main() runs,
//     so the program behaves identically.
//
// Encryption:
//   - XOR with a 4-byte key derived from hash(GlobalVariable.name).
//   - Deterministic: same source → same binary.
//   - The string global is changed from `constant` to non-constant so
//     the compiler cannot constant-fold loads through it.
//
// Usage:
//   -passes=armorcomp-strenc       (annotation mode)
//   -passes=armorcomp-strenc-all   (all string globals in the module)
//
// Source annotation:
//   __attribute__((annotate("strenc"))) int my_fn(...) { ... }
//
// Note: only strings exclusively used by annotated functions are encrypted,
// to avoid breaking non-annotated callers.  For a string shared between an
// annotated and a non-annotated function, skip encryption.
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

struct StrEncPass : llvm::PassInfoMixin<StrEncPass> {
  bool annotateOnly;

  explicit StrEncPass(bool annotateOnly = true) : annotateOnly(annotateOnly) {}

  /// Module-level entry point.
  llvm::PreservedAnalyses run(llvm::Module &M,
                              llvm::ModuleAnalysisManager &AM);

  static bool isRequired() { return true; }
};
