//===----------------------------------------------------------------------===//
// ArmorComp — ObfuscationConfig
//
// YAML-based per-function pass selection (no source annotations required).
//
// Activation (with clang -fpass-plugin):
//   ARMORCOMP_CONFIG=/path/to/armorcomp.yaml \
//     clang -fpass-plugin=ArmorComp.dylib source.c -o output
//
// Note: clang loads pass plugins AFTER command-line parsing, so -mllvm flags
// cannot be used to pass the config path.  Use the ARMORCOMP_CONFIG env var
// instead.  When using `opt` directly, -armorcomp-config=<path> also works.
//
// Config format (YAML):
// ──────────────────────
//   functions:
//     - name: "verify_license"          # exact function name
//       passes: [cff, bcf, sub, mba, icall, ibr, igv]
//
//     - pattern: "^Java_"               # POSIX ERE, matches any function name
//       passes: [cff, bcf, icall, ibr]
//
//     - pattern: "^secure_"
//       passes: [strenc, split, sub, cff]
//
// Pass names (same as annotation strings):
//   cff, bcf, sub, mba, split, strenc, icall, ibr, igv
//
// Semantics:
//   - Config rules are evaluated top-to-bottom; first matching rule wins.
//   - Config is additive with __attribute__((annotate(...))):
//     a function is transformed if EITHER the annotation OR a config rule
//     says to apply the pass.
//   - If no config file is specified, all behaviour is annotation-driven
//     (backward-compatible).
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/ADT/StringRef.h"

#include <string>
#include <vector>

namespace armorcomp {

// ─────────────────────────────────────────────────────────────────────────────
// Data structures
// ─────────────────────────────────────────────────────────────────────────────

/// One entry in the config `functions:` list.
struct FunctionRule {
  /// Exact function name to match (mutually exclusive with pattern).
  std::string name;

  /// POSIX ERE pattern matched against the function name (mutually exclusive
  /// with name).  An anchored pattern like "^Java_" is recommended.
  std::string pattern;

  /// Pass names to apply when this rule matches.
  /// Valid values: cff, bcf, sub, mba, split, strenc, icall, ibr, igv
  std::vector<std::string> passes;
};

/// Parsed representation of armorcomp.yaml.
struct ObfuscationConfig {
  std::vector<FunctionRule> rules;

  /// Returns true if any rule matches `fnName` and lists `passName`.
  /// Rules are evaluated top-to-bottom; the first matching rule is used.
  bool shouldApplyPass(llvm::StringRef fnName,
                       llvm::StringRef passName) const;

  bool empty() const { return rules.empty(); }
};

// ─────────────────────────────────────────────────────────────────────────────
// Global config accessor (loaded lazily from -armorcomp-config=<path>)
// ─────────────────────────────────────────────────────────────────────────────

/// Returns a pointer to the process-wide ObfuscationConfig, or nullptr if
/// no config file was specified or parsing failed.
///
/// Thread-safety: this function is NOT thread-safe.  LLVM pass pipelines are
/// single-threaded by default, so this is fine for normal use.
const ObfuscationConfig *getGlobalObfuscationConfig();

/// Helper: returns true if the global config says to apply `passName` to `fn`.
/// Returns false (not "true") when no config is loaded — callers still fall
/// back to annotation-driven selection.
bool configSaysApply(llvm::StringRef fnName, llvm::StringRef passName);

} // namespace armorcomp
