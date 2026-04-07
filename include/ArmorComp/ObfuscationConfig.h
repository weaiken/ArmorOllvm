#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — ObfuscationConfig
//
// YAML-driven per-function pass selection.
//
// Config format (armorcomp.yaml):
//   functions:
//     - name: "exact_fn_name"       # exact match
//       passes: [cff, bcf, sub, mba]
//     - pattern: "^Java_"           # POSIX ERE regex
//       passes: [cff, bcf, icall, ibr]
//
// Activation (in priority order):
//   1. cl::opt  --armorcomp-config=<path>   (works with `opt`, not clang)
//   2. Env var  ARMORCOMP_CONFIG=<path>
//   3. Auto-discovery: armorcomp.yaml in CWD
//
// All passes call armorcomp::configSaysApply(fnName, passName) to check
// whether the config file enables a given pass for a given function.
//===----------------------------------------------------------------------===//

#include "llvm/ADT/StringRef.h"

#include <string>
#include <vector>

namespace armorcomp {

/// One rule entry in the YAML config.
struct FunctionRule {
  std::string name;                  ///< Exact function name (or empty)
  std::string pattern;               ///< POSIX ERE regex (or empty)
  std::vector<std::string> passes;   ///< Pass names to apply
};

/// Parsed representation of the YAML config file.
struct ObfuscationConfig {
  std::vector<FunctionRule> rules;

  /// Returns true if passName should be applied to fnName according to the
  /// loaded rules.  First matching rule wins; if no rule matches returns false.
  bool shouldApplyPass(llvm::StringRef fnName, llvm::StringRef passName) const;
};

/// Returns the global config singleton (loaded once from file).
/// Returns nullptr if no config file was found or parsing failed.
const ObfuscationConfig *getGlobalObfuscationConfig();

/// Convenience wrapper: returns true if the config says to apply passName
/// to fnName.  Returns false if no config is loaded.
bool configSaysApply(llvm::StringRef fnName, llvm::StringRef passName);

} // namespace armorcomp
