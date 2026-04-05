//===----------------------------------------------------------------------===//
// ArmorComp — ObfuscationConfig implementation
//
// YAML config format:
//   functions:
//     - name: "exact_fn_name"
//       passes: [cff, bcf, sub]
//     - pattern: "^Java_"
//       passes: [cff, bcf, icall, ibr]
//
// Parsing uses the low-level llvm::yaml::YAMLParser (YAMLParser.h) to avoid
// template-specialization conflicts with LLVM's internal YAMLTraits use.
//===----------------------------------------------------------------------===//

#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Regex.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/YAMLParser.h"
#include "llvm/Support/raw_ostream.h"

#include <memory>
#include <string>
#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Config path resolution
// ─────────────────────────────────────────────────────────────────────────────
//
// IMPORTANT: -fpass-plugin DSOs are loaded during LLVM backend init, which
// happens AFTER cl::ParseCommandLineOptions() has already run.  Therefore
// cl::opt cannot be used to receive -mllvm -armorcomp-config=... from clang.
//
// Two supported mechanisms (in priority order):
//
//   1. Environment variable  ARMORCOMP_CONFIG=/path/to/armorcomp.yaml
//      Set this before running clang; works in any build system.
//
//   2. Auto-discovery       armorcomp.yaml in the current working directory
//      Convenient for project-local configs (checked last).
//
// Legacy cl::opt "armorcomp-config" is still registered so the option is
// usable when invoking the plugin via `opt -load-pass-plugin ... -passes=...`
// (where command-line parsing happens AFTER plugin loading).

static cl::opt<std::string> ArmorCompConfigPath(
    "armorcomp-config",
    cl::desc("Path to ArmorComp YAML configuration file "
             "(for use with `opt`; use ARMORCOMP_CONFIG env var with clang)"),
    cl::value_desc("filename"),
    cl::init(""));

/// Returns the config file path to use, or empty string if none.
static std::string resolveConfigPath() {
  // Priority 1: explicit cl::opt (works with `opt`, not with clang)
  if (!ArmorCompConfigPath.empty())
    return ArmorCompConfigPath.getValue();

  // Priority 2: environment variable
  if (const char *envPath = std::getenv("ARMORCOMP_CONFIG"))
    return envPath;

  // Priority 3: auto-discovery — armorcomp.yaml in CWD
  if (llvm::sys::fs::exists("armorcomp.yaml"))
    return "armorcomp.yaml";

  return "";
}

// ─────────────────────────────────────────────────────────────────────────────
// shouldApplyPass
// ─────────────────────────────────────────────────────────────────────────────

bool armorcomp::ObfuscationConfig::shouldApplyPass(StringRef fnName,
                                                    StringRef passName) const {
  for (const auto &rule : rules) {
    // Step 1: does the rule match the function?
    bool matches = false;

    if (!rule.name.empty()) {
      matches = (fnName == rule.name);
    } else if (!rule.pattern.empty()) {
      Regex re(rule.pattern);
      std::string errMsg;
      if (!re.isValid(errMsg)) {
        errs() << "[ArmorComp][Config] invalid regex \"" << rule.pattern
               << "\": " << errMsg << "\n";
        continue;
      }
      matches = re.match(fnName);
    }

    if (!matches) continue;

    // Step 2: does this rule list the requested pass?
    for (const auto &p : rule.passes) {
      if (StringRef(p) == passName) return true;
    }

    // First matching rule wins (no pass listed → don't apply).
    return false;
  }

  return false; // no rule matched
}

// ─────────────────────────────────────────────────────────────────────────────
// YAML parsing helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the string value of a ScalarNode into a std::string.
static std::string scalarValue(yaml::ScalarNode *SN) {
  SmallString<128> storage;
  return SN->getValue(storage).str();
}

/// Parse a passes sequence node into a vector of pass-name strings.
static void parsePassesList(yaml::SequenceNode *seq,
                            std::vector<std::string> &out) {
  if (!seq) return;
  for (auto &elem : *seq) {
    auto *S = dyn_cast<yaml::ScalarNode>(&elem);
    if (S) out.push_back(scalarValue(S));
  }
}

/// Parse one function-rule mapping node.
static bool parseFunctionRule(yaml::MappingNode *map,
                               armorcomp::FunctionRule &rule) {
  for (auto &KV : *map) {
    auto *K = dyn_cast<yaml::ScalarNode>(KV.getKey());
    if (!K) continue;
    SmallString<32> keyStorage;
    StringRef key = K->getValue(keyStorage);

    yaml::Node *V = KV.getValue();

    if (key == "name") {
      auto *S = dyn_cast<yaml::ScalarNode>(V);
      if (S) rule.name = scalarValue(S);
    } else if (key == "pattern") {
      auto *S = dyn_cast<yaml::ScalarNode>(V);
      if (S) rule.pattern = scalarValue(S);
    } else if (key == "passes") {
      auto *seq = dyn_cast<yaml::SequenceNode>(V);
      parsePassesList(seq, rule.passes);
    }
    // Unknown keys are silently ignored for forward-compatibility.
  }

  // A rule must have either a name or a pattern, and at least one pass.
  if (rule.name.empty() && rule.pattern.empty()) {
    errs() << "[ArmorComp][Config] rule has neither 'name' nor 'pattern' — "
              "skipped\n";
    return false;
  }
  if (rule.passes.empty()) {
    errs() << "[ArmorComp][Config] rule for \""
           << (rule.name.empty() ? rule.pattern : rule.name)
           << "\" has no passes — skipped\n";
    return false;
  }
  return true;
}

/// Parse the top-level YAML document into an ObfuscationConfig.
static bool parseYAMLConfig(StringRef buffer,
                             armorcomp::ObfuscationConfig &cfg) {
  SourceMgr SM;
  yaml::Stream YS(buffer, SM);

  auto docIt = YS.begin();
  if (docIt == YS.end()) {
    errs() << "[ArmorComp][Config] empty YAML document\n";
    return false;
  }

  auto *Root = dyn_cast_or_null<yaml::MappingNode>(docIt->getRoot());
  if (!Root) {
    errs() << "[ArmorComp][Config] top-level must be a YAML mapping\n";
    return false;
  }

  for (auto &KV : *Root) {
    auto *K = dyn_cast<yaml::ScalarNode>(KV.getKey());
    if (!K) continue;
    SmallString<32> keyStorage;
    StringRef key = K->getValue(keyStorage);

    if (key != "functions") continue; // ignore unknown top-level keys

    auto *funcSeq = dyn_cast<yaml::SequenceNode>(KV.getValue());
    if (!funcSeq) {
      errs() << "[ArmorComp][Config] 'functions' must be a sequence\n";
      continue;
    }

    for (auto &elem : *funcSeq) {
      auto *ruleMap = dyn_cast<yaml::MappingNode>(&elem);
      if (!ruleMap) continue;

      armorcomp::FunctionRule rule;
      if (parseFunctionRule(ruleMap, rule))
        cfg.rules.push_back(std::move(rule));
    }
  }

  return !cfg.rules.empty();
}

// ─────────────────────────────────────────────────────────────────────────────
// Global config singleton
// ─────────────────────────────────────────────────────────────────────────────

/// Loads the config file, populates the singleton, and returns a pointer to it.
/// Returns nullptr if no path was given or parsing failed.
static const armorcomp::ObfuscationConfig *loadConfig() {
  static armorcomp::ObfuscationConfig cfg;

  std::string path = resolveConfigPath();
  if (path.empty()) return nullptr;

  auto bufOrErr = MemoryBuffer::getFile(path);
  if (!bufOrErr) {
    errs() << "[ArmorComp][Config] cannot open \""
           << path << "\": "
           << bufOrErr.getError().message() << "\n";
    return nullptr;
  }

  StringRef buffer = (*bufOrErr)->getBuffer();
  if (!parseYAMLConfig(buffer, cfg)) {
    errs() << "[ArmorComp][Config] no valid rules loaded from \""
           << path << "\"\n";
    return nullptr;
  }

  errs() << "[ArmorComp][Config] loaded " << cfg.rules.size()
         << " rule(s) from \"" << path << "\"\n";
  return &cfg;
}

const armorcomp::ObfuscationConfig *
armorcomp::getGlobalObfuscationConfig() {
  // Lazy initialisation — safe in single-threaded LLVM pass pipelines.
  static const armorcomp::ObfuscationConfig *instance = loadConfig();
  return instance;
}

bool armorcomp::configSaysApply(StringRef fnName, StringRef passName) {
  const ObfuscationConfig *cfg = getGlobalObfuscationConfig();
  if (!cfg) return false;
  return cfg->shouldApplyPass(fnName, passName);
}
