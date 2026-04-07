#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — AntiDebugPass (反调试检测 Pass)
//
// 在目标函数中注入多层反调试检测代码，防止运行时被调试器附加。
//
// 检测技术:
//   1. ptrace(PTRACE_TRACEME) 自身附加检测 — Linux/Android
//   2. /proc/self/status TracerPid 检查 — Linux/Android
//   3. sysconf(_SC_NPROCESSORS_ONLN) 时间差异检测
//   4. 父进程名检测 (调试器特征)
//   5. 环境变量检测 (LD_PRELOAD 等)
//
// 使用方式:
//   -passes=armorcomp-adb       (注解模式)
//   -passes=armorcomp-adb-all   (所有函数)
//
// 注解: __attribute__((annotate("adb")))
//
// Pipeline 位置:
//   建议在 VMP 之后、SPLIT 之前运行，使反调试代码也被后续 Pass 混淆。
//===----------------------------------------------------------------------===//

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"

namespace llvm {

struct AntiDebugPass : PassInfoMixin<AntiDebugPass> {
  bool annotateOnly;

  explicit AntiDebugPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};

} // namespace llvm
