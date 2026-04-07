#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — AntiTamperPass (防篡改完整性校验 Pass)
//
// 在目标函数中注入运行时完整性检查代码，检测代码/数据是否被篡改。
//
// 保护技术:
//   1. 函数 CRC32 校验和 — 检测函数体被修改
//   2. 关键全局变量完整性守护 — 检测 GV 被篡改
//   3. .text 段哈希校验 — 检测代码段被 patch
//   4. 自修改代码检测 — 检测运行时 patch
//
// 使用方式:
//   -passes=armorcomp-at       (注解模式)
//   -passes=armorcomp-at-all   (所有函数)
//
// 注解: __attribute__((annotate("at")))
//
// Pipeline 位置:
//   建议在所有混淆 Pass 之后运行，保护最终生成的代码。
//===----------------------------------------------------------------------===//

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"

namespace llvm {

struct AntiTamperPass : PassInfoMixin<AntiTamperPass> {
  bool annotateOnly;

  explicit AntiTamperPass(bool annotateOnly = true)
      : annotateOnly(annotateOnly) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};

} // namespace llvm
