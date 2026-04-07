#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — ControlFlowRandomizationPass (控制流随机布局 Pass)
//
// 随机化函数内基本块的布局顺序，增加静态分析的难度。
//
// 技术原理:
//   正常编译器生成的代码中，基本块按拓扑排序或执行频率排列。
//   这使得反编译器 (IDA Pro, Ghidra) 能够轻松重建控制流图。
//
//   本 Pass 打乱基本块在函数中的物理顺序，同时保持:
//   - 入口块保持在函数开头 (或伪装入口)
//   - 控制流语义完全不变
//   - 调试信息更新 (如果存在)
//
// 高级特性:
//   1. 虚假入口点: 创建多个看起来像入口的块，只有一个真正执行
//   2. 块分裂: 将大块随机拆分为小块后重排
//   3. 冷热分离干扰: 故意打乱热点分析预测
//
// 使用方式:
//   -passes=armorcomp-cfr       (注解模式)
//   -passes=armorcomp-cfr-all   (所有函数)
//
// 注解: __attribute__((annotate("cfr")))
//
// Pipeline 位置:
//   建议在 CFF/BCF 之后运行，因为那些 Pass 会改变 CFG 结构。
//===----------------------------------------------------------------------===//

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"

namespace llvm {

struct ControlFlowRandomizationPass : PassInfoMixin<ControlFlowRandomizationPass> {
  bool annotateOnly;
  bool splitBlocks;      // 是否先分裂大块
  bool fakeEntries;      // 是否添加虚假入口

  explicit ControlFlowRandomizationPass(bool annotateOnly = true,
                                         bool splitBlocks = false,
                                         bool fakeEntries = false)
      : annotateOnly(annotateOnly),
        splitBlocks(splitBlocks),
        fakeEntries(fakeEntries) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};

} // namespace llvm
