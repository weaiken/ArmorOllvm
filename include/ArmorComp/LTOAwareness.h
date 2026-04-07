#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — LTOAwareness (LTO 感知的混淆支持)
//
// 当使用 -flto (Link Time Optimization) 编译时，LLVM 的 Pass 管道会变化:
//   - ThinLTO: 每个 Module 是部分编译单元，需要跨模块信息
//   - FullLTO: 所有代码合并为单个 Module，需要避免 O(N²) 复杂度
//   - Regular: 标准 Per-Module 编译，无特殊需求
//
// 本头文件提供:
//   1. LTO 模式检测接口
//   2. 跨模块函数可见性控制
//   3. LTO-safe 的全局变量管理
//   4. ThinLTO Summary 信息利用 (选择性混淆)
//===----------------------------------------------------------------------===//

#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"

namespace armorcomp {
namespace lto {

/// LTO 编译模式枚举
enum class LTOMode {
  None,      // 非 LTO 编译 (-flto 未启用)
  Thin,      // ThinLTO (默认 -flto=thin)
  Full       // FullLTO (-flto=full)
};

/// 检测当前编译是否处于 LTO 模式
///
/// 检测方法:
///   1. 检查 Module 标志中的 "ThinLTO" / "FullLTO" 属性
///   2. 检查是否存在 __llvm_profile_* 全局变量 (PGO + LTO)
///   3. 检查 Module 的大小和结构特征
static LTOMode detectLTOMode(const llvm::Module &M) {
  // 方法 1: 检查 Module flags
  if (auto *MD = M.getModuleFlagsMetadata()) {
    for (unsigned i = 0, e = MD->getNumOperands(); i < e; ++i) {
      auto *Entry = llvm::cast<llvm::MDNode>(MD->getOperand(i));
      auto *Str = llvm::cast<llvm::MDString>(Entry->getOperand(1));

      if (Str->getString() == "ThinLTO")
        return LTOMode::Thin;
      if (Str->getString() == "FullLTO")
        return LTOMode::Full;
    }
  }

  // 方法 2: 启发式检测 (基于 Module 特征)
  // FullLTO 通常合并了大量函数
  if (M.size() > 1000 && M.getName().empty())
    return LTOMode::Full;

  // 默认: 非 LTO
  return LTOMode::None;
}

/// 判断函数是否应该被混淆 (考虑 LTO 可见性)
///
/// 在 LTO 模式下:
//    - 内联函数 (internal linkage) 可以安全混淆
//    - 外部可见函数 (external linkage) 需要谨慎:
//      * 如果是 API 函数 → 不混淆或仅轻量混淆
//      * 如果是内部实现但被错误标记为 external → 需要用户注解
///
/// @param F 要检查的函数
/// @param mode 当前 LTO 模式
/// @return true 如果可以安全混淆
inline bool canSafelyObfuscate(const llvm::Function &F,
                                LTOMode mode) {
  switch (mode) {
    case LTOMode::None:
      // 非 LTO: 所有非声明函数都可以混淆
      return !F.isDeclaration();

    case LTOMode::Thin:
      // ThinLTO: 仅处理定义在本 Module 且非外部引用的函数
      if (F.isDeclaration())
        return false;

      // 有外部使用记录的函数需要谨慎
      if (!F.hasLocalLinkage() &&
          !F.hasFnAttribute("armorcomp-force-obfuscate"))
        return false;

      return true;

    case LTOMode::Full:
      // FullLTO: 所有函数都在本 Module 中
      // 但要保留 C 运行时库等关键函数
      if (F.isDeclaration())
        return false;

      // 跳过已知的运行时函数
      StringRef name = F.getName();
      if (name.startswith("__") ||
          name.startswith("_ZSt") ||  // STL 内部
          name.startswith("llvm."))   // LLVM intrinsics
        return false;

      return true;
  }
}

/// 为 LTO 模式调整混淆强度
///
/// 在 LTO 下可能需要降低某些 Pass 的强度以避免:
//    - 过长的编译时间
//    - 过大的代码膨胀
//    - 跨模块调用图破坏
///
/// @param baseStrength 基础强度值 (0-5)
/// @param mode LTO 模式
/// @return 调整后的强度值
inline int adjustStrengthForLTO(int baseStrength, LTOMode mode) {
  switch (mode) {
    case LTOMode::None:
      return baseStrength;

    case LTOMode::Thin:
      // ThinLTO: 轻微降低 (减少跨模块影响)
      return std::max(1, baseStrength - 1);

    case LTOMode::Full:
      // FullLTO: 显著降低 (避免 O(N²))
      return std::max(1, baseStrength - 2);
  }
}

/// 打印 LTO 相关的诊断信息
static void printLTODiagnostics(const llvm::Module &M) {
  LTOMode mode = detectLTOMode(M);

  const char *modeStr = "";
  switch (mode) {
    case LTOMode::None: modeStr = "None"; break;
    case LTOMode::Thin: modeStr = "ThinLTO"; break;
    case LTOMode::Full: modeStr = "FullLTO"; break;
  }

  errs() << "[ArmorComp][LTO] detected mode: " << modeStr
         << " (functions: " << M.size()
         << ", globals: " << M.global_size() << ")\n";
}

} // namespace lto
} // namespace armorcomp
