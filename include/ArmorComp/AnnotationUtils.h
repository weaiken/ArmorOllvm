#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — AnnotationUtils (统一注解检测工具)
//
// 消除各 Pass 中重复的 hasXXXAnnotation() 函数。
// 提供统一的注解检测、配置检查和函数过滤接口。
//===----------------------------------------------------------------------===//

#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/ADT/StringRef.h"

namespace armorcomp {

/// 检查函数 F 是否有指定的 __attribute__((annotate("tag")))
inline bool hasAnnotation(const llvm::Function &F, llvm::StringRef tag) {
  const llvm::Module *M = F.getParent();
  if (!M) return false;

  const llvm::GlobalVariable *GV =
      M->getGlobalVariable("llvm.global.annotations");
  if (!GV || !GV->hasInitializer()) return false;

  const auto *arr =
      llvm::dyn_cast<llvm::ConstantArray>(GV->getInitializer());
  if (!arr) return false;

  for (unsigned i = 0, e = arr->getNumOperands(); i < e; ++i) {
    const auto *cs =
        llvm::dyn_cast<llvm::ConstantStruct>(arr->getOperand(i));
    if (!cs || cs->getNumOperands() < 2) continue;

    if (cs->getOperand(0)->stripPointerCasts() != &F) continue;

    const auto *strGV = llvm::dyn_cast<llvm::GlobalVariable>(
        cs->getOperand(1)->stripPointerCasts());
    if (!strGV || !strGV->hasInitializer()) continue;

    const auto *strData =
        llvm::dyn_cast<llvm::ConstantDataArray>(strGV->getInitializer());
    if (strData && strData->getAsCString() == tag) return true;
  }
  return false;
}

/// 组合检查: 注解 OR 配置文件 OR 全量模式
inline bool shouldTransform(const llvm::Function &F,
                            llvm::StringRef tag,
                            bool annotateOnly) {
  if (!annotateOnly) return true;
  if (hasAnnotation(F, tag)) return true;
  if (armorcomp::configSaysApply(F.getName(), tag)) return true;
  return false;
}

/// 跳过条件集合 (大多数 Pass 都需要这些检查)
inline bool shouldSkip(const llvm::Function &F) {
  if (F.isDeclaration()) return true;
  if (F.empty()) return true;
  if (F.getName().startswith("__armorcomp_")) return true;
  return false;
}

} // namespace armorcomp
