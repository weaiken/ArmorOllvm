#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — ObfuscationGlobals (统一 volatile global 变量管理)
//
// 消除 7+ 个 Pass 中重复的 volatile zero global 创建逻辑。
// 提供统一的、类型安全的全局变量管理接口。
//
// 使用场景:
//   - JCI: __armorcomp_jci_zero
//   - CO: __armorcomp_co_zero
//   - OP: __armorcomp_op_zero
//   - DF: __armorcomp_df_zero
//   - ICall: __armorcomp_icall_off
//   - IBr: __armorcomp_ibr_off
//   - BCF: __armorcomp_opaque_key
//===----------------------------------------------------------------------===//

#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/Alignment.h"

namespace armorcomp {

/// 获取或创建一个 volatile zero 全局变量
///
/// 统一管理所有混淆 Pass 需要的 volatile zero global。
/// 每个名称只创建一次 (getOrCreate 语义)。
///
/// @param M          所属 Module
/// @param name       全局变量名
/// @param Ty         变量类型 (通常是 i64 或 i32)
/// @param alignment  对齐要求 (默认 8 字节)
/// @return 已存在或新创建的 GlobalVariable*
inline llvm::GlobalVariable *getOrCreateVolatileZero(llvm::Module &M,
                                                      llvm::StringRef name,
                                                      llvm::Type *Ty,
                                                      unsigned alignment = 8) {
  if (auto *Existing = M.getNamedGlobal(name))
    return Existing;

  auto *GV = new llvm::GlobalVariable(
      M, Ty,
      /*isConstant=*/false,
      llvm::GlobalValue::WeakAnyLinkage,
      llvm::ConstantInt::get(Ty, 0),
      name);
  GV->setAlignment(llvm::Align(alignment));
  return GV;
}

/// 预定义的 volatile zero global 名称常量
namespace Globals {
  constexpr const char *JCI_ZERO     = "__armorcomp_jci_zero";      // JunkCodePass
  constexpr const char *CO_ZERO      = "__armorcomp_co_zero";       // ConstObfPass
  constexpr const char *OP_ZERO      = "__armorcomp_op_zero";       // OpaquePredicatePass
  constexpr const char *DF_ZERO      = "__armorcomp_df_zero";       // FlattenDataFlowPass
  constexpr const char *ICALL_OFF    = "__armorcomp_icall_off";      // IndirectCallPass
  constexpr const char *IBR_OFF      = "__armorcomp_ibr_off";        // IndirectBranchPass
  constexpr const char *BCF_OPAQUE   = "__armorcomp_opaque_key";     // BCFPass
  constexpr const char *NTC_ZERO     = "__armorcomp_ntc_zero";      // NeonTypeConfusionPass
  constexpr const char *RVO_ZERO     = "__armorcomp_rvo_zero";      // ReturnValueObfPass
  constexpr const char *SPO_ZERO     = "__armorcomp_spo_zero";      // SPOPass
}

/// 快捷获取函数: 各 Pass 专用
namespace quick {

/// 获取 JCI 的 volatile i64 zero
inline llvm::GlobalVariable *jciZero(llvm::Module &M) {
  return getOrCreateVolatileZero(M, Globals::JCI_ZERO,
                                  llvm::Type::getInt64Ty(M.getContext()));
}

/// 获取 CO 的 volatile i64 zero
inline llvm::GlobalVariable *coZero(llvm::Module &M) {
  return getOrCreateVolatileZero(M, Globals::CO_ZERO,
                                  llvm::Type::getInt64Ty(M.getContext()));
}

/// 获取 OP 的 volatile i64 zero
inline llvm::GlobalVariable *opZero(llvm::Module &M) {
  return getOrCreateVolatileZero(M, Globals::OP_ZERO,
                                  llvm::Type::getInt64Ty(M.getContext()));
}

/// 获取 DF 的 volatile i64 zero
inline llvm::GlobalVariable *dfZero(llvm::Module &M) {
  return getOrCreateVolatileZero(M, Globals::DF_ZERO,
                                  llvm::Type::getInt64Ty(M.getContext()));
}

/// 获取 ICall 的 volatile pointer-sized zero
inline llvm::GlobalVariable *icallOff(llvm::Module &M, llvm::Type *IPtrTy) {
  return getOrCreateVolatileZero(M, Globals::ICALL_OFF, IPtrTy);
}

/// 获取 IBr 的 volatile pointer-sized zero
inline llvm::GlobalVariable *ibrOff(llvm::Module &M, llvm::Type *IPtrTy) {
  return getOrCreateVolatileZero(M, Globals::IBR_OFF, IPtrTy);
}

/// 获取 BCF 的 opaque key (i32)
inline llvm::GlobalVariable *bcfOpaqueKey(llvm::Module &M) {
  return getOrCreateVolatileZero(M, Globals::BCF_OPAQUE,
                                  llvm::Type::getInt32Ty(M.getContext()));
}

} // namespace quick

} // namespace armorcomp
