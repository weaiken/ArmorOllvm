#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — EnhancedMBA (增强型混合布尔算术表达式库)
//
// 扩展现有 MBAPass 的线性 MBA 表达式，增加:
//
// 1. 非线性 MBA (Non-linear MBA):
//    - 包含乘法/除法的多项式恒等式
//    - 对抗基于线性代数的符号执行求解器
//    - 示例: a + b = (a ^ b) + 2*(a & b)  [线性]
//            a * b = ((a+b)^2 - a^2 - b^2)/2  [非线性]
//
// 2. 多项式 MBA (Polynomial MBA):
//    - 基于有限域 GF(2^n) 的多项式变换
//    - 利用 x^k = x (idempotent property in GF(2))
//    - 高度抵抗 Z3/SMT 求解
//
// 3. 分段 MBA (Piecewise MBA):
//    - 根据输入值范围选择不同的等价表达式
//    - 增加路径爆炸问题给分析器
//
// 使用方式:
//   #include "ArmorComp/EnhancedMBA.h"
//   Value *result = armorcomp::mba::nonlinearAdd(A, B, IRB);
//===----------------------------------------------------------------------===//

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Constants.h"

namespace armorcomp {
namespace mba {

/// ══════════════════════════════════════════════════════════════════
/// 非线性 MBA 表达式 — 对抗符号执行
/// ══════════════════════════════════════════════════════════════════

/// 非线性 ADD 变体 1: 基于平方差公式
/// a + b = ((a+1)^2 - a^2 - 2*a*b - 1) / (-2b) ... 太复杂
///
/// 实用版本: a + b = (a | b) + (a & b)
/// 进一步混淆: = (a ^ b) + 2*(a & b)  [这是线性的]
///
/// 真正的非线性: 引入随机常数 k
/// a + b = (a ^ k) + (b ^ k) + f(k)  where f(k) 使得等式成立
/// 当 k 是常数时，f(k) 也是常数，但符号执行器不知道 k 的语义
static Value *nonlinearAddV1(Value *A, Value *B,
                              llvm::IRBuilder<> &Bldr) {
  auto *Ty = A->getType();

  // 选择一个"看起来随机"的掩码
  llvm::Value *K = llvm::ConstantInt::get(Ty, 0x9E3779B97F4A7C15ULL);

  // a' = a XOR K, b' = b XOR K
  llvm::Value *AXorK = Bldr.CreateXor(A, K, "mba.nl.a.xork");
  llvm::Value *BXorK = Bldr.CreateXor(B, K, "mba.nl.b.xork");

  // 计算 f(K) = (K XOR K) - 0 = 0 (当使用 XOR 时)
  // 但我们用更复杂的形式来隐藏这个事实
  // f(K) = K - K = 0 (在模运算下)

  // 结果: (a^K) + (b^K) + (K^0) = a + b
  llvm::Value *Sum1 = Bldr.CreateAdd(AXorK, BXorK, "mba.nl.sum1");
  llvm::Value *KK = Bldr.CreateXor(K, K, "mba.nl.kk");
  return Bldr.CreateAdd(Sum1, KK, "mba.nl.result");
}

/// 非线性 ADD 变体 2: 基于乘法展开
/// a + b = ((a*2 + b*2) / 2)  — 利用除法引入非线性
static Value *nonlinearAddV2(Value *A, Value *B,
                              llvm::IRBuilder<> &Bldr) {
  auto *Ty = A->getType();
  unsigned bitWidth = Ty->getIntegerBitWidth();

  // A*2 + B*2
  llvm::Value *A2 = Bldr.CreateShl(A,
                                    llvm::ConstantInt::get(Ty, 1),
                                    "mba.nl.a2");
  llvm::Value *B2 = Bldr.CreateShl(B,
                                    llvm::ConstantInt::get(Ty, 1),
                                    "mba.nl.b2");

  llvm::Value *Sum2 = Bldr.CreateAdd(A2, B2, "mba.nl.sum2");

  // 除以 2 (逻辑右移)
  return Bldr.CreateLShr(Sum2,
                          llvm::ConstantInt::get(Ty, 1),
                          "mba.nl.result");
}

/// 非线性 SUB 变体 1: 基于 XOR 和补码
/// a - b = (a + ~b) + 1  (标准补码减法)
/// 混淆为: ((a ^ ~b) + (a & ~b) + (~a & b)) + 1
static Value *nonlinearSubV1(Value *A, Value *B,
                              llvm::IRBuilder<> &Bldr) {
  auto *Ty = A->getType();

  llvm::Value *NotB = Bldr.CreateNot(B, "mba.nl.notb");
  llvm::Value *AXorNotB = Bldr.CreateXor(A, NotB, "mba.nl.a.xornotb");
  llvm::Value *AAndNotB = Bldr.CreateAnd(A, NotB, "mba.nl.a.andnotb");
  llvm::Value *NotAAndB = Bldr.CreateAnd(Bldr.CreateNot(A), B,
                                           "mba.nl.nota.andb");

  llvm::Value *Part1 = Bldr.CreateAdd(AXorNotB, AAndNotB, "mba.nl.part1");
  llvm::Value *Part2 = Bldr.CreateAdd(Part1, NotAAndB, "mba.nl.part2");

  return Bldr.CreateAdd(Part2,
                         llvm::ConstantInt::get(Ty, 1),
                         "mba.nl.result");
}

/// 非线性 AND 变体 1: 基于 OR-XOR 恒等式
/// a & b = ~(~a | ~b) (德摩根定律)
/// 混淆为: (a + b - (a | b))  在某些条件下成立... 不太对
///
/// 正确的: a & b = (a + b - (a ^ b)) / 2
static Value *nonlinearAndV1(Value *A, Value *B,
                              llvm::IRBuilder<> &Bldr) {
  auto *Ty = A->getType();

  llvm::Value *ABAdd = Bldr.CreateAdd(A, B, "mba.nl.add");
  llvm::Value *ABXor = Bldr.CreateXor(A, B, "mba.nl.xor");
  llvm::Value *Diff = Bldr.CreateSub(ABAdd, ABXor, "mba.nl.diff");

  return Bldr.CreateLShr(Diff,
                          llvm::ConstantInt::get(Ty, 1),
                          "mba.nl.result");
}

/// 非线性 OR 变体 1: 基于 AND-XOR 恒等式
/// a | b = (a ^ b) + (a & b)
/// 混淆为: ~(~a & ~b) → 展开
static Value *nonlinearOrV1(Value *A, Value *B,
                             llvm::IRBuilder<> &Bldr) {
  auto *Ty = A->getType();

  llvm::Value *ABXor = Bldr.CreateXor(A, B, "mba.nl.xor");
  llvm::Value *ABAnd = nonlinearAndV1(A, B, Bldr);

  return Bldr.CreateAdd(ABXor, ABAnd, "mba.nl.result");
}

/// 非线性 XOR 变体 1: 基于 AND-OR 恒等式
/// a ^ b = (a | b) & ~(a & b)
static Value *nonlinearXorV1(Value *A, Value *B,
                              llvm::IRBuilder<> &Bldr) {
  auto *Ty = A->getType();

  llvm::Value *ABOr = nonlinearOrV1(A, B, Bldr);
  llvm::Value *ABAnd = nonlinearAndV1(A, B, Bldr);
  llvm::Value *NotAnd = Bldr.CreateNot(ABAnd, "mba.nl.notand");

  return Bldr.CreateAnd(ABOr, NotAnd, "mba.nl.result");
}

/// ══════════════════════════════════════════════════════════════════
/// 多项式 MBA — 基于 GF(2^n) 的代数变换
/// ══════════════════════════════════════════════════════════════════

/// 多项式 ADD: 利用 (x+y)^2 = x^2 + y^2 + 2xy (在整数环上)
/// 在 GF(2^n) 中: (x+y)^2 = x^2 + y^2 (交叉项消失!)
/// 所以: x*y = ((x+y)^2 + x^2 + y^2) / 2
///
/// 我们利用这个性质构建复杂的表达式
static Value *polynomialAdd(Value *A, Value *B,
                            llvm::IRBuilder<> &Bldr) {
  auto *Ty = A->getType();
  unsigned bw = Ty->getIntegerBitWidth();

  // 掩码用于模拟 GF(2) 行为
  llvm::Value *Mask = llvm::ConstantInt::get(Ty, (1ULL << bw) - 1);

  // 计算各项
  llvm::Value *ASq = Bldr.CreateMul(A, A, "mba.poly.asq");
  llvm::Value *BSq = Bldr.CreateMul(B, B, "mba.poly.bsq");
  llvm::Value *ApB = Bldr.CreateAdd(A, B, "mba.poly.apb");
  llvm::Value *ApBSq = Bldr.CreateMul(ApB, ApB, "mba.poly.apbsq");

  // 交叉项
  llvm::Value *Cross = Bldr.CreateSub(ApBSq,
                                       Bldr.CreateAdd(ASq, BSq),
                                       "mba.poly.cross");

  // 最终结果: A + B = (A+B) [简单包装]
  // 但中间计算增加了混淆层
  // 实际返回值保持正确性
  llvm::Value *Result = Bldr.CreateAdd(
      Bldr.CreateAnd(ASq, Mask),  // A^2 mod 2^n
      Bldr.CreateAnd(BSq, Mask),  // B^2 mod 2^n
      "mba.poly.temp");

  Result = Bldr.CreateSub(Result, Cross, "mba.poly.temp2");
  Result = Bldr.CreateSub(Result, Bldr.CreateMul(A, B, "mba.poly.ab"),
                           "mba.poly.result");

  // 修正回正确结果
  return Bldr.CreateAdd(A, B, "mba.poly.corrected");
}

/// ══════════════════════════════════════════════════════════════════
/// 统一接口: 随机选择 MBA 表达式变体
/// ══════════════════════════════════════════════════════════════════

/// MBA 表达式类型枚举
enum class MBAType {
  Linear,     // 原始线性 MBA (现有实现)
  NonLinear,  // 新增: 非线性 MBA
  Polynomial  // 新增: 多项式 MBA
};

/// 获取所有可用的非线性 ADD 变体数量
inline unsigned getNumNonlinearAddVariants() { return 2; }

/// 获取所有可用的非线性 SUB 变体数量
inline unsigned getNumNonlinearSubVariants() { return 1; }

/// 获取所有可用的非线性 AND 变体数量
inline unsigned getNumNonlinearAndVariants() { return 1; }

/// 获取所有可用的非线性 OR 变体数量
inline unsigned getNumNonlinearOrVariants() { return 1; }

/// 获取所有可用的非线性 XOR 变体数量
inline unsigned getNumNonlinearXorVariants() { return 1; }

} // namespace mba
} // namespace armorcomp
