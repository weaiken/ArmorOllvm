#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — PRNGUtils (统一伪随机数生成工具)
//
// 消除 6+ 个 Pass 中重复的 xorshift64/FNV-1a 实现。
// 提供确定性的、可复现的 PRNG 接口。
//===----------------------------------------------------------------------===//

#include <cstdint>
#include <string>
#include <random>
#include <llvm/ADT/StringRef.h>

namespace armorcomp {

/// FNV-1a 64-bit 哈希函数
///
/// 用于从字符串生成确定性种子。
/// 特点: 快速、良好的雪崩效应、确定性输出。
///
/// @param input 输入字符串
/// @return 64-bit 哈希值
inline uint64_t fnv1a64(llvm::StringRef input) {
  uint64_t h = 14695981039346656037ULL;
  for (unsigned char c : input) {
    h ^= static_cast<uint64_t>(c);
    h *= 1099511628211ULL;
  }
  return h;
}

/// xorshift64 伪随机数生成器 (单步)
///
/// Marsaglia 的 xorshift64 算法。
/// 周期: 2^64 - 1
///
/// @param state 当前状态 (会被修改)
/// @return 生成的随机值
inline uint64_t xorshift64(uint64_t &state) {
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return state;
}

/// 从函数名生成确定性种子的辅助函数
///
/// 用法:
///   uint64_t seed = armorcomp::seedFromFunction(F.getName(), "pass_name");
///   std::mt19937 rng(seed);
///
/// @param fnName 函数名称
/// @param suffix 后缀标识 (区分不同 Pass)
/// @return 确定性种子值
inline uint64_t seedFromFunction(llvm::StringRef fnName,
                                  llvm::StringRef suffix) {
  std::string combined = fnName.str() + "_" + suffix.str();
  return fnv1a64(combined);
}

/// 从函数名创建确定性 std::mt19937 实例
///
/// 封装了常见的 "hash(fn_name) → mt19937" 模式。
///
/// @param fnName 函数名称
/// @param suffix 后缀标识
/// @return 已初始化的 MT19937 实例
inline std::mt19937 createRNG(llvm::StringRef fnName,
                                llvm::StringRef suffix) {
  return std::mt19937(seedFromFunction(fnName, suffix));
}

/// 生成非零随机密钥 (指定位宽)
///
/// 用于确保 XOR 密钥不为零 (避免退化情况)。
///
/// @param state PRNG 状态 (会被推进)
/// @param bitWidth 目标位宽 (8/16/32/64)
/// @return 非零的掩码后随机值
inline uint64_t generateNonZeroKey(uint64_t &state, unsigned bitWidth) {
  uint64_t val = xorshift64(state);
  uint64_t mask = (bitWidth < 64) ? ((1ULL << bitWidth) - 1) : ~0ULL;
  uint64_t key = val & mask;
  if (key == 0) key = 1;  // 避免零密钥
  return key;
}

} // namespace armorcomp
