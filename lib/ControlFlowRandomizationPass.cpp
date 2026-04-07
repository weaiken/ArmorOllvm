//===----------------------------------------------------------------------===//
// ArmorComp — ControlFlowRandomizationPass implementation
//
// 控制流随机布局的核心算法:
//
// 1. 收集所有基本块 (排除 entry block)
// 2. 使用确定性 PRNG 对块进行 Fisher-Yates 洗牌
// 3. 将洗牌后的块从函数中移除并按新顺序重新插入
// 4. (可选) 分裂大块增加打乱效果
// 5. (可选) 创建虚假入口点混淆分析器
//===----------------------------------------------------------------------===//

#include "ArmorComp/ControlFlowRandomizationPass.h"
#include "ArmorComp/AnnotationUtils.h"
#include "ArmorComp/PRNGUtils.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>
#include <algorithm>

using namespace llvm;

/// Fisher-Yates 洗牌算法 (Knuth shuffle)
///
/// 使用确定性种子确保:
//    - 同一输入始终产生相同输出 (可复现构建)
//    - 不同函数产生不同排列 (避免模式识别)
template <typename Container, typename RNG>
static void fisherYatesShuffle(Container &items, RNG &rng) {
  for (size_t i = items.size() - 1; i > 0; --i) {
    std::uniform_int_distribution<size_t> dist(0, i);
    size_t j = dist(rng);
    if (i != j)
      std::swap(items[i], items[j]);
  }
}

/// 分裂包含多个前驱的大基本块
///
/// 在每个 PHI node 之后或指定指令数处分裂，
/// 增加可重排的基本块数量。
static void splitLargeBlocks(Function &F,
                              unsigned maxInstructionsPerBlock = 20) {
  std::vector<BasicBlock*> toSplit;

  for (auto &BB : F) {
    unsigned count = 0;
    for (auto &I : BB) {
      if (I.isTerminator()) break;
      ++count;
    }

    if (count > maxInstructionsPerBlock && BB.getSinglePredecessor() == nullptr)
      toSplit.push_back(&BB);
  }

  for (auto *BB : toSplit) {
    auto it = BB->begin();
    unsigned currentCount = 0;
    unsigned splitNum = 0;

    while (it != BB->end()) {
      if (it->isTerminator()) break;

      ++currentCount;
      ++it;

      if (currentCount >= maxInstructionsPerBlock &&
          !it->isTerminator()) {
        BB->splitBasicBlock(it,
                             BB->getName() + ".cfr.split" +
                             Twine(splitNum++));
        currentCount = 0;
        // it 现在指向新块的开始，需要重新获取 BB 的迭代器
        break; // 外层循环会处理新创建的块
      }
    }
  }
}

/// 创建虚假入口点
///
/// 在真实入口之前插入一个看起来像入口的空块，
/// 包含一些虚假指令来迷惑反编译器。
static void createFakeEntries(Function &F, unsigned count = 2) {
  LLVMContext &Ctx = F.getContext();

  BasicBlock &RealEntry = F.getEntryBlock();

  for (unsigned i = 0; i < count; ++i) {
    // 创建虚假入口块
    BasicBlock *FakeEntry = BasicBlock::Create(
        Ctx, "cfr.fake_entry" + Twine(i), &F, &RealEntry);

    IRBuilder<> B(FakeEntry);

    // 插入一些看起来像初始化代码的虚假指令
    Type *I64Ty = Type::getInt64Ty(Ctx);

    // 虚假的 alloca + store
    AllocaInst *FakeAlloca = B.CreateAlloca(I64Ty, nullptr,
                                             "cfr.fake.alloca" + Twine(i));
    B.CreateStore(ConstantInt::get(I64Ty, 0xDEADBEEFCAFEBABEULL),
                   FakeAlloca);

    // 虚假的条件跳转 (永远不会执行)
    Value *FakeCond = B.CreateICmpEQ(
        ConstantInt::get(I64Ty, 42),
        ConstantInt::get(I64Ty, 42),
        "cfr.fake.cond");

    BasicBlock *FakeTarget = BasicBlock::Create(
        Ctx, "cfr.fake_target" + Twine(i), &F);

    B.CreateCondBr(FakeCond, FakeTarget, &RealEntry);

    // 填充假目标块 (unreachable)
    IRBuilder<> FakeB(FakeTarget);
    FakeB.CreateUnreachable();
  }
}

PreservedAnalyses ControlFlowRandomizationPass::run(
    Function &F, FunctionAnalysisManager & /*AM*/) {

  if (!armorcomp::shouldTransform(F, "cfr", annotateOnly))
    return PreservedAnalyses::all();

  if (armorcomp::shouldSkip(F))
    return PreservedAnalyses::all();

  if (F.size() <= 2)  // 至少需要 3 个块才值得打乱
    return PreservedAnalyses::all();

  // ── 阶段 1: 可选的块分裂 ────────────────────────────────
  if (splitBlocks) {
    splitLargeBlocks(F);
  }

  // ── 阶段 2: 可选的虚假入口 ──────────────────────────────
  if (fakeEntries) {
    createFakeEntries(F);
  }

  // ── 阶段 3: 收集并打乱非入口块 ──────────────────────────
  BasicBlock *EntryBB = &F.getEntryBlock();

  std::vector<BasicBlock*> blocks;
  for (auto &BB : F) {
    if (&BB != EntryBB)
      blocks.push_back(&BB);
  }

  if (blocks.empty())
    return PreservedAnalyses::all();

  // 使用确定性 PRNG 进行洗牌
  auto rng = armorcomp::createRNG(F.getName(), "cfr");
  fisherYatesShuffle(blocks, rng);

  // ── 阶段 4: 从函数中移除所有非入口块 ────────────────────
  for (auto *BB : blocks) {
    BB->removeFromParent();
  }

  // ── 阶段 5: 按新顺序重新插入 ────────────────────────────
  for (auto *BB : blocks) {
    F.insert(F.end(), BB);  // 追加到函数末尾
  }

  errs() << "[ArmorComp][CFR] randomized layout: "
         << F.getName() << " (" << blocks.size() << " BBs)\n";

  return PreservedAnalyses::none();
}
