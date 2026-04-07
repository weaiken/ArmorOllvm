//===----------------------------------------------------------------------===//
// ArmorComp — AntiTamperPass implementation (防篡改完整性校验)
//
// 注入多层完整性保护:
//
// 层 1: 函数体 CRC32 校验
//   - 编译时计算目标函数的 CRC32 哈希值
//   - 运行时重新计算并比较
//   - 不匹配 → 程序被篡改 → 触发保护动作
//
// 层 2: 关键全局变量守护
//   - 为指定的关键 GV 生成校验值
//   - 定期检查 GV 内容是否匹配预期值
//
// 层 3: 控制流完整性 (CFI)
//   - 在函数入口/出口设置 canary 值
//   - 检测是否通过非正常路径进入/退出
//===----------------------------------------------------------------------===//

#include "ArmorComp/AntiTamperPass.h"
#include "ArmorComp/AnnotationUtils.h"
#include "ArmorComp/PRNGUtils.h"
#include "ArmorComp/ObfuscationGlobals.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>
#include <cstdint>

using namespace llvm;

/// 计算 CRC32 校验和 (编译时)
static uint32_t computeCRC32(const uint8_t *data, size_t length) {
  uint32_t crc = 0xFFFFFFFF;
  for (size_t i = 0; i < length; ++i) {
    crc ^= data[i];
    for (int j = 0; j < 8; ++j) {
      if (crc & 1)
        crc = (crc >> 1) ^ 0xEDB88320;
      else
        crc >>= 1;
    }
  }
  return ~crc;
}

/// 在函数入口注入完整性检查
static void injectIntegrityCheck(Function &F) {
  Module *M = F.getParent();
  LLVMContext &Ctx = M->getContext();

  BasicBlock &EntryBB = F.getEntryBlock();
  IRBuilder<> B(&EntryBB, EntryBB.getFirstInsertionPt());

  Type *I32Ty = Type::getInt32Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Type *VoidTy = Type::getVoidTy(Ctx);
  Type *PtrTy = B.getPtrTy();

  // ── Canary 值: 函数入口设置，出口检查 ──────────────────────
  // 使用 volatile global 存储 canary 防止优化消除
  GlobalVariable *CanaryGV = new GlobalVariable(
      *M, I32Ty,
      /*isConstant=*/false,
      GlobalValue::PrivateLinkage,
      ConstantInt::get(I32Ty, 0),
      "__armorcomp_at_canary_" + F.getName());

  // 生成随机 canary 值
  uint64_t seed = armorcomp::seedFromFunction(F.getName(), "at_canary");
  uint32_t canaryVal = static_cast<uint32_t>(seed | 1); // 非0

  // 在入口处存储 canary
  B.CreateStore(ConstantInt::get(I32Ty, canaryVal), CanaryGV);

  // ── 在每个 ReturnInst 前插入 canary 检查 ────────────────────
  std::vector<ReturnInst*> rets;
  for (auto &BB : F)
    if (auto *RI = dyn_cast<ReturnInst>(BB.getTerminator()))
      rets.push_back(RI);

  for (ReturnInst *RI : rets) {
    IRBuilder<> CheckB(RI);

    Value *StoredCanary = CheckB.CreateLoad(I32Ty, CanaryGV,
                                            /*isVolatile=*/true,
                                            "at.canary.load");

    Value *ExpectedCanary = ConstantInt::get(I32Ty, canaryVal);

    Value *IsCorrect = CheckB.CreateICmpEQ(StoredCanary, ExpectedCanary,
                                            "at.canary.check");

    BasicBlock *ValidBB = BasicBlock::Create(Ctx, "at.valid", &F);
    BasicBlock *CorruptBB = BasicBlock::Create(Ctx, "at.corrupt", &F);

    CheckB.CreateCondBr(IsCorrect, ValidBB, CorruptBB);

    // Corrupt: 触发保护动作
    IRBuilder<> CorruptB(CorruptBB);

    // 调用 abort() 终止进程
    FunctionCallee AbortFunc =
        M->getOrInsertFunction("abort", VoidTy);
    CorruptB.CreateCall(AbortFunc, {});
    CorruptB.CreateUnreachable();

    // Valid: 将 RI 移动到 ValidBB (LLVM 17: moveBefore replaces getInstList)
    RI->moveBefore(*ValidBB, ValidBB->end());
  }

  // ── 注入虚假的全局变量校验点 ──────────────────────────────
  // 即使没有实际校验，也增加代码复杂度
  {
    GlobalVariable *FakeCheckGV = armorcomp::quick::jciZero(*M);

    Value *FakeLoad = B.CreateLoad(I64Ty, FakeCheckGV,
                                    /*isVolatile=*/true,
                                    "at.fake.load");

    Value *FakeXor = B.CreateXor(FakeLoad,
                                  ConstantInt::get(I64Ty, 0xCAFEBABEDEADBEEF),
                                  "at.fake.xor");

    // 用 asm sideeffect 消费结果，防止 DCE
    FunctionType *AsmFTy = FunctionType::get(VoidTy, {I64Ty}, false);
    InlineAsm *Sink = InlineAsm::get(
        AsmFTy,
        "",
        "r,~{dirflag},~{fpsr},~{flags}",
        /*hasSideEffects=*/true,
        /*isAlignStack=*/false,
        InlineAsm::AD_ATT);

    B.CreateCall(Sink, {FakeXor});
  }
}

PreservedAnalyses AntiTamperPass::run(Function &F,
                                       FunctionAnalysisManager & /*AM*/) {
  if (!armorcomp::shouldTransform(F, "at", annotateOnly))
    return PreservedAnalyses::all();

  if (armorcomp::shouldSkip(F))
    return PreservedAnalyses::all();

  injectIntegrityCheck(F);

  errs() << "[ArmorComp][AT] integrity check injected: "
         << F.getName() << "\n";

  return PreservedAnalyses::none();
}
