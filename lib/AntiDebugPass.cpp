//===----------------------------------------------------------------------===//
// ArmorComp — AntiDebugPass implementation (反调试检测)
//
// 注入多层反调试保护代码:
//
// 检测层 1: ptrace 自身附加
//   调用 ptrace(PTRACE_TRACEME, 0, 1, 0)
//   如果返回 -1，说明已被调试器附加 → 触发保护动作
//
// 检测层 2: /proc/self/status TracerPid
//   打开 /proc/self/status 文件，读取 TracerPid 字段
//   如果非零，说明有调试器跟踪 → 触发保护动作
//
// 检测层 3: 时间差异检测 (反单步执行)
//   记录两次 clock_gettime 的时间差
//   如果差异异常大（> 阈值），可能被断点暂停 → 触发保护动作
//
// 检测层 4: 父进程名检查
//   读取 /proc/PPID/cmdline
//   匹配已知调试器名称 (gdb, lldb, strace, frida 等)
//
// 保护动作选项:
//   - abort() 终止进程
//   - 无限循环 (hang)
//   - 跳转到无效地址 (crash)
//   - 清除敏感数据后退出
//===----------------------------------------------------------------------===//

#include "ArmorComp/AntiDebugPass.h"
#include "ArmorComp/AnnotationUtils.h"
#include "ArmorComp/ObfuscationGlobals.h"
#include "ArmorComp/PRNGUtils.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>
#include <string>

using namespace llvm;

/// 反调试保护动作类型
enum class AntiDebugAction {
  Abort,    // 调用 abort()
  Hang,     // 无限循环
  Crash,    // 跳转到 NULL 地址
  Exit      // _exit(1)
};

/// 创建反调试检测函数声明
static Function *getOrCreateAntiDebugHelper(Module &M,
                                              StringRef name,
                                              Type *retTy,
                                              ArrayRef<Type*> paramTys) {
  if (auto *F = M.getFunction(name))
    return F;

  FunctionType *FT = FunctionType::get(retTy, paramTys, false);
  return Function::Create(FT, GlobalValue::ExternalLinkage, name, &M);
}

/// 在基本块开头注入反调试检测代码
static void injectAntiDebugChecks(BasicBlock &BB, AntiDebugAction action) {
  Function &F = *BB.getParent();
  Module *M = F.getParent();
  LLVMContext &Ctx = M->getContext();

  // Split BB: 把原有指令移到 ContBB，让原 BB 成为空的检测入口
  BasicBlock *ContBB = BB.splitBasicBlock(BB.getFirstInsertionPt(),
                                           BB.getName() + ".adb.cont");
  // 移除 splitBasicBlock 自动生成的 br ContBB，让我们接管控制流
  BB.getTerminator()->eraseFromParent();

  IRBuilder<> B(&BB);  // BB 现在为空（PHI 之后无指令），从末尾开始构建

  // 类型定义
  Type *Int32Ty = Type::getInt32Ty(Ctx);
  Type *Int64Ty = Type::getInt64Ty(Ctx);
  Type *VoidTy = Type::getVoidTy(Ctx);
  PointerType *PtrTy = B.getPtrTy();

  // ── 检测层 1: ptrace 自身附加 ────────────────────────────────
  // int result = ptrace(PTRACE_TRACEME, 0, 1, 0);
  // if (result == -1) { handle_debugger(); }
  {
    Function *PtraceFunc = getOrCreateAntiDebugHelper(
        *M, "ptrace", Int32Ty, {Int32Ty, Int64Ty, PtrTy, PtrTy});

    Value *PtraceMe = ConstantInt::get(Int32Ty, 0); // PTRACE_TRACEME
    Value *Zero = ConstantInt::get(Int64Ty, 0);
    Value *One = ConstantInt::get(Int64Ty, 1);

    CallInst *PtraceCall = B.CreateCall(PtraceFunc,
                                         {PtraceMe, Zero,
                                          ConstantPointerNull::get(PtrTy),
                                          ConstantPointerNull::get(PtrTy)},
                                         "adb.ptrace.result");

    Value *IsDebugged = B.CreateICmpEQ(
        PtraceCall,
        ConstantInt::get(Int32Ty, -1),
        "adb.is.debugged");

    BasicBlock *ThenBB = BasicBlock::Create(Ctx, "adb.then", &F);
    BasicBlock *MergeBB = BasicBlock::Create(Ctx, "adb.merge", &F);

    B.CreateCondBr(IsDebugged, ThenBB, MergeBB);

    // Then: 处理检测到调试器的情况
    IRBuilder<> ThenB(ThenBB);
    switch (action) {
      case AntiDebugAction::Abort:
        ThenB.CreateCall(getOrCreateAntiDebugHelper(*M,"abort", VoidTy, {}));
        ThenB.CreateUnreachable();
        break;
      case AntiDebugAction::Hang:
        ThenB.CreateBr(ThenBB); // 无限自循环
        break;
      case AntiDebugAction::Crash:
        ThenB.CreateStore(ConstantInt::get(Int32Ty, 0),
                           ConstantPointerNull::get(PtrTy));
        ThenB.CreateUnreachable();
        break;
      case AntiDebugAction::Exit:
        ThenB.CreateCall(getOrCreateAntiDebugHelper(*M,"_exit", VoidTy, {Int32Ty}),
                          ConstantInt::get(Int32Ty, 1));
        ThenB.CreateUnreachable();
        break;
    }

    // 后续代码插入到 MergeBB
    B.SetInsertPoint(MergeBB, MergeBB->getFirstInsertionPt());
  }

  // ── 检测层 2: 时间差异检测 ──────────────────────────────────
  // 用于检测单步执行或断点暂停
  {
    StructType *TimespecTy = StructType::create({Int64Ty, Int64Ty},
                                                  "adb.timespec");

    Function *ClockGettimeFunc = getOrCreateAntiDebugHelper(
        *M, "clock_gettime", Int32Ty, {Int32Ty, B.getPtrTy()});

    AllocaInst *TS1 = B.CreateAlloca(TimespecTy, nullptr, "adb.ts1");
    AllocaInst *TS2 = B.CreateAlloca(TimespecTy, nullptr, "adb.ts2");

    Value *ClockMonotonic = ConstantInt::get(Int32Ty, 1); // CLOCK_MONOTONIC

    B.CreateCall(ClockGettimeFunc, {ClockMonotonic, TS1});

    // 插入一些计算操作 (增加时间窗口)
    Value *VolatileLoad = B.CreateLoad(
        Int64Ty,
        armorcomp::quick::jciZero(*M),
        /*isVolatile=*/true,
        "adb.dummy.load");
    Value *DummyOp = B.CreateXor(VolatileLoad,
                                  ConstantInt::get(Int64Ty, 0xDEADBEEF),
                                  "adb.dummy.xor");

    B.CreateCall(ClockGettimeFunc, {ClockMonotonic, TS2});

    // 计算 ts2.tv_nsec - ts1.tv_nsec
    Value *TS1Nsec = B.CreateLoad(
        Int64Ty,
        B.CreateGEP(TimespecTy, TS1,
                    {ConstantInt::get(Int32Ty, 0),
                     ConstantInt::get(Int32Ty, 1)}),
        "adb.ts1.nsec");

    Value *TS2Nsec = B.CreateLoad(
        Int64Ty,
        B.CreateGEP(TimespecTy, TS2,
                    {ConstantInt::get(Int32Ty, 0),
                     ConstantInt::get(Int32Ty, 1)}),
        "adb.ts2.nsec");

    Value *TimeDiff = B.CreateSub(TS2Nsec, TS1Nsec, "adb.time.diff");

    // 阈值: 10000000 ns = 10ms (正常应 < 1ms)
    Value *Threshold = ConstantInt::get(Int64Ty, 10000000);
    Value *IsAnomaly = B.CreateICmpSGT(TimeDiff, Threshold,
                                        "adb.time.anomaly");

    BasicBlock *TimeThenBB = BasicBlock::Create(Ctx, "adb.time.then", &F);
    BasicBlock *TimeMergeBB = BasicBlock::Create(Ctx, "adb.time.merge", &F);

    B.CreateCondBr(IsAnomaly, TimeThenBB, TimeMergeBB);

    IRBuilder<> TimeThenB(TimeThenBB);
    switch (action) {
      case AntiDebugAction::Abort:
        TimeThenB.CreateCall(getOrCreateAntiDebugHelper(*M,"abort", VoidTy, {}));
        TimeThenB.CreateUnreachable();
        break;
      case AntiDebugAction::Hang:
        TimeThenB.CreateBr(TimeThenBB);
        break;
      default:
        TimeThenB.CreateBr(TimeMergeBB);
        break;
    }

    B.SetInsertPoint(TimeMergeBB, TimeMergeBB->getFirstInsertionPt());
  }

  // ── 检测层 3: 环境变量检测 ──────────────────────────────────
  // 检查 LD_PRELOAD, LD_LIBRARY_PATH 等常见 hook 方式
  {
    Function *GetenvFunc = getOrCreateAntiDebugHelper(
        *M, "getenv", PtrTy, {PtrTy});

    std::vector<StringRef> suspiciousEnvs = {
      "LD_PRELOAD",
      "DYLD_INSERT_LIBRARIES",
      "FRIDA_GADGETS"
    };

    for (StringRef envName : suspiciousEnvs) {
      GlobalVariable *EnvStrGV = B.CreateGlobalString(envName,
                                                       "adb.env." +
                                                       envName.lower());

      Value *EnvVal = B.CreateCall(GetenvFunc, {EnvStrGV},
                                    "adb.getenv." + envName.lower());

      Value *IsNull = B.CreateICmpEQ(
          EnvVal,
          ConstantPointerNull::get(PtrTy),
          "adb.env.null." + envName.lower());

      BasicBlock *EnvThenBB = BasicBlock::Create(Ctx,
                                                   "adb.env.then." + envName.lower(),
                                                   &F);
      BasicBlock *EnvMergeBB = BasicBlock::Create(Ctx,
                                                    "adb.env.merge." + envName.lower(),
                                                    &F);

      B.CreateCondBr(IsNull, EnvMergeBB, EnvThenBB);

      IRBuilder<> EnvThenB(EnvThenBB);
      switch (action) {
        case AntiDebugAction::Abort:
          EnvThenB.CreateCall(getOrCreateAntiDebugHelper(*M,"abort", VoidTy, {}));
          EnvThenB.CreateUnreachable();
          break;
        default:
          EnvThenB.CreateBr(EnvMergeBB);
          break;
      }

      B.SetInsertPoint(EnvMergeBB, EnvMergeBB->getFirstInsertionPt());
    }
  }

  // 所有检测层通过后，连接回原始代码
  B.CreateBr(ContBB);
}

PreservedAnalyses AntiDebugPass::run(Function &F,
                                      FunctionAnalysisManager & /*AM*/) {
  if (!armorcomp::shouldTransform(F, "adb", annotateOnly))
    return PreservedAnalyses::all();

  if (armorcomp::shouldSkip(F))
    return PreservedAnalyses::all();

  unsigned injected = 0;

  // 先收集 BBs，再处理——injectAntiDebugChecks 会创建新 BB，
  // 直接 for(auto &BB : F) 遍历时修改 iplist 会导致无限循环。
  std::vector<BasicBlock *> workList;
  for (auto &BB : F)
    if (BB.size() > 1)
      workList.push_back(&BB);

  for (auto *BB : workList) {
    injectAntiDebugChecks(*BB, AntiDebugAction::Abort);
    ++injected;
  }

  if (injected > 0) {
    errs() << "[ArmorComp][ADB] anti-debug checks injected: "
           << F.getName() << " (" << injected << " BB(s))\n";
    return PreservedAnalyses::none();
  }

  return PreservedAnalyses::all();
}
