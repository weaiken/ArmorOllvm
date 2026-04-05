//===----------------------------------------------------------------------===//
// ArmorComp — RetAddrObfPass implementation
//
// Inserts "sub sp, sp, xN" before each call and "add sp, sp, xN" after each
// call in an annotated function.
//
// xN = TPIDR_EL0 XOR TPIDR_EL0 (two reads separated by ISB barrier).
// Runtime value: both mrs reads return the same TLS pointer within the thread
//                → XOR = 0 → sub/add are genuine no-ops → SP undisturbed.
// IDA value:     each mrs is an independent UNKNOWN (hardware register, no
//                static model); ISB prevents IDA from coalescing the pair
//                → XOR = UNKNOWN → sp_delta = UNKNOWN at every call site.
//
// Why the two-read XOR pattern is required (not a single mrs):
//   A single `mrs x0, TPIDR_EL0` returns the actual TLS base pointer, which
//   is an ASLR-randomised non-zero address (e.g. 0x7f000040).  Using that
//   value directly in `sub sp, sp, x0` would corrupt SP to an unmapped region
//   before the callee could execute — instant SIGSEGV.  The XOR of two reads
//   cancels to 0 at runtime while remaining UNKNOWN to IDA.
//
// Pattern emitted for each qualifying CallInst:
//
//   mrs  x_a, TPIDR_EL0       ; pre-A
//   isb
//   mrs  x_b, TPIDR_EL0       ; pre-B
//   sub  sp,  sp, (x_a ^ x_b) ; = 0 at runtime  / UNKNOWN to IDA
//   bl   <callee>
//   mrs  x_c, TPIDR_EL0       ; post-C
//   isb
//   mrs  x_d, TPIDR_EL0       ; post-D
//   add  sp,  sp, (x_c ^ x_d) ; = 0 at runtime  / UNKNOWN to IDA
//
// IDA sp-delta analysis: at the call site it sees sp += UNKNOWN + UNKNOWN,
// marks sp_delta = UNKNOWN, and Hex-Rays emits "sp-analysis failed".
//===----------------------------------------------------------------------===//

#include "ArmorComp/RetAddrObfPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"

#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasRAOAnnotation(Function &F) {
  Module *M = F.getParent();
  GlobalVariable *GV = M->getGlobalVariable("llvm.global.annotations");
  if (!GV || !GV->hasInitializer()) return false;
  auto *CA = dyn_cast<ConstantArray>(GV->getInitializer());
  if (!CA) return false;

  for (unsigned i = 0, n = CA->getNumOperands(); i < n; ++i) {
    auto *CS = dyn_cast<ConstantStruct>(CA->getOperand(i));
    if (!CS || CS->getNumOperands() < 2) continue;
    if (CS->getOperand(0)->stripPointerCasts() != &F) continue;

    auto *StrGV =
        dyn_cast<GlobalVariable>(CS->getOperand(1)->stripPointerCasts());
    if (!StrGV || !StrGV->hasInitializer()) continue;
    auto *StrData = dyn_cast<ConstantDataArray>(StrGV->getInitializer());
    if (StrData && StrData->getAsCString() == "rao") return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// RetAddrObfPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses RetAddrObfPass::run(Function &F,
                                      FunctionAnalysisManager & /*AM*/) {
  if (F.isDeclaration()) return PreservedAnalyses::all();

  // AArch64 only — the asm uses AArch64 mnemonics and TPIDR_EL0
  Module *M = F.getParent();
  Triple T(M->getTargetTriple());
  if (!T.isAArch64()) return PreservedAnalyses::all();

  // Never instrument ArmorComp's own injected functions
  if (F.getName().startswith("__armorcomp_")) return PreservedAnalyses::all();

  bool shouldObf = !annotateOnly
                   || hasRAOAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "rao");
  if (!shouldObf) return PreservedAnalyses::all();

  LLVMContext &ctx = F.getContext();
  Type *VoidTy = Type::getVoidTy(ctx);
  Type *I64Ty  = Type::getInt64Ty(ctx);

  // ── TPIDR_EL0 reader (reused across all injection points) ─────────────────
  // `mrs $0, TPIDR_EL0` reads the AArch64 TLS base register.
  //  Runtime: constant per-thread (ASLR TLS pointer, not 0!).
  //  IDA:     hardware system register → no static value → UNKNOWN.
  //  hasSideEffects=false: the read itself is pure; scheduler may move it.
  FunctionType *TpidrTy = FunctionType::get(I64Ty, {}, /*isVarArg=*/false);
  InlineAsm    *TpidrAsm = InlineAsm::get(TpidrTy,
                               "mrs $0, TPIDR_EL0",
                               "=r",
                               /*hasSideEffects=*/false);

  // ── ISB barrier ───────────────────────────────────────────────────────────
  // Instruction Synchronization Barrier between the two mrs reads forces IDA
  // to treat them as independent snapshots, not the same value.
  FunctionType *IsbTy  = FunctionType::get(VoidTy, {}, /*isVarArg=*/false);
  InlineAsm    *IsbAsm = InlineAsm::get(IsbTy,
                             "isb", "",
                             /*hasSideEffects=*/true);

  // ── sub/add SP inline asm ─────────────────────────────────────────────────
  // "r"               — LLVM allocates a general-purpose Xn register
  // hasSideEffects=true — prevents optimizer removal
  // No "~{sp}" clobber — correct since the operand = 0 at runtime
  FunctionType *AsmTy  = FunctionType::get(VoidTy, {I64Ty}, false);
  InlineAsm *SubAsm =
      InlineAsm::get(AsmTy, "sub sp, sp, $0", "r", /*hasSideEffects=*/true);
  InlineAsm *AddAsm =
      InlineAsm::get(AsmTy, "add sp, sp, $0", "r", /*hasSideEffects=*/true);

  // Helper: emit two TPIDR_EL0 reads separated by ISB, then XOR.
  // At runtime: T1 == T2 (same TLS pointer in same thread) → XOR = 0 → NOP.
  // To IDA: UNKNOWN_A ISB UNKNOWN_B → can't prove equal → XOR = UNKNOWN.
  auto makeTpidrXor = [&](IRBuilder<> &B,
                          const char *n1, const char *n2) -> Value * {
    Value *TA = B.CreateCall(TpidrTy, TpidrAsm, {}, n1);
    B.CreateCall(IsbTy, IsbAsm, {});           // barrier between reads
    Value *TB = B.CreateCall(TpidrTy, TpidrAsm, {}, n2);
    return B.CreateXor(TA, TB, "rao.xor");
  };

  // Snapshot qualifying call instructions to avoid iterator invalidation
  // while we insert instructions around them.
  std::vector<CallInst *> calls;
  for (auto &BB : F)
    for (auto &I : BB)
      if (auto *CI = dyn_cast<CallInst>(&I)) {
        // Skip inline asm calls (already asm, no useful callee)
        if (CI->isInlineAsm()) continue;

        // Skip LLVM intrinsics — must remain as-is
        Function *Callee = CI->getCalledFunction();
        if (Callee && Callee->isIntrinsic()) continue;

        // Skip ArmorComp's own injected functions
        if (Callee && Callee->getName().startswith("__armorcomp_")) continue;

        calls.push_back(CI);
      }

  if (calls.empty()) return PreservedAnalyses::all();

  for (CallInst *CI : calls) {
    // ── Before the call: (TPIDR ^ TPIDR) + sub sp ───────────────────────
    // The XOR = 0 at runtime → sub sp, sp, 0 → NOP.
    // IDA sees UNKNOWN → sub sp, sp, UNKNOWN → sp_delta = UNKNOWN.
    {
      IRBuilder<> Pre(CI);
      Value *Key = makeTpidrXor(Pre, "rao.pre.a", "rao.pre.b");
      Pre.CreateCall(AsmTy, SubAsm, {Key});
    }

    // ── After the call: (TPIDR ^ TPIDR) + add sp ────────────────────────
    // CI->getNextNode() is safe: CallInst is never a terminator.
    // A fresh pair of TPIDR reads ensures independence from the pre-pair;
    // IDA cannot correlate the two pairs across the call boundary.
    {
      IRBuilder<> Post(CI->getNextNode());
      Value *Key = makeTpidrXor(Post, "rao.post.a", "rao.post.b");
      Post.CreateCall(AsmTy, AddAsm, {Key});
    }
  }

  errs() << "[ArmorComp][RAO] obfuscated: " << F.getName()
         << " (" << calls.size() << " call" << (calls.size() > 1 ? "s" : "")
         << ")\n";

  return PreservedAnalyses::none();
}
