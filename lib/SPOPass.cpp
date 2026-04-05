//===----------------------------------------------------------------------===//
// ArmorComp — SPOPass implementation
//
// Injects "sub sp, sp, xN" at function entry and "add sp, sp, xN" before
// each ret, where xN = TPIDR_EL0 XOR TPIDR_EL0 (two reads with ISB barrier).
//
// TPIDR_EL0 is the AArch64 thread-local storage base register:
//   - Set by the OS kernel at thread creation (ASLR-randomised pointer).
//   - Constant within a thread — both reads return the same value at runtime,
//     so sub/add cancel and the function stack is undisturbed.
//   - No PLT stub, no FLIRT symbol: it is a raw `mrs` instruction.
//
// IDA Pro F5 effect (why TPIDR_EL0 wins):
//   IDA has no static model for the numeric value of TPIDR_EL0 — it is a
//   kernel-set address, randomised by ASLR.  Each `mrs $0, TPIDR_EL0` is
//   treated as an independent UNKNOWN value.  The ISB instruction between
//   the two reads prevents IDA from coalescing them into a single snapshot.
//   Result: xN = UNKNOWN_A XOR UNKNOWN_B = UNKNOWN, sp_delta = UNKNOWN,
//   Hex-Rays bails out with "sp-analysis failed".
//
// Why earlier approaches were defeated by IDA 8.4:
//   • BSS-zero volatile global: IDA reads .data and proves value = 0.
//   • getpid() via PLT: IDA FLIRT-matches the symbol; pure-function model
//     proves two sequential calls in the same process return the same PID
//     → XOR = 0 → sp_delta = 0 → F5 proceeds.
//   • TPIDR_EL0: hardware system register, runtime-only, no IDA model.
//===----------------------------------------------------------------------===//

#include "ArmorComp/SPOPass.h"
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

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasSPOAnnotation(Function &F) {
  Module *M = F.getParent();
  GlobalVariable *GV = M->getGlobalVariable("llvm.global.annotations");
  if (!GV || !GV->hasInitializer()) return false;
  auto *CA = dyn_cast<ConstantArray>(GV->getInitializer());
  if (!CA) return false;

  for (unsigned i = 0, n = CA->getNumOperands(); i < n; ++i) {
    auto *CS = dyn_cast<ConstantStruct>(CA->getOperand(i));
    if (!CS || CS->getNumOperands() < 2) continue;

    // Operand 0: the annotated symbol — stripPointerCasts() handles the
    // bitcast wrapper that Clang emits around the function pointer.
    if (CS->getOperand(0)->stripPointerCasts() != &F) continue;

    // Operand 1: pointer to the annotation string — stripPointerCasts()
    // removes the GEP/bitcast wrapper.
    auto *StrGV =
        dyn_cast<GlobalVariable>(CS->getOperand(1)->stripPointerCasts());
    if (!StrGV || !StrGV->hasInitializer()) continue;
    auto *StrData = dyn_cast<ConstantDataArray>(StrGV->getInitializer());
    if (StrData && StrData->getAsCString() == "spo") return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the first non-AllocaInst in BB (or the terminator if all are alloca).
/// Used to insert the entry-block SP stub after the function's own allocas.
static Instruction *firstNonAlloca(BasicBlock &BB) {
  for (Instruction &I : BB)
    if (!isa<AllocaInst>(&I))
      return &I;
  return BB.getTerminator();
}

// ─────────────────────────────────────────────────────────────────────────────
// SPOPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses SPOPass::run(Function &F, FunctionAnalysisManager & /*AM*/) {
  if (F.isDeclaration()) return PreservedAnalyses::all();

  // AArch64 only — TPIDR_EL0 and the sp asm are AArch64-specific
  Module *M = F.getParent();
  Triple T(M->getTargetTriple());
  if (!T.isAArch64()) return PreservedAnalyses::all();

  // Skip ArmorComp's own injected functions
  if (F.getName().startswith("__armorcomp_")) return PreservedAnalyses::all();

  // Decide whether to obfuscate this function
  bool shouldObfuscate = !annotateOnly
                         || hasSPOAnnotation(F)
                         || armorcomp::configSaysApply(F.getName(), "spo");
  if (!shouldObfuscate) return PreservedAnalyses::all();

  LLVMContext &ctx = F.getContext();
  Type *I64Ty  = Type::getInt64Ty(ctx);
  Type *VoidTy = Type::getVoidTy(ctx);

  // ── TPIDR_EL0 reader ──────────────────────────────────────────────────────
  // `mrs $0, TPIDR_EL0` reads the thread-local storage base register.
  //  • Runtime: constant per-thread (ASLR-derived TLS pointer).
  //  • IDA: hardware system register → no static value model → UNKNOWN.
  //  • Constraint "=r": output value in any general-purpose register.
  //  • hasSideEffects=false: LLVM may schedule this freely (we add ISB
  //    between reads ourselves to prevent IDA from coalescing them).
  FunctionType *TpidrTy = FunctionType::get(I64Ty, {}, /*isVarArg=*/false);
  InlineAsm    *TpidrAsm = InlineAsm::get(TpidrTy,
                               "mrs $0, TPIDR_EL0",
                               "=r",
                               /*hasSideEffects=*/false);

  // ── ISB barrier ───────────────────────────────────────────────────────────
  // Instruction Synchronization Barrier: forces IDA to treat the next
  // `mrs TPIDR_EL0` as a fresh, independent read rather than the same
  // snapshot as the previous read.  At runtime this is a pipeline flush
  // only — it does not change register values.
  FunctionType *IsbTy  = FunctionType::get(VoidTy, {}, /*isVarArg=*/false);
  InlineAsm    *IsbAsm = InlineAsm::get(IsbTy,
                             "isb",
                             "",
                             /*hasSideEffects=*/true);

  // Build InlineAsm nodes for sub and add
  // Constraint "r" — LLVM allocates any general-purpose Xn register (AArch64)
  // hasSideEffects=true — prevents the optimizer from removing the asm call
  // No "~{sp}" clobber declared:
  //   - LLVM won't attempt to save/restore SP around the asm
  //   - Correct at runtime because xN = 0 (TPIDR_EL0 XOR TPIDR_EL0 == 0)
  FunctionType *AsmTy = FunctionType::get(VoidTy, {I64Ty}, false);
  InlineAsm *SubAsm = InlineAsm::get(AsmTy, "sub sp, sp, $0", "r",
                                     /*hasSideEffects=*/true);
  InlineAsm *AddAsm = InlineAsm::get(AsmTy, "add sp, sp, $0", "r",
                                     /*hasSideEffects=*/true);

  // Helper: emit two TPIDR_EL0 reads separated by ISB, then XOR.
  // At runtime: both reads return the same TLS base → XOR = 0 → no-op.
  // To IDA: UNKNOWN_A ISB UNKNOWN_B → can't prove equal → XOR = UNKNOWN.
  auto makeSpoOperand = [&](IRBuilder<> &B,
                            const char *n1, const char *n2) -> Value * {
    Value *T1 = B.CreateCall(TpidrTy, TpidrAsm, {}, n1);
    B.CreateCall(IsbTy, IsbAsm, {});                // barrier between reads
    Value *T2 = B.CreateCall(TpidrTy, TpidrAsm, {}, n2);
    return B.CreateXor(T1, T2, "spo.xor");          // i64, no ZExt needed
  };

  // ── Entry block: sub sp, sp, (TPIDR^TPIDR) after function allocas ─────────
  BasicBlock &Entry = F.getEntryBlock();
  IRBuilder<> EntryIR(firstNonAlloca(Entry));
  Value *EntryOp = makeSpoOperand(EntryIR, "spo.t1", "spo.t2");
  EntryIR.CreateCall(AsmTy, SubAsm, {EntryOp});

  // ── Return blocks: add sp, sp, (TPIDR^TPIDR) before each ret ─────────────
  // Skip rets whose immediately-preceding instruction is a musttail call.
  // VMP-generated shim functions have the pattern `musttail call / ret`;
  // inserting any instruction between them violates LLVM's musttail invariant
  // and causes the AArch64 backend to crash with "failed to perform tail call
  // elimination on a call site marked musttail".
  unsigned retCount = 0;
  for (BasicBlock &BB : F) {
    auto *Ret = dyn_cast<ReturnInst>(BB.getTerminator());
    if (!Ret) continue;

    // Guard: skip if the prev instruction is a musttail call
    Instruction *Prev = Ret->getPrevNode();
    if (Prev && isa<CallInst>(Prev) && cast<CallInst>(Prev)->isMustTailCall())
      continue;

    IRBuilder<> RetIR(Ret);
    Value *RetOp = makeSpoOperand(RetIR, "spo.t3", "spo.t4");
    RetIR.CreateCall(AsmTy, AddAsm, {RetOp});
    ++retCount;
  }

  errs() << "[ArmorComp][SPO] obfuscated: " << F.getName()
         << " (" << retCount << " ret(s))\n";
  return PreservedAnalyses::none();
}
