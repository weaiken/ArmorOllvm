//===----------------------------------------------------------------------===//
// ArmorComp — NeonTypeConfusionPass (Neon Type Confusion)
//
// Strategy: inject fmov GPR↔SIMD roundtrips at function entry and before
// each ReturnInst.  Values routed through NEON/FP registers confuse IDA
// Hex-Rays type inference — integer parameters and locals are annotated
// as float/double in the F5 decompiler output.
//
// INJECTION PATTERN
// ─────────────────
// At function entry (after allocas), two independent roundtrips:
//
//   ZeroI32 = load volatile i32, @__armorcomp_ntc_zero   ; = 0 at runtime
//   Block A: fmov s16, w<ZeroI32> ; fmov w9,  s16        ; 0-valued trip
//   Block B: fmov s17, w<ZeroI32> ; fmov w10, s17        ; 0-valued trip
//
// Before each ReturnInst, a wider roundtrip:
//
//   ZeroI32 = load volatile i32, @__armorcomp_ntc_zero
//   Block C: fmov s18, w<ZeroI32> ; fmov s19, w<ZeroI32>
//            fmov w11, s18        ; fmov w12, s19
//
// WHY THESE REGISTERS
// ───────────────────
// s16-s19 are caller-saved scratch SIMD/FP registers (AAPCS64 §6.1.2).
// w9-w12 / x9-x12 are caller-saved scratch GPRs.
// Neither group needs save/restore — clobbering them does not change ABI.
// s0-s7  are FP argument/result registers — NOT used (would corrupt args).
// s8-s15 are callee-saved FP registers    — NOT used (would require prologue save).
//
// INLINE ASM CONSTRAINTS
// ──────────────────────
// AsmFTy : void (i32) — one i32 input, void return
// $0     : the ZeroI32 value; constraint "r" → LLVM allocates a 32-bit GPR
//          (wN) and expands $0 to the register name → fmov sN, wN is valid.
// ~{s16} : clobbers the 32-bit SIMD register s16 (written by fmov s16, $0)
// ~{x9}  : clobbers 64-bit x9 / w9 (writing to w9 zero-extends to x9)
// hasSideEffects=true: prevents DCE even though outputs are void.
//
// IDA HEX-RAYS EFFECT
// ───────────────────
// IDA's type inference system inspects register classes when it sees data
// movement instructions.  When it observes that an integer parameter value
// flows into s16 (a 32-bit FP register), it infers the type as float.
// Consequently:
//   - Parameters inferred as float/double instead of int
//   - Local variables near the SIMD roundtrips annotated as FP types
//   - Hex-Rays generates wrong type declarations in F5 pseudo-C output
//   - Combined with FSIG's fake register reads: prototype analysis fails
//     from both the liveness side (FSIG) and the type side (NTC)
//
// VOLATILE SEMANTICS
// ──────────────────
// The volatile i32 load of @__armorcomp_ntc_zero prevents the optimizer
// from constant-folding the operand to 0.  LLVM cannot remove a volatile
// load even if it "knows" the initializer is 0.  Therefore the fmov
// instructions remain in the final binary with non-constant source operands.
//===----------------------------------------------------------------------===//

#include "ArmorComp/NeonTypeConfusionPass.h"
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

static bool hasNTCAnnotation(Function &F) {
  Module *M = F.getParent();
  GlobalVariable *annGV = M->getGlobalVariable("llvm.global.annotations");
  if (!annGV || !annGV->hasInitializer()) goto check_config;

  {
    auto *arr = dyn_cast<ConstantArray>(annGV->getInitializer());
    if (arr) {
      for (unsigned i = 0, e = arr->getNumOperands(); i < e; ++i) {
        auto *cs = dyn_cast<ConstantStruct>(arr->getOperand(i));
        if (!cs || cs->getNumOperands() < 2) continue;

        auto *fn = dyn_cast<Function>(cs->getOperand(0)->stripPointerCasts());
        if (fn != &F) continue;

        auto *strGV =
            dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
        if (!strGV || !strGV->hasInitializer()) continue;

        auto *strData = dyn_cast<ConstantDataArray>(strGV->getInitializer());
        if (!strData) continue;

        if (strData->getAsCString() == "ntc") return true;
      }
    }
  }

check_config:
  return armorcomp::configSaysApply(F.getName(), "ntc");
}

// ─────────────────────────────────────────────────────────────────────────────
// NeonTypeConfusionPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses NeonTypeConfusionPass::run(Function &F,
                                              FunctionAnalysisManager & /*AM*/) {
  if (F.isDeclaration()) return PreservedAnalyses::all();

  // Never instrument ArmorComp's own injected functions
  if (F.getName().startswith("__armorcomp_")) return PreservedAnalyses::all();

  bool shouldObf = !annotateOnly
                   || hasNTCAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "ntc");
  if (!shouldObf) return PreservedAnalyses::all();

  // AArch64 only — fmov GPR↔SIMD is an AArch64-specific instruction
  Module     *M  = F.getParent();
  Triple TT(M->getTargetTriple());
  if (!TT.isAArch64()) return PreservedAnalyses::all();

  LLVMContext &Ctx   = F.getContext();
  Type        *VoidTy = Type::getVoidTy(Ctx);
  Type        *I32Ty  = Type::getInt32Ty(Ctx);

  // ── Get or create the shared volatile-zero global ─────────────────────────
  // WeakAny linkage: multiple TUs defining the same global → linker merges.
  // Volatile loads prevent the optimizer from constant-folding to 0.
  GlobalVariable *NtcZero = M->getGlobalVariable("__armorcomp_ntc_zero");
  if (!NtcZero) {
    NtcZero = new GlobalVariable(
        *M,
        I32Ty,
        /*isConstant=*/false,
        GlobalValue::WeakAnyLinkage,
        ConstantInt::get(I32Ty, 0),
        "__armorcomp_ntc_zero"
    );
  }

  // ── Build inline asm types ─────────────────────────────────────────────────
  // All asm blocks: void (i32) — one GPR input (the zero value), void return.
  FunctionType *AsmFTy = FunctionType::get(VoidTy, {I32Ty}, false);

  // Block A (entry): fmov s16, w<input>  then  fmov w9, s16
  // ${0:w} forces the 32-bit register form (wN) instead of the default 64-bit
  // xN that LLVM prints for the 'r' constraint.  fmov Sd, Wn requires Wn (32-bit).
  // Clobbers: s16 (written by first fmov), x9 (w9 zero-extends to x9)
  auto *AsmA = InlineAsm::get(
      AsmFTy,
      "fmov s16, ${0:w}\n\tfmov w9, s16",
      "r,~{s16},~{x9}",
      /*hasSideEffects=*/true
  );

  // Block B (entry): fmov s17, w<input>  then  fmov w10, s17
  auto *AsmB = InlineAsm::get(
      AsmFTy,
      "fmov s17, ${0:w}\n\tfmov w10, s17",
      "r,~{s17},~{x10}",
      /*hasSideEffects=*/true
  );

  // Block C (before ret): 2-source roundtrip using s18, s19, w11, w12
  auto *AsmC = InlineAsm::get(
      AsmFTy,
      "fmov s18, ${0:w}\n\tfmov s19, ${0:w}\n\tfmov w11, s18\n\tfmov w12, s19",
      "r,~{s18},~{s19},~{x11},~{x12}",
      /*hasSideEffects=*/true
  );

  // ── Inject at function entry (first insertion point, after PHIs) ──────────
  // The asm uses only scratch registers — it is safe to insert before allocas.
  BasicBlock  &EntryBB    = F.getEntryBlock();
  Instruction *EntryInsert = &*EntryBB.getFirstInsertionPt();
  IRBuilder<>  EntryBldr(EntryInsert);

  // One fresh volatile load feeds both entry asm blocks.  Two distinct asm
  // calls ensure IDA cannot merge them into a single annotation.
  Value *EntryZero = EntryBldr.CreateLoad(I32Ty, NtcZero,
                                          /*isVolatile=*/true, "ntc.entry.zero");
  EntryBldr.CreateCall(AsmFTy, AsmA, {EntryZero});
  EntryBldr.CreateCall(AsmFTy, AsmB, {EntryZero});

  // ── Inject before each ReturnInst ─────────────────────────────────────────
  // Snapshot rets before iteration to avoid invalidating iterators.
  std::vector<ReturnInst *> rets;
  for (BasicBlock &BB : F)
    if (auto *RI = dyn_cast<ReturnInst>(BB.getTerminator())) {
      // Guard: skip if preceding instruction is a musttail call (VMP thunk).
      // Inserting fmov before ret would break the musttail → ret invariant.
      Instruction *Prev = RI->getPrevNode();
      if (Prev && isa<CallInst>(Prev) && cast<CallInst>(Prev)->isMustTailCall())
        continue;
      rets.push_back(RI);
    }

  for (ReturnInst *RI : rets) {
    IRBuilder<> Bldr(RI);
    Value *RetZero = Bldr.CreateLoad(I32Ty, NtcZero,
                                     /*isVolatile=*/true, "ntc.ret.zero");
    Bldr.CreateCall(AsmFTy, AsmC, {RetZero});
  }

  unsigned retCount = (unsigned)rets.size();

  errs() << "[ArmorComp][NTC] obfuscated: " << F.getName()
         << " (2 injection(s), " << retCount << " ret(s))\n";

  return PreservedAnalyses::none();
}
