//===----------------------------------------------------------------------===//
// ArmorComp — LRObfPass (Link Register / Return Address Obfuscation)
//
// Strategy: inject inline asm before every ReturnInst that XORs x30 (lr)
// with a volatile-loaded zero value.  At runtime the XOR is a no-op
// (x30 ^ 0 == x30), but IDA Pro cannot prove the operand is zero and
// therefore cannot resolve the return address statically.
//
// Emitted IR before each ret:
//
//   %lro.zero = load volatile i64, @__armorcomp_lro_zero   ; = 0 at runtime
//   call void asm sideeffect "eor x30, x30, $0",
//             "r,~{x30},~{dirflag},~{fpsr},~{flags}"(i64 %lro.zero)
//   ret ...
//
// AArch64 codegen produces:
//   ldr  x9, [__armorcomp_lro_zero]   ; volatile load
//   eor  x30, x30, x9                 ; x30 ^= 0  (no-op at runtime)
//   ret                               ; branches to x30 = correct return addr
//
// See include/ArmorComp/LRObfPass.h for full design documentation.
//===----------------------------------------------------------------------===//

#include "ArmorComp/LRObfPass.h"
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

static bool hasLROAnnotation(Function &F) {
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

        if (strData->getAsCString() == "lro") return true;
      }
    }
  }

check_config:
  return armorcomp::configSaysApply(F.getName(), "lro");
}

// ─────────────────────────────────────────────────────────────────────────────
// Get or create the shared volatile-zero global for LRO.
// Separate from __armorcomp_rvo_zero / __armorcomp_sob_zero so the globals
// remain independent — IDA cannot trivially alias them.
// WeakAny: multiple TUs → linker merges to a single instance.
// ─────────────────────────────────────────────────────────────────────────────

static GlobalVariable *getOrCreateLroZero(Module &M, Type *I64Ty) {
  const StringRef name = "__armorcomp_lro_zero";
  if (auto *G = M.getGlobalVariable(name)) return G;

  auto *G = new GlobalVariable(
      M, I64Ty, /*isConstant=*/false,
      GlobalValue::WeakAnyLinkage,
      ConstantInt::get(I64Ty, 0),
      name);
  G->setAlignment(Align(8));
  return G;
}

// ─────────────────────────────────────────────────────────────────────────────
// LRObfPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses LRObfPass::run(Function &F,
                                  FunctionAnalysisManager & /*AM*/) {
  if (F.isDeclaration() || F.empty()) return PreservedAnalyses::all();
  if (F.getName().startswith("__armorcomp_")) return PreservedAnalyses::all();

  // ── AArch64-only guard ────────────────────────────────────────────────────
  // x30 is the AArch64 link register.  On other architectures this pass
  // is a no-op (the inline asm constraint references AArch64 registers).
  Module *M = F.getParent();
  if (!Triple(M->getTargetTriple()).isAArch64())
    return PreservedAnalyses::all();

  bool shouldObf = !annotateOnly
                   || hasLROAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "lro");
  if (!shouldObf) return PreservedAnalyses::all();

  LLVMContext &Ctx = M->getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Type *VoidTy = Type::getVoidTy(Ctx);

  GlobalVariable *LroZero = getOrCreateLroZero(*M, I64Ty);

  // ── Build the inline-asm CallInst prototype (reused for all rets) ─────────
  //
  // asm sideeffect "eor x30, x30, $0", "r,~{x30},~{dirflag},~{fpsr},~{flags}"
  //
  // Constraint breakdown:
  //   "r"               : input operand in any general-purpose register
  //   "~{x30}"          : clobber x30 (lr) — register allocator must not
  //                       assume x30 retains any value after this call
  //   "~{dirflag},~{fpsr},~{flags}" : standard x86-compat clobbers (harmless
  //                       on AArch64, suppresses unused-clobber warnings)
  //
  // sideeffect: prevents the asm from being optimised away as dead code.
  // The function type takes one i64 input and returns void.
  FunctionType *AsmFTy = FunctionType::get(VoidTy, {I64Ty}, /*isVarArg=*/false);
  InlineAsm *LroAsm = InlineAsm::get(
      AsmFTy,
      /*AsmString=*/"eor x30, x30, $0",
      /*Constraints=*/"r,~{x30},~{dirflag},~{fpsr},~{flags}",
      /*hasSideEffects=*/true,
      /*isAlignStack=*/false,
      InlineAsm::AD_ATT);

  // ── Snapshot return instructions ──────────────────────────────────────────
  std::vector<ReturnInst *> rets;
  for (BasicBlock &BB : F)
    if (auto *RI = dyn_cast<ReturnInst>(BB.getTerminator()))
      rets.push_back(RI);

  if (rets.empty()) return PreservedAnalyses::all();

  // ── Inject before each ret ────────────────────────────────────────────────
  for (ReturnInst *RI : rets) {
    IRBuilder<> Bldr(RI);

    // Step 1: volatile load of the XOR mask (= 0 at runtime).
    //   %lro.zero = load volatile i64, @__armorcomp_lro_zero
    Value *Zero = Bldr.CreateLoad(I64Ty, LroZero, /*isVolatile=*/true,
                                  "lro.zero");

    // Step 2: inline asm — eor x30, x30, <zero_reg>
    //   call void asm sideeffect "eor x30, x30, $0", "r,~{x30},..."(i64 zero)
    Bldr.CreateCall(AsmFTy, LroAsm, {Zero});
  }

  unsigned retCount = (unsigned)rets.size();

  errs() << "[ArmorComp][LRO] obfuscated: " << F.getName()
         << " (" << retCount << " ret(s))\n";

  return PreservedAnalyses::none();
}
