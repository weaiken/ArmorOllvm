//===----------------------------------------------------------------------===//
// ArmorComp — GEPObfPass (GEP Index Obfuscation)
//
// Converts every constant-offset GetElementPtrInst in a targeted function into
// an i8-pointer GEP with an XOR-obfuscated byte offset, defeating IDA Pro's
// structure field recognition, array subscript analysis, and C++ vtable
// dispatch identification.  See include/ArmorComp/GEPObfPass.h for design doc.
//===----------------------------------------------------------------------===//

#include "ArmorComp/GEPObfPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/ADT/APInt.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasGEPOAnnotation(Function &F) {
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

        if (strData->getAsCString() == "gepo") return true;
      }
    }
  }

check_config:
  return armorcomp::configSaysApply(F.getName(), "gepo");
}

// ─────────────────────────────────────────────────────────────────────────────
// Get or create the shared volatile-zero global for GEPO.
// Separate from CO / SOB / LRO / RVO zeros so that IDA cannot alias them.
// WeakAny: multiple TUs → linker merges to a single instance.
// ─────────────────────────────────────────────────────────────────────────────

static GlobalVariable *getOrCreateGepoZero(Module &M, Type *I64Ty) {
  const StringRef name = "__armorcomp_gepo_zero";
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
// GEPObfPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses GEPObfPass::run(Function &F,
                                   FunctionAnalysisManager & /*AM*/) {
  if (F.isDeclaration() || F.empty()) return PreservedAnalyses::all();
  if (F.getName().startswith("__armorcomp_")) return PreservedAnalyses::all();

  bool shouldObf = !annotateOnly
                   || hasGEPOAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "gepo");
  if (!shouldObf) return PreservedAnalyses::all();

  Module      *M   = F.getParent();
  LLVMContext &Ctx  = M->getContext();
  const DataLayout &DL = M->getDataLayout();
  Type *I8Ty  = Type::getInt8Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);

  GlobalVariable *GepoZero = getOrCreateGepoZero(*M, I64Ty);

  // ── Snapshot all GEP instructions before modification ─────────────────────
  // We erase GEPs via RAUW+erase, so snapshotting avoids iterator invalidation.
  std::vector<GetElementPtrInst *> geps;
  for (auto &BB : F)
    for (auto &I : BB)
      if (auto *GEP = dyn_cast<GetElementPtrInst>(&I))
        geps.push_back(GEP);

  if (geps.empty()) return PreservedAnalyses::all();

  unsigned obfCount = 0;

  for (GetElementPtrInst *GEP : geps) {
    // ── Compute the total constant byte offset ────────────────────────────
    // accumulateConstantOffset folds ALL index operands (including struct field
    // indices, array strides, and outer pointer arithmetic) into a single
    // signed byte offset.  Returns false if any index is non-constant.
    unsigned AS = GEP->getPointerAddressSpace();
    APInt TotalOffset(DL.getIndexSizeInBits(AS), 0);
    if (!GEP->accumulateConstantOffset(DL, TotalOffset)) continue;

    int64_t ByteOffset = TotalOffset.getSExtValue();
    if (ByteOffset == 0) continue;  // zero offset — no obfuscation entropy

    // ── Replace the typed GEP with an i8-pointer byte-offset GEP ─────────
    //
    // Original (e.g. struct field at byte offset 4):
    //   getelementptr %S, ptr base, i64 0, i32 1
    //
    // Replaced:
    //   %gepo.zero = load volatile i64, @__armorcomp_gepo_zero  ; = 0
    //   %gepo.off  = xor i64 4, %gepo.zero                      ; = 4 @ runtime
    //   %gepo.ptr  = getelementptr i8, ptr base, i64 %gepo.off  ; legal GEP
    //
    // IDA sees: ldr x9, [gepo_zero]; eor x9, x9, #4; ldr w0, [base, x9]
    // → offset unknown → struct layout unrecoverable.
    //
    // Using i8 GEP avoids the LLVM constraint that struct field indices must
    // be ConstantInt — i8 GEP only performs pointer arithmetic, which can
    // accept any integer index.
    IRBuilder<> IRB(GEP);

    Value *ZeroI64  = IRB.CreateLoad(I64Ty, GepoZero, /*isVolatile=*/true,
                                      "gepo.zero");
    Value *OffConst = ConstantInt::get(I64Ty,
                                       static_cast<uint64_t>(ByteOffset));
    Value *ObfOff   = IRB.CreateXor(OffConst, ZeroI64, "gepo.off");
    Value *NewGEP   = IRB.CreateGEP(I8Ty, GEP->getPointerOperand(),
                                     {ObfOff}, "gepo.ptr");

    GEP->replaceAllUsesWith(NewGEP);
    GEP->eraseFromParent();
    ++obfCount;
  }

  if (obfCount == 0) return PreservedAnalyses::all();

  errs() << "[ArmorComp][GEPO] obfuscated: " << F.getName()
         << " (" << obfCount << " GEP" << (obfCount > 1 ? "s" : "") << ")\n";

  return PreservedAnalyses::none();
}
