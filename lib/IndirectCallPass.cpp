//===----------------------------------------------------------------------===//
// ArmorComp — IndirectCallPass (Indirect Call Obfuscation)
//
// Transforms every direct call to a named function into an indirect call via
// a runtime-computed pointer, defeating static call-graph reconstruction.
//
// Transformation per call site:
//
//   Before:  %r = call <retTy> @foo(<args>)
//
//   After:   %off  = load volatile i64, ptr @__armorcomp_icall_off  ; always 0
//            %base = ptrtoint ptr @foo to i64
//            %addr = add  i64 %base, %off
//            %fp   = inttoptr i64 %addr to ptr
//            %r    = call <retTy> %fp(<args>)
//
// @__armorcomp_icall_off is a module-level global initialized to 0.
// The volatile qualifier forces the optimizer to assume the value is unknown
// at compile time, preventing constant-folding of %addr back to @foo.
//
// The ptrtoint→add→inttoptr chain signals to alias analysis that the result
// pointer is "derived from arithmetic" and may point anywhere — breaking
// static call-graph tools (IDA, Ghidra, BinaryNinja, Frida stalker).
//
// Skips:
//   - LLVM intrinsics (llvm.*)  — must remain direct
//   - Indirect calls (already indirect)
//   - Calls with no callee name (function pointers)
//   - Functions with personality / landing pads (exception handling)
//===----------------------------------------------------------------------===//

#include "ArmorComp/IndirectCallPass.h"
#include "ArmorComp/ObfuscationConfig.h"

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

static bool hasICallAnnotation(Function &F) {
  Module *M = F.getParent();
  GlobalVariable *GV = M->getGlobalVariable("llvm.global.annotations");
  if (!GV || !GV->hasInitializer()) return false;

  auto *arr = dyn_cast<ConstantArray>(GV->getInitializer());
  if (!arr) return false;

  for (unsigned i = 0, e = arr->getNumOperands(); i < e; ++i) {
    auto *cs = dyn_cast<ConstantStruct>(arr->getOperand(i));
    if (!cs || cs->getNumOperands() < 2) continue;
    if (cs->getOperand(0)->stripPointerCasts() != &F) continue;

    auto *strGV =
        dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
    if (!strGV || !strGV->hasInitializer()) continue;

    auto *strData = dyn_cast<ConstantDataArray>(strGV->getInitializer());
    if (!strData) continue;

    if (strData->getAsCString() == "icall") return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Get or create the shared volatile-zero offset global
// ─────────────────────────────────────────────────────────────────────────────

static GlobalVariable *getOrCreateOpaqueOffset(Module &M,
                                                IntegerType *IPtrTy) {
  const StringRef name = "__armorcomp_icall_off";

  if (auto *existing = M.getNamedGlobal(name))
    return existing;

  // volatile global i64/i32 = 0
  // WeakAnyLinkage: one copy across TUs; survives LTO; can be overridden.
  auto *GV = new GlobalVariable(
      M, IPtrTy, /*isConstant=*/false,
      GlobalValue::WeakAnyLinkage,
      ConstantInt::get(IPtrTy, 0), name);
  GV->setAlignment(Align(8));
  return GV;
}

// ─────────────────────────────────────────────────────────────────────────────
// Transform one call instruction into an indirect call
// ─────────────────────────────────────────────────────────────────────────────

static void indirectifyCall(CallInst *CI, GlobalVariable *OpaqueOffset,
                            IntegerType *IPtrTy) {
  Function *Callee = CI->getCalledFunction();
  if (!Callee) return;                         // already indirect
  if (Callee->isIntrinsic()) return;           // must stay direct

  IRBuilder<> IRB(CI);

  // Step 1: load the volatile zero offset
  Value *Off = IRB.CreateLoad(IPtrTy, OpaqueOffset, /*isVolatile=*/true,
                              "icall.off");

  // Step 2: ptrtoint @callee → integer
  Value *Base = IRB.CreatePtrToInt(Callee, IPtrTy, "icall.base");

  // Step 3: add offset (0 at runtime, unknown at compile time)
  Value *Addr = IRB.CreateAdd(Base, Off, "icall.addr");

  // Step 4: inttoptr → opaque function pointer
  Value *FP = IRB.CreateIntToPtr(Addr, IRB.getPtrTy(), "icall.fp");

  // Step 5: rebuild the call using the indirect pointer
  // Keep the same function type and arguments as the original call.
  SmallVector<Value *, 8> Args(CI->args());

  CallInst *NewCI = IRB.CreateCall(CI->getFunctionType(), FP, Args);
  NewCI->setCallingConv(CI->getCallingConv());
  NewCI->setAttributes(CI->getAttributes());
  NewCI->takeName(CI);

  if (!CI->getType()->isVoidTy())
    CI->replaceAllUsesWith(NewCI);

  CI->eraseFromParent();
}

// ─────────────────────────────────────────────────────────────────────────────
// IndirectCallPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses IndirectCallPass::run(Function &F,
                                        FunctionAnalysisManager & /*AM*/) {
  bool shouldICF = !annotateOnly || hasICallAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "icall");
  if (!shouldICF) return PreservedAnalyses::all();

  if (F.isDeclaration() || F.empty()) return PreservedAnalyses::all();

  // Skip exception-handling functions (landing pads complicate CFG)
  if (F.hasPersonalityFn()) return PreservedAnalyses::all();

  Module *M      = F.getParent();
  LLVMContext &Ctx = M->getContext();
  const DataLayout &DL = M->getDataLayout();

  // Integer type sized to hold a pointer (i64 on aarch64, i32 on 32-bit)
  IntegerType *IPtrTy = DL.getIntPtrType(Ctx);

  // Lazily create the shared opaque-zero global
  GlobalVariable *OpaqueOffset = getOrCreateOpaqueOffset(*M, IPtrTy);

  // Snapshot: collect all direct CallInsts before modifying the function.
  std::vector<CallInst *> calls;
  for (auto &BB : F)
    for (auto &I : BB)
      if (auto *CI = dyn_cast<CallInst>(&I)) {
        // Only process calls that have a concrete named callee.
        Function *Callee = CI->getCalledFunction();
        if (!Callee) continue;
        if (Callee->isIntrinsic()) continue;
        calls.push_back(CI);
      }

  if (calls.empty()) return PreservedAnalyses::all();

  for (auto *CI : calls)
    indirectifyCall(CI, OpaqueOffset, IPtrTy);

  errs() << "[ArmorComp][ICALL] indirected: " << F.getName()
         << " (" << calls.size() << " call" << (calls.size() > 1 ? "s" : "") << ")\n";

  return PreservedAnalyses::none();
}
