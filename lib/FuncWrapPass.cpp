//===----------------------------------------------------------------------===//
// ArmorComp — FuncWrapPass implementation
//
// For each annotated function, every direct call to a named callee is replaced
// with a call to a thin internal wrapper that forwards all arguments and the
// return value.
//
// The wrapper is created once per (annotated-function, callee) pair.
// Multiple call sites in the same annotated function that call the same callee
// reuse the same wrapper via a DenseMap.
//
// Wrapper anatomy:
//   define internal <retTy> @__armorcomp_fw_N(<args>) noinline optnone {
//     %fw.z = load volatile i64, ptr @__armorcomp_fw_zero
//     %r    = call <retTy> @original(<args>)
//     ret <retTy> %r
//   }
//
// The volatile load adds noise to the decompiler output and prevents the
// optimizer from recognising the wrapper as a trivial passthrough.
//===----------------------------------------------------------------------===//

#include "ArmorComp/FuncWrapPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/Constants.h"
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

static bool hasFWAnnotation(Function &F) {
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
    if (StrData && StrData->getAsCString() == "fw") return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Get or create the shared volatile-zero noise global
// ─────────────────────────────────────────────────────────────────────────────

static GlobalVariable *getOrCreateFWZero(Module &M) {
  const char *Name = "__armorcomp_fw_zero";
  if (GlobalVariable *GV = M.getGlobalVariable(Name))
    return GV;

  return new GlobalVariable(
      M, Type::getInt64Ty(M.getContext()), /*isConstant=*/false,
      GlobalValue::WeakAnyLinkage,
      ConstantInt::get(Type::getInt64Ty(M.getContext()), 0), Name);
}

// ─────────────────────────────────────────────────────────────────────────────
// Create a wrapper function for one callee
// ─────────────────────────────────────────────────────────────────────────────

static Function *createWrapper(Function *Callee, GlobalVariable *FWZero,
                                unsigned &Counter) {
  Module &M = *Callee->getParent();
  LLVMContext &Ctx = M.getContext();
  FunctionType *CalleeTy = Callee->getFunctionType();

  // Build the wrapper's parameter list — same types as the callee.
  SmallVector<Type *, 8> ParamTys(CalleeTy->param_begin(),
                                   CalleeTy->param_end());
  FunctionType *WrapTy =
      FunctionType::get(CalleeTy->getReturnType(), ParamTys, false);

  // Unique name: __armorcomp_fw_<N>
  std::string WrapName =
      "__armorcomp_fw_" + std::to_string(Counter++);

  Function *Wrapper = Function::Create(
      WrapTy, GlobalValue::InternalLinkage, WrapName, &M);

  // Prevent inlining at -O1+ so the call graph indirection survives.
  Wrapper->addFnAttr(Attribute::NoInline);
  Wrapper->addFnAttr(Attribute::OptimizeNone);

  // Build the single basic block.
  BasicBlock *BB = BasicBlock::Create(Ctx, "entry", Wrapper);
  IRBuilder<> IRB(BB);

  // Volatile load of the noise zero — adds a false dependency in the CFG
  // and prevents the decompiler from collapsing the wrapper into a NOP.
  Type *I64Ty = Type::getInt64Ty(Ctx);
  IRB.CreateLoad(I64Ty, FWZero, /*isVolatile=*/true, "fw.z");

  // Forward all arguments to the original callee.
  SmallVector<Value *, 8> Args;
  for (Argument &Arg : Wrapper->args())
    Args.push_back(&Arg);

  Value *Ret = IRB.CreateCall(CalleeTy, Callee, Args, "fw.r");

  if (CalleeTy->getReturnType()->isVoidTy())
    IRB.CreateRetVoid();
  else
    IRB.CreateRet(Ret);

  return Wrapper;
}

// ─────────────────────────────────────────────────────────────────────────────
// FuncWrapPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses FuncWrapPass::run(Function &F,
                                    FunctionAnalysisManager & /*AM*/) {
  if (F.isDeclaration()) return PreservedAnalyses::all();

  // Never wrap ArmorComp's own injected functions.
  if (F.getName().startswith("__armorcomp_")) return PreservedAnalyses::all();

  bool shouldWrap = !annotateOnly
                    || hasFWAnnotation(F)
                    || armorcomp::configSaysApply(F.getName(), "fw");
  if (!shouldWrap) return PreservedAnalyses::all();

  Module *M = F.getParent();
  GlobalVariable *FWZero = getOrCreateFWZero(*M);

  // Collect all qualifying direct CallInsts before we start modifying.
  std::vector<CallInst *> calls;
  for (auto &BB : F)
    for (auto &I : BB)
      if (auto *CI = dyn_cast<CallInst>(&I)) {
        Function *Callee = CI->getCalledFunction();
        if (!Callee) continue;                          // indirect call

        // Must be a named callee (not an intrinsic name mismatch).
        if (Callee->isIntrinsic()) continue;            // llvm.*

        // Vararg callees: can't create a type-safe fixed-signature wrapper.
        if (Callee->isVarArg()) continue;

        // Don't wrap our own wrappers or other injected functions.
        if (Callee->getName().startswith("__armorcomp_")) continue;

        calls.push_back(CI);
      }

  if (calls.empty()) return PreservedAnalyses::all();

  // Counter for unique wrapper names — static so it monotonically increases
  // across all invocations of FuncWrapPass within a compilation unit.
  static unsigned WrapperCounter = 0;

  // Reuse wrappers within this annotated function for the same callee.
  DenseMap<Function *, Function *> calleeToWrapper;

  unsigned replaced = 0;
  for (CallInst *CI : calls) {
    Function *Callee = CI->getCalledFunction();

    // Lazy-create wrapper for this callee.
    Function *&Wrapper = calleeToWrapper[Callee];
    if (!Wrapper)
      Wrapper = createWrapper(Callee, FWZero, WrapperCounter);

    // Rebuild the call using the wrapper.
    IRBuilder<> IRB(CI);
    SmallVector<Value *, 8> Args(CI->args());

    CallInst *NewCI = IRB.CreateCall(Wrapper->getFunctionType(), Wrapper, Args);
    NewCI->setCallingConv(CI->getCallingConv());
    NewCI->takeName(CI);

    if (!CI->getType()->isVoidTy())
      CI->replaceAllUsesWith(NewCI);

    CI->eraseFromParent();
    ++replaced;
  }

  errs() << "[ArmorComp][FW] wrapped: " << F.getName()
         << " (" << replaced << " call" << (replaced > 1 ? "s" : "")
         << ", " << calleeToWrapper.size() << " wrapper"
         << (calleeToWrapper.size() > 1 ? "s" : "") << ")\n";

  return PreservedAnalyses::none();
}
