//===----------------------------------------------------------------------===//
// ArmorComp — FakeAPICallPass (FAPI — Fake API Call Injection)
//
// Inserts real libc calls (getpid / getpagesize) before each basic block's
// terminator.  The call results are consumed by asm sideeffect sinks, which
// prevents DCE from removing the calls.  Unlike JunkCodePass's arithmetic
// chains (which operate on dead values), these calls have genuine side effects
// that no analysis tool can prove are zero-cost.
//
// IDA/Ghidra effect:
//   - Every basic block (except entry) has a `bl getpid` or `bl getpagesize`
//     before its branch/return.  Analysts see plausible system-call usage.
//   - Cross-reference from getpid back to this function adds noise to xref
//     views.  Anti-debug heuristics see getpid() calls and may flag this as
//     a PID-check pattern.
//   - Alternate between getpid / getpagesize per BB for visual variety.
//===----------------------------------------------------------------------===//

#include "ArmorComp/FakeAPICallPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasFAPIAnnotation(Function &F) {
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

        if (strData->getAsCString() == "fapi") return true;
      }
    }
  }

check_config:
  return armorcomp::configSaysApply(F.getName(), "fapi");
}

// ─────────────────────────────────────────────────────────────────────────────
// Get or create the declaration for getpid() / getpagesize()
// ─────────────────────────────────────────────────────────────────────────────

/// getpid() — returns i32, no args.
static FunctionCallee getOrCreateGetpid(Module &M) {
  LLVMContext &Ctx = M.getContext();
  FunctionType *FT = FunctionType::get(Type::getInt32Ty(Ctx), /*isVarArg=*/false);
  return M.getOrInsertFunction("getpid", FT);
}

/// getpagesize() — returns i32, no args.
static FunctionCallee getOrCreateGetpagesize(Module &M) {
  LLVMContext &Ctx = M.getContext();
  FunctionType *FT = FunctionType::get(Type::getInt32Ty(Ctx), /*isVarArg=*/false);
  return M.getOrInsertFunction("getpagesize", FT);
}

// ─────────────────────────────────────────────────────────────────────────────
// Main injection
// ─────────────────────────────────────────────────────────────────────────────

static bool injectFakeAPICalls(Function &F) {
  Module *M = F.getParent();
  LLVMContext &Ctx = F.getContext();

  FunctionCallee getpidFn   = getOrCreateGetpid(*M);
  FunctionCallee getpagesizeFn = getOrCreateGetpagesize(*M);

  // asm sideeffect sink: void = asm("", "r,~{memory}")(i32 %r)
  // The "r" constraint keeps the result in a register; "~{memory}" marks the
  // asm as having a memory side-effect so the call cannot be hoisted/deleted.
  Type *I32Ty  = Type::getInt32Ty(Ctx);
  FunctionType *sinkTy = FunctionType::get(
      Type::getVoidTy(Ctx), {I32Ty}, /*isVarArg=*/false);
  InlineAsm *sink = InlineAsm::get(sinkTy, "", "r,~{memory}", /*hasSideEffects=*/true);

  unsigned bbIdx   = 0;
  unsigned injected = 0;

  for (BasicBlock &BB : F) {
    ++bbIdx;

    // Skip the entry block — allocas live there; modifying it can confuse
    // downstream passes that look for entry-block alloca patterns.
    if (&BB == &F.getEntryBlock()) continue;

    // Skip landing pads (exception handling blocks).
    if (BB.isLandingPad()) continue;

    Instruction *term = BB.getTerminator();
    if (!term) continue;

    // Skip UnreachableInst — nothing meaningful to insert before it.
    if (isa<UnreachableInst>(term)) continue;

    IRBuilder<> B(term);

    // Alternate getpid / getpagesize for visual variety.
    FunctionCallee &callee = (bbIdx % 2 == 0) ? getpidFn : getpagesizeFn;
    Value *result = B.CreateCall(callee, {}, "fapi.r");

    // Consume result via asm sideeffect sink.
    B.CreateCall(sink, {result});

    ++injected;
  }

  if (injected == 0) return false;

  errs() << "[ArmorComp][FAPI] injected: " << F.getName()
         << " (" << injected << " API call(s))\n";
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// FakeAPICallPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses FakeAPICallPass::run(Function &F,
                                       FunctionAnalysisManager & /*AM*/) {
  if (annotateOnly && !hasFAPIAnnotation(F))
    return PreservedAnalyses::all();

  if (!injectFakeAPICalls(F))
    return PreservedAnalyses::all();

  return PreservedAnalyses::none();
}
