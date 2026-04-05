//===----------------------------------------------------------------------===//
// ArmorComp — IndirectBranchPass (Indirect Branch Obfuscation)
//
// Transforms every BranchInst (conditional and unconditional) in a targeted
// function into an IndirectBrInst via a runtime-computed block address,
// defeating static CFG reconstruction by disassemblers.
//
// Transformation (unconditional):
//   Before:  br label %target
//   After:   %off  = load volatile i64, @__armorcomp_ibr_off  ; always 0
//            %base = ptrtoint blockaddress(@fn, %target) to i64
//            %addr = add i64 %base, %off
//            %ptr  = inttoptr i64 %addr to ptr
//            indirectbr ptr %ptr, [label %target]
//
// Transformation (conditional):
//   Before:  br i1 %cond, label %T, label %F
//   After:   (compute both ptr_t and ptr_f via ptrtoint/add/inttoptr)
//            %ptr = select i1 %cond, ptr %ptr_t, ptr %ptr_f
//            indirectbr ptr %ptr, [label %T, label %F]
//
// SwitchInst is intentionally skipped — it is handled by CFFPass and
// converting it here would interfere with the dispatch loop.
//
// Constraints / skips:
//   - Entry block's address cannot be taken (LLVM IR rule) — skip branches
//     whose ANY successor is the function entry block.
//   - Functions with personality functions (exception handling) are skipped.
//   - LLVM intrinsic calls that look like branches are never a BranchInst, so
//     there is no special handling needed.
//===----------------------------------------------------------------------===//

#include "ArmorComp/IndirectBranchPass.h"
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

static bool hasIBrAnnotation(Function &F) {
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

    if (strData->getAsCString() == "ibr") return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Get or create the shared volatile-zero offset global (separate from icall's)
// ─────────────────────────────────────────────────────────────────────────────

static GlobalVariable *getOrCreateOpaqueOffset(Module &M,
                                                IntegerType *IPtrTy) {
  const StringRef name = "__armorcomp_ibr_off";

  if (auto *existing = M.getNamedGlobal(name))
    return existing;

  // volatile global i64/i32 = 0
  // WeakAnyLinkage: one copy across TUs; survives LTO; can be overridden.
  auto *OG = new GlobalVariable(
      M, IPtrTy, /*isConstant=*/false,
      GlobalValue::WeakAnyLinkage,
      ConstantInt::get(IPtrTy, 0), name);
  OG->setAlignment(Align(8));
  return OG;
}

// ─────────────────────────────────────────────────────────────────────────────
// Transform one BranchInst → IndirectBrInst
// Returns true if the transformation was applied.
// ─────────────────────────────────────────────────────────────────────────────

static bool indirectifyBranch(BranchInst *BI, GlobalVariable *OpaqueOffset,
                               IntegerType *IPtrTy) {
  Function *F = BI->getParent()->getParent();
  BasicBlock *EntryBB = &F->getEntryBlock();

  // Guard: cannot take blockaddress of the entry block.
  for (unsigned i = 0; i < BI->getNumSuccessors(); ++i)
    if (BI->getSuccessor(i) == EntryBB)
      return false;

  IRBuilder<> IRB(BI);

  // Step 1: load the volatile zero offset (shared across all branches in fn)
  Value *Off = IRB.CreateLoad(IPtrTy, OpaqueOffset, /*isVolatile=*/true,
                              "ibr.off");

  if (BI->isUnconditional()) {
    BasicBlock *Dest = BI->getSuccessor(0);

    // Step 2-4: blockaddress → ptrtoint → add zero → inttoptr
    Value *BA   = BlockAddress::get(F, Dest);
    Value *Base = IRB.CreatePtrToInt(BA, IPtrTy, "ibr.base");
    Value *Addr = IRB.CreateAdd(Base, Off, "ibr.addr");
    Value *Ptr  = IRB.CreateIntToPtr(Addr, IRB.getPtrTy(), "ibr.ptr");

    // Step 5: replace BranchInst with IndirectBrInst
    IndirectBrInst *IBI = IndirectBrInst::Create(Ptr, 1, BI);
    IBI->addDestination(Dest);

  } else {
    // Conditional branch: compute addresses for both successors,
    // then select based on the original condition.
    BasicBlock *TrueDest  = BI->getSuccessor(0);
    BasicBlock *FalseDest = BI->getSuccessor(1);
    Value *Cond = BI->getCondition();

    Value *BA_T = BlockAddress::get(F, TrueDest);
    Value *BA_F = BlockAddress::get(F, FalseDest);

    Value *Base_T = IRB.CreatePtrToInt(BA_T, IPtrTy, "ibr.base_t");
    Value *Base_F = IRB.CreatePtrToInt(BA_F, IPtrTy, "ibr.base_f");
    Value *Addr_T = IRB.CreateAdd(Base_T, Off, "ibr.addr_t");
    Value *Addr_F = IRB.CreateAdd(Base_F, Off, "ibr.addr_f");
    Value *Ptr_T  = IRB.CreateIntToPtr(Addr_T, IRB.getPtrTy(), "ibr.ptr_t");
    Value *Ptr_F  = IRB.CreateIntToPtr(Addr_F, IRB.getPtrTy(), "ibr.ptr_f");
    Value *SelPtr = IRB.CreateSelect(Cond, Ptr_T, Ptr_F, "ibr.sel");

    IndirectBrInst *IBI = IndirectBrInst::Create(SelPtr, 2, BI);
    IBI->addDestination(TrueDest);
    IBI->addDestination(FalseDest);
  }

  BI->eraseFromParent();
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// IndirectBranchPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses IndirectBranchPass::run(Function &F,
                                          FunctionAnalysisManager & /*AM*/) {
  bool shouldIBR = !annotateOnly || hasIBrAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "ibr");
  if (!shouldIBR) return PreservedAnalyses::all();

  if (F.isDeclaration() || F.empty()) return PreservedAnalyses::all();

  // Skip exception-handling functions (personality fns + landing pads)
  if (F.hasPersonalityFn()) return PreservedAnalyses::all();

  Module *M       = F.getParent();
  LLVMContext &Ctx = M->getContext();
  const DataLayout &DL = M->getDataLayout();

  // Integer type sized to hold a pointer (i64 on aarch64, i32 on 32-bit)
  IntegerType *IPtrTy = DL.getIntPtrType(Ctx);

  GlobalVariable *OpaqueOffset = getOrCreateOpaqueOffset(*M, IPtrTy);

  // Snapshot all BranchInsts before modifying the function.
  // (Only BranchInst — SwitchInst is intentionally skipped.)
  std::vector<BranchInst *> branches;
  for (auto &BB : F)
    if (auto *BI = dyn_cast<BranchInst>(BB.getTerminator()))
      branches.push_back(BI);

  if (branches.empty()) return PreservedAnalyses::all();

  unsigned count = 0;
  for (auto *BI : branches)
    if (indirectifyBranch(BI, OpaqueOffset, IPtrTy))
      ++count;

  if (count == 0) return PreservedAnalyses::all();

  errs() << "[ArmorComp][IBR] indirected: " << F.getName()
         << " (" << count << " branch" << (count > 1 ? "es" : "") << ")\n";

  return PreservedAnalyses::none();
}
