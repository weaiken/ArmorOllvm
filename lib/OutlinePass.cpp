//===----------------------------------------------------------------------===//
// ArmorComp — OutlinePass implementation
//
// Extracts each non-entry basic block of a targeted function into an
// independent internal function using LLVM's CodeExtractor.
//
// The outlined function is named "__armorcomp_outline_N" (N = global counter)
// and carries noinline + optnone attributes.
//
// Steps:
//   1. Demote PHI nodes to alloca/load/store (avoids live-out PHI problems).
//   2. Demote cross-block SSA register values to alloca (same as BCF).
//   3. For each eligible non-entry BB, use CodeExtractor to extract it.
//   4. Rename extracted function and add protection attributes.
//===----------------------------------------------------------------------===//

#include "ArmorComp/OutlinePass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"
#include "llvm/Transforms/Utils/Local.h"   // DemotePHIToStack, DemoteRegToStack

#include <string>
#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasOutlineAnnotation(Function &F) {
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
    if (StrData && StrData->getAsCString() == "outline") return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// SSA demotion — identical to BCFPass's demoteForBCF
// ─────────────────────────────────────────────────────────────────────────────

static void demoteForOutline(Function &F) {
  // 1. Demote PHI nodes to alloca/load/store.
  //    CodeExtractor cannot handle PHI outputs (values flowing out via PHIs),
  //    so we must remove all PHI nodes before extraction.
  bool changed = true;
  while (changed) {
    changed = false;
    for (auto &BB : F)
      for (auto &I : BB)
        if (auto *phi = dyn_cast<PHINode>(&I)) {
          DemotePHIToStack(phi);
          changed = true;
          break;
        } else {
          break;
        }
    if (changed) continue;
  }

  // 2. Demote cross-block SSA register values.
  //    Any value defined in one BB and used in another becomes a alloca/load/store.
  //    After this, each BB's live-ins come only from alloca pointers and function args.
  std::vector<Instruction *> todemote;
  for (auto &BB : F)
    for (auto &I : BB) {
      if (I.isTerminator() || isa<AllocaInst>(&I)) continue;
      for (auto *U : I.users())
        if (auto *UI = dyn_cast<Instruction>(U); UI && UI->getParent() != &BB) {
          todemote.push_back(&I);
          break;
        }
    }
  for (auto *I : todemote)
    DemoteRegToStack(*I, false);
}

// ─────────────────────────────────────────────────────────────────────────────
// Main transformation
// ─────────────────────────────────────────────────────────────────────────────

static bool outlineBlocks(Function &F) {
  if (F.isDeclaration()) return false;
  if (F.size() <= 1) return false;

  // Skip functions with invoke (C++ exception edges would need special handling).
  for (auto &BB : F)
    if (isa<InvokeInst>(BB.getTerminator())) return false;

  // Never outline our own injected functions.
  if (F.getName().startswith("__armorcomp_")) return false;

  // ── Phase 1: SSA demotion ─────────────────────────────────────────────────
  demoteForOutline(F);

  // ── Phase 2: Collect eligible non-entry BBs ───────────────────────────────
  // Snapshot the list BEFORE extraction begins — extraction modifies the
  // function's BB list (adds entry stub blocks), invalidating live iterators.
  std::vector<BasicBlock *> targets;
  BasicBlock *entryBB = &F.getEntryBlock();
  for (auto &BB : F) {
    if (&BB == entryBB) continue;
    // Skip BBs with only a terminator (nothing to outline).
    if (BB.size() <= 1) continue;
    // Skip already-unreachable BBs (dead blocks from OPP).
    if (isa<UnreachableInst>(BB.getTerminator())) continue;
    targets.push_back(&BB);
  }

  if (targets.empty()) return false;

  // ── Phase 3: Extract each BB ──────────────────────────────────────────────
  // We use a static counter for globally unique names across translation units.
  static unsigned OutlineCounter = 0;

  unsigned outlined = 0;
  for (BasicBlock *BB : targets) {
    // Guard: the BB must still belong to F (a previous extraction might have
    // moved it into a different function if it was merged or referenced).
    if (BB->getParent() != &F) continue;

    // Build a fresh analysis cache for this function.  The cache must be
    // constructed AFTER demotion and BEFORE extraction.  Consecutive
    // extractCodeRegion calls are safe to use with the same cache only when
    // no other IR mutations happen between them; since we rename / add attrs
    // on each extracted function, we rebuild the cache each iteration.
    CodeExtractorAnalysisCache CEAC(F);

    CodeExtractor CE(
        {BB},
        /*DT=*/nullptr,
        /*AggregateArgs=*/false,
        /*BFI=*/nullptr,
        /*BPI=*/nullptr,
        /*AC=*/nullptr,
        /*AllowVarArgs=*/false,
        /*AllowAlloca=*/false,       // allocas are only in the entry block now
        /*AllocationBlock=*/nullptr,
        /*Suffix=*/"armorcomp_outline");

    if (!CE.isEligible()) continue;

    Function *NewFn = CE.extractCodeRegion(CEAC);
    if (!NewFn) continue;

    // Rename to __armorcomp_outline_N and add protection attributes.
    NewFn->setName("__armorcomp_outline_" + std::to_string(OutlineCounter++));
    NewFn->setLinkage(GlobalValue::InternalLinkage);
    NewFn->addFnAttr(Attribute::NoInline);
    NewFn->addFnAttr(Attribute::OptimizeNone);

    ++outlined;
  }

  if (outlined == 0) return false;

  errs() << "[ArmorComp][OUTLINE] outlined: " << F.getName()
         << " (" << outlined << " block" << (outlined > 1 ? "s" : "") << ")\n";
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// OutlinePass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses OutlinePass::run(Function &F,
                                   FunctionAnalysisManager & /*AM*/) {
  if (F.isDeclaration()) return PreservedAnalyses::all();

  bool shouldObf = !annotateOnly
                   || hasOutlineAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "outline");
  if (!shouldObf) return PreservedAnalyses::all();

  bool changed = outlineBlocks(F);
  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
