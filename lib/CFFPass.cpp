//===----------------------------------------------------------------------===//
// ArmorComp — CFFPass (Control Flow Flattening)
//
// OLLVM-style CFG flattening as an out-of-tree LLVM 17 pass plugin.
//
// Algorithm overview
// ──────────────────
//  1. Annotation check  — skip non-annotated functions in annotateOnly mode
//  2. PHI demotion      — DemotePHIToStack for all PHI nodes (predecessors
//                         change after flatten, PHIs become invalid)
//  3. Cross-block demotion — DemoteRegToStack for SSA values used outside
//                            their defining block (occurs at -O1+)
//  4. Entry block split — split at first non-alloca instruction so the entry
//                         block only holds allocas + dispatch init
//  5. Dispatch scaffold — alloca switchVar, switch BB in dispatch block
//  6. ID assignment     — assign random uint32 IDs to each flattened BB
//  7. Terminator rewrite — replace every branch with store+br dispatch
//
// Supported terminators: BranchInst (cond & uncond), SwitchInst,
//                        ReturnInst, UnreachableInst
// Skipped:               InvokeInst (exception handling — not needed for NDK)
//
// References
// ──────────
//   OLLVM original  — https://github.com/obfuscator-llvm/obfuscator
//   Pluto-Obfuscator — https://github.com/za233/Pluto-Obfuscator
//   LLVM PassManager — https://llvm.org/docs/WritingAnLLVMNewPMPass.html
//===----------------------------------------------------------------------===//

#include "ArmorComp/CFFPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h" // DemotePHIToStack, DemoteRegToStack

#include <algorithm>
#include <map>
#include <random>
#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

/// Return true if F has __attribute__((annotate("cff"))) in source.
///
/// Clang lowers annotate attributes to the "llvm.global.annotations" global,
/// which is a ConstantArray of { value*, string*, file*, line* } structs.
static bool hasCFFAnnotation(Function &F) {
  Module *M = F.getParent();
  GlobalVariable *GV = M->getGlobalVariable("llvm.global.annotations");
  if (!GV || !GV->hasInitializer()) return false;

  auto *arr = dyn_cast<ConstantArray>(GV->getInitializer());
  if (!arr) return false;

  for (unsigned i = 0, e = arr->getNumOperands(); i < e; ++i) {
    auto *cs = dyn_cast<ConstantStruct>(arr->getOperand(i));
    if (!cs || cs->getNumOperands() < 2) continue;

    // Operand 0 — the annotated symbol (bitcast-stripped)
    if (cs->getOperand(0)->stripPointerCasts() != &F) continue;

    // Operand 1 — pointer to the annotation string constant
    auto *strGV =
        dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
    if (!strGV || !strGV->hasInitializer()) continue;

    auto *strData = dyn_cast<ConstantDataArray>(strGV->getInitializer());
    if (!strData) continue;

    if (strData->getAsCString() == "cff") return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2 & 3 — SSA demotion helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Demote all PHI nodes in F to alloca+load/store.
///
/// After CFG flattening every block's unique predecessor becomes dispatchBB,
/// so PHI nodes (which reference specific predecessor blocks) become invalid.
/// We must demote them BEFORE touching the CFG.
static void demotePhiNodes(Function &F) {
  // Collect first — demotion modifies the IR so we can't iterate live.
  std::vector<PHINode *> phis;
  for (auto &BB : F)
    for (auto &I : BB)
      if (auto *phi = dyn_cast<PHINode>(&I))
        phis.push_back(phi);
      else
        break; // PHIs are always at the top of a BB

  for (auto *phi : phis)
    DemotePHIToStack(phi);
}

/// Demote SSA instructions whose results are used outside their defining BB.
///
/// At -O0 clang already uses alloca for all locals, so this is rarely needed.
/// At -O1+ SROA/mem2reg can create cross-block live ranges that would violate
/// dominance after flattening (dispatchBB breaks the original dominator tree).
static void demoteCrossBlockValues(Function &F) {
  std::vector<Instruction *> todemote;

  for (auto &BB : F) {
    for (auto &I : BB) {
      if (I.isTerminator() || isa<AllocaInst>(&I)) continue;
      for (auto *U : I.users()) {
        auto *UI = dyn_cast<Instruction>(U);
        if (UI && UI->getParent() != &BB) {
          todemote.push_back(&I);
          break;
        }
      }
    }
  }

  for (auto *I : todemote)
    DemoteRegToStack(*I, /*VolatileLoads=*/false);
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 7 — Terminator rewriting
// ─────────────────────────────────────────────────────────────────────────────

using IdMap = std::map<BasicBlock *, ConstantInt *>;

/// Replace the terminator of BB so that all control flow is routed through
/// dispatchBB via an integer stored in switchVar.
///
/// Supported terminators
///   BranchInst (unconditional) → store target_id + br dispatch
///   BranchInst (conditional)   → select true/false id + store + br dispatch
///   SwitchInst                 → chain of selects → store + br dispatch
///   ReturnInst / UnreachableInst → left untouched (function exits)
static void rewriteTerminator(BasicBlock *BB, AllocaInst *switchVar,
                               BasicBlock *dispatchBB, const IdMap &idMap,
                               ConstantInt *fallbackId) {
  Instruction *term = BB->getTerminator();
  IRBuilder<> B(term); // inserts before `term`

  auto getIdFor = [&](BasicBlock *target) -> ConstantInt * {
    auto it = idMap.find(target);
    return it != idMap.end() ? it->second : fallbackId;
  };

  if (auto *br = dyn_cast<BranchInst>(term)) {
    if (br->isUnconditional()) {
      // ── Unconditional branch ─────────────────────────────────────────────
      // Before: br label %succ
      // After:  store <succ_id>, %switchVar
      //         br %dispatch
      B.CreateStore(getIdFor(br->getSuccessor(0)), switchVar);
      B.CreateBr(dispatchBB);
      term->eraseFromParent();

    } else {
      // ── Conditional branch ───────────────────────────────────────────────
      // Before: br i1 %cond, label %true_bb, label %false_bb
      // After:  %sel = select i1 %cond, i32 <true_id>, i32 <false_id>
      //         store i32 %sel, %switchVar
      //         br %dispatch
      //
      // A select keeps the dispatch as a single-exit switch, which is simpler
      // than splitting into two store+br paths. It also makes the decision
      // opaque: a decompiler sees an opaque integer store, not a branch target.
      ConstantInt *trueId  = getIdFor(br->getSuccessor(0));
      ConstantInt *falseId = getIdFor(br->getSuccessor(1));
      Value *sel = B.CreateSelect(br->getCondition(), trueId, falseId,
                                  "cff.sel");
      B.CreateStore(sel, switchVar);
      B.CreateBr(dispatchBB);
      term->eraseFromParent();
    }

  } else if (auto *sw = dyn_cast<SwitchInst>(term)) {
    // ── Switch statement ────────────────────────────────────────────────────
    // Build a chain of ICmpEQ + select to compute the target ID, then
    // store it and branch to dispatch.
    //
    // Start with the default case ID; fold in each explicit case:
    //   result = default_id
    //   for each (caseVal, caseBB):
    //     result = select (sw_cond == caseVal) ? caseBB_id : result
    Value *result = getIdFor(sw->getDefaultDest());
    Value *swCond = sw->getCondition();

    for (auto &cas : sw->cases()) {
      Value *cmp = B.CreateICmpEQ(swCond, cas.getCaseValue(), "cff.sw.cmp");
      result = B.CreateSelect(cmp, getIdFor(cas.getCaseSuccessor()), result,
                               "cff.sw.sel");
    }
    B.CreateStore(result, switchVar);
    B.CreateBr(dispatchBB);
    term->eraseFromParent();

  } else if (isa<ReturnInst>(term) || isa<UnreachableInst>(term)) {
    // ── Exit terminators ────────────────────────────────────────────────────
    // These must not be touched — they carry the actual return value / signal
    // that the function ends here.  The dispatch loop naturally exits when
    // control reaches a ret/unreachable case.
    /* no-op */

  } else {
    // ── Unsupported terminator (InvokeInst, IndirectBrInst, …) ────────────
    // Leave as-is and emit a diagnostic.  For Android NDK C code this should
    // never trigger (-fno-exceptions rules out invoke).
    errs() << "[ArmorComp][CFF] WARNING: unsupported terminator in "
           << BB->getParent()->getName() << "::" << BB->getName()
           << " — skipped\n";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level: flattenCFG
// ─────────────────────────────────────────────────────────────────────────────

/// Flatten the control flow of function F.
/// Returns true if the function was modified.
static bool flattenCFG(Function &F) {
  // ── Pre-conditions ────────────────────────────────────────────────────────
  if (F.isDeclaration() || F.size() <= 1) return false;

  // Skip functions that contain invoke instructions (C++ exception landing
  // pads) — their exception table metadata is tightly coupled to the CFG.
  for (auto &BB : F)
    if (isa<InvokeInst>(BB.getTerminator())) return false;

  LLVMContext &Ctx = F.getContext();
  IntegerType *I32  = Type::getInt32Ty(Ctx);

  // ── Phase 2 & 3: demote PHI nodes and cross-block SSA values ─────────────
  demotePhiNodes(F);
  demoteCrossBlockValues(F);

  // ── Phase 4: split entry block at first non-alloca instruction ────────────
  //
  // We want the entry block to contain ONLY:
  //   • all alloca instructions (required to stay in entry for LLVM invariants)
  //   • the new switchVar alloca we are about to add
  //   • store (initial case ID) + br dispatchBB
  //
  // Everything else (the "real" first content) goes into a new BB that becomes
  // the first switch case.
  BasicBlock *entryBB = &F.getEntryBlock();

  BasicBlock::iterator splitPt = entryBB->begin();
  while (splitPt != entryBB->end() && isa<AllocaInst>(*splitPt))
    ++splitPt;

  // splitPt now points to the first non-alloca instruction (may be a branch
  // if the entry block contains only allocas).  splitBasicBlock moves
  // everything from splitPt onwards into a new block and inserts an
  // unconditional br from entryBB to the new block.
  BasicBlock *firstContentBB = entryBB; // default: no split needed
  if (splitPt != entryBB->end())
    firstContentBB = entryBB->splitBasicBlock(splitPt, "cff.entry_tail");

  // ── Phase 5: build dispatch scaffold ──────────────────────────────────────

  // Remove the br that splitBasicBlock (or the original code) left in entryBB.
  entryBB->getTerminator()->eraseFromParent();

  BasicBlock *dispatchBB =
      BasicBlock::Create(Ctx, "cff.dispatch", &F);
  BasicBlock *defaultBB =
      BasicBlock::Create(Ctx, "cff.unreachable", &F);
  new UnreachableInst(Ctx, defaultBB);

  // Alloca for the dispatch variable — lives in the entry block.
  IRBuilder<> entryIRB(entryBB); // appends to (now empty-of-code) entryBB
  AllocaInst *switchVar = entryIRB.CreateAlloca(I32, nullptr, "cff.sv");

  // ── Phase 6: assign random IDs to every non-entry BB ─────────────────────

  // Collect all BBs that will become switch cases (everything except entryBB).
  std::vector<BasicBlock *> flatBBs;
  for (auto &BB : F)
    if (&BB != entryBB && &BB != dispatchBB && &BB != defaultBB)
      flatBBs.push_back(&BB);

  if (flatBBs.empty()) return false; // degenerate — shouldn't happen

  // Seed with function name for reproducible-but-per-function IDs.
  std::mt19937 rng(std::hash<std::string>{}(
      (F.getParent()->getName() + "::" + F.getName()).str()));
  std::uniform_int_distribution<uint32_t> dist(1u, 0x7FFFFFFFu);

  IdMap idMap;
  for (auto *BB : flatBBs)
    idMap[BB] = ConstantInt::get(I32, dist(rng));

  // Initialize switchVar to the first content BB's ID, then jump to dispatch.
  ConstantInt *initId = idMap.at(flatBBs[0]);
  entryIRB.CreateStore(initId, switchVar);
  entryIRB.CreateBr(dispatchBB);

  // Build the switch in dispatchBB.
  IRBuilder<> dispIRB(dispatchBB);
  LoadInst  *swLoad  = dispIRB.CreateLoad(I32, switchVar, "cff.sv.val");
  SwitchInst *swInst = dispIRB.CreateSwitch(swLoad, defaultBB,
                                             (unsigned)flatBBs.size());
  for (auto *BB : flatBBs)
    swInst->addCase(idMap.at(BB), BB);

  // ── Phase 7: rewrite terminators ─────────────────────────────────────────
  for (auto *BB : flatBBs)
    rewriteTerminator(BB, switchVar, dispatchBB, idMap, initId);

  // ── Verification (debug builds only) ─────────────────────────────────────
#ifndef NDEBUG
  if (verifyFunction(F, &errs()))
    errs() << "[ArmorComp][CFF] ERROR: IR verification failed after flattening "
           << F.getName() << "\n";
#endif

  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// CFFPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses CFFPass::run(Function &F, FunctionAnalysisManager & /*AM*/) {
  bool shouldFlatten = !annotateOnly || hasCFFAnnotation(F)
                       || armorcomp::configSaysApply(F.getName(), "cff");
  if (!shouldFlatten) return PreservedAnalyses::all();

  bool changed = flattenCFG(F);
  if (changed)
    errs() << "[ArmorComp][CFF] flattened: " << F.getName() << "\n";

  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
