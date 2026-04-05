//===----------------------------------------------------------------------===//
// ArmorComp — SplitPass (Basic Block Splitting)
//
// For each targeted function, every basic block with enough instructions is
// split at a randomly-chosen point into two sub-blocks joined by an
// unconditional branch.  Running this before CFF/BCF multiplies the number
// of switch cases / bogus branches produced by those passes.
//
// Split algorithm per BB:
//   1. Collect "splittable" instructions: skip PHI nodes (must stay at top),
//      skip alloca (must stay in entry), skip the first eligible instruction
//      (need at least one instruction in each half), skip terminator.
//   2. Pick a uniformly random split point from the remaining candidates.
//   3. Call BB.splitBasicBlock(splitPoint) — LLVM inserts an unconditional
//      branch at the split and moves the rest to a new ".splt" block.
//
// RNG seeded from hash(FunctionName) for deterministic output.
//===----------------------------------------------------------------------===//

#include "ArmorComp/SplitPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"    // ConstantArray, ConstantStruct, ConstantDataArray
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <random>
#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasSplitAnnotation(Function &F) {
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

    if (strData->getAsCString() == "split") return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-function split
// ─────────────────────────────────────────────────────────────────────────────

static bool splitFunction(Function &F, std::mt19937 &rng) {
  // Snapshot: collect all BBs before we start adding new ones.
  // (splitBasicBlock inserts new BBs into the function's BB list.)
  std::vector<BasicBlock *> snapshot;
  for (auto &BB : F)
    snapshot.push_back(&BB);

  bool changed = false;

  for (auto *BB : snapshot) {
    // Collect eligible split points:
    //   - Skip PHI nodes  (must remain at block entry per SSA rules)
    //   - Skip alloca     (keep allocas together in entry block)
    //   - Skip terminator (can't move the branch/ret instruction)
    //   - Skip the *first* eligible instruction to ensure the first half
    //     has at least one non-branch instruction.
    std::vector<BasicBlock::iterator> cands;
    bool skippedFirst = false;

    for (auto it = BB->begin(); it != BB->end(); ++it) {
      if (isa<PHINode>(&*it))    continue;
      if (isa<AllocaInst>(&*it)) continue;
      if (it->isTerminator())    continue;

      if (!skippedFirst) {
        skippedFirst = true;
        continue;  // at least one instruction must stay in the first half
      }

      cands.push_back(it);
    }

    if (cands.empty()) continue;  // block too small to split

    // Uniformly random split point.
    std::uniform_int_distribution<size_t> pick(0, cands.size() - 1);
    BasicBlock::iterator splitAt = cands[pick(rng)];

    // splitBasicBlock(I): keeps everything before I in BB (+ inserts br),
    // moves I and everything after into a fresh ".splt" block.
    BB->splitBasicBlock(splitAt, BB->getName() + ".splt");
    changed = true;
  }

  return changed;
}

// ─────────────────────────────────────────────────────────────────────────────
// SplitPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses SplitPass::run(Function &F, FunctionAnalysisManager & /*AM*/) {
  bool shouldSplit = !annotateOnly || hasSplitAnnotation(F)
                     || armorcomp::configSaysApply(F.getName(), "split");
  if (!shouldSplit) return PreservedAnalyses::all();

  if (F.isDeclaration() || F.size() < 2) return PreservedAnalyses::all();

  std::mt19937 rng(std::hash<std::string>{}(F.getName().str()));

  bool changed = splitFunction(F, rng);

  if (changed)
    errs() << "[ArmorComp][SPLT] split: " << F.getName()
           << " (" << F.size() << " basic blocks after)\n";

  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
