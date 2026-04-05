//===----------------------------------------------------------------------===//
// ArmorComp — BCFPass (Bogus Control Flow)
//
// For each targeted basic block B, we:
//
//   1. Split B into a new empty "cond" block + B (the real content)
//   2. Clone B into a "bogus" block with the same instructions
//   3. In cond: `if (always_true_predicate) → B_real else → B_bogus`
//   4. B_bogus terminator: `br cond`  ← never-entered infinite loop
//
// This creates a pattern that looks like a real branch to static analyzers:
//
//       ┌──────────────────────────────────────┐
//       ↓                                      │
//   [cond: if (x*(x+1)&1==0)]                  │
//       │  true            false               │
//       ↓                  ↓                   │
//   [B_real: …]        [B_bogus: …] ───────────┘
//       │                  (unreachable at runtime)
//       ↓
//   [successors]
//
// The opaque predicate (x*(x+1))&1 == 0 is ALWAYS true for any integer x,
// but the compiler cannot prove this without special reasoning.
//
// When combined with CFF (run CFF AFTER BCF), both the real cases and the
// bogus cases appear as entries in the flat dispatch switch — making it
// impossible to distinguish real control flow from the obfuscation noise.
//===----------------------------------------------------------------------===//

#include "ArmorComp/BCFPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"    // CloneBasicBlock
#include "llvm/Transforms/Utils/Local.h"       // DemotePHIToStack, DemoteRegToStack
#include "llvm/Transforms/Utils/ValueMapper.h" // ValueToValueMapTy, RemapInstruction

#include <algorithm>
#include <random>
#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection  (identical pattern to CFFPass)
// ─────────────────────────────────────────────────────────────────────────────

static bool hasBCFAnnotation(Function &F) {
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

    if (strData->getAsCString() == "bcf") return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// SSA demotion (same as CFF — avoids PHI issues after CFG restructuring)
// ─────────────────────────────────────────────────────────────────────────────

static void demoteForBCF(Function &F) {
  // 1. Demote PHI nodes
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
    if (changed) continue; // restart outer loop
  }

  // 2. Demote cross-block SSA values
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
// Opaque predicate construction
// ─────────────────────────────────────────────────────────────────────────────

/// Get a runtime-opaque i32 value for use in the always-true predicate.
///
/// Priority:
///   1. First integer argument of F (truly unknown at compile time)
///   2. Truncation of a larger integer argument
///   3. Volatile load from a module-level global (prevents LTO folding)
static Value *getOpaqueValue(Function &F, IRBuilder<> &B) {
  IntegerType *I32 = Type::getInt32Ty(F.getContext());

  for (auto &arg : F.args()) {
    if (arg.getType() == I32)
      return &arg;
    if (arg.getType()->isIntegerTy())
      return B.CreateTrunc(&arg, I32, "bcf.opq.trunc");
  }

  // Volatile global — the optimizer cannot constant-fold a volatile load even
  // at LTO, because volatile semantics prohibit reordering/elimination.
  Module *M = F.getParent();
  const StringRef keyName = "__armorcomp_opaque_key";
  GlobalVariable *GV = M->getNamedGlobal(keyName);
  if (!GV) {
    GV = new GlobalVariable(*M, I32, /*isConstant=*/false,
                            GlobalValue::WeakAnyLinkage,
                            ConstantInt::get(I32, 0x1337beef), keyName);
    GV->setAlignment(Align(4));
  }
  // volatile = true prevents the load from being optimized away
  return B.CreateLoad(I32, GV, /*isVolatile=*/true, "bcf.opq");
}

/// Build the always-true predicate: (x * (x + 1)) & 1 == 0
///
/// Proof: for any integer x, exactly one of {x, x+1} is even.
/// Therefore x*(x+1) is always even → its LSB is always 0.
///
/// This identity holds for all 32-bit signed/unsigned integers including
/// overflow cases (since LLVM integer arithmetic wraps by default).
static Value *buildAlwaysTruePredicate(Value *opaqueVal, IRBuilder<> &B) {
  // x + 1
  Value *xp1    = B.CreateAdd(opaqueVal,
                               ConstantInt::get(opaqueVal->getType(), 1),
                               "bcf.xp1");
  // x * (x + 1)
  Value *product = B.CreateMul(opaqueVal, xp1, "bcf.prod");
  // product & 1
  Value *lsb     = B.CreateAnd(product,
                                ConstantInt::get(opaqueVal->getType(), 1),
                                "bcf.lsb");
  // lsb == 0  →  always true
  return B.CreateICmpEQ(lsb,
                         ConstantInt::get(opaqueVal->getType(), 0),
                         "bcf.pred");
}

// ─────────────────────────────────────────────────────────────────────────────
// Bogus block construction
// ─────────────────────────────────────────────────────────────────────────────

/// Clone realBB into a new "bogus" block and patch its terminator to loop
/// back to loopTarget instead of jumping to the real successors.
///
/// The clone contains the same instructions as realBB (making it look like
/// real code to static analyzers), but since it's never entered at runtime,
/// its output is irrelevant.
///
/// We also lightly perturb integer constants in arithmetic instructions:
/// changing a constant by ±1 makes the bogus block look semantically similar
/// but computationally distinct — harder for clone-detection to flag.
static BasicBlock *createBogusBB(BasicBlock *realBB,
                                  BasicBlock *loopTarget,
                                  Function &F) {
  // Clone the block and remap internal value references.
  ValueToValueMapTy VMap;
  BasicBlock *bogusBB = CloneBasicBlock(realBB, VMap, ".bogus", &F);

  // Fix operands: values defined within realBB → use the cloned versions.
  for (auto &I : *bogusBB)
    RemapInstruction(&I, VMap,
                     RF_NoModuleLevelChanges | RF_IgnoreMissingLocals);

  // Perturb integer constants in arithmetic operations.
  // This makes the bogus block look "real but slightly different".
  std::mt19937 rng(std::hash<std::string>{}(
      (F.getName() + realBB->getName()).str()));
  std::bernoulli_distribution coin(0.5); // perturb ~50% of constants

  for (auto &I : *bogusBB) {
    if (I.isTerminator()) continue;
    // Only perturb binary arithmetic ops (add, sub, mul)
    if (!isa<BinaryOperator>(&I)) continue;
    for (unsigned op = 0; op < I.getNumOperands(); op++) {
      auto *ci = dyn_cast<ConstantInt>(I.getOperand(op));
      if (!ci || ci->getBitWidth() > 64) continue;
      if (!coin(rng)) continue; // ~50% chance to perturb
      uint64_t orig = ci->getZExtValue();
      // Flip the LSB — preserves magnitude, breaks exact-clone detection
      I.setOperand(op, ConstantInt::get(ci->getType(), orig ^ 1ULL));
    }
  }

  // Replace the bogus block's original terminator with an unconditional
  // branch back to loopTarget (= the cond block), creating the never-entered
  // infinite loop: cond → bogus → cond → bogus → ...
  bogusBB->getTerminator()->eraseFromParent();
  BranchInst::Create(loopTarget, bogusBB);

  return bogusBB;
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-block BCF transformation
// ─────────────────────────────────────────────────────────────────────────────

/// Apply one round of BCF to basic block BB.
///
/// Before:  [predecessors] → BB → [successors]
///
/// After:   [predecessors] → condBB ──true──→ BB → [successors]
///                               │
///                               └─false──→ bogusBB → condBB
///                                          (never reached)
static void applyBCFToBlock(BasicBlock *BB, Function &F) {
  // Skip trivial blocks: a block with only a terminator can't be meaningfully
  // obfuscated (nothing to clone).
  if (BB->size() <= 1) return;

  // Skip blocks that already end with an unreachable (e.g. from CFF default).
  if (isa<UnreachableInst>(BB->getTerminator())) return;

  LLVMContext &Ctx = F.getContext();

  // ── Step 1: split BB into condBB + BB ────────────────────────────────────
  // condBB:  empty body + auto-added br BB   (we'll replace the br)
  // BB:      original content
  //
  // splitBasicBlock(begin) moves ALL instructions (including terminator) to
  // the new block; condBB gets an unconditional br to BB.
  BasicBlock *condBB = BB;
  BasicBlock *realBB = BB->splitBasicBlock(BB->begin(), BB->getName() + ".real");

  // ── Step 2: build the bogus clone ────────────────────────────────────────
  // The bogus block clones realBB but loops back to condBB.
  BasicBlock *bogusBB = createBogusBB(realBB, condBB, F);

  // ── Step 3: replace condBB's auto-added br with the conditional ──────────
  condBB->getTerminator()->eraseFromParent();

  IRBuilder<> B(condBB); // appends to (now terminator-free) condBB
  Value *opaqueVal = getOpaqueValue(F, B);
  Value *pred      = buildAlwaysTruePredicate(opaqueVal, B);
  B.CreateCondBr(pred, realBB, bogusBB);
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level: addBogusFlow
// ─────────────────────────────────────────────────────────────────────────────

static bool addBogusFlow(Function &F) {
  if (F.isDeclaration() || F.size() <= 1) return false;

  // Skip functions with invoke (C++ exceptions complicate the CFG).
  for (auto &BB : F)
    if (isa<InvokeInst>(BB.getTerminator())) return false;

  // Demote PHI nodes and cross-block SSA values before restructuring the CFG.
  demoteForBCF(F);

  // Collect blocks to obfuscate.  We take a snapshot before modifying F
  // because applyBCFToBlock inserts new blocks.
  // Skip the entry block — inserting a cond before it would break the
  // function preamble (alloca section must stay first).
  std::vector<BasicBlock *> targets;
  BasicBlock *entryBB = &F.getEntryBlock();
  for (auto &BB : F)
    if (&BB != entryBB)
      targets.push_back(&BB);

  if (targets.empty()) return false;

  for (auto *BB : targets)
    applyBCFToBlock(BB, F);

#ifndef NDEBUG
  if (verifyFunction(F, &errs()))
    errs() << "[ArmorComp][BCF] ERROR: IR verification failed after BCF on "
           << F.getName() << "\n";
#endif

  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// BCFPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses BCFPass::run(Function &F, FunctionAnalysisManager & /*AM*/) {
  bool shouldObfuscate = !annotateOnly || hasBCFAnnotation(F)
                         || armorcomp::configSaysApply(F.getName(), "bcf");
  if (!shouldObfuscate) return PreservedAnalyses::all();

  bool changed = addBogusFlow(F);
  if (changed)
    errs() << "[ArmorComp][BCF] obfuscated: " << F.getName() << "\n";

  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
