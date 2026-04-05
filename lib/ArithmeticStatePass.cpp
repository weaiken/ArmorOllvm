//===----------------------------------------------------------------------===//
// ArmorComp — ArithmeticStatePass (ASP — Arithmetic State Encoding)
//
// Runs AFTER CFFPass to defeat automated CFF deobfuscation tools (d810,
// msynack) that trace constant state values through the switch dispatcher.
//
// Detection algorithm:
//   A "state variable" is an integer alloca where:
//     - ALL StoreInst users store ConstantInt values (explicit state IDs).
//     - ALL LoadInst results are used ONLY as the discriminant of SwitchInst
//       (the switch %state, label %default [...] pattern from CFF).
//
// Transformation (pure compile-time, zero runtime overhead):
//   Let K = xorshift64(FNV1a(fn_name + "_asp_" + alloca_idx))
//   1. Each "store i32 C, %state_var" → "store i32 (C XOR K)"
//   2. Each SwitchInst case "i32 C" → "i32 (C XOR K)"
//
//   Correctness: stored value == XOR(C, K) and case value == XOR(C, K),
//   so the dispatch logic is perfectly preserved at runtime.
//
// Defeat mechanism:
//   d810 works by: (1) identify %state_var alloca, (2) trace all constant
//   store values to build state-ID → BB mapping, (3) reconstruct CFG.
//   After ASP: step (2) sees only (C XOR K) constants.  Since K is a
//   compile-time-only value not stored anywhere in the binary, the state
//   graph is unrecoverable without solving a keyed XOR — effectively a
//   brute-force 32-bit or 64-bit search space.
//===----------------------------------------------------------------------===//

#include "ArmorComp/ArithmeticStatePass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <string>
#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Key derivation helpers
// ─────────────────────────────────────────────────────────────────────────────

static uint64_t asphash(StringRef S) {
  uint64_t h = 14695981039346656037ULL;
  for (unsigned char c : S) {
    h ^= c;
    h *= 1099511628211ULL;
  }
  return h;
}

static uint64_t xorshift64(uint64_t &state) {
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return state;
}

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasASPAnnotation(Function &F) {
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

        if (strData->getAsCString() == "asp") return true;
      }
    }
  }

check_config:
  return armorcomp::configSaysApply(F.getName(), "asp");
}

// ─────────────────────────────────────────────────────────────────────────────
// State variable detection
// ─────────────────────────────────────────────────────────────────────────────

/// Return true if V is a CFF-style "next state" value:
///   - ConstantInt, OR
///   - SelectInst whose both true/false operands are ConstantInt
///     (CFF uses: %ns = select i1 %cond, i32 STATE_A, i32 STATE_B)
static bool isCFFStateValue(Value *V) {
  if (isa<ConstantInt>(V)) return true;
  if (auto *Sel = dyn_cast<SelectInst>(V))
    return isa<ConstantInt>(Sel->getTrueValue()) &&
           isa<ConstantInt>(Sel->getFalseValue());
  return false;
}

/// Return true if AI is a "state variable" alloca:
///   - Integer type (i32 or i64)
///   - ALL stores are with ConstantInt or SelectInst{ConstantInt, ConstantInt}
///   - ALL loads feed directly into SwitchInst as the discriminant
static bool isStateVarAlloca(AllocaInst *AI) {
  auto *ITy = dyn_cast<IntegerType>(AI->getAllocatedType());
  if (!ITy) return false;
  unsigned bw = ITy->getBitWidth();
  if (bw != 32 && bw != 64) return false;
  if (!isa<ConstantInt>(AI->getArraySize())) return false;

  bool hasStores = false;
  bool hasLoads  = false;

  for (User *U : AI->users()) {
    // Intrinsics (lifetime, dbg) are fine — skip them
    if (auto *II = dyn_cast<IntrinsicInst>(U)) {
      Intrinsic::ID id = II->getIntrinsicID();
      if (id == Intrinsic::lifetime_start || id == Intrinsic::lifetime_end ||
          id == Intrinsic::dbg_declare    || id == Intrinsic::dbg_value   ||
          id == Intrinsic::dbg_assign)
        continue;
      // Unrecognized intrinsic → fall through to disqualify below
    }

    // Stores must use ConstantInt or SelectInst{ConstantInt, ConstantInt}
    if (auto *SI = dyn_cast<StoreInst>(U)) {
      if (SI->getPointerOperand() != AI) return false;
      if (!isCFFStateValue(SI->getValueOperand())) return false;
      hasStores = true;
      continue;
    }

    // Loads must be from AI and used ONLY as switch discriminant
    if (auto *LI = dyn_cast<LoadInst>(U)) {
      if (LI->getPointerOperand() != AI) return false;
      // Every use of the loaded value must be a SwitchInst (as discriminant)
      for (User *LU : LI->users()) {
        auto *SW = dyn_cast<SwitchInst>(LU);
        if (!SW) return false;
        if (SW->getCondition() != LI) return false;
      }
      hasLoads = true;
      continue;
    }

    // Any other user disqualifies this alloca
    return false;
  }

  return hasStores && hasLoads;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main transformation
// ─────────────────────────────────────────────────────────────────────────────

static bool encodeStateVars(Function &F) {
  BasicBlock &entry = F.getEntryBlock();

  struct StateVarInfo {
    AllocaInst  *AI;
    uint64_t     key;   // full 64-bit key (truncated to type width when used)
    unsigned     bw;    // 32 or 64
  };
  SmallVector<StateVarInfo, 8> targets;

  unsigned idx = 0;
  for (auto &I : entry) {
    auto *AI = dyn_cast<AllocaInst>(&I);
    if (!AI) continue;
    if (!isStateVarAlloca(AI)) continue;

    std::string keyStr = F.getName().str() + "_asp_" + std::to_string(idx++);
    uint64_t state = asphash(keyStr);
    uint64_t key   = xorshift64(state);

    unsigned bw = cast<IntegerType>(AI->getAllocatedType())->getBitWidth();
    uint64_t mask = (bw < 64) ? ((1ULL << bw) - 1) : ~0ULL;
    key &= mask;
    if (key == 0) key = 1;

    targets.push_back({AI, key, bw});
  }

  if (targets.empty()) return false;

  unsigned encodedStates = 0;

  for (auto &[AI, key, bw] : targets) {
    IntegerType *ITy = cast<IntegerType>(AI->getAllocatedType());

    // ── Step 1: XOR-encode all CFF-style state stores ──────────────────────
    // Accept two store patterns:
    //   (a) store i32 C, %state         → ConstantInt C → encode as C^K
    //   (b) store (select cond, C1, C2) → SelectInst with both arms ConstantInt
    //         encode each arm: C1^K, C2^K
    SmallVector<StoreInst *, 16> stores;
    for (User *U : AI->users()) {
      if (auto *SI = dyn_cast<StoreInst>(U))
        if (SI->getPointerOperand() == AI &&
            isCFFStateValue(SI->getValueOperand()))
          stores.push_back(SI);
    }

    for (StoreInst *SI : stores) {
      Value *val = SI->getValueOperand();
      if (auto *oldConst = dyn_cast<ConstantInt>(val)) {
        // Pattern (a): direct ConstantInt
        uint64_t origVal = oldConst->getZExtValue();
        SI->setOperand(0, ConstantInt::get(ITy, origVal ^ key));
        ++encodedStates;
      } else if (auto *Sel = dyn_cast<SelectInst>(val)) {
        // Pattern (b): select{ConstantInt, ConstantInt} — encode both arms
        auto *trueC  = cast<ConstantInt>(Sel->getTrueValue());
        auto *falseC = cast<ConstantInt>(Sel->getFalseValue());
        Sel->setOperand(1, ConstantInt::get(ITy, trueC->getZExtValue()  ^ key));
        Sel->setOperand(2, ConstantInt::get(ITy, falseC->getZExtValue() ^ key));
        encodedStates += 2;
      }
    }

    // ── Step 2: XOR-encode all SwitchInst case values ─────────────────────
    SmallVector<LoadInst *, 8> loads;
    for (User *U : AI->users()) {
      if (auto *LI = dyn_cast<LoadInst>(U))
        if (LI->getPointerOperand() == AI)
          loads.push_back(LI);
    }

    for (LoadInst *LI : loads) {
      SmallVector<SwitchInst *, 4> switches;
      for (User *LU : LI->users()) {
        if (auto *SW = dyn_cast<SwitchInst>(LU))
          if (SW->getCondition() == LI)
            switches.push_back(SW);
      }

      for (SwitchInst *SW : switches) {
        // Collect all (case_val, case_BB) pairs first to avoid iterator invalidation
        SmallVector<std::pair<uint64_t, BasicBlock *>, 32> caseList;
        for (auto &C : SW->cases()) {
          uint64_t origCase = C.getCaseValue()->getZExtValue();
          caseList.push_back({origCase, C.getCaseSuccessor()});
        }

        // Remove all existing cases
        while (SW->getNumCases() > 0)
          SW->removeCase(SW->case_begin());

        // Re-add with encoded values
        for (auto &[origCase, caseBB] : caseList) {
          uint64_t encCase = origCase ^ key;
          SW->addCase(ConstantInt::get(ITy, encCase), caseBB);
        }
      }
    }
  }

  errs() << "[ArmorComp][ASP] encoded: " << F.getName()
         << " (" << targets.size() << " state var(s), "
         << encodedStates << " state constant(s))\n";
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// ArithmeticStatePass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses ArithmeticStatePass::run(Function &F,
                                           FunctionAnalysisManager & /*AM*/) {
  if (annotateOnly && !hasASPAnnotation(F))
    return PreservedAnalyses::all();

  if (!encodeStateVars(F))
    return PreservedAnalyses::all();

  return PreservedAnalyses::none();
}
