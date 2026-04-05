//===----------------------------------------------------------------------===//
// ArmorComp — DataEncodingPass (Integer Local-Variable Memory Encoding)
//
// Strategy: encode/decode wrapper around every alloca load/store
// ───────────────────────────────────────────────────────────────
//  1. Find all statically-sized integer allocas (i8/i16/i32/i64) in the
//     entry block whose only users are direct loads, stores, and LLVM
//     lifetime/debug intrinsics.
//  2. For each qualifying alloca, derive a per-alloca XOR key:
//       state = FNV1a(fn_name + "_" + alloca_index)
//       K     = xorshift64(state) & type_mask    (forced non-zero)
//  3. Wrap every store:
//       %de.enc = xor iN original_value, K
//       store iN %de.enc, ptr %alloca
//  4. Wrap every load:
//       %raw    = load iN, ptr %alloca        (unchanged load instruction)
//       %de.dec = xor iN %raw, K              (inserted immediately after)
//       Replace all prior uses of %raw with %de.dec
//
// Binary result:
//   - Stack memory always contains XOR-scrambled values.
//   - IDA decompiler shows `eor` sequences around every ldr/str instead of
//     plain variable reads/writes; type recovery and value tracking are
//     hindered at the source-variable level.
//   - Composable with FlattenDataFlowPass (runs after DENC): DF merges the
//     same allocas into a pool, so both the address (pool GEP) and the
//     stored value (DENC XOR) are obfuscated simultaneously.
//   - Composable with ConstObfPass (runs after DENC): CO further hides the
//     XOR key constants K behind secondary XOR-key split expressions.
//===----------------------------------------------------------------------===//

#include "ArmorComp/DataEncodingPass.h"
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

static uint64_t denchash(StringRef S) {
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

static bool hasDencAnnotation(Function &F) {
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

        if (strData->getAsCString() == "denc") return true;
      }
    }
  }

check_config:
  return armorcomp::configSaysApply(F.getName(), "denc");
}

// ─────────────────────────────────────────────────────────────────────────────
// Eligibility check: only allocas whose users are direct loads/stores/intrinsics
// ─────────────────────────────────────────────────────────────────────────────

static bool isSimpleIntAlloca(AllocaInst *AI) {
  // Must be a statically-sized integer alloca
  auto *ITy = dyn_cast<IntegerType>(AI->getAllocatedType());
  if (!ITy) return false;
  unsigned bw = ITy->getBitWidth();
  if (bw != 8 && bw != 16 && bw != 32 && bw != 64) return false;
  if (!isa<ConstantInt>(AI->getArraySize())) return false;

  // All users must be direct loads, direct stores, or LLVM intrinsics
  for (User *U : AI->users()) {
    if (auto *LI = dyn_cast<LoadInst>(U)) {
      if (LI->getPointerOperand() == AI) continue;
    }
    if (auto *SI = dyn_cast<StoreInst>(U)) {
      // OK if AI is the pointer operand (normal store through AI)
      if (SI->getPointerOperand() == AI) continue;
      // Storing the address of AI itself — skip alloca
    }
    if (auto *II = dyn_cast<IntrinsicInst>(U)) {
      Intrinsic::ID id = II->getIntrinsicID();
      if (id == Intrinsic::lifetime_start || id == Intrinsic::lifetime_end ||
          id == Intrinsic::dbg_declare    || id == Intrinsic::dbg_value   ||
          id == Intrinsic::dbg_assign)
        continue;
    }
    // Any other user (GEP, call, etc.) → skip this alloca
    return false;
  }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main encoding transformation for one function
// ─────────────────────────────────────────────────────────────────────────────

static bool encodeLocals(Function &F) {
  BasicBlock &entry = F.getEntryBlock();

  // Collect eligible allocas and assign per-alloca keys
  struct AllocaKey {
    AllocaInst *AI;
    uint64_t    key;
  };
  SmallVector<AllocaKey, 16> targets;

  unsigned idx = 0;
  for (auto &I : entry) {
    auto *AI = dyn_cast<AllocaInst>(&I);
    if (!AI) continue;
    if (!isSimpleIntAlloca(AI)) continue;

    // Derive a unique, deterministic key for this alloca
    std::string keyStr =
        F.getName().str() + "_denc_" + std::to_string(idx++);
    uint64_t state = denchash(keyStr);
    uint64_t k64   = xorshift64(state);

    auto *ITy = cast<IntegerType>(AI->getAllocatedType());
    unsigned bw   = ITy->getBitWidth();
    uint64_t mask = (bw < 64) ? ((1ULL << bw) - 1) : ~0ULL;
    uint64_t key  = k64 & mask;
    if (key == 0) key = 1;  // degenerate guard

    targets.push_back({AI, key});
  }

  if (targets.empty()) return false;

  // Apply encode/decode wrappers
  for (auto &[AI, key] : targets) {
    auto *ITy  = cast<IntegerType>(AI->getAllocatedType());
    Value *Kval = ConstantInt::get(ITy, key);

    // Snapshot users to avoid iterator invalidation during modification
    SmallVector<User *, 16> users(AI->users());

    for (User *U : users) {
      // ── STORE: encode the value before storing ──────────────────────────
      if (auto *SI = dyn_cast<StoreInst>(U)) {
        if (SI->getPointerOperand() != AI) continue;
        IRBuilder<> B(SI);
        Value *origVal = SI->getValueOperand();
        Value *enc = B.CreateXor(origVal, Kval, "de.enc");
        SI->setOperand(0, enc);  // operand 0 = value operand of StoreInst
        continue;
      }

      // ── LOAD: decode the value after loading ────────────────────────────
      if (auto *LI = dyn_cast<LoadInst>(U)) {
        if (LI->getPointerOperand() != AI) continue;

        // Insert XOR immediately after the load instruction
        Instruction *insertPt = LI->getNextNode();
        if (!insertPt) continue;  // load is last inst? skip (shouldn't happen)

        IRBuilder<> B(insertPt);
        Value *dec = B.CreateXor(LI, Kval, "de.dec");

        // Replace all uses of the load result with the decoded value,
        // except for the XOR decode instruction itself (avoid a use cycle).
        SmallVector<Use *, 8> toUpdate;
        for (Use &use : LI->uses()) {
          if (use.getUser() != dec)
            toUpdate.push_back(&use);
        }
        for (Use *use : toUpdate)
          use->set(dec);
        continue;
      }
    }
  }

  errs() << "[ArmorComp][DENC] encoded: " << F.getName()
         << " (" << targets.size() << " alloca(s))\n";
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// DataEncodingPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses DataEncodingPass::run(Function &F,
                                        FunctionAnalysisManager & /*AM*/) {
  if (annotateOnly && !hasDencAnnotation(F))
    return PreservedAnalyses::all();

  if (!encodeLocals(F))
    return PreservedAnalyses::all();

  return PreservedAnalyses::none();
}
