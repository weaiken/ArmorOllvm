//===----------------------------------------------------------------------===//
// ArmorComp — PointerXorPass (PXOR — Pointer XOR Memory Encoding)
//
// Complements DataEncodingPass (DENC) which only handles integer allocas.
// PXOR fills the gap: pointer-typed local variables stored on-stack are
// XOR-scrambled with a per-alloca compile-time key.
//
// Binary result:
//   - Stack memory always holds (real_ptr ^ K) instead of real_ptr.
//   - IDA decompiler sees ptrtoint / xor / inttoptr sequences around every
//     pointer load/store; pointer type recovery and NULL-check analysis fail.
//   - Combined with DENC and DF: the pool byte representation of all locals
//     (both integer and pointer) is scrambled.
//===----------------------------------------------------------------------===//

#include "ArmorComp/PointerXorPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
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

static uint64_t pxorhash(StringRef S) {
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

static bool hasPXORAnnotation(Function &F) {
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

        if (strData->getAsCString() == "pxor") return true;
      }
    }
  }

check_config:
  return armorcomp::configSaysApply(F.getName(), "pxor");
}

// ─────────────────────────────────────────────────────────────────────────────
// Eligibility check: pointer allocas with only load/store/intrinsic users
// ─────────────────────────────────────────────────────────────────────────────

static bool isSimplePtrAlloca(AllocaInst *AI) {
  // Must be a statically-sized pointer alloca
  if (!AI->getAllocatedType()->isPointerTy()) return false;
  if (!isa<ConstantInt>(AI->getArraySize())) return false;

  // All users must be direct loads, direct stores, or LLVM intrinsics
  for (User *U : AI->users()) {
    if (auto *LI = dyn_cast<LoadInst>(U)) {
      if (LI->getPointerOperand() == AI) continue;
    }
    if (auto *SI = dyn_cast<StoreInst>(U)) {
      if (SI->getPointerOperand() == AI) continue;
    }
    if (auto *II = dyn_cast<IntrinsicInst>(U)) {
      Intrinsic::ID id = II->getIntrinsicID();
      if (id == Intrinsic::lifetime_start || id == Intrinsic::lifetime_end ||
          id == Intrinsic::dbg_declare    || id == Intrinsic::dbg_value   ||
          id == Intrinsic::dbg_assign)
        continue;
    }
    return false;
  }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main encoding transformation
// ─────────────────────────────────────────────────────────────────────────────

static bool encodePointerLocals(Function &F) {
  Module *M = F.getParent();
  const DataLayout &DL = M->getDataLayout();
  LLVMContext &Ctx = F.getContext();

  // Use pointer-size integer type for XOR (i64 on 64-bit, i32 on 32-bit)
  unsigned PtrBits = DL.getPointerSizeInBits();
  IntegerType *PtrIntTy = Type::getIntNTy(Ctx, PtrBits);

  BasicBlock &entry = F.getEntryBlock();

  struct AllocaKey {
    AllocaInst *AI;
    uint64_t    key;
  };
  SmallVector<AllocaKey, 16> targets;

  unsigned idx = 0;
  for (auto &I : entry) {
    auto *AI = dyn_cast<AllocaInst>(&I);
    if (!AI) continue;
    if (!isSimplePtrAlloca(AI)) continue;

    std::string keyStr =
        F.getName().str() + "_pxor_" + std::to_string(idx++);
    uint64_t state = pxorhash(keyStr);
    uint64_t key   = xorshift64(state);
    if (key == 0) key = 0xDEADBEEFCAFE0001ULL;

    // Truncate to pointer bit width if 32-bit
    if (PtrBits < 64) key &= ((1ULL << PtrBits) - 1);

    targets.push_back({AI, key});
  }

  if (targets.empty()) return false;

  for (auto &[AI, key] : targets) {
    Value *Kval = ConstantInt::get(PtrIntTy, key);

    SmallVector<User *, 16> users(AI->users());
    for (User *U : users) {

      // ── STORE: encode before storing ──────────────────────────────────────
      if (auto *SI = dyn_cast<StoreInst>(U)) {
        if (SI->getPointerOperand() != AI) continue;
        // Only handle ptr-typed values (not storing AI itself somewhere else)
        Value *origVal = SI->getValueOperand();
        if (!origVal->getType()->isPointerTy()) continue;

        IRBuilder<> B(SI);
        // ptrtoint → xor key → inttoptr → store
        Value *asInt = B.CreatePtrToInt(origVal, PtrIntTy, "px.enc.i");
        Value *xored = B.CreateXor(asInt, Kval, "px.enc.x");
        Value *asPtr = B.CreateIntToPtr(xored, origVal->getType(), "px.enc.p");
        SI->setOperand(0, asPtr);
        continue;
      }

      // ── LOAD: decode after loading ────────────────────────────────────────
      if (auto *LI = dyn_cast<LoadInst>(U)) {
        if (LI->getPointerOperand() != AI) continue;
        if (!LI->getType()->isPointerTy()) continue;

        Instruction *insertPt = LI->getNextNode();
        if (!insertPt) continue;

        IRBuilder<> B(insertPt);
        // load → ptrtoint → xor key → inttoptr → replace uses
        Value *asInt = B.CreatePtrToInt(LI, PtrIntTy, "px.dec.i");
        Value *xored = B.CreateXor(asInt, Kval, "px.dec.x");
        Value *dec   = B.CreateIntToPtr(xored, LI->getType(), "px.dec");

        SmallVector<Use *, 8> toUpdate;
        for (Use &use : LI->uses()) {
          if (use.getUser() != asInt && use.getUser() != dec)
            toUpdate.push_back(&use);
        }
        for (Use *use : toUpdate)
          use->set(dec);
        continue;
      }
    }
  }

  errs() << "[ArmorComp][PXOR] encoded: " << F.getName()
         << " (" << targets.size() << " pointer alloca(s))\n";
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// PointerXorPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses PointerXorPass::run(Function &F,
                                      FunctionAnalysisManager & /*AM*/) {
  if (annotateOnly && !hasPXORAnnotation(F))
    return PreservedAnalyses::all();

  if (!encodePointerLocals(F))
    return PreservedAnalyses::all();

  return PreservedAnalyses::none();
}
