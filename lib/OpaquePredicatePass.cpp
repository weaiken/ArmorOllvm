//===----------------------------------------------------------------------===//
// ArmorComp — OpaquePredicatePass implementation
//
// Splits each non-entry basic block into a head + tail.  The head evaluates
// one of 6 opaque predicate formulas and branches to the real tail (always
// taken at runtime) or a dead-end block (never taken at runtime).
//
// The dead-end block contains junk volatile arithmetic and terminates with a
// ret of the function's null value — no loop-back, no clone of real code.
//
// 6 predicate formulas (P0-P2 always-true, P3-P5 always-false):
//   P0: (z*(z+1)) & 1 == 0   P3: (z & ~z) != 0
//   P1: (z | ~z)  == -1      P4: (z * 2) & 1 != 0
//   P2: (z & ~z)  == 0       P5: (z*z + 1) & 3 == 0
//
// z = volatile load from @__armorcomp_op_zero (weak global = 0).
//===----------------------------------------------------------------------===//

#include "ArmorComp/OpaquePredicatePass.h"
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

#include <functional>
#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasOPAnnotation(Function &F) {
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
    if (StrData && StrData->getAsCString() == "op") return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Volatile-zero global
// ─────────────────────────────────────────────────────────────────────────────

static GlobalVariable *getOrCreateOPZero(Module &M) {
  const char *Name = "__armorcomp_op_zero";
  if (GlobalVariable *GV = M.getGlobalVariable(Name))
    return GV;

  return new GlobalVariable(
      M, Type::getInt64Ty(M.getContext()), /*isConstant=*/false,
      GlobalValue::WeakAnyLinkage,
      ConstantInt::get(Type::getInt64Ty(M.getContext()), 0), Name);
}

// ─────────────────────────────────────────────────────────────────────────────
// xorshift64 PRNG — seeded with hash(function name) for deterministic selection
// ─────────────────────────────────────────────────────────────────────────────

static uint64_t xorshift64(uint64_t &state) {
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return state;
}

// ─────────────────────────────────────────────────────────────────────────────
// Predicate formulas
// ─────────────────────────────────────────────────────────────────────────────

/// Build one of 6 opaque predicates using z (volatile i64 load from OPZero).
/// Returns an i1 Value.  z is always 0 at runtime, but the optimizer cannot
/// prove this — each formula has a clear mathematical proof of its invariant.
static Value *buildPredicate(unsigned idx, Value *z, IRBuilder<> &B) {
  Type *I64 = z->getType();

  switch (idx % 6) {
  default:
  case 0: {
    // P0 (always-true): (z*(z+1)) & 1 == 0
    // Proof: one of z, z+1 is even → product always even → LSB always 0.
    Value *zp1  = B.CreateAdd(z, ConstantInt::get(I64, 1), "op.p0.zp1");
    Value *prod = B.CreateMul(z, zp1, "op.p0.prod");
    Value *lsb  = B.CreateAnd(prod, ConstantInt::get(I64, 1), "op.p0.lsb");
    return B.CreateICmpEQ(lsb, ConstantInt::get(I64, 0), "op.p0");
  }
  case 1: {
    // P1 (always-true): (z | ~z) == -1
    // Proof: OR-with-complement sets every bit → equals all-ones (-1 in two's complement).
    Value *notz  = B.CreateNot(z, "op.p1.notz");
    Value *orval = B.CreateOr(z, notz, "op.p1.or");
    return B.CreateICmpEQ(orval, ConstantInt::getSigned(I64, -1), "op.p1");
  }
  case 2: {
    // P2 (always-true): (z & ~z) == 0
    // Proof: AND-with-complement clears every bit → always 0.
    Value *notz   = B.CreateNot(z, "op.p2.notz");
    Value *andval = B.CreateAnd(z, notz, "op.p2.and");
    return B.CreateICmpEQ(andval, ConstantInt::get(I64, 0), "op.p2");
  }
  case 3: {
    // P3 (always-false): (z & ~z) != 0
    // Proof: same as P2 — AND-with-complement is always 0, so != 0 is always false.
    Value *notz   = B.CreateNot(z, "op.p3.notz");
    Value *andval = B.CreateAnd(z, notz, "op.p3.and");
    return B.CreateICmpNE(andval, ConstantInt::get(I64, 0), "op.p3");
  }
  case 4: {
    // P4 (always-false): (z * 2) & 1 != 0
    // Proof: z*2 is always even → LSB always 0 → condition always false.
    Value *dbl = B.CreateMul(z, ConstantInt::get(I64, 2), "op.p4.dbl");
    Value *lsb = B.CreateAnd(dbl, ConstantInt::get(I64, 1), "op.p4.lsb");
    return B.CreateICmpNE(lsb, ConstantInt::get(I64, 0), "op.p4");
  }
  case 5: {
    // P5 (always-false): (z*z + 1) & 3 == 0
    // Proof: z^2 mod 4 ∈ {0, 1} for all integers, so (z^2+1) mod 4 ∈ {1, 2}, never 0.
    Value *zz   = B.CreateMul(z, z, "op.p5.zz");
    Value *zzp1 = B.CreateAdd(zz, ConstantInt::get(I64, 1), "op.p5.zzp1");
    Value *mod4 = B.CreateAnd(zzp1, ConstantInt::get(I64, 3), "op.p5.mod4");
    return B.CreateICmpEQ(mod4, ConstantInt::get(I64, 0), "op.p5");
  }
  }
}

/// Returns true if predicate idx is always-true, false if always-false.
static bool isPredicateAlwaysTrue(unsigned idx) {
  return (idx % 6) < 3;
}

// ─────────────────────────────────────────────────────────────────────────────
// Dead-end block construction
// ─────────────────────────────────────────────────────────────────────────────

/// Create a dead-end block: contains junk volatile loads + arithmetic, then
/// terminates with ret (null value for non-void, void otherwise).
///
/// This block is unreachable at runtime (always-true/false predicate ensures
/// the real tail is always taken), but static analysis cannot distinguish it
/// from real code.
static BasicBlock *createDeadBB(Function &F, GlobalVariable *OPZero,
                                 LLVMContext &Ctx) {
  BasicBlock *Dead = BasicBlock::Create(Ctx, "op.dead", &F);
  IRBuilder<> B(Dead);

  Type *I64 = Type::getInt64Ty(Ctx);

  // Junk: volatile load + arithmetic so the dead block looks non-trivial.
  // The constant 0x4F50 ("OP" in ASCII) is a marker visible in disassembly.
  Value *Z  = B.CreateLoad(I64, OPZero, /*isVolatile=*/true, "op.dead.z");
  Value *J1 = B.CreateAdd(Z, ConstantInt::get(I64, 0x4F50), "op.dead.j1");
  Value *J2 = B.CreateMul(J1, Z, "op.dead.j2");
  Value *J3 = B.CreateXor(J2, ConstantInt::get(I64, 0x0BF5CA7ED), "op.dead.j3");
  (void)J3;

  // Return the function's null value.  For void functions: ret void.
  Type *RetTy = F.getReturnType();
  if (RetTy->isVoidTy())
    B.CreateRetVoid();
  else
    B.CreateRet(Constant::getNullValue(RetTy));

  return Dead;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main transformation
// ─────────────────────────────────────────────────────────────────────────────

static bool insertOpaquePredicates(Function &F) {
  if (F.isDeclaration()) return false;
  if (F.size() <= 1) return false;

  // Skip functions with invoke (C++ exception edges complicate the CFG).
  for (auto &BB : F)
    if (isa<InvokeInst>(BB.getTerminator())) return false;

  // Never instrument ArmorComp's own injected functions.
  if (F.getName().startswith("__armorcomp_")) return false;

  Module *M = F.getParent();
  LLVMContext &Ctx = F.getContext();
  GlobalVariable *OPZero = getOrCreateOPZero(*M);

  // xorshift64 seed = hash(function name) — deterministic per-function cycle.
  uint64_t state = std::hash<std::string>{}(F.getName().str());
  if (state == 0) state = 0xDEADBEEF13370ULL; // avoid all-zero state

  // Snapshot non-entry blocks before modifying the function.
  // Modifications during the loop (splitBasicBlock, createDeadBB) would
  // invalidate a live iterator.
  std::vector<BasicBlock *> targets;
  BasicBlock *entryBB = &F.getEntryBlock();
  for (auto &BB : F) {
    if (&BB == entryBB) continue;             // entry block: skip
    if (BB.size() <= 1) continue;            // trivial block: skip
    if (isa<UnreachableInst>(BB.getTerminator())) continue; // already dead
    targets.push_back(&BB);
  }

  if (targets.empty()) return false;

  unsigned inserted = 0;
  for (BasicBlock *BB : targets) {
    // Find split point: first non-PHI instruction.
    // getFirstInsertionPt() returns the insertion point after any leading PHIs.
    Instruction *SplitPt = &*BB->getFirstInsertionPt();

    // Skip if split point is the terminator — no real content to split before it.
    if (SplitPt == BB->getTerminator()) continue;

    // Split BB → head (BB, keeps leading PHIs) + tail (everything from SplitPt).
    // splitBasicBlock auto-inserts an unconditional br from head to tail.
    BasicBlock *tail =
        BB->splitBasicBlock(SplitPt, BB->getName() + ".op.tail");

    // Choose predicate for this block (advances xorshift state once per block).
    uint64_t idx = xorshift64(state);
    bool alwaysTrue = isPredicateAlwaysTrue(idx);

    // Remove head's auto-inserted br to tail; we'll replace it.
    BB->getTerminator()->eraseFromParent();

    // Create the dead-end block.
    BasicBlock *dead = createDeadBB(F, OPZero, Ctx);

    // Build predicate in head (appends after PHI nodes, before any original code).
    IRBuilder<> Builder(BB);
    Value *z    = Builder.CreateLoad(Type::getInt64Ty(Ctx), OPZero,
                                     /*isVolatile=*/true, "op.z");
    Value *pred = buildPredicate(idx, z, Builder);

    // Branch: always-true pred → (tail, dead); always-false pred → (dead, tail).
    if (alwaysTrue)
      Builder.CreateCondBr(pred, tail, dead);
    else
      Builder.CreateCondBr(pred, dead, tail);

    ++inserted;
  }

  if (inserted == 0) return false;

  errs() << "[ArmorComp][OP] obfuscated: " << F.getName()
         << " (" << inserted << " predicate" << (inserted > 1 ? "s" : "")
         << ")\n";
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// OpaquePredicatePass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses OpaquePredicatePass::run(Function &F,
                                           FunctionAnalysisManager & /*AM*/) {
  if (F.isDeclaration()) return PreservedAnalyses::all();

  bool shouldObf = !annotateOnly
                   || hasOPAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "op");
  if (!shouldObf) return PreservedAnalyses::all();

  bool changed = insertOpaquePredicates(F);
  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
