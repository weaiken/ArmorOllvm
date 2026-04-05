//===----------------------------------------------------------------------===//
// ArmorComp — LoopObfuscationPass (LOB — Loop Obfuscation)
//
// Uses LoopAnalysis (LLVM new PM) to locate natural loops and injects opaque
// arithmetic noise into loop preheaders and headers.  Must run BEFORE BCF/CFF
// so the loop structure is still visible in the IR.
//
// Three obfuscations per loop:
//
//  1. Preheader junk injection (if loop has a single preheader):
//       %z  = load volatile i64, @__armorcomp_lob_zero    ; = 0 at runtime
//       %s0 = mul i64 %z, CONST_A       ; = 0
//       %s1 = add i64 %s0, CONST_B      ; = CONST_B  (opaque to static analysis)
//       %s2 = xor i64 %s1, CONST_C      ; = CONST_B ^ CONST_C
//       call void asm sideeffect "", "r,~{memory}"(i64 %s2)
//     IDA sees a 4-op expression before the loop; loop bound detection tools
//     fail to cleanly separate the loop setup from preheader "noise."
//
//  2. Header noise (at top of loop header, after PHIs):
//       %hn = load volatile i64, @__armorcomp_lob_zero
//       %ha = add i64 %hn, 0             ; = 0, but not provably dead
//       call void asm sideeffect "", "r,~{memory}"(i64 %ha)
//     Symbolic executors must track this value through the header.
//
//  3. Fake invariant alloca (in preheader before junk):
//       %fake = alloca i64               ; dead local — mimics a loop variable
//       store i64 (volatile_zero * PRIME), %fake    ; = 0
//     IDA/Ghidra decompilers show an extra local variable used in the loop.
//
// Note: modifications are applied to a pre-collected snapshot of loops.
// LoopAnalysis is invalidated after the pass since we modify the CFG's domtree.
//===----------------------------------------------------------------------===//

#include "ArmorComp/LoopObfuscationPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <string>
#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// PRNG helpers — deterministic per (function, loop index)
// ─────────────────────────────────────────────────────────────────────────────

static uint64_t lobhash(const std::string &s) {
  uint64_t h = 14695981039346656037ULL;
  for (unsigned char c : s)
    h = (h ^ c) * 1099511628211ULL;
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

static bool hasLOBAnnotation(Function &F) {
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

        if (strData->getAsCString() == "lob") return true;
      }
    }
  }

check_config:
  return armorcomp::configSaysApply(F.getName(), "lob");
}

// ─────────────────────────────────────────────────────────────────────────────
// Get or create @__armorcomp_lob_zero = weak global i64 0
// ─────────────────────────────────────────────────────────────────────────────

static GlobalVariable *getLobZero(Module &M) {
  if (auto *GV = M.getGlobalVariable("__armorcomp_lob_zero"))
    return GV;

  LLVMContext &Ctx = M.getContext();
  auto *GV = new GlobalVariable(
      M, Type::getInt64Ty(Ctx), /*isConstant=*/false,
      GlobalValue::WeakAnyLinkage,
      ConstantInt::get(Type::getInt64Ty(Ctx), 0),
      "__armorcomp_lob_zero");
  GV->setAlignment(MaybeAlign(8));
  return GV;
}

// ─────────────────────────────────────────────────────────────────────────────
// Obfuscate a single loop
// ─────────────────────────────────────────────────────────────────────────────

static void obfuscateLoop(Loop *L, Function &F, GlobalVariable *zeroGV,
                          uint64_t &rng) {
  LLVMContext &Ctx = F.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);

  // Get constant seeds for this loop (deterministic)
  uint64_t cA = xorshift64(rng) | 1;     // odd constant
  uint64_t cB = xorshift64(rng);
  uint64_t cC = xorshift64(rng);
  uint64_t prime = 0x9E3779B97F4A7C15ULL; // Fibonacci hash constant

  // ── Obfuscation 1 + 3: Preheader junk + fake invariant ──────────────────
  BasicBlock *preheader = L->getLoopPreheader();
  if (preheader) {
    Instruction *term = preheader->getTerminator();
    IRBuilder<> B(term);

    // Fake invariant alloca (inserted in preheader; appears as loop variable)
    // Note: normally allocas go in entry block, but we put it here deliberately
    // to confuse loop-variable detection in decompilers.
    AllocaInst *fakeAlloca = B.CreateAlloca(I64Ty, nullptr, "lob.fake");
    Value *zLoad0 = B.CreateLoad(I64Ty, zeroGV, true /*volatile*/, "lob.z0");
    Value *fakeMul = B.CreateMul(zLoad0, ConstantInt::get(I64Ty, prime), "lob.fm");
    B.CreateStore(fakeMul, fakeAlloca);

    // Preheader junk chain
    Value *z = B.CreateLoad(I64Ty, zeroGV, true /*volatile*/, "lob.z");
    Value *s0 = B.CreateMul(z, ConstantInt::get(I64Ty, cA), "lob.s0");
    Value *s1 = B.CreateAdd(s0, ConstantInt::get(I64Ty, cB), "lob.s1");
    Value *s2 = B.CreateXor(s1, ConstantInt::get(I64Ty, cC), "lob.s2");

    // Consume via asm sideeffect: cannot be DCE'd
    FunctionType *sinkTy = FunctionType::get(
        Type::getVoidTy(Ctx), {I64Ty}, /*isVarArg=*/false);
    InlineAsm *sink = InlineAsm::get(sinkTy, "", "r,~{memory}",
                                     /*hasSideEffects=*/true);
    B.CreateCall(sink, {s2});

    // Also consume fake alloca via load → sink to prevent alloca elimination
    Value *fakeLoad = B.CreateLoad(I64Ty, fakeAlloca, "lob.fl");
    B.CreateCall(sink, {fakeLoad});
  }

  // ── Obfuscation 2: Header noise ───────────────────────────────────────────
  BasicBlock *header = L->getHeader();
  if (header) {
    // Find first non-PHI instruction to insert before
    Instruction *insertBefore = header->getFirstNonPHI();
    if (insertBefore) {
      IRBuilder<> Bh(insertBefore);

      Value *hn = Bh.CreateLoad(I64Ty, zeroGV, true /*volatile*/, "lob.hn");
      Value *ha = Bh.CreateAdd(hn, ConstantInt::get(I64Ty, 0), "lob.ha");

      FunctionType *sinkTy = FunctionType::get(
          Type::getVoidTy(Ctx), {I64Ty}, /*isVarArg=*/false);
      InlineAsm *sink = InlineAsm::get(sinkTy, "", "r,~{memory}",
                                       /*hasSideEffects=*/true);
      Bh.CreateCall(sink, {ha});
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main loop obfuscation
// ─────────────────────────────────────────────────────────────────────────────

static bool obfuscateLoops(Function &F, LoopInfo &LI) {
  Module *M = F.getParent();
  GlobalVariable *zeroGV = getLobZero(*M);

  // Collect top-level loops (snapshot before modifying)
  SmallVector<Loop *, 8> loops;
  for (Loop *L : LI.getTopLevelLoops())
    loops.push_back(L);

  if (loops.empty()) return false;

  // Initialize PRNG from function name
  std::string seed = F.getName().str() + "_lob";
  uint64_t rng = lobhash(seed);

  unsigned count = 0;
  for (Loop *L : loops) {
    obfuscateLoop(L, F, zeroGV, rng);
    ++count;
  }

  errs() << "[ArmorComp][LOB] obfuscated: " << F.getName()
         << " (" << count << " loop(s))\n";
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopObfuscationPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses LoopObfuscationPass::run(Function &F,
                                           FunctionAnalysisManager &AM) {
  if (annotateOnly && !hasLOBAnnotation(F))
    return PreservedAnalyses::all();

  auto &LI = AM.getResult<LoopAnalysis>(F);

  if (!obfuscateLoops(F, LI))
    return PreservedAnalyses::all();

  // We added new instructions and allocas; invalidate most analyses.
  PreservedAnalyses PA;
  PA.preserveSet<CFGAnalyses>();  // we didn't change BB structure (only added insts)
  return PA;
}
