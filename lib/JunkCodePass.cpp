//===----------------------------------------------------------------------===//
// ArmorComp — JunkCodePass (JCI — Junk Code Injection)
//
// Inserts dead arithmetic computation chains into each targeted basic block.
// See include/ArmorComp/JunkCodePass.h for full design documentation.
//===----------------------------------------------------------------------===//

#include "ArmorComp/JunkCodePass.h"
#include "ArmorComp/ObfuscationConfig.h"

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
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasJCIAnnotation(Function &F) {
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

        if (strData->getAsCString() == "jci") return true;
      }
    }
  }

check_config:
  return armorcomp::configSaysApply(F.getName(), "jci");
}

// ─────────────────────────────────────────────────────────────────────────────
// PRNG helpers — deterministic per (function, BB index) pair
// ─────────────────────────────────────────────────────────────────────────────

// FNV-1a 64-bit hash — fast, deterministic, good avalanche.
static uint64_t fnv1a64(const std::string &s) {
  uint64_t h = 14695981039346656037ULL;
  for (unsigned char c : s)
    h = (h ^ c) * 1099511628211ULL;
  return h;
}

// xorshift64 — one step of Marsaglia's xorshift PRNG.
static uint64_t xorshift64(uint64_t x) {
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  return x;
}

// ─────────────────────────────────────────────────────────────────────────────
// Volatile-zero global — shared across all JCI-obfuscated functions.
// WeakAnyLinkage: multiple TUs → linker merges to a single copy.
// Separate from CO/GEPO/SOB zeros so IDA cannot alias them.
// ─────────────────────────────────────────────────────────────────────────────

static GlobalVariable *getOrCreateJciZero(Module &M, Type *I64Ty) {
  const StringRef name = "__armorcomp_jci_zero";
  if (auto *G = M.getGlobalVariable(name)) return G;

  auto *G = new GlobalVariable(
      M, I64Ty, /*isConstant=*/false,
      GlobalValue::WeakAnyLinkage,
      ConstantInt::get(I64Ty, 0),
      name);
  G->setAlignment(Align(8));
  return G;
}

// ─────────────────────────────────────────────────────────────────────────────
// JunkCodePass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses JunkCodePass::run(Function &F,
                                     FunctionAnalysisManager & /*AM*/) {
  if (F.isDeclaration() || F.empty()) return PreservedAnalyses::all();
  if (F.getName().startswith("__armorcomp_")) return PreservedAnalyses::all();

  bool shouldObf = !annotateOnly
                   || hasJCIAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "jci");
  if (!shouldObf) return PreservedAnalyses::all();

  Module      *M    = F.getParent();
  LLVMContext &Ctx  = M->getContext();
  Type *VoidTy = Type::getVoidTy(Ctx);
  Type *I64Ty  = Type::getInt64Ty(Ctx);

  GlobalVariable *JciZero = getOrCreateJciZero(*M, I64Ty);

  // ── Inline-asm sink: asm volatile("" : : "r"(v)); ─────────────────────────
  // The "r" input constraint forces the compiler to materialise the value in
  // a register before the asm boundary.  hasSideEffects=true prevents DCE.
  // "~{dirflag},~{fpsr},~{flags}" are the standard ABI clobbers.
  // No instructions are emitted — the sink is purely a use anchor for LLVM.
  FunctionType *AsmTy =
      FunctionType::get(VoidTy, {I64Ty}, /*isVarArg=*/false);
  InlineAsm *Sink =
      InlineAsm::get(AsmTy, "",
                     "r,~{dirflag},~{fpsr},~{flags}",
                     /*hasSideEffects=*/true,
                     /*isAlignStack=*/false,
                     InlineAsm::AD_ATT);

  // ── Snapshot all BBs before modification ──────────────────────────────────
  std::vector<BasicBlock *> bbs;
  for (auto &BB : F)
    bbs.push_back(&BB);

  unsigned totalInstr = 0;
  unsigned totalBBs   = 0;
  std::string fnName  = F.getName().str();

  for (unsigned bbIdx = 0, e = (unsigned)bbs.size(); bbIdx < e; ++bbIdx) {
    BasicBlock *BB = bbs[bbIdx];

    // Skip BBs that consist solely of a terminator (degenerate landing pads,
    // placeholder BBs from other passes, etc.)
    if (BB->size() == 1 && BB->getTerminator()) continue;

    // Insert junk chain just before the BB terminator.
    Instruction *InsertBefore = BB->getTerminator();
    IRBuilder<> IRB(InsertBefore);

    // Seed PRNG deterministically per (function, BB) pair.
    std::string seedStr = fnName + "_jci_" + std::to_string(bbIdx);
    uint64_t state = fnv1a64(seedStr);
    state = xorshift64(state); // first advance to escape seed bias

    // Number of arithmetic ops: 4–7, varies per BB.
    unsigned numOps = 4 + (unsigned)(state % 4);
    state = xorshift64(state);

    // ── Chain: volatile_zero base → N ops → asm sink ──────────────────────
    Value *Chain = IRB.CreateLoad(I64Ty, JciZero, /*isVolatile=*/true,
                                   "jci.base");
    unsigned instrCount = 1; // volatile load

    // Arithmetic operations pool (8 kinds).
    // opKind selects the operation; K is the immediate constant.
    // For shift amounts, K is masked to [0..63] to stay in-range.
    for (unsigned k = 0; k < numOps; ++k) {
      state = xorshift64(state);
      uint64_t K = state | 1; // force non-zero (avoids trivial no-ops)
      state = xorshift64(state);
      unsigned opKind = (unsigned)(state % 8);
      state = xorshift64(state);

      Value *Kval = ConstantInt::get(I64Ty, K);

      switch (opKind) {
        case 0:
          Chain = IRB.CreateXor(Chain, Kval, "jci.xor");
          break;
        case 1:
          Chain = IRB.CreateOr(Chain, Kval, "jci.or");
          break;
        case 2:
          Chain = IRB.CreateAnd(Chain, Kval, "jci.and");
          break;
        case 3: {
          uint64_t shamt = K & 63;
          Chain = IRB.CreateShl(Chain, ConstantInt::get(I64Ty, shamt),
                                 "jci.shl");
          break;
        }
        case 4: {
          uint64_t shamt = K & 63;
          Chain = IRB.CreateLShr(Chain, ConstantInt::get(I64Ty, shamt),
                                  "jci.lshr");
          break;
        }
        case 5:
          Chain = IRB.CreateMul(Chain, Kval, "jci.mul");
          break;
        case 6:
          Chain = IRB.CreateAdd(Chain, Kval, "jci.add");
          break;
        default:
          Chain = IRB.CreateSub(Chain, Kval, "jci.sub");
          break;
      }
      ++instrCount;
    }

    // Consume chain with asm sideeffect sink (prevents DCE of entire chain).
    IRB.CreateCall(Sink, {Chain});
    ++instrCount;

    totalInstr += instrCount;
    ++totalBBs;
  }

  if (totalBBs == 0) return PreservedAnalyses::all();

  errs() << "[ArmorComp][JCI] injected: " << F.getName()
         << " (" << totalInstr << " junk instr(s), "
         << totalBBs << " BB(s))\n";

  return PreservedAnalyses::none();
}
