//===----------------------------------------------------------------------===//
// ArmorComp — ConstObfPass implementation
//
// For each ConstantInt operand in qualifying instructions (BinaryOperator,
// ICmpInst), replaces the bare constant with a 3-instruction XOR sequence:
//
//   %co.z   = load volatile i64, @__armorcomp_co_zero
//   %co.k64 = or i64 %co.z, K64          ; runtime = K64; IDA: volatile | K64
//   %co.k   = trunc i64 %co.k64 to iN    ; (identity when N==64)
//   %co.v   = xor iN (C ^ Kn), %co.k     ; runtime = C
//
// K64 is a compile-time random 64-bit key. Kn = K64 truncated to N bits.
// C ^ Kn is stored as a plain immediate. The result is always C at runtime.
//===----------------------------------------------------------------------===//

#include "ArmorComp/ConstObfPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <utility>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasCOAnnotation(Function &F) {
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
    if (StrData && StrData->getAsCString() == "co") return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

static GlobalVariable *getOrCreateCOZero(Module &M) {
  const char *Name = "__armorcomp_co_zero";
  if (GlobalVariable *GV = M.getGlobalVariable(Name))
    return GV;
  return new GlobalVariable(
      M, Type::getInt64Ty(M.getContext()), /*isConstant=*/false,
      GlobalValue::WeakAnyLinkage,
      ConstantInt::get(Type::getInt64Ty(M.getContext()), 0), Name);
}

/// Fast xorshift64 PRNG — deterministic given the seed.
static uint64_t xorshift64(uint64_t &state) {
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return state;
}

/// Returns true if the instruction is one whose constant operands we can
/// safely replace with computed values.
static bool isQualifyingInst(const Instruction &I) {
  if (isa<BinaryOperator>(I)) return true;
  if (isa<ICmpInst>(I))       return true;
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstObfPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses ConstObfPass::run(Function &F,
                                    FunctionAnalysisManager & /*AM*/) {
  if (F.isDeclaration()) return PreservedAnalyses::all();
  if (F.getName().startswith("__armorcomp_")) return PreservedAnalyses::all();

  bool shouldObfuscate = !annotateOnly
                         || hasCOAnnotation(F)
                         || armorcomp::configSaysApply(F.getName(), "co");
  if (!shouldObfuscate) return PreservedAnalyses::all();

  Module *M = F.getParent();
  LLVMContext &ctx = F.getContext();
  Type *I64Ty = Type::getInt64Ty(ctx);
  GlobalVariable *COZero = getOrCreateCOZero(*M);

  // Seed PRNG with a hash of the function name for deterministic builds.
  uint64_t rng = std::hash<std::string>{}(F.getName().str()) | 1ULL;

  // Collect qualifying (instruction, operand-index) pairs first to avoid
  // iterator invalidation while we insert new instructions.
  SmallVector<std::pair<Instruction *, unsigned>, 64> worklist;

  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      if (!isQualifyingInst(I)) continue;

      for (unsigned i = 0, n = I.getNumOperands(); i < n; ++i) {
        auto *CI = dyn_cast<ConstantInt>(I.getOperand(i));
        if (!CI) continue;

        unsigned width = CI->getType()->getBitWidth();
        // Only handle standard widths; skip i1 (boolean) and wide types.
        if (width != 8 && width != 16 && width != 32 && width != 64) continue;

        worklist.emplace_back(&I, i);
      }
    }
  }

  if (worklist.empty()) return PreservedAnalyses::all();

  unsigned count = 0;
  for (auto &[Inst, OpIdx] : worklist) {
    auto *CI = cast<ConstantInt>(Inst->getOperand(OpIdx));
    unsigned width = CI->getType()->getBitWidth();
    Type *CITy = CI->getType();

    // Generate a random 64-bit key at compile time.
    uint64_t K64 = xorshift64(rng);
    uint64_t mask = (width == 64) ? ~0ULL : ((1ULL << width) - 1ULL);
    uint64_t Kn   = K64 & mask;
    uint64_t C64  = CI->getZExtValue();
    uint64_t CxK  = (C64 ^ Kn) & mask;  // stored as immediate

    // Insert the obfuscation sequence immediately before Inst.
    IRBuilder<> Builder(Inst);

    // %co.z   = load volatile i64, @__armorcomp_co_zero   ; = 0 at runtime
    auto *ZLoad = Builder.CreateLoad(I64Ty, COZero, /*isVolatile=*/true,
                                     "co.z");

    // %co.k64 = or i64 %co.z, K64_const   ; = K64 at runtime
    // IDA decompiler sees: (volatile_load | large_random_constant)
    auto *KOr = Builder.CreateOr(ZLoad, ConstantInt::get(I64Ty, K64),
                                 "co.k64");

    // %co.k = trunc i64 %co.k64 to iN   (skip trunc when N == 64)
    Value *KeyN = (width < 64)
                      ? Builder.CreateTrunc(KOr, CITy, "co.k")
                      : static_cast<Value *>(KOr);

    // %co.v = xor iN (C ^ Kn)_const, %co.k   ; = C at runtime
    auto *ObfVal = Builder.CreateXor(ConstantInt::get(CITy, CxK), KeyN,
                                     "co.v");

    Inst->setOperand(OpIdx, ObfVal);
    ++count;
  }

  errs() << "[ArmorComp][CO] obfuscated: " << F.getName()
         << " (" << count << " constant(s))\n";
  return PreservedAnalyses::none();
}
