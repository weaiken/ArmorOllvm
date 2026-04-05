//===----------------------------------------------------------------------===//
// ArmorComp — ConditionObfPass (Comparison Obfuscation)
//
// Strategy: inject opaque noise into the operands of every ICmpInst so that
// IDA Hex-Rays cannot statically resolve comparison conditions to their
// original form.  All other ArmorComp passes target BinaryOperator; this
// pass closes the gap by targeting the comparisons that drive control flow.
//
// NOISE CONSTRUCTION
// ──────────────────
// Given icmp pred A, B with operand type iN:
//
//   zero    = load volatile i64, @__armorcomp_cob_zero   ; = 0 at runtime
//   Ka      = FNV(fn_name) ⊕ LCG(seqNo, mul_A, add_A)   ; compile-time const
//   Kb      = FNV(fn_name) ⊕ LCG(seqNo, mul_B, add_B)   ; different const
//   Na_wide = mul  i64 zero, Ka                          ; = 0 at runtime
//   Nb_wide = mul  i64 zero, Kb                          ; = 0 at runtime
//   Na      = trunc Na_wide to iN                        ; = 0 at runtime
//   Nb      = trunc Nb_wide to iN                        ; = 0 at runtime
//   A'      = add  iN A, Na                              ; = A at runtime
//   B'      = add  iN B, Nb                              ; = B at runtime
//   result  = icmp pred A', B'                           ; identical result ✓
//
// WHY ADD (NOT XOR) FOR ALL PREDICATES
// ─────────────────────────────────────
// XOR can flip the sign bit of an operand, which changes the result of signed
// ordered comparisons (SLT, SGT, SLE, SGE) even though the noise is "zero".
// ADD 0 is always neutral for every comparison predicate in Z/2^n:
//   A + 0 = A, B + 0 = B  →  A cmp B unchanged ✓
//
// VOLATILE SEMANTICS
// ──────────────────
// The volatile load prevents the optimizer from constant-folding the load to
// the known initializer value (0).  LLVM's alias analysis and value-range
// analysis cannot look through volatile loads.  Therefore:
//   mul(volatile_load, K) → not-known-zero to the optimizer
//   trunc(not-known-zero) → not-known-zero
//   add(A, not-known-zero) → not-equal-to-A from IDA's perspective
//===----------------------------------------------------------------------===//

#include "ArmorComp/ConditionObfPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasCOBAnnotation(Function &F) {
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

        if (strData->getAsCString() == "cob") return true;
      }
    }
  }

check_config:
  return armorcomp::configSaysApply(F.getName(), "cob");
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// FNV-1a 64-bit hash of a string — deterministic per-function seed.
static uint64_t fnvHash(StringRef S) {
  uint64_t h = 14695981039346656037ULL;
  for (char C : S) {
    h ^= (unsigned char)C;
    h *= 1099511628211ULL;
  }
  return h;
}

// ─────────────────────────────────────────────────────────────────────────────
// ConditionObfPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses ConditionObfPass::run(Function &F,
                                        FunctionAnalysisManager & /*AM*/) {
  if (F.isDeclaration()) return PreservedAnalyses::all();

  // Never instrument ArmorComp's own injected functions
  if (F.getName().startswith("__armorcomp_")) return PreservedAnalyses::all();

  bool shouldObf = !annotateOnly
                   || hasCOBAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "cob");
  if (!shouldObf) return PreservedAnalyses::all();

  Module     *M   = F.getParent();
  LLVMContext &Ctx = F.getContext();
  Type       *I64Ty = Type::getInt64Ty(Ctx);

  // ── Get or create the shared volatile-zero global ─────────────────────────
  // WeakAny linkage: multiple TUs defining the same global → linker merges them.
  // Initialized to 0; never written by generated code; volatile loads prevent
  // constant-folding back to the initializer value.
  GlobalVariable *CobZero = M->getGlobalVariable("__armorcomp_cob_zero");
  if (!CobZero) {
    CobZero = new GlobalVariable(
        *M,
        I64Ty,
        /*isConstant=*/false,
        GlobalValue::WeakAnyLinkage,
        ConstantInt::get(I64Ty, 0),
        "__armorcomp_cob_zero"
    );
  }

  // Per-function seed — ensures different noise keys across functions.
  const uint64_t seed = fnvHash(F.getName());

  // ── Snapshot all ICmpInst instructions before mutating ────────────────────
  std::vector<ICmpInst *> cmps;
  for (BasicBlock &BB : F)
    for (Instruction &I : BB)
      if (auto *IC = dyn_cast<ICmpInst>(&I))
        cmps.push_back(IC);

  if (cmps.empty()) return PreservedAnalyses::all();

  unsigned seqNo = 0;
  unsigned count = 0;

  for (ICmpInst *IC : cmps) {
    Value *A    = IC->getOperand(0);
    Value *B    = IC->getOperand(1);
    Type  *OpTy = A->getType();

    // Skip: non-integer types (pointers, vectors, floats)
    if (!OpTy->isIntegerTy()) continue;

    unsigned width = OpTy->getIntegerBitWidth();
    // Skip: i1 (single-bit flag, usually result of another cmp)
    // Skip: > 64 bits (i128, arbitrary-precision — rare, truncation loses bits)
    if (width == 1 || width > 64) continue;

    IRBuilder<> Bldr(IC); // inserts before IC

    // ── Load volatile zero ──────────────────────────────────────────────────
    // Fresh load per ICmpInst — independent volatile accesses give IDA no
    // way to CSE them into a single known value.
    Value *ZeroI64 = Bldr.CreateLoad(I64Ty, CobZero, /*isVolatile=*/true,
                                     "cob.zero");

    // ── Derive keys via LCG mixing (two independent streams for A and B) ───
    // Stream A: Knuth multiplicative LCG
    uint64_t Ka = seed
                  ^ ((uint64_t)seqNo * 6364136223846793005ULL
                     + 1442695040888963407ULL);
    // Stream B: Alternate LCG — different multiplier so Ka ≠ Kb
    uint64_t Kb = seed
                  ^ ((uint64_t)seqNo * 2862933555777941757ULL
                     + 3037000493ULL);
    // Ensure non-zero keys so mul(zero, K) is not obviously a zero multiply
    if (Ka == 0) Ka = 0xDEADBEEFCAFEBABEULL;
    if (Kb == 0) Kb = 0xFEEDFACEDEADC0DEULL;

    Value *KaVal = ConstantInt::get(I64Ty, Ka);
    Value *KbVal = ConstantInt::get(I64Ty, Kb);

    // ── Opaque noise terms (= 0 at runtime, unknown to analyzer) ────────────
    Value *NaWide = Bldr.CreateMul(ZeroI64, KaVal, "cob.na.wide");
    Value *NbWide = Bldr.CreateMul(ZeroI64, KbVal, "cob.nb.wide");

    Value *Na, *Nb;
    if (width == 64) {
      Na = NaWide; // already i64, no truncation needed
      Nb = NbWide;
    } else {
      Na = Bldr.CreateTrunc(NaWide, OpTy, "cob.na");
      Nb = Bldr.CreateTrunc(NbWide, OpTy, "cob.nb");
    }

    // ── Noisy operands: A' = A + 0 = A,  B' = B + 0 = B (at runtime) ───────
    Value *APrime = Bldr.CreateAdd(A, Na, "cob.a");
    Value *BPrime = Bldr.CreateAdd(B, Nb, "cob.b");

    // ── Replace comparison with noisy version, same predicate ────────────────
    // CreateICmp inserts the new instruction immediately before IC (via Bldr).
    Value *NewIC = Bldr.CreateICmp(IC->getPredicate(), APrime, BPrime, "cob.cmp");
    IC->replaceAllUsesWith(NewIC);
    IC->eraseFromParent();

    ++seqNo;
    ++count;
  }

  if (count == 0) return PreservedAnalyses::all();

  errs() << "[ArmorComp][COB] obfuscated: " << F.getName()
         << " (" << count << " icmp(s))\n";

  return PreservedAnalyses::none();
}
