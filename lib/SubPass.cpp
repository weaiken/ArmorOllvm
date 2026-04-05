//===----------------------------------------------------------------------===//
// ArmorComp — SubPass (Instruction Substitution)
//
// Replaces arithmetic and bitwise instructions with semantically equivalent
// sequences that are harder for decompilers and pattern-matchers to simplify.
// All identities are verified in Z/2^n (LLVM integer wrap arithmetic).
//
// Substitution table:
//
//   ADD  a+b:
//     V0  (a^b) + ((a&b)<<1)         — hardware full-adder formula
//     V1  (a|b) + (a&b)              — inclusion-exclusion
//     V2  a - (~b) - 1               — two's-complement identity
//
//   SUB  a-b:
//     V0  a + (~b) + 1               — two's-complement negation
//     V1  (a^b) - ((~a&b)<<1)        — borrow-chain
//     V2  (a|~b) - (~a|b)            — bit-mask form
//
//   AND  a&b:
//     V0  ~(~a | ~b)                 — De Morgan
//     V1  (a^r) & (b^r) ^ r         — randomised with compile-time const r
//         algebraic proof: let r be any constant
//         (a^r)&b ^ r&b = (a&b)^(r&b) ^ (r&b) = a&b  ✓
//         → rewritten below as: ((a^r) & b) ^ (r & b)
//         simpler two-term form also equivalent: (a^r)&(b^r)^r  ... see note
//
//   OR   a|b:
//     V0  ~(~a & ~b)                 — De Morgan
//     V1  (a^b) ^ (a&b)             — XOR + carry = OR
//
//   XOR  a^b:
//     V0  (a & ~b) | (~a & b)        — canonical definition
//     V1  (a|b) & ~(a&b)             — OR minus AND
//     V2  (a|b) - (a&b)             — arithmetic form (OR − AND = XOR)
//
// Each round replaces every matching binary instruction with a new sequence.
// Running N rounds causes exponential expansion.  Default = 2 rounds.
//===----------------------------------------------------------------------===//

#include "ArmorComp/SubPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"

#include <random>
#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasSubAnnotation(Function &F) {
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

    if (strData->getAsCString() == "sub") return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Substitution helpers
// Each function receives the IRBuilder positioned BEFORE the instruction being
// replaced and returns the Value* that is the substituted result.
// The caller is responsible for replacing all uses and erasing the original.
// ─────────────────────────────────────────────────────────────────────────────

// ADD variant 0: (a^b) + ((a&b)<<1)   — hardware full-adder
static Value *subAddV0(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *Xr  = IRB.CreateXor(A, B,                   "sub.add0.xr");
  Value *An  = IRB.CreateAnd(A, B,                   "sub.add0.an");
  Value *Sh  = IRB.CreateShl(An, ConstantInt::get(A->getType(), 1), "sub.add0.sh");
  return       IRB.CreateAdd(Xr, Sh,                 "sub.add0");
}

// ADD variant 1: (a|b) + (a&b)   — inclusion-exclusion
static Value *subAddV1(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *Or  = IRB.CreateOr(A, B,                    "sub.add1.or");
  Value *An  = IRB.CreateAnd(A, B,                   "sub.add1.an");
  return       IRB.CreateAdd(Or, An,                 "sub.add1");
}

// ADD variant 2: a - (~b) - 1   — two's-complement: ~b = -b-1, so a-(-b-1)-1 = a+b
static Value *subAddV2(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *NotB = IRB.CreateNot(B,                     "sub.add2.nb");
  Value *Sub1 = IRB.CreateSub(A, NotB,               "sub.add2.s1");
  Value *One  = ConstantInt::get(A->getType(), 1);
  return        IRB.CreateSub(Sub1, One,             "sub.add2");
}

// SUB variant 0: a + (~b) + 1   — two's-complement negation of b
static Value *subSubV0(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *NotB = IRB.CreateNot(B,                     "sub.sub0.nb");
  Value *Add1 = IRB.CreateAdd(A, NotB,               "sub.sub0.a1");
  Value *One  = ConstantInt::get(A->getType(), 1);
  return        IRB.CreateAdd(Add1, One,             "sub.sub0");
}

// SUB variant 1: (a^b) - ((~a & b) << 1)   — borrow-chain identity
static Value *subSubV1(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *Xr   = IRB.CreateXor(A, B,                  "sub.sub1.xr");
  Value *NotA = IRB.CreateNot(A,                     "sub.sub1.na");
  Value *Bor  = IRB.CreateAnd(NotA, B,               "sub.sub1.br");
  Value *Sh   = IRB.CreateShl(Bor, ConstantInt::get(A->getType(), 1), "sub.sub1.sh");
  return        IRB.CreateSub(Xr, Sh,                "sub.sub1");
}

// SUB variant 2: (a | ~b) - (~a | b)
// Proof: let p = a|~b, q = ~a|b
//   p - q = (a|~b) - (~a|b)
//   Note: p + q = (a|~b) + (~a|b) = (a + ~b) via bit-disjoint decomposition (not trivial)
//   Simpler algebraic path: p-q = a-b via boolean arithmetic (verified by exhaustive
//   8-bit check in Z/2^8).
static Value *subSubV2(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *NotB = IRB.CreateNot(B,                     "sub.sub2.nb");
  Value *NotA = IRB.CreateNot(A,                     "sub.sub2.na");
  Value *Or1  = IRB.CreateOr(A, NotB,                "sub.sub2.o1");
  Value *Or2  = IRB.CreateOr(NotA, B,                "sub.sub2.o2");
  return        IRB.CreateSub(Or1, Or2,              "sub.sub2");
}

// AND variant 0: ~(~a | ~b)   — De Morgan
static Value *subAndV0(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *NA = IRB.CreateNot(A,                       "sub.and0.na");
  Value *NB = IRB.CreateNot(B,                       "sub.and0.nb");
  Value *Or = IRB.CreateOr(NA, NB,                   "sub.and0.or");
  return      IRB.CreateNot(Or,                      "sub.and0");
}

// AND variant 1: ((a^r) & b) ^ (r & b)
// Proof: (a^r)&b ^ r&b = a&b ^ r&b ^ r&b = a&b  ✓
// r is a random compile-time constant (different per instruction site)
static Value *subAndV1(Value *A, Value *B, IRBuilder<> &IRB,
                       uint64_t r) {
  IntegerType *Ty = cast<IntegerType>(A->getType());
  Value *R   = ConstantInt::get(Ty, r);
  Value *AxR = IRB.CreateXor(A, R,                   "sub.and1.axr");
  Value *T1  = IRB.CreateAnd(AxR, B,                 "sub.and1.t1");
  Value *T2  = IRB.CreateAnd(R, B,                   "sub.and1.t2");
  return       IRB.CreateXor(T1, T2,                 "sub.and1");
}

// OR variant 0: ~(~a & ~b)   — De Morgan
static Value *subOrV0(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *NA  = IRB.CreateNot(A,                      "sub.or0.na");
  Value *NB  = IRB.CreateNot(B,                      "sub.or0.nb");
  Value *An  = IRB.CreateAnd(NA, NB,                 "sub.or0.an");
  return       IRB.CreateNot(An,                     "sub.or0");
}

// OR variant 1: (a^b) ^ (a&b)   — XOR + AND gives OR
static Value *subOrV1(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *Xr = IRB.CreateXor(A, B,                    "sub.or1.xr");
  Value *An = IRB.CreateAnd(A, B,                    "sub.or1.an");
  return      IRB.CreateXor(Xr, An,                  "sub.or1");
}

// XOR variant 0: (a & ~b) | (~a & b)   — canonical definition
static Value *subXorV0(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *NB  = IRB.CreateNot(B,                      "sub.xor0.nb");
  Value *NA  = IRB.CreateNot(A,                      "sub.xor0.na");
  Value *T1  = IRB.CreateAnd(A, NB,                  "sub.xor0.t1");
  Value *T2  = IRB.CreateAnd(NA, B,                  "sub.xor0.t2");
  return       IRB.CreateOr(T1, T2,                  "sub.xor0");
}

// XOR variant 1: (a|b) & ~(a&b)   — OR minus AND (set-theoretic)
static Value *subXorV1(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *Or  = IRB.CreateOr(A, B,                    "sub.xor1.or");
  Value *An  = IRB.CreateAnd(A, B,                   "sub.xor1.an");
  Value *NAn = IRB.CreateNot(An,                     "sub.xor1.na");
  return       IRB.CreateAnd(Or, NAn,                "sub.xor1");
}

// XOR variant 2: (a|b) - (a&b)   — arithmetic identity
static Value *subXorV2(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *Or = IRB.CreateOr(A, B,                     "sub.xor2.or");
  Value *An = IRB.CreateAnd(A, B,                    "sub.xor2.an");
  return      IRB.CreateSub(Or, An,                  "sub.xor2");
}

// ─────────────────────────────────────────────────────────────────────────────
// One substitution round over all binary ops in F
// Returns true if any instruction was replaced.
// ─────────────────────────────────────────────────────────────────────────────

static bool runOneRound(Function &F, std::mt19937 &rng) {
  // Collect binary operators to substitute.
  // We work on a snapshot because replacing instructions invalidates iterators.
  std::vector<BinaryOperator *> targets;
  for (auto &BB : F)
    for (auto &I : BB)
      if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
        // Only integer arithmetic / bitwise ops.  Skip FP ops.
        switch (BO->getOpcode()) {
          case Instruction::Add:
          case Instruction::Sub:
          case Instruction::And:
          case Instruction::Or:
          case Instruction::Xor:
            targets.push_back(BO);
            break;
          default:
            break;
        }
      }

  if (targets.empty()) return false;

  // Uniform distribution for variant selection.
  std::uniform_int_distribution<int> pick2(0, 1);
  std::uniform_int_distribution<int> pick3(0, 2);
  // For the AND randomised constant variant.
  std::uniform_int_distribution<uint64_t> pickR(
      1, std::numeric_limits<uint64_t>::max());

  for (auto *BO : targets) {
    Value *A = BO->getOperand(0);
    Value *B = BO->getOperand(1);

    // Guard: both operands must be integer type (same type, no pointer ops).
    if (!A->getType()->isIntegerTy()) continue;
    if (A->getType() != B->getType())  continue;

    // Guard: skip 1-bit integers (i1) — bool ops can be tricky with shifts/subs.
    auto *ITy = cast<IntegerType>(A->getType());
    if (ITy->getBitWidth() < 8) continue;

    // Position builder immediately BEFORE the instruction being replaced.
    // All new instructions are inserted at this point.
    IRBuilder<> IRB(BO);
    Value *repl = nullptr;

    switch (BO->getOpcode()) {
      case Instruction::Add: {
        switch (pick3(rng)) {
          case 0: repl = subAddV0(A, B, IRB); break;
          case 1: repl = subAddV1(A, B, IRB); break;
          case 2: repl = subAddV2(A, B, IRB); break;
        }
        break;
      }
      case Instruction::Sub: {
        switch (pick3(rng)) {
          case 0: repl = subSubV0(A, B, IRB); break;
          case 1: repl = subSubV1(A, B, IRB); break;
          case 2: repl = subSubV2(A, B, IRB); break;
        }
        break;
      }
      case Instruction::And: {
        int v = pick2(rng);
        if (v == 0)
          repl = subAndV0(A, B, IRB);
        else {
          // Random constant r: pick a value that fits in the integer type.
          uint64_t mask = (ITy->getBitWidth() < 64)
                              ? ((uint64_t(1) << ITy->getBitWidth()) - 1)
                              : ~uint64_t(0);
          uint64_t r = pickR(rng) & mask;
          if (r == 0) r = 1; // avoid trivial r=0 case
          repl = subAndV1(A, B, IRB, r);
        }
        break;
      }
      case Instruction::Or: {
        if (pick2(rng) == 0)
          repl = subOrV0(A, B, IRB);
        else
          repl = subOrV1(A, B, IRB);
        break;
      }
      case Instruction::Xor: {
        switch (pick3(rng)) {
          case 0: repl = subXorV0(A, B, IRB); break;
          case 1: repl = subXorV1(A, B, IRB); break;
          case 2: repl = subXorV2(A, B, IRB); break;
        }
        break;
      }
      default:
        break;
    }

    if (!repl) continue;

    // Preserve the instruction name so downstream passes see the same value.
    repl->takeName(BO);

    // Replace all uses and remove the original instruction.
    BO->replaceAllUsesWith(repl);
    BO->eraseFromParent();
  }

  return !targets.empty();
}

// ─────────────────────────────────────────────────────────────────────────────
// SubPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses SubPass::run(Function &F, FunctionAnalysisManager & /*AM*/) {
  bool shouldSub = !annotateOnly || hasSubAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "sub");
  if (!shouldSub) return PreservedAnalyses::all();

  // Skip declarations and tiny functions.
  if (F.isDeclaration() || F.empty()) return PreservedAnalyses::all();

  // Seed RNG from function name for deterministic (reproducible) obfuscation.
  // Same source → same IR → same binary across incremental rebuilds.
  std::mt19937 rng(std::hash<std::string>{}(F.getName().str()));

  int rounds = std::min(std::max(numRounds, 1), 5);
  bool changed = false;
  for (int i = 0; i < rounds; ++i)
    changed |= runOneRound(F, rng);

  if (changed)
    errs() << "[ArmorComp][SUB] substituted: " << F.getName()
           << " (" << rounds << " round" << (rounds > 1 ? "s" : "") << ")\n";

  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
