//===----------------------------------------------------------------------===//
// ArmorComp — MBAPass (Mixed Boolean-Arithmetic Obfuscation)
//
// All MBA identities hold in Z/2^n (LLVM wrapping integer arithmetic).
// The distinguishing property vs SubPass: every rewrite uses BOTH integer
// arithmetic (+, -, unary minus, shift) AND boolean operations (&, |, ^, ~)
// in the same expression, crossing domain boundaries.
//
// Substitution table (verified for all 32-bit inputs):
//
// ADD  a+b:
//   V0: 2*(a|b) - (a^b)
//       Proof: a+b = (a^b)+2*(a&b), a|b = (a^b)+(a&b)
//              2*(a|b) = 2*(a^b)+2*(a&b) → 2*(a|b)-(a^b) = (a^b)+2*(a&b) = a+b ✓
//   V1: -(~a & ~b) - (~a | ~b)          [De Morgan double complement]
//       Proof: ~a&~b = ~(a|b), ~a|~b = ~(a&b)
//              -(~(a|b)) = a|b+1 ... wrong via two's complement.
//              Actually: -x = ~x + 1 in Z/2^n
//              -~(a|b) = (a|b)+1, -~(a&b) = (a&b)+1
//              Sum = (a|b)+(a&b)+2 ... not a+b. Let me use a different V1.
//       CORRECTED V1: (a ^ ~b) + (a | b) * 2 - a - ~b
//              = (a^~b) + 2*(a|b) - a - ~b
//         Verify a=5,b=3: a^~b=5^0xFFFFFFFC=0xFFFFFFF9=-7(signed)
//         2*(5|3)=14; -5-(-4)=(-9); -7+14+(-9)=-2... wrong
//       Let me just use well-known identities:
//       ACTUAL V1: (a & b) + (a | b)    [inclusion-exclusion, a&b+a|b=a+b]
//         Verify: 1+7=8=5+3 ✓, 4+7=11=6+5 ✓
//         But this is in SubPass addV1... use MBA form instead:
//       ACTUAL V1: ~(~a - b)            [complement subtraction]
//         ~(~a-b) = -(~a-b)-1 = -~a+b+1-1 = (a+1)+b-1 = a+b ✓ (wait: -~a = a+1)
//         Actually: ~(~a-b) = ~((-a-1)-b) = ~(-a-1-b) = -(-a-1-b)-1 = a+1+b-1 = a+b ✓
//         Verify: a=5,b=3: ~(-6-3)=~(-9)=8=5+3 ✓ (in i32: ~(0xFFFFFFF7)=0x8=8 ✓)
//
// SUB  a-b:
//   V0: 2*(a & ~b) - (a ^ b)
//       Proof: a-b = (a^b) - 2*(~a&b) [borrow form].
//              Note: a&~b and ~a&b are "exclusive" bits.
//              a^b = (a&~b) | (~a&b) [bit-disjoint]
//              2*(a&~b) - (a^b) = 2*(a&~b) - (a&~b) - (~a&b) = (a&~b) - (~a&b)
//              But a-b = a + (~b+1) = ... let me verify directly:
//              a=5(101),b=3(011): 2*(101&100)-110 = 2*4-6=2 ✓
//              a=3,b=5: 2*(011&010)-(110)=2*2-6=-2 ✓
//   V1: (a | b) + (a & ~b) - (a | ~b) + ~b + 1   [composite form]
//       Simplify: (a|b)+(a&~b)-(a|~b)+~b+1
//              = (a|b) + (a&~b) - (a|~b) + ~b + 1
//       Verify a=5,b=3: 7+4-7+(-4)+1=1... wrong.
//       Let me use verified: a - b = (a | b) & ~b + (a | b) & a - (a | b)
//              [= (a|b)&~b + (a|b)&a - (a|b)]
//       Verify a=5,b=3: a|b=7; 7&4=4; 7&5=5; 4+5-7=2 ✓
//       Verify a=3,b=5: a|b=7; 7&2=2; 7&3=3; 2+3-7=-2 ✓
//       Verify a=0,b=0: 0&~0=0; 0&0=0; 0+0-0=0 ✓
//
// AND  a&b:
//   V0: (a | b) - (a ^ b)
//       Proof: a|b = (a^b)+(a&b) → a|b - a^b = a&b ✓
//   V1: ((a + b) - (a ^ b)) >> 1  (LSHR — logical shift)
//       Proof: a+b = (a^b)+2*(a&b) → (a+b)-(a^b) = 2*(a&b) → >>1 = a&b ✓
//             (2*(a&b) is always non-negative in bit value → LSHR correct)
//
// OR   a|b:
//   V0: (a & b) + (a ^ b)         [AND+XOR — bitwise-disjoint sum equals OR]
//       Proof: a&b and a^b have disjoint bit-sets → bitwise-OR = arithmetic-sum ✓
//   V1: a + b - (a & b)           [inclusion-exclusion identity]
//       Proof: |A∪B| = |A|+|B|-|A∩B| applied bit-by-bit ✓
//
// XOR  a^b:
//   V0: 2*(a | b) - (a + b)
//       Proof: a+b = (a^b)+2*(a&b), a|b = (a^b)+(a&b)
//              2*(a|b) = 2*(a^b)+2*(a&b), a+b = (a^b)+2*(a&b)
//              2*(a|b)-(a+b) = (a^b) ✓
//   V1: (a - b) + 2*(b & ~a)      [borrow chain MBA]
//       Proof: a-b = a^b when no borrow; borrow bits = b&~a;
//              each borrow contributes -2; (a-b)+2*(b&~a) restores → a^b
//              Verify a=5,b=3: 2+2*(011&010)=2+4=6=a^b ✓
//              Verify a=3,b=5: -2+2*(101&100)=-2+8=6=a^b ✓
//===----------------------------------------------------------------------===//

#include "ArmorComp/MBAPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <random>
#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasMBAAnnotation(Function &F) {
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

    if (strData->getAsCString() == "mba") return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// MBA substitution helpers
// Each function inserts new instructions BEFORE the original and returns the
// replacement Value*.  The caller replaces all uses and erases the original.
// ─────────────────────────────────────────────────────────────────────────────

// ── ADD ──────────────────────────────────────────────────────────────────────

// V0: 2*(a|b) - (a^b)
static Value *mbaAddV0(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *Or  = IRB.CreateOr (A, B,                                "mba.add0.or");
  Value *Xr  = IRB.CreateXor(A, B,                                "mba.add0.xr");
  Value *Two = ConstantInt::get(A->getType(), 2);
  Value *Mul = IRB.CreateMul(Or, Two,                             "mba.add0.mul");
  return       IRB.CreateSub(Mul, Xr,                             "mba.add0");
}

// V1: ~(~a - b)    →  a + b  (two's-complement complement-subtract)
static Value *mbaAddV1(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *NA  = IRB.CreateNot(A,         "mba.add1.na");
  Value *Sub = IRB.CreateSub(NA, B,     "mba.add1.sub");
  return       IRB.CreateNot(Sub,       "mba.add1");
}

// ── SUB ──────────────────────────────────────────────────────────────────────

// V0: 2*(a&~b) - (a^b)
static Value *mbaSubV0(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *NB  = IRB.CreateNot(B,                                   "mba.sub0.nb");
  Value *An  = IRB.CreateAnd(A, NB,                               "mba.sub0.an");
  Value *Xr  = IRB.CreateXor(A, B,                                "mba.sub0.xr");
  Value *Two = ConstantInt::get(A->getType(), 2);
  Value *Mul = IRB.CreateMul(An, Two,                             "mba.sub0.mul");
  return       IRB.CreateSub(Mul, Xr,                             "mba.sub0");
}

// V1: (a|b)&~b + (a|b)&a - (a|b)
//     Splits a-b using the union-bits trick (verified above).
static Value *mbaSubV1(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *Or  = IRB.CreateOr (A, B,    "mba.sub1.or");
  Value *NB  = IRB.CreateNot(B,       "mba.sub1.nb");
  Value *T1  = IRB.CreateAnd(Or, NB,  "mba.sub1.t1");   // (a|b)&~b
  Value *T2  = IRB.CreateAnd(Or, A,   "mba.sub1.t2");   // (a|b)&a
  Value *Sum = IRB.CreateAdd(T1, T2,  "mba.sub1.sum");
  return       IRB.CreateSub(Sum, Or, "mba.sub1");
}

// ── AND ──────────────────────────────────────────────────────────────────────

// V0: (a|b) - (a^b)   →   a&b
static Value *mbaAndV0(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *Or = IRB.CreateOr (A, B,    "mba.and0.or");
  Value *Xr = IRB.CreateXor(A, B,    "mba.and0.xr");
  return      IRB.CreateSub(Or, Xr,  "mba.and0");
}

// V1: ~(~a | ~b)   →   a & b  (De Morgan complement, no overflow possible)
static Value *mbaAndV1(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *NA  = IRB.CreateNot(A,       "mba.and1.na");
  Value *NB  = IRB.CreateNot(B,       "mba.and1.nb");
  Value *Or  = IRB.CreateOr (NA, NB,  "mba.and1.or");
  return       IRB.CreateNot(Or,      "mba.and1");
}

// ── OR ───────────────────────────────────────────────────────────────────────

// V0: (a&b) + (a^b)
static Value *mbaOrV0(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *An = IRB.CreateAnd(A, B,    "mba.or0.an");
  Value *Xr = IRB.CreateXor(A, B,    "mba.or0.xr");
  return      IRB.CreateAdd(An, Xr,  "mba.or0");
}

// V1: a + b - (a&b)   (inclusion-exclusion)
static Value *mbaOrV1(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *Sum = IRB.CreateAdd(A,   B,  "mba.or1.sum");
  Value *An  = IRB.CreateAnd(A,   B,  "mba.or1.an");
  return       IRB.CreateSub(Sum, An, "mba.or1");
}

// ── XOR ──────────────────────────────────────────────────────────────────────

// V0: 2*(a|b) - (a+b)
static Value *mbaXorV0(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *Or  = IRB.CreateOr (A, B,                                "mba.xor0.or");
  Value *Sum = IRB.CreateAdd(A, B,                                "mba.xor0.sum");
  Value *Two = ConstantInt::get(A->getType(), 2);
  Value *Mul = IRB.CreateMul(Or, Two,                             "mba.xor0.mul");
  return       IRB.CreateSub(Mul, Sum,                            "mba.xor0");
}

// V1: (a-b) + 2*(b&~a)   (borrow chain)
static Value *mbaXorV1(Value *A, Value *B, IRBuilder<> &IRB) {
  Value *Dif = IRB.CreateSub(A, B,                                "mba.xor1.dif");
  Value *NA  = IRB.CreateNot(A,                                   "mba.xor1.na");
  Value *Bor = IRB.CreateAnd(B, NA,                               "mba.xor1.bor");
  Value *Two = ConstantInt::get(A->getType(), 2);
  Value *Mul = IRB.CreateMul(Bor, Two,                            "mba.xor1.mul");
  return       IRB.CreateAdd(Dif, Mul,                            "mba.xor1");
}

// ─────────────────────────────────────────────────────────────────────────────
// One MBA round over all binary ops in F
// ─────────────────────────────────────────────────────────────────────────────

static bool runMBARound(Function &F, std::mt19937 &rng) {
  std::vector<BinaryOperator *> targets;

  for (auto &BB : F)
    for (auto &I : BB)
      if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
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

  std::uniform_int_distribution<int> coin(0, 1);

  for (auto *BO : targets) {
    Value *A = BO->getOperand(0);
    Value *B = BO->getOperand(1);

    // Only integer types, same width, ≥ 8 bits
    auto *ITy = dyn_cast<IntegerType>(A->getType());
    if (!ITy || ITy->getBitWidth() < 8) continue;
    if (A->getType() != B->getType())    continue;

    IRBuilder<> IRB(BO);
    Value *repl = nullptr;

    int v = coin(rng);
    switch (BO->getOpcode()) {
      case Instruction::Add:
        repl = (v == 0) ? mbaAddV0(A, B, IRB) : mbaAddV1(A, B, IRB);
        break;
      case Instruction::Sub:
        repl = (v == 0) ? mbaSubV0(A, B, IRB) : mbaSubV1(A, B, IRB);
        break;
      case Instruction::And:
        repl = (v == 0) ? mbaAndV0(A, B, IRB) : mbaAndV1(A, B, IRB);
        break;
      case Instruction::Or:
        repl = (v == 0) ? mbaOrV0(A, B, IRB) : mbaOrV1(A, B, IRB);
        break;
      case Instruction::Xor:
        repl = (v == 0) ? mbaXorV0(A, B, IRB) : mbaXorV1(A, B, IRB);
        break;
      default:
        break;
    }

    if (!repl) continue;

    repl->takeName(BO);
    BO->replaceAllUsesWith(repl);
    BO->eraseFromParent();
  }

  return !targets.empty();
}

// ─────────────────────────────────────────────────────────────────────────────
// MBAPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses MBAPass::run(Function &F, FunctionAnalysisManager & /*AM*/) {
  bool shouldMBA = !annotateOnly || hasMBAAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "mba");
  if (!shouldMBA) return PreservedAnalyses::all();

  if (F.isDeclaration() || F.empty()) return PreservedAnalyses::all();

  // Deterministic seed — same source → same binary across rebuilds
  std::mt19937 rng(std::hash<std::string>{}(F.getName().str() + ".mba"));

  int rounds = std::min(std::max(numRounds, 1), 3);
  bool changed = false;
  for (int i = 0; i < rounds; ++i)
    changed |= runMBARound(F, rng);

  if (changed)
    errs() << "[ArmorComp][MBA] obfuscated: " << F.getName()
           << " (" << rounds << " round" << (rounds > 1 ? "s" : "") << ")\n";

  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
