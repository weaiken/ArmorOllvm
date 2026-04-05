//===----------------------------------------------------------------------===//
// ArmorComp — DwarfPoisonPass (DWARF CFI Table Poisoning)
//
// Strategy: inject misleading DWARF Call Frame Information (CFI) rows into
// the .eh_frame section to disrupt IDA Pro's stack-frame / sp-delta analysis.
// ─────────────────────────────────────────────────────────────────────────────
//
//  MECHANISM — .cfi_remember_state / fake CFI / .cfi_restore_state
//  ─────────────────────────────────────────────────────────────────
//  At each injection point we emit a self-contained inline-asm block:
//
//    .cfi_remember_state           ; push current (correct) CFI state onto stack
//    .cfi_def_cfa <fake_reg,ofs>   ; replace CFA with huge / unexpected value
//    .cfi_undefined x30            ; LR "lost": IDA thinks return address is gone
//    .cfi_undefined x29            ; FP "lost": IDA frame-pointer chain broken
//    nop                           ; one real instruction → DWARF row emitted here
//    .cfi_restore_state            ; pop saved state → correct CFA restored
//
//  DWARF CFI table effect (what IDA reads from .eh_frame):
//    At PC(nop):  CFA = <fake>,  x30 = undefined → IDA sp-delta: UNKNOWN
//    At PC(next): CFA = <real>,  x30 = [CFA-8]   → runtime unwinder: correct
//
//  sp-delta consequence for IDA:
//    IDA's sp_delta tracker processes every CFI row in order.  When it
//    encounters CFA=x15+16 (a scratch register, unknown value) or
//    CFA=sp+524288 (enormous, contradicts observed prologue), it marks the
//    region — and often the whole function — as sp_delta UNKNOWN.  This
//    propagates: callers whose sp-delta is derived from the call site's
//    known sp may also be marked UNKNOWN.
//    Hex-Rays displays "stack analysis failed" and produces incorrect
//    decompiled code with wrong local-variable addresses.
//
//  RUNTIME SAFETY
//  ──────────────
//  .cfi_restore_state pops the saved CFI state.  In the DWARF table this
//  creates a new row at the NEXT instruction's PC, restoring the correct
//  CFA record.  The fake row covers only the single nop instruction (4 B).
//  The GNU/LLVM unwinder (libunwind / libgcc_s) uses DWARF rows keyed by
//  PC: at any real code PC the correct state is in effect.
//  The only runtime overhead is one extra nop (4 bytes) per injection point.
//
//  ORTHOGONALITY WITH SPOPass
//  ──────────────────────────
//  SPOPass injects "sub sp, sp, volatile_zero / add sp, sp, volatile_zero"
//  via inline asm.  This targets IDA's runtime-trace / pattern-match SP
//  analysis (the sp_delta tracker that follows SP modifications in code).
//  DwarfPoisonPass targets a completely different analysis path: the DWARF
//  table reader that IDA uses to check its code-derived sp_delta against the
//  declared CFI state.  Both attacks are active simultaneously when a
//  function carries both annotate("spo") and annotate("dpoison").
//
//  INJECTION POINTS
//  ────────────────
//  1. Entry block (after allocas):  2 injections — different patterns
//  2. Each non-entry BB (before terminator): 1 injection per BB
//  3. Before each ReturnInst: 1 extra injection (maximum noise at exit)
//     Note: if a non-entry BB ends with ret, it receives both a terminator
//     injection (step 2) and an exit injection (step 3) — two blocks total.
//
//  PATTERN VARIETY (6 patterns, keyed by FNV(fn_name) XOR seqNo)
//  ─────────────────────────────────────────────────────────────────
//   A) CFA=sp+524288,  LR+FP undefined — 0.5 MB fake stack, both critical regs lost
//   B) CFA=sp+131072,  LR undefined    — 128 KB fake stack, LR lost
//   C) CFA=x15+16,     FP undefined    — scratch reg as CFA base, FP lost
//   D) CFA=sp+65536,   LR+FP undefined — 64 KB fake stack, both lost
//   E) CFA=x16+0,      LR undefined    — linker scratch reg (ip0) as CFA, LR lost
//   F) CFA=sp+32767,   FP undefined    — near-max i16 offset, FP lost
//===----------------------------------------------------------------------===//

#include "ArmorComp/DwarfPoisonPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"

#include <string>
#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasDPoisonAnnotation(Function &F) {
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

        if (strData->getAsCString() == "dpoison") return true;
      }
    }
  }

check_config:
  return armorcomp::configSaysApply(F.getName(), "dpoison");
}

// ─────────────────────────────────────────────────────────────────────────────
// CFI poison patterns
// ─────────────────────────────────────────────────────────────────────────────

namespace {
struct PoisonPattern {
  const char *fakeCFA; ///< Argument to .cfi_def_cfa (e.g. "sp, 524288")
  bool killLR;         ///< Emit .cfi_undefined x30 (return address "lost")
  bool killFP;         ///< Emit .cfi_undefined x29 (frame pointer "lost")
};
} // namespace

// 6 patterns provide variety across injection points and functions.
// Patterns that claim CFA is in a scratch register (x15, x16) are especially
// effective: IDA cannot determine a numeric sp_delta when the CFA base is an
// unpredictable register whose value is unknown at analysis time.
static constexpr PoisonPattern Patterns[] = {
  {"sp, 524288",  true,  true},  // A: 0.5 MB fake stack, LR+FP "lost"
  {"sp, 131072",  true,  false}, // B: 128 KB fake stack, LR "lost"
  {"x15, 16",     false, true},  // C: scratch reg as CFA base, FP "lost"
  {"sp, 65536",   true,  true},  // D: 64 KB fake stack, LR+FP "lost"
  {"x16, 0",      true,  false}, // E: linker scratch (ip0) as CFA, LR "lost"
  {"sp, 32767",   false, true},  // F: near-max i16 offset, FP "lost"
};
static constexpr unsigned NumPatterns =
    sizeof(Patterns) / sizeof(Patterns[0]);

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the first non-AllocaInst instruction in BB.
static Instruction *firstNonAlloca(BasicBlock &BB) {
  for (Instruction &I : BB)
    if (!isa<AllocaInst>(&I))
      return &I;
  return BB.getTerminator();
}

/// FNV-1a 64-bit hash of a string — deterministic per-function seed.
static uint64_t fnvHash(StringRef S) {
  uint64_t h = 14695981039346656037ULL;
  for (char C : S) {
    h ^= (unsigned char)C;
    h *= 1099511628211ULL;
  }
  return h;
}

/// Build the CFI-poison asm string for the given pattern index.
/// Output:
///   .cfi_remember_state
///   .cfi_def_cfa <fakeCFA>
///   [.cfi_undefined x30]
///   [.cfi_undefined x29]
///   nop
///   .cfi_restore_state
static std::string buildPoisonAsm(unsigned patIdx) {
  const PoisonPattern &P = Patterns[patIdx % NumPatterns];
  std::string S;
  S.reserve(128);
  S += ".cfi_remember_state\n\t";
  S += ".cfi_def_cfa ";
  S += P.fakeCFA;
  S += "\n\t";
  if (P.killLR) S += ".cfi_undefined x30\n\t";
  if (P.killFP) S += ".cfi_undefined x29\n\t";
  S += "nop\n\t";
  S += ".cfi_restore_state";
  return S;
}

// ─────────────────────────────────────────────────────────────────────────────
// DwarfPoisonPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses DwarfPoisonPass::run(Function &F,
                                       FunctionAnalysisManager & /*AM*/) {
  if (F.isDeclaration()) return PreservedAnalyses::all();

  // AArch64 only — CFI register names (x15, x16, x29, x30) are AArch64-specific
  Module *M = F.getParent();
  Triple T(M->getTargetTriple());
  if (!T.isAArch64()) return PreservedAnalyses::all();

  // Never instrument ArmorComp's own injected functions
  if (F.getName().startswith("__armorcomp_")) return PreservedAnalyses::all();

  bool shouldObf = !annotateOnly
                   || hasDPoisonAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "dpoison");
  if (!shouldObf) return PreservedAnalyses::all();

  LLVMContext &Ctx       = F.getContext();
  Type *VoidTy           = Type::getVoidTy(Ctx);
  FunctionType *PoisonTy = FunctionType::get(VoidTy, {}, /*isVarArg=*/false);

  // Per-function seed — ensures pattern variety differs across functions.
  // Mixed with a per-injection sequence number via LCG-style step.
  const uint64_t seed = fnvHash(F.getName());

  unsigned injCount = 0;

  // Inject one CFI-poison block at the given builder position.
  // seqNo is mixed with seed to select the pattern.
  auto inject = [&](IRBuilder<> &B, unsigned seqNo) {
    // LCG mix: seed XOR (seqNo * Knuth_multiplier + addend) → pattern index
    uint64_t mix = seed
                   ^ ((uint64_t)seqNo * 6364136223846793005ULL
                      + 1442695040888963407ULL);
    unsigned patIdx = (unsigned)(mix % NumPatterns);
    std::string asmStr = buildPoisonAsm(patIdx);
    InlineAsm *IA = InlineAsm::get(PoisonTy, asmStr,
                                   /*constraints=*/"",
                                   /*hasSideEffects=*/true);
    B.CreateCall(PoisonTy, IA, {});
    ++injCount;
  };

  // ── 1. Entry block — 2 injections after allocas ───────────────────────────
  // Placed after allocas so they appear in the function's prologue region.
  // IDA reads CFI rows top-to-bottom; two conflicting rows early on establish
  // doubt about the frame size throughout the function.
  BasicBlock &Entry = F.getEntryBlock();
  {
    IRBuilder<> B(firstNonAlloca(Entry));
    inject(B, 0);
    inject(B, 1);
  }

  // ── 2. Non-entry BBs — 1 injection before each terminator ────────────────
  // Snapshot terminators first (safe: we only insert, never remove BBs).
  // Skip terminators whose immediately-preceding instruction is a musttail
  // call — inserting anything between a musttail call and its ret violates
  // LLVM's musttail invariant and causes the AArch64 backend to crash
  // ("failed to perform tail call elimination on a call site marked musttail").
  // VMP-generated shim functions always have this pattern.
  std::vector<Instruction *> terms;
  for (BasicBlock &BB : F)
    if (&BB != &Entry) {
      Instruction *T = BB.getTerminator();
      Instruction *P = T->getPrevNode();
      bool hasMustTailPred = P && isa<CallInst>(P) &&
                             cast<CallInst>(P)->isMustTailCall();
      if (!hasMustTailPred)
        terms.push_back(T);
    }

  for (unsigned i = 0; i < terms.size(); ++i) {
    IRBuilder<> B(terms[i]);
    inject(B, 2 + i);
  }

  // ── 3. Before each ReturnInst — 1 extra injection ────────────────────────
  // An extra row immediately before ret is the last thing IDA's sp_delta
  // tracker sees before "function exits" — injecting here maximises the
  // probability that IDA marks the exit frame as UNKNOWN.
  //
  // Note: rets in non-entry BBs already received a step-2 injection above;
  // this step adds a second injection right before the ret instruction,
  // increasing noise density at function exits.
  //
  // Same musttail guard: skip ret whose predecessor is a musttail call.
  std::vector<ReturnInst *> rets;
  for (BasicBlock &BB : F)
    if (auto *R = dyn_cast<ReturnInst>(BB.getTerminator())) {
      Instruction *P = R->getPrevNode();
      bool hasMustTailPred = P && isa<CallInst>(P) &&
                             cast<CallInst>(P)->isMustTailCall();
      if (!hasMustTailPred)
        rets.push_back(R);
    }

  for (unsigned i = 0; i < rets.size(); ++i) {
    IRBuilder<> B(rets[i]);
    inject(B, 100 + i);
  }

  errs() << "[ArmorComp][DPOISON] obfuscated: " << F.getName()
         << " (" << injCount << " CFI poison injection(s), "
         << rets.size() << " ret(s))\n";

  return PreservedAnalyses::none();
}
