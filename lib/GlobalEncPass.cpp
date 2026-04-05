//===----------------------------------------------------------------------===//
// ArmorComp — GlobalEncPass (Integer Global Variable Encryption)
//
// Strategy: module constructor decryption
// ────────────────────────────────────────
//  1. Identify all integer globals (i8/i16/i32/i64) that are used by
//     functions annotated with annotate("genc") (or all eligible globals
//     when annotateOnly=false).
//  2. XOR-encrypt each integer GV initializer: newInit = original ^ K
//     where K = xorshift64(FNV1a(gv->getName())) truncated to the GV's width.
//  3. Mark each encrypted GV as setConstant(false) so the optimizer cannot
//     constant-fold loads from it.
//  4. Generate a single module constructor __armorcomp_genc_init that:
//       for each encrypted GV:
//         ct = load volatile iN, ptr @gv
//         pt = xor iN ct, K
//         store iN pt, ptr @gv
//     and register it via appendToGlobalCtors (runs before main).
//
// Binary result:
//   - Integer GVs land in .data (writable) instead of .rodata (read-only).
//   - Static-analysis tools see only ciphertext values, not the real constants.
//   - IDA/Ghidra display wrong initializer values; analyst must trace the ctor.
//   - The ctor itself only shows XOR constants (keys), not the plaintext values.
//
// Key derivation (per GV, deterministic):
//   state = FNV-1a hash of the GV name string
//   K64   = xorshift64(state)
//   K     = K64 & mask_for_type_width    (truncated to i8/i16/i32/i64 width)
//===----------------------------------------------------------------------===//

#include "ArmorComp/GlobalEncPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"  // appendToGlobalCtors

#include <set>
#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Key derivation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// FNV-1a 64-bit hash of a string.
static uint64_t genchash(StringRef S) {
  uint64_t h = 14695981039346656037ULL;
  for (unsigned char c : S) {
    h ^= c;
    h *= 1099511628211ULL;
  }
  return h;
}

/// xorshift64 PRNG step; modifies state in-place and returns next value.
static uint64_t xorshift64(uint64_t &state) {
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return state;
}

/// Derive a per-GV key for the given integer bit width (8/16/32/64).
static uint64_t deriveKey(StringRef Name, unsigned BitWidth) {
  uint64_t state = genchash(Name);
  uint64_t k = xorshift64(state);
  // Truncate to the type's bit width; ensure non-zero so ciphertext != original
  uint64_t mask = (BitWidth < 64) ? ((1ULL << BitWidth) - 1) : ~0ULL;
  k &= mask;
  if (k == 0) k = 1;   // degenerate-case guard (XOR with 0 is a no-op)
  return k;
}

// ─────────────────────────────────────────────────────────────────────────────
// Eligibility check for a GlobalVariable
// ─────────────────────────────────────────────────────────────────────────────

static bool isEligibleGlobal(const GlobalVariable &GV) {
  // Must be defined in this module (not a declaration)
  if (GV.isDeclaration()) return false;

  // Must have a ConstantInt initializer
  auto *CI = dyn_cast_or_null<ConstantInt>(GV.getInitializer());
  if (!CI) return false;

  // Non-zero: XOR with zero is a no-op and the GV already appears encrypted
  if (CI->isZero()) return false;

  // Integer type in {i8, i16, i32, i64} — skip wider types (rare, edge-case)
  unsigned bw = CI->getType()->getBitWidth();
  if (bw != 8 && bw != 16 && bw != 32 && bw != 64) return false;

  // Skip LLVM-internal and ArmorComp-internal globals
  StringRef name = GV.getName();
  if (name.starts_with("llvm.")) return false;
  if (name.starts_with("__armorcomp_")) return false;

  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Collect annotated functions (annotation mode) or all functions (all mode)
// ─────────────────────────────────────────────────────────────────────────────

static void collectAnnotatedFunctions(Module &M, bool annotateOnly,
                                      std::set<Function *> &result) {
  if (!annotateOnly) {
    for (auto &F : M)
      if (!F.isDeclaration()) result.insert(&F);
    return;
  }

  GlobalVariable *annGV = M.getGlobalVariable("llvm.global.annotations");
  if (!annGV || !annGV->hasInitializer()) goto check_config;

  {
    auto *arr = dyn_cast<ConstantArray>(annGV->getInitializer());
    if (arr) {
      for (unsigned i = 0, e = arr->getNumOperands(); i < e; ++i) {
        auto *cs = dyn_cast<ConstantStruct>(arr->getOperand(i));
        if (!cs || cs->getNumOperands() < 2) continue;

        auto *fn = dyn_cast<Function>(cs->getOperand(0)->stripPointerCasts());
        if (!fn) continue;

        auto *strGV =
            dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
        if (!strGV || !strGV->hasInitializer()) continue;

        auto *strData = dyn_cast<ConstantDataArray>(strGV->getInitializer());
        if (!strData) continue;

        if (strData->getAsCString() == "genc")
          result.insert(fn);
      }
    }
  }

check_config:
  // Config-file based selection
  for (auto &F : M) {
    if (F.isDeclaration()) continue;
    if (armorcomp::configSaysApply(F.getName(), "genc"))
      result.insert(&F);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Find integer GVs referenced by a function (as direct operands of instructions)
// ─────────────────────────────────────────────────────────────────────────────

static void findIntegerGlobals(Function &F,
                                std::set<GlobalVariable *> &out) {
  for (auto &BB : F) {
    for (auto &I : BB) {
      for (Use &U : I.operands()) {
        Value *V = U.get()->stripPointerCasts();
        auto *GV = dyn_cast<GlobalVariable>(V);
        if (GV && isEligibleGlobal(*GV))
          out.insert(GV);
      }
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Build __armorcomp_genc_init: XOR-decrypt each encrypted GV at startup
// ─────────────────────────────────────────────────────────────────────────────

struct GencEntry {
  GlobalVariable *GV;
  uint64_t        Key;
};

static void buildDecryptorCtor(Module &M,
                               const std::vector<GencEntry> &entries) {
  LLVMContext &Ctx = M.getContext();
  Type *VoidTy     = Type::getVoidTy(Ctx);

  FunctionType *FTy = FunctionType::get(VoidTy, /*isVarArg=*/false);
  Function     *CtorFn = Function::Create(
      FTy, GlobalValue::InternalLinkage, "__armorcomp_genc_init", M);

  // NoInline + OptimizeNone: keep the ctor intact so analysts see only
  // the XOR key, not an inlined compute of the plaintext.
  CtorFn->addFnAttr(Attribute::NoInline);
  CtorFn->addFnAttr(Attribute::OptimizeNone);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", CtorFn);
  IRBuilder<> IRB(Entry);

  for (const auto &e : entries) {
    IntegerType *ITy = cast<IntegerType>(
        cast<ConstantInt>(e.GV->getInitializer())->getType());

    // ct = load volatile iN, ptr @gv
    LoadInst *ct = IRB.CreateLoad(ITy, e.GV, "gc.ct");
    ct->setVolatile(true);

    // pt = xor iN ct, K
    Value *key = ConstantInt::get(ITy, e.Key);
    Value *pt  = IRB.CreateXor(ct, key, "gc.pt");

    // store iN pt, ptr @gv
    IRB.CreateStore(pt, e.GV);
  }

  IRB.CreateRetVoid();

  // Priority 0 = runs very early, before most ctors.
  appendToGlobalCtors(M, CtorFn, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Main encryption pass over the module
// ─────────────────────────────────────────────────────────────────────────────

static bool encryptGlobals(Module &M, bool annotateOnly) {
  // ── Step 1: find functions whose globals we should encrypt ──────────────
  std::set<Function *> annotated;
  collectAnnotatedFunctions(M, annotateOnly, annotated);
  if (annotated.empty()) return false;

  // ── Step 2: collect eligible integer globals used by annotated fns ──────
  std::set<GlobalVariable *> candidates;

  if (annotateOnly) {
    for (auto *F : annotated)
      findIntegerGlobals(*F, candidates);
  } else {
    // All-mode: every eligible GV in the module
    for (auto &GV : M.globals())
      if (isEligibleGlobal(GV))
        candidates.insert(&GV);
  }

  if (candidates.empty()) return false;

  // ── Step 3: encrypt each GV initializer ─────────────────────────────────
  std::vector<GencEntry> entries;
  entries.reserve(candidates.size());

  for (auto *GV : candidates) {
    auto *CI = cast<ConstantInt>(GV->getInitializer());
    unsigned bw  = CI->getType()->getBitWidth();
    uint64_t orig = CI->getZExtValue();
    uint64_t key  = deriveKey(GV->getName(), bw);
    uint64_t ct   = orig ^ key;

    // Replace initializer with ciphertext
    GV->setInitializer(ConstantInt::get(CI->getType(), ct));

    // Allow the symbol to live in writable .data (required for ctor store)
    GV->setConstant(false);

    entries.push_back({GV, key});
    errs() << "[ArmorComp][GENC] encrypted: " << GV->getName()
           << "  (i" << bw << ", key=0x" << llvm::Twine::utohexstr(key)
           << ")\n";
  }

  // ── Step 4: inject the decryptor constructor ─────────────────────────────
  buildDecryptorCtor(M, entries);
  errs() << "[ArmorComp][GENC] injected constructor: __armorcomp_genc_init ("
         << entries.size() << " global(s))\n";

  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// GlobalEncPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses GlobalEncPass::run(Module &M, ModuleAnalysisManager & /*AM*/) {
  if (!encryptGlobals(M, annotateOnly))
    return PreservedAnalyses::all();

  return PreservedAnalyses::none();
}
