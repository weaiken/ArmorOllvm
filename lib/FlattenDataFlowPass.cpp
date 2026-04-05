//===----------------------------------------------------------------------===//
// ArmorComp — FlattenDataFlowPass implementation
//
// Merges all statically-sized alloca instructions in a function's entry block
// into a single byte pool: alloca [N x i8].
//
// Each original alloca at byte offset O is replaced by a GEP with an
// obfuscated index that evaluates to O at runtime but is opaque to static
// analysis:
//
//   pool  = alloca [total_bytes x i8]                  ; merged pool
//   z     = load volatile i64 @__armorcomp_df_zero      ; = 0 always
//   idx   = xor i64 (O ^ KEY), (or i64 z, KEY)          ; = O always
//   ptr   = gep i8, ptr pool, i64 idx                   ; = pool + O
//
// The KEY is derived from xorshift64(hash(function_name)).
//
// Alignment is preserved: each offset is rounded up to the alloca's alignment
// requirement before assigning.  The pool alloca itself is aligned to the
// maximum alignment required by any merged alloca.
//
// LLVM 17 opaque pointers: all alloca results have type 'ptr', so no bitcast
// is needed after the GEP — replaceAllUsesWith is type-compatible.
//===----------------------------------------------------------------------===//

#include "ArmorComp/FlattenDataFlowPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/raw_ostream.h"

#include <string>
#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasDFAnnotation(Function &F) {
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
    if (StrData && StrData->getAsCString() == "df") return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// Volatile zero global — prevents the optimizer from folding the index
// computation at compile time.
static GlobalVariable *getOrCreateDFZero(Module &M) {
  const char *Name = "__armorcomp_df_zero";
  if (auto *G = M.getGlobalVariable(Name)) return G;
  auto *GV = new GlobalVariable(
      M, Type::getInt64Ty(M.getContext()),
      /*isConstant=*/false, GlobalValue::WeakAnyLinkage,
      ConstantInt::get(Type::getInt64Ty(M.getContext()), 0), Name);
  GV->setVisibility(GlobalValue::DefaultVisibility);
  return GV;
}

// FNV-1a hash — same approach used in ConstObfPass for deterministic keys.
static uint64_t dfhash(StringRef S) {
  uint64_t h = 14695981039346656037ULL;
  for (char c : S) {
    h ^= (uint8_t)c;
    h *= 1099511628211ULL;
  }
  return h;
}

static void xorshift64(uint64_t &s) {
  s ^= s << 13;
  s ^= s >> 7;
  s ^= s << 17;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main transformation
// ─────────────────────────────────────────────────────────────────────────────

static bool flattenDataFlow(Function &F) {
  if (F.isDeclaration()) return false;
  if (F.isVarArg()) return false;  // vararg ABI is too complex to merge safely

  // Never transform our own injected helpers.
  if (F.getName().startswith("__armorcomp_")) return false;

  const DataLayout &DL = F.getParent()->getDataLayout();
  BasicBlock &entry = F.getEntryBlock();

  // ── Phase 1: Collect eligible allocas ─────────────────────────────────────
  // Only allocas with a statically-known size can be merged into the pool.
  // Dynamic allocas (VLAs) are kept as-is.
  std::vector<AllocaInst *> allocas;
  for (auto &I : entry) {
    auto *AI = dyn_cast<AllocaInst>(&I);
    if (!AI) continue;
    if (!isa<ConstantInt>(AI->getArraySize())) continue;
    allocas.push_back(AI);
  }

  if (allocas.size() < 2) return false;  // nothing useful to merge

  // ── Phase 2: Compute per-alloca byte offsets (respecting alignment) ────────
  uint64_t maxAlign  = 1;
  uint64_t totalBytes = 0;
  std::vector<uint64_t> offsets;

  for (auto *AI : allocas) {
    Type    *Ty    = AI->getAllocatedType();
    uint64_t align = AI->getAlign().value();

    if (align > maxAlign) maxAlign = align;

    // Align current offset up to this alloca's requirement.
    totalBytes = (totalBytes + align - 1) & ~(align - 1);
    offsets.push_back(totalBytes);

    uint64_t sz = DL.getTypeAllocSize(Ty) *
                  cast<ConstantInt>(AI->getArraySize())->getZExtValue();
    totalBytes += sz;
  }
  // Pad total to max alignment so the pool can be safely reused at any offset.
  totalBytes = (totalBytes + maxAlign - 1) & ~(maxAlign - 1);

  // ── Phase 3: Build obfuscation key ────────────────────────────────────────
  // Key is deterministic per function name; different functions get different
  // keys, making cross-function pool analysis harder.
  uint64_t seed = dfhash(F.getName());
  xorshift64(seed);
  const uint64_t KEY = seed;

  // ── Phase 4: Insert pool alloca and obfuscated GEPs ───────────────────────
  // Position at the first-insertion-pt (after all original allocas).
  // Each new instruction is inserted there (in order) via IRBuilder.
  LLVMContext &Ctx  = F.getContext();  (void)Ctx;
  IRBuilder<>  B(&entry, entry.getFirstInsertionPt());
  Type *i8ty  = B.getInt8Ty();
  Type *i64ty = B.getInt64Ty();

  // Single merged pool — aligned to max requirement of any merged alloca.
  auto *poolTy = ArrayType::get(i8ty, totalBytes);
  auto *pool   = B.CreateAlloca(poolTy, nullptr, "armorcomp.df.pool");
  pool->setAlignment(Align(maxAlign));

  // Volatile zero global (shared across all transformed functions in the TU).
  GlobalVariable *DFZero = getOrCreateDFZero(*F.getParent());

  for (size_t i = 0; i < allocas.size(); ++i) {
    AllocaInst *AI = allocas[i];
    uint64_t    O  = offsets[i];

    // Obfuscated index:
    //   z      = load volatile i64 @__armorcomp_df_zero    ; = 0 at runtime
    //   masked = or  i64 z, KEY                            ; = KEY (z is 0)
    //   idx    = xor i64 (O ^ KEY), masked                 ; = (O^K) ^ K = O
    // The optimizer cannot fold this because z comes from a volatile load.
    Value *z = B.CreateLoad(i64ty, DFZero, /*isVolatile=*/true,
                            "df.z" + std::to_string(i));
    Value *masked = B.CreateOr(z, ConstantInt::get(i64ty, KEY),
                               "df.m" + std::to_string(i));
    Value *idx = B.CreateXor(ConstantInt::get(i64ty, O ^ KEY), masked,
                             "df.i" + std::to_string(i));

    // GEP: treat pool as flat [totalBytes x i8] and advance by idx bytes.
    // In LLVM 17 opaque pointers, pool is 'ptr' and GEP returns 'ptr'.
    // No bitcast is needed — AI->getType() is also 'ptr'.
    Value *ptr = B.CreateGEP(i8ty, pool, idx,
                             "df.p" + std::to_string(i));

    AI->replaceAllUsesWith(ptr);
  }

  // ── Phase 5: Erase original allocas ───────────────────────────────────────
  // All uses have been replaced; the allocas are now unreachable and safe to
  // remove.  Erasing in reverse order avoids iterator invalidation issues.
  for (int i = (int)allocas.size() - 1; i >= 0; --i)
    allocas[i]->eraseFromParent();

  errs() << "[ArmorComp][DF] flattened: " << F.getName()
         << " (" << allocas.size() << " alloca(s), "
         << totalBytes << " bytes)\n";
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// FlattenDataFlowPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses FlattenDataFlowPass::run(Function &F,
                                           FunctionAnalysisManager & /*AM*/) {
  if (F.isDeclaration()) return PreservedAnalyses::all();

  bool shouldObf = !annotateOnly
                   || hasDFAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "df");
  if (!shouldObf) return PreservedAnalyses::all();

  bool changed = flattenDataFlow(F);
  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
