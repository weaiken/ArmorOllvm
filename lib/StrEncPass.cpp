//===----------------------------------------------------------------------===//
// ArmorComp — StrEncPass (String Encryption)
//
// Strategy: module constructor decryption
// ────────────────────────────────────────
//  1. Identify all string GlobalVariables (ConstantDataArray of i8) that are
//     exclusively referenced by annotated functions.
//  2. XOR-encrypt each string in-place in the IR (modifies the GV initializer).
//  3. Mark each encrypted GV as non-constant (so optimizer can't fold loads).
//  4. Generate a single module constructor  __armorcomp_str_init  that:
//       for each encrypted GV:
//         for each byte: *ptr = *ptr ^ key[i % 4]
//     and register it via @llvm.global_ctors (runs before main).
//
// Binary result:
//   - String GVs land in .data (writable) instead of .rodata (read-only).
//   - The binary contains only ciphertext; "strings" / Ghidra find nothing.
//   - At runtime the ctor decrypts them in-place before any code runs.
//
// Key derivation:
//   - 4-byte key per GV, derived from hash(GV.name) for determinism.
//   - All key bytes are in range [1, 255] (never zero) to avoid creating
//     apparent null terminators in the encrypted data.
//===----------------------------------------------------------------------===//

#include "ArmorComp/ObfuscationConfig.h"
#include "ArmorComp/StrEncPass.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"  // appendToGlobalCtors

#include <array>
#include <random>
#include <set>
#include <unordered_map>
#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection (module-level: returns the set of annotated functions)
// ─────────────────────────────────────────────────────────────────────────────

static void collectAnnotatedFunctions(Module &M, bool annotateOnly,
                                      std::set<Function *> &result) {
  if (!annotateOnly) {
    for (auto &F : M)
      if (!F.isDeclaration()) result.insert(&F);
    return;
  }

  GlobalVariable *GV = M.getGlobalVariable("llvm.global.annotations");
  if (!GV || !GV->hasInitializer()) return;

  auto *arr = dyn_cast<ConstantArray>(GV->getInitializer());
  if (!arr) return;

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

    if (strData->getAsCString() == "strenc")
      result.insert(fn);
  }

  // Config-file based selection: also include functions the config says to
  // apply "strenc" to, even if they lack the annotation.
  for (auto &F : M) {
    if (F.isDeclaration()) continue;
    if (armorcomp::configSaysApply(F.getName(), "strenc"))
      result.insert(&F);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Find string GlobalVariables referenced by a function
// Matches: GEP into a [N x i8] global, or direct use of such a global.
// ─────────────────────────────────────────────────────────────────────────────

static void findStringGlobals(Function &F, std::set<GlobalVariable *> &out) {
  for (auto &BB : F) {
    for (auto &I : BB) {
      for (Use &U : I.operands()) {
        Value *V = U.get();

        // Unwrap ConstantExpr GEPs (the common pattern for C string literals)
        if (auto *ce = dyn_cast<ConstantExpr>(V)) {
          if (ce->getOpcode() == Instruction::GetElementPtr)
            V = ce->getOperand(0);
        }

        auto *gv = dyn_cast<GlobalVariable>(V);
        if (!gv || !gv->hasInitializer()) continue;

        auto *init = gv->getInitializer();
        auto *cda  = dyn_cast<ConstantDataArray>(init);
        if (!cda) continue;

        // Only i8 arrays (byte strings)
        if (!cda->getType()->getElementType()->isIntegerTy(8)) continue;

        out.insert(gv);
      }
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Encrypt a GV's initializer in-place, return the 4-byte key used
// ─────────────────────────────────────────────────────────────────────────────

static std::array<uint8_t, 4> encryptGlobal(GlobalVariable *GV) {
  auto *cda = cast<ConstantDataArray>(GV->getInitializer());
  unsigned len = cda->getNumElements();

  // Deterministic 4-byte key from GV name hash
  std::mt19937 rng(std::hash<std::string>{}(GV->getName().str()));
  std::uniform_int_distribution<unsigned> dist(1, 255);  // never zero
  std::array<uint8_t, 4> key;
  for (auto &k : key) k = (uint8_t)dist(rng);

  // Build encrypted byte array
  SmallVector<uint8_t, 256> enc(len);
  for (unsigned i = 0; i < len; ++i) {
    uint8_t orig = (uint8_t)cda->getElementAsInteger(i);
    enc[i] = orig ^ key[i % 4];
  }

  // Replace initializer with encrypted version
  LLVMContext &Ctx = GV->getContext();
  Constant *newInit = ConstantDataArray::get(
      Ctx, ArrayRef<uint8_t>(enc.data(), len));
  GV->setInitializer(newInit);

  // Make non-constant so the optimizer cannot fold loads from this global.
  // This moves the GV from .rodata to .data (writable section) in the ELF.
  GV->setConstant(false);

  return key;
}

// ─────────────────────────────────────────────────────────────────────────────
// Build __armorcomp_str_init: the module constructor that decrypts all
// encrypted string GVs at program startup (before main).
// ─────────────────────────────────────────────────────────────────────────────

static void buildDecryptorCtor(
    Module &M,
    const std::unordered_map<GlobalVariable *, std::array<uint8_t, 4>> &keyMap)
{
  LLVMContext &Ctx = M.getContext();
  Type *I8Ty  = Type::getInt8Ty(Ctx);
  Type *VoidTy = Type::getVoidTy(Ctx);

  // Create the constructor function
  FunctionType *FTy = FunctionType::get(VoidTy, /*isVarArg=*/false);
  Function *CtorFn  = Function::Create(
      FTy, GlobalValue::InternalLinkage, "__armorcomp_str_init", M);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", CtorFn);
  IRBuilder<> IRB(Entry);

  // For each encrypted GV, emit a fully-unrolled XOR decryption loop.
  // "Unrolled" avoids creating new basic blocks (which would complicate
  // subsequent CFF if the ctor is ever obfuscated).
  for (auto &[GV, key] : keyMap) {
    auto *cda = cast<ConstantDataArray>(GV->getInitializer());
    unsigned len = cda->getNumElements();
    ArrayType *AT = ArrayType::get(I8Ty, len);

    for (unsigned i = 0; i < len; ++i) {
      // ptr = &GV[i]
      Value *ptr = IRB.CreateConstGEP2_64(AT, GV, 0, i, "se.ptr");
      // encrypted = *ptr
      Value *enc = IRB.CreateLoad(I8Ty, ptr, "se.enc");
      // decrypted = encrypted ^ key[i % 4]
      Value *dec = IRB.CreateXor(
          enc, ConstantInt::get(I8Ty, key[i % 4]), "se.dec");
      // *ptr = decrypted
      IRB.CreateStore(dec, ptr);
    }
  }

  IRB.CreateRetVoid();

  // Register as module constructor.
  // Priority 65535 = highest priority = this runs FIRST among all ctors.
  // LLVM's appendToGlobalCtors handles @llvm.global_ctors correctly.
  appendToGlobalCtors(M, CtorFn, 65535);

  errs() << "[ArmorComp][STRENC] injected constructor: __armorcomp_str_init\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// StrEncPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses StrEncPass::run(Module &M, ModuleAnalysisManager & /*AM*/) {
  // Step 1: find annotated functions
  std::set<Function *> annotated;
  collectAnnotatedFunctions(M, annotateOnly, annotated);
  if (annotated.empty()) return PreservedAnalyses::all();

  // Step 2: find string globals used by annotated functions
  std::set<GlobalVariable *> candidates;
  for (auto *F : annotated)
    findStringGlobals(*F, candidates);

  if (candidates.empty()) return PreservedAnalyses::all();

  // Step 3: remove globals also referenced by non-annotated functions
  // (encrypting a shared string would break callers we don't control)
  for (auto &F : M) {
    if (annotated.count(&F)) continue;  // annotated: already included
    std::set<GlobalVariable *> refs;
    findStringGlobals(F, refs);
    for (auto *gv : refs)
      candidates.erase(gv);
  }

  // Also skip annotation-related strings themselves (GVs whose name starts
  // with ".str" used only by llvm.global.annotations infrastructure).
  // We detect this by checking if the GV is an operand of global.annotations.
  {
    GlobalVariable *annGV = M.getGlobalVariable("llvm.global.annotations");
    if (annGV && annGV->hasInitializer()) {
      // All GVs directly reachable from llvm.global.annotations should be
      // preserved — they are annotation strings like "strenc", "cff", etc.
      std::set<GlobalVariable *> annStrings;
      auto collectAnnotationStrings = [&](Constant *C, auto &self) -> void {
        if (auto *gv = dyn_cast<GlobalVariable>(C)) {
          annStrings.insert(gv);
          return;
        }
        for (unsigned i = 0; i < C->getNumOperands(); ++i)
          if (auto *operC = dyn_cast<Constant>(C->getOperand(i)))
            self(operC, self);
      };
      collectAnnotationStrings(annGV->getInitializer(),
                               collectAnnotationStrings);
      for (auto *gv : annStrings)
        candidates.erase(gv);
    }
  }

  if (candidates.empty()) return PreservedAnalyses::all();

  // Step 4: encrypt each candidate and record the key
  std::unordered_map<GlobalVariable *, std::array<uint8_t, 4>> keyMap;
  for (auto *GV : candidates) {
    keyMap[GV] = encryptGlobal(GV);
    errs() << "[ArmorComp][STRENC] encrypted: " << GV->getName() << "\n";
  }

  // Step 5: inject the module constructor that decrypts at startup
  buildDecryptorCtor(M, keyMap);

  return PreservedAnalyses::none();
}
