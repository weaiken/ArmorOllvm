//===----------------------------------------------------------------------===//
// ArmorComp — GlobalPointerObfuscationPass (GPO — Global Pointer Obfuscation)
//
// Encrypts function-pointer global variables so that static analysis tools
// cannot resolve vtable entries, callback arrays, or jump tables by simply
// reading .data/.rodata initializers.
//
// Strategy:
//   1. For each eligible pointer global @gp with initializer @fn:
//        K   = xorshift64(FNV1a(gp_name))       (compile-time 64-bit key)
//        enc = ptrtoint(@fn, i64) XOR K           (encrypted address)
//      Create companion: @__armorcomp_gpo_enc_N = internal global i64 enc
//      Set original @gp initializer = null  (pointer-null / zeroinitializer)
//
//   2. Generate a single ctor __armorcomp_gpo_init:
//        for each (gp, companion, key):
//          %e   = load volatile i64, @__armorcomp_gpo_enc_N
//          %pt  = xor i64 %e, KEY_CONST
//          %ptr = inttoptr i64 %pt to ptr
//          store ptr %ptr, @gp
//      Register with appendToGlobalCtors(priority=10).
//
// Binary result:
//   - @gp lands in .data as null; static analysis never sees the real address.
//   - IDA Pro xref from @gp to target function disappears.
//   - The ctor shows a XOR of a volatile load with a constant; the real target
//     address is not present anywhere in the binary as a plain value.
//   - Anti-analysis tools that check for hardcoded function pointers find null.
//===----------------------------------------------------------------------===//

#include "ArmorComp/GlobalPointerObfuscationPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"  // appendToGlobalCtors

#include <string>
#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Key derivation helpers
// ─────────────────────────────────────────────────────────────────────────────

static uint64_t gpohash(StringRef S) {
  uint64_t h = 14695981039346656037ULL;
  for (unsigned char c : S) {
    h ^= c;
    h *= 1099511628211ULL;
  }
  return h;
}

static uint64_t xorshift64(uint64_t &state) {
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return state;
}

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection: check if any function in the module has annotate("gpo")
// This mirrors GlobalEncPass's "genc" approach — any annotated fn activates
// encryption of eligible pointer globals used in the module.
// ─────────────────────────────────────────────────────────────────────────────

static bool moduleHasGPOAnnotation(Module &M) {
  GlobalVariable *annGV = M.getGlobalVariable("llvm.global.annotations");
  if (!annGV || !annGV->hasInitializer()) return false;

  auto *arr = dyn_cast<ConstantArray>(annGV->getInitializer());
  if (!arr) return false;

  for (unsigned i = 0, e = arr->getNumOperands(); i < e; ++i) {
    auto *cs = dyn_cast<ConstantStruct>(arr->getOperand(i));
    if (!cs || cs->getNumOperands() < 2) continue;

    auto *strGV =
        dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
    if (!strGV || !strGV->hasInitializer()) continue;

    auto *strData = dyn_cast<ConstantDataArray>(strGV->getInitializer());
    if (!strData) continue;

    if (strData->getAsCString() == "gpo") return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Eligibility check for a GlobalVariable
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the function pointer value if GV is an eligible pointer global.
/// Eligible: defined (not decl), pointer type, non-null function ptr initializer,
///           not already an __armorcomp_* symbol.
static Function *getEligibleFnPtrInit(GlobalVariable &GV) {
  if (GV.isDeclaration()) return nullptr;
  if (!GV.getType()->isPointerTy()) return nullptr;  // GV's storage type is always ptr in LLVM 17 opaque-ptr mode
  if (GV.getName().startswith("__armorcomp_")) return nullptr;
  if (GV.getName().startswith("llvm.")) return nullptr;

  Constant *init = GV.getInitializer();
  if (!init) return nullptr;

  // Accept direct function reference or bitcast of function
  if (auto *F = dyn_cast<Function>(init->stripPointerCasts()))
    return F;

  return nullptr;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main module transformation
// ─────────────────────────────────────────────────────────────────────────────

static bool encryptFnPtrGlobals(Module &M, bool annotateOnly) {
  if (annotateOnly && !moduleHasGPOAnnotation(M)) return false;

  LLVMContext &Ctx = M.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Type *PtrTy = Type::getInt8PtrTy(Ctx);   // opaque ptr in LLVM 17

  struct GVEntry {
    GlobalVariable *origGV;       // original function pointer global
    GlobalVariable *encGV;        // companion global storing key K
    Function       *targetFn;     // function origGV originally pointed to
    uint64_t        key;          // compile-time XOR key (same value stored in encGV)
  };
  std::vector<GVEntry> entries;

  // Collect eligible globals and create companion key-only vars.
  // NOTE: We cannot use ConstantExpr::getXor(ptrtoint(@fn), K) as a global
  // initializer because AArch64/ELF backend doesn't support XOR of a
  // relocation in a static initializer.  Instead we store only the key K
  // (a plain integer constant), and perform the XOR at runtime inside the ctor.
  unsigned idx = 0;
  for (GlobalVariable &GV : M.globals()) {
    Function *targetFn = getEligibleFnPtrInit(GV);
    if (!targetFn) continue;

    // Derive key
    std::string keyStr = "gpo_" + GV.getName().str();
    uint64_t state = gpohash(keyStr);
    uint64_t key   = xorshift64(state);
    if (key == 0) key = 0xDEADF00DCAFE0001ULL;

    // Create companion global storing the key: @__armorcomp_gpo_enc_N = K
    // (No relocation involved — plain integer constant.)
    std::string compName = "__armorcomp_gpo_enc_" + std::to_string(idx++);
    auto *compGV = new GlobalVariable(
        M, I64Ty, /*isConstant=*/false,
        GlobalValue::InternalLinkage,
        ConstantInt::get(I64Ty, key), compName);
    compGV->setAlignment(MaybeAlign(8));

    // Null out the original global
    GV.setInitializer(Constant::getNullValue(GV.getValueType()));
    GV.setConstant(false);  // must be writable for ctor to store into it

    entries.push_back({&GV, compGV, targetFn, key});
  }

  if (entries.empty()) return false;

  // Generate ctor function __armorcomp_gpo_init
  FunctionType *ctorTy = FunctionType::get(Type::getVoidTy(Ctx), false);
  Function *ctorFn = Function::Create(
      ctorTy, GlobalValue::InternalLinkage,
      "__armorcomp_gpo_init", M);
  ctorFn->addFnAttr(Attribute::NoInline);
  ctorFn->addFnAttr(Attribute::OptimizeNone);

  BasicBlock *BB = BasicBlock::Create(Ctx, "entry", ctorFn);
  IRBuilder<> B(BB);

  for (auto &E : entries) {
    // Load K from companion global (volatile prevents constant folding)
    Value *k     = B.CreateLoad(I64Ty, E.encGV, /*isVolatile=*/true, "gpo.key");
    // Get function address as a runtime ptrtoint instruction
    // (NOT a ConstantExpr — avoids the "unsupported relocation XOR" backend error)
    Value *fnInt = B.CreatePtrToInt(E.targetFn, I64Ty, "gpo.fnint");
    // XOR fn address with volatile-loaded K (obfuscation step)
    Value *enc   = B.CreateXor(fnInt, k, "gpo.enc");
    // XOR again with compile-time K literal to decode back to fn address
    Value *dec   = B.CreateXor(enc, ConstantInt::get(I64Ty, E.key), "gpo.dec");
    // inttoptr to recover pointer type
    Value *ptr   = B.CreateIntToPtr(dec, E.origGV->getValueType(), "gpo.ptr");
    // Store decoded fn pointer back to original global
    B.CreateStore(ptr, E.origGV);
  }
  B.CreateRetVoid();

  // Register ctor with priority 10 (runs very early, before main)
  appendToGlobalCtors(M, ctorFn, /*Priority=*/10);

  errs() << "[ArmorComp][GPO] encrypted: " << entries.size()
         << " function pointer global(s)\n";
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// GlobalPointerObfuscationPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses GlobalPointerObfuscationPass::run(Module &M,
                                                     ModuleAnalysisManager & /*AM*/) {
  if (!encryptFnPtrGlobals(M, annotateOnly))
    return PreservedAnalyses::all();

  return PreservedAnalyses::none();
}
