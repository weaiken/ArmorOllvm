//===----------------------------------------------------------------------===//
// ArmorComp — ReturnValueObfPass (Return Value Obfuscation)
//
// Strategy: XOR every integer/pointer return value with a volatile-loaded
// zero immediately before each ReturnInst.  Runtime behavior is unchanged
// (x ^ 0 == x), but IDA Hex-Rays cannot prove the XOR operand is zero and
// therefore cannot recover the function's return type or value statically.
//
// INJECTION PATTERN
// ─────────────────
// For integer-returning functions (i8/i16/i32/i64):
//
//   rvo.zero = load volatile iN, @__armorcomp_rvo_zero   ; = 0 at runtime
//   rvo.xor  = <original_retval> xor rvo.zero             ; = original_retval
//   ret rvo.xor                                            ; replaces original
//
// For pointer-returning functions (i8*/i64* etc.):
//
//   rvo.zero  = load volatile i64, @__armorcomp_rvo_zero
//   rvo.int   = ptrtoint <original_retval> to i64
//   rvo.xor   = rvo.int xor rvo.zero
//   rvo.ptr   = inttoptr rvo.xor to <original_ptr_type>
//   ret rvo.ptr
//
// AArch64 disassembly produced (i32 return):
//   ldr  w8, [__armorcomp_rvo_zero]   ; volatile i32 load
//   eor  w0, w0, w8                   ; w0 ^= volatile_zero (no-op at runtime)
//   ret
//
// AArch64 disassembly produced (i64 return):
//   ldr  x8, [__armorcomp_rvo_zero]
//   eor  x0, x0, x8
//   ret
//
// WHY VOLATILE ZERO
// ─────────────────
// A plain XOR with the literal 0 would be constant-folded away by any
// optimizer.  A volatile load of @__armorcomp_rvo_zero (always 0 at runtime)
// cannot be constant-folded: LLVM assumes that volatile memory may change
// between reads.  The resulting eor instruction is always present in the
// final binary with a non-constant source operand.
//
// IDA HEX-RAYS EFFECT
// ───────────────────
// Hex-Rays observes `eor x0, x0, x8` where x8 is loaded from a global
// symbol.  It cannot determine statically that x8 == 0 at every call, so:
//   1. Return-type inference: the XOR makes x0 appear to be a computed
//      value; IDA may infer __int64 / void* / _UNKNOWN for the return type.
//   2. Return-value propagation: callers that capture the return value track
//      an unresolvable XOR expression; data-flow analysis across calls fails.
//   3. Combined with FSIG (fake arg/retval register writes) and NTC (fmov
//      roundtrips): the function prototype — parameter types, count, and
//      return type — is unrecoverable from static analysis alone.
//===----------------------------------------------------------------------===//

#include "ArmorComp/ReturnValueObfPass.h"
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

static bool hasRVOAnnotation(Function &F) {
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

        if (strData->getAsCString() == "rvo") return true;
      }
    }
  }

check_config:
  return armorcomp::configSaysApply(F.getName(), "rvo");
}

// ─────────────────────────────────────────────────────────────────────────────
// ReturnValueObfPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses ReturnValueObfPass::run(Function &F,
                                           FunctionAnalysisManager & /*AM*/) {
  if (F.isDeclaration()) return PreservedAnalyses::all();
  if (F.getName().startswith("__armorcomp_")) return PreservedAnalyses::all();

  bool shouldObf = !annotateOnly
                   || hasRVOAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "rvo");
  if (!shouldObf) return PreservedAnalyses::all();

  // Determine return type.  We handle:
  //   - Integer types (i8/i16/i32/i64)
  //   - Pointer types (lowered to i64 XOR then back to ptr)
  // Skip void, float/double, struct/array, and wider integers.
  Type *RetTy = F.getReturnType();
  if (RetTy->isVoidTy()) return PreservedAnalyses::all();

  LLVMContext &Ctx = F.getContext();
  Module     *M    = F.getParent();

  // Determine XOR operand width and whether we need ptrtoint/inttoptr.
  bool isPtr      = false;
  Type *XorTy     = nullptr;  // i8/i16/i32/i64 to use for XOR

  if (auto *IT = dyn_cast<IntegerType>(RetTy)) {
    unsigned bw = IT->getBitWidth();
    if (bw != 8 && bw != 16 && bw != 32 && bw != 64)
      return PreservedAnalyses::all();  // skip i1, i128, etc.
    XorTy = IT;
  } else if (RetTy->isPointerTy()) {
    isPtr  = true;
    XorTy  = M->getDataLayout().getIntPtrType(Ctx);  // i32 on arm32, i64 on arm64
  } else {
    // float/double/struct/etc — skip
    return PreservedAnalyses::all();
  }

  // ── Get or create the volatile-zero global ────────────────────────────────
  // WeakAny: multiple TUs → linker merges to a single instance.
  // i64 wide — we cast the volatile load to narrower widths as needed.
  GlobalVariable *RvoZero = M->getGlobalVariable("__armorcomp_rvo_zero");
  if (!RvoZero) {
    Type *I64Ty = Type::getInt64Ty(Ctx);
    RvoZero = new GlobalVariable(
        *M,
        I64Ty,
        /*isConstant=*/false,
        GlobalValue::WeakAnyLinkage,
        ConstantInt::get(I64Ty, 0),
        "__armorcomp_rvo_zero"
    );
  }

  // ── Snapshot return instructions ──────────────────────────────────────────
  std::vector<ReturnInst *> rets;
  for (BasicBlock &BB : F)
    if (auto *RI = dyn_cast<ReturnInst>(BB.getTerminator()))
      if (RI->getReturnValue()) {  // skip void returns (shouldn't happen here)
        // Guard: skip if preceding instruction is a musttail call (VMP thunk).
        // Inserting XOR before ret would break the musttail → ret invariant.
        Instruction *Prev = RI->getPrevNode();
        if (Prev && isa<CallInst>(Prev) && cast<CallInst>(Prev)->isMustTailCall())
          continue;
        rets.push_back(RI);
      }

  if (rets.empty()) return PreservedAnalyses::all();

  // ── Inject XOR before each ReturnInst ─────────────────────────────────────
  for (ReturnInst *RI : rets) {
    IRBuilder<> Bldr(RI);

    Value *OrigVal = RI->getReturnValue();

    // Load volatile zero, sized to the XOR width.
    // If XorTy is narrower than i64, truncate after the load (still volatile).
    Value *ZeroLoad;
    Type *I64Ty = Type::getInt64Ty(Ctx);
    if (XorTy == I64Ty) {
      ZeroLoad = Bldr.CreateLoad(I64Ty, RvoZero, /*isVolatile=*/true,
                                  "rvo.zero");
    } else {
      // Load full i64 volatile, then trunc to the target width.
      // The volatile property is on the i64 load; truncation is pure IR.
      Value *Raw = Bldr.CreateLoad(I64Ty, RvoZero, /*isVolatile=*/true,
                                    "rvo.zero.raw");
      ZeroLoad = Bldr.CreateTrunc(Raw, XorTy, "rvo.zero");
    }

    Value *NewRet;

    if (!isPtr) {
      // Integer: direct XOR
      Value *Xored = Bldr.CreateXor(OrigVal, ZeroLoad, "rvo.xor");
      NewRet = Xored;
    } else {
      // Pointer: ptrtoint → XOR → inttoptr
      Value *AsInt  = Bldr.CreatePtrToInt(OrigVal, XorTy, "rvo.ptrtoint");
      Value *Xored  = Bldr.CreateXor(AsInt, ZeroLoad, "rvo.xor");
      Value *AsPtr  = Bldr.CreateIntToPtr(Xored, RetTy, "rvo.inttoptr");
      NewRet = AsPtr;
    }

    // Replace the return value operand.
    RI->setOperand(0, NewRet);
  }

  unsigned retCount = (unsigned)rets.size();

  errs() << "[ArmorComp][RVO] obfuscated: " << F.getName()
         << " (" << retCount << " ret(s), "
         << (isPtr ? "ptr" : std::to_string(XorTy->getIntegerBitWidth()) + "-bit")
         << ")\n";

  return PreservedAnalyses::none();
}
