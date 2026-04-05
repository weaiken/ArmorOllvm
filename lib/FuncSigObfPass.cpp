//===----------------------------------------------------------------------===//
// ArmorComp — FuncSigObfPass (Function Signature Obfuscation)
//
// Strategy: poison IDA's register-liveness analysis at function boundaries
// ──────────────────────────────────────────────────────────────────────────
//
//  ENTRY OBFUSCATION — fake extra-argument reads
//  ──────────────────────────────────────────────
//  At function entry (after allocas), inject one inline-asm read per fake
//  argument register (x1, x2, x3):
//
//    %fv0 = load volatile i64, @__armorcomp_fsig_zero   ; = 0
//    %r1  = call i64 asm sideeffect "mov $0, x1", "=r"()
//    %r2  = call i64 asm sideeffect "mov $0, x2", "=r"()
//    %r3  = call i64 asm sideeffect "mov $0, x3", "=r"()
//    %acc = or i64 (or i64 %r1, %r2), %r3
//    %mix = xor i64 %acc, %fv0                          ; = acc ^ 0 = acc
//    store volatile i64 %mix, @__armorcomp_fsig_sink
//
//  IDA's liveness analysis: x1, x2, x3 are READ before any WRITE → they are
//  treated as function arguments → IDA infers a 4+-argument prototype.
//
//  EXIT OBFUSCATION — fake return-value register writes
//  ─────────────────────────────────────────────────────
//  Before each ReturnInst, inject:
//
//    %rv = load volatile i64, @__armorcomp_fsig_zero    ; = 0
//    call void asm sideeffect "mov x1, $0", "r,~{x1}"(i64 %rv)
//    call void asm sideeffect "mov x2, $0", "r,~{x2}"(i64 %rv)
//    ret ...
//
//  IDA's return-value analysis: x1, x2 are WRITTEN before every ret →
//  IDA infers a multi-register or struct return type.
//  Hex-Rays generates a wrong prototype (extra parameters, struct return,
//  or "int64[2]" return) for the annotated function.
//
//  RUNTIME CORRECTNESS
//  ──────────────────
//  - Reads of x1–x3: no side effect, values discarded into volatile sink.
//  - Writes of 0 to x1, x2: x1/x2 are caller-saved registers in AArch64;
//    callers cannot depend on their values after a call, so overwriting them
//    with 0 before ret does not violate the ABI.
//  - All "zero" values come from a volatile global whose initializer is 0
//    and is never modified by ArmorComp code — always 0 at runtime.
//===----------------------------------------------------------------------===//

#include "ArmorComp/FuncSigObfPass.h"
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

#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasFSigAnnotation(Function &F) {
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

        if (strData->getAsCString() == "fsig") return true;
      }
    }
  }

check_config:
  return armorcomp::configSaysApply(F.getName(), "fsig");
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared volatile globals
// ─────────────────────────────────────────────────────────────────────────────

/// Zero source — volatile load always returns 0 at runtime.
/// WeakAny linkage: survives LTO deduplication.
static GlobalVariable *getOrCreateFSigZero(Module &M) {
  const char *Name = "__armorcomp_fsig_zero";
  if (GlobalVariable *GV = M.getGlobalVariable(Name))
    return GV;
  return new GlobalVariable(
      M, Type::getInt64Ty(M.getContext()), /*isConstant=*/false,
      GlobalValue::WeakAnyLinkage,
      ConstantInt::get(Type::getInt64Ty(M.getContext()), 0), Name);
}

/// Write sink — volatile stores here; value is never read by ArmorComp code.
/// Forces the entry-block fake-arg computation to be fully evaluated.
static GlobalVariable *getOrCreateFSigSink(Module &M) {
  const char *Name = "__armorcomp_fsig_sink";
  if (GlobalVariable *GV = M.getGlobalVariable(Name))
    return GV;
  return new GlobalVariable(
      M, Type::getInt64Ty(M.getContext()), /*isConstant=*/false,
      GlobalValue::WeakAnyLinkage,
      ConstantInt::get(Type::getInt64Ty(M.getContext()), 0), Name);
}

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

// ─────────────────────────────────────────────────────────────────────────────
// FuncSigObfPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses FuncSigObfPass::run(Function &F,
                                      FunctionAnalysisManager & /*AM*/) {
  if (F.isDeclaration()) return PreservedAnalyses::all();

  // AArch64 only — inline asm uses AArch64 register names
  Module *M = F.getParent();
  Triple T(M->getTargetTriple());
  if (!T.isAArch64()) return PreservedAnalyses::all();

  // Never instrument ArmorComp's own injected functions
  if (F.getName().startswith("__armorcomp_")) return PreservedAnalyses::all();

  bool shouldObf = !annotateOnly
                   || hasFSigAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "fsig");
  if (!shouldObf) return PreservedAnalyses::all();

  LLVMContext &Ctx  = F.getContext();
  Type *I64Ty       = Type::getInt64Ty(Ctx);
  Type *VoidTy      = Type::getVoidTy(Ctx);

  GlobalVariable *Zero = getOrCreateFSigZero(*M);
  GlobalVariable *Sink = getOrCreateFSigSink(*M);

  // ── ENTRY: inject fake argument reads ─────────────────────────────────────
  //
  // Insertion point: first non-alloca instruction in the entry block.
  // This guarantees the fake reads appear before any real uses of x1–x3,
  // so IDA's liveness analysis sees them as "read before write" → arguments.
  BasicBlock &Entry = F.getEntryBlock();
  IRBuilder<> EntryIR(firstNonAlloca(Entry));

  // Inline-asm type: no inputs, one i64 output (the register value)
  FunctionType *ReadTy = FunctionType::get(I64Ty, {}, /*isVarArg=*/false);

  // Read x1, x2, x3 via separate inline-asm calls.
  // "=r" allocates any GP register for the output; LLVM substitutes $0.
  // hasSideEffects=true prevents the optimizer from removing the call.
  // The resulting AArch64 assembly: "mov <alloc_reg>, x1" etc.
  static const char *FakeArgRegs[] = {"x1", "x2", "x3"};
  static const char *FakeArgAsmStr[] = {
      "mov $0, x1", "mov $0, x2", "mov $0, x3"
  };

  // Accumulator starts with a volatile load of zero.
  // This forces the entire accumulation chain to be volatile-dependent,
  // preventing LLVM from constant-folding any part of it.
  Value *Acc = EntryIR.CreateLoad(I64Ty, Zero, /*isVolatile=*/true, "fsig.z");

  for (unsigned i = 0; i < 3; ++i) {
    (void)FakeArgRegs[i];  // name is for documentation only
    InlineAsm *ReadAsm = InlineAsm::get(ReadTy, FakeArgAsmStr[i],
                                        "=r", /*hasSideEffects=*/true);
    Value *FakeVal = EntryIR.CreateCall(ReadTy, ReadAsm, {},
                                        std::string("fsig.rd") + std::to_string(i));
    // OR-accumulate: Acc |= FakeVal.  This creates a data-flow chain through
    // all three register reads; IDA must track all three to reason about Acc.
    Acc = EntryIR.CreateOr(Acc, FakeVal, std::string("fsig.or") + std::to_string(i));
  }

  // Volatile store to sink forces LLVM to materialise the full chain.
  // IDA sees: volatile_read(x1) | volatile_read(x2) | volatile_read(x3)
  // stored to a global — it cannot simplify or remove this computation.
  EntryIR.CreateStore(Acc, Sink, /*isVolatile=*/true);

  // ── EXIT: inject fake return-value writes ──────────────────────────────────
  //
  // Before each ReturnInst, write volatile 0 to x1 and x2.
  // "r"      — input register (holds the volatile zero value)
  // "~{xN}"  — tells LLVM that xN is clobbered by the asm.
  //            At function exit x1/x2 are caller-saved and dead, so LLVM
  //            will not insert save/restore — the writes stick in the binary.
  // hasSideEffects=true — prevents removal.
  // Result in assembly: "mov x1, <zero_reg>" immediately before ret.
  FunctionType *WriteTy = FunctionType::get(VoidTy, {I64Ty}, /*isVarArg=*/false);

  static const char *FakeRetAsmStr[] = {
      "mov x1, $0", "mov x2, $0"
  };
  static const char *FakeRetClobbers[] = {
      "r,~{x1}", "r,~{x2}"
  };

  // Snapshot ret instructions before modifying the function
  std::vector<ReturnInst *> rets;
  for (BasicBlock &BB : F)
    if (auto *Ret = dyn_cast<ReturnInst>(BB.getTerminator()))
      rets.push_back(Ret);

  for (ReturnInst *Ret : rets) {
    IRBuilder<> RetIR(Ret);
    // Fresh volatile zero load at each ret site — IDA tracks each load
    // independently and sees a separate "unknown volatile" per write.
    Value *RZ = RetIR.CreateLoad(I64Ty, Zero, /*isVolatile=*/true, "fsig.rz");

    for (unsigned i = 0; i < 2; ++i) {
      InlineAsm *WriteAsm = InlineAsm::get(WriteTy, FakeRetAsmStr[i],
                                           FakeRetClobbers[i],
                                           /*hasSideEffects=*/true);
      RetIR.CreateCall(WriteTy, WriteAsm, {RZ});
    }
  }

  errs() << "[ArmorComp][FSIG] obfuscated: " << F.getName()
         << " (3 fake arg-reads at entry, "
         << rets.size() << " ret(s) with fake return-val writes)\n";

  return PreservedAnalyses::none();
}
