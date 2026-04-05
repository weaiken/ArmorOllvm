//===----------------------------------------------------------------------===//
// ArmorComp — VMPCodeGen
// Generates the VM dispatcher in LLVM IR and replaces the original function.
// See include/ArmorComp/VMPCodeGen.h for architecture documentation.
//===----------------------------------------------------------------------===//

#include "ArmorComp/VMPCodeGen.h"
#include "ArmorComp/VMPOpcodes.h"

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/raw_ostream.h"

#include <array>
#include <cassert>
#include <functional>
#include <string>

using namespace llvm;
using namespace armorcomp::vmp;

// ─────────────────────────────────────────────────────────────────────────────
// Constructor
// ─────────────────────────────────────────────────────────────────────────────

VMPCodeGen::VMPCodeGen(Module &M) : M(M), Ctx(M.getContext()) {}

// ─────────────────────────────────────────────────────────────────────────────
// addAnnotationToFunction — inject F into llvm.global.annotations with Anno
//
// This enables downstream passes (SubPass, MBAPass) that key off annotation
// strings to automatically process the newly-created dispatcher function.
// The VMP dispatcher runs BEFORE Sub/MBA in the pipeline (see HelloPass.cpp),
// so entries added here are visible when those passes iterate the module.
//
// llvm.global.annotations format (AppendingLinkage):
//   [N x { ptr, ptr, ptr, i32, i32 }]
//     [0] ptr  — function pointer (no bitcast needed; stripPointerCasts handles it)
//     [1] ptr  — ptr-to-annotation-string GV (PrivateLinkage, null-terminated)
//     [2] ptr  — ptr-to-filename-string GV   (PrivateLinkage)
//     [3] i32  — source line (0 for synthetic entries)
//     [4] i32  — source column (0 for synthetic entries)
//
// Because the array type changes length (N → N+1), we must erase the old GV
// and create a fresh one.  setInitializer alone is insufficient — the GV's
// value type would remain [N x ...], causing a type mismatch assertion.
// ─────────────────────────────────────────────────────────────────────────────

static void addAnnotationToFunction(Module &M, LLVMContext &Ctx,
                                     Function *F, StringRef Anno) {
  // Build annotation string GV.
  // Must be in "llvm.metadata" section so the AsmPrinter handles it the same
  // way as frontend-generated annotation strings (it skips emission of GVs in
  // that section, treating them as pure IR metadata).
  Constant *annoStr = ConstantDataArray::getString(Ctx, Anno, /*AddNull=*/true);
  GlobalVariable *annoGV = new GlobalVariable(
      M, annoStr->getType(), /*isConstant=*/true,
      GlobalValue::PrivateLinkage, annoStr,
      ".str.armorcomp.anno." + Anno.str());
  annoGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  annoGV->setSection("llvm.metadata");

  // Dummy filename GV — also in "llvm.metadata".
  Constant *fileStr = ConstantDataArray::getString(
      Ctx, "armorcomp-generated", /*AddNull=*/true);
  GlobalVariable *fileGV = new GlobalVariable(
      M, fileStr->getType(), /*isConstant=*/true,
      GlobalValue::PrivateLinkage, fileStr,
      ".str.armorcomp.file." + Anno.str());
  fileGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  fileGV->setSection("llvm.metadata");

  // ── Determine the exact struct element type to use ─────────────────────────
  // LLVM 17 (NDK clang 17.0.2) changed the annotation struct from
  //   { ptr, ptr, ptr, i32, i32 }  (older: line, col as integers)
  // to
  //   { ptr, ptr, ptr, i32, ptr }  (newer: 5th field is "annotation arg" ptr)
  //
  // We derive the struct type from the existing llvm.global.annotations entries
  // so our synthetic entry is always type-compatible, regardless of LLVM version.
  // ─────────────────────────────────────────────────────────────────────────────
  GlobalVariable *existingGV = M.getNamedGlobal("llvm.global.annotations");

  Constant *entry;
  if (existingGV) {
    // Mirror the element type of the first existing entry.
    auto *arrTy  = cast<ArrayType>(existingGV->getValueType());
    auto *elemTy = cast<StructType>(arrTy->getElementType());

    Type *I32Ty = Type::getInt32Ty(Ctx);
    SmallVector<Constant *, 5> fields = {F, annoGV, fileGV,
                                         ConstantInt::get(I32Ty, 0)};
    // Field [4]: i32 (old format) or ptr (new LLVM 17 format).
    Type *f4Ty = elemTy->getElementType(4);
    if (f4Ty->isPointerTy())
      fields.push_back(ConstantPointerNull::get(cast<PointerType>(f4Ty)));
    else
      fields.push_back(ConstantInt::get(f4Ty, 0));

    entry = ConstantStruct::get(elemTy, fields);
  } else {
    // No prior annotations — use the LLVM 17 { ptr, ptr, ptr, i32, ptr } layout.
    Type *I32Ty = Type::getInt32Ty(Ctx);
    Type *PtrTy = PointerType::getUnqual(Ctx);
    StructType *elemTy = StructType::get(Ctx, {PtrTy, PtrTy, PtrTy, I32Ty, PtrTy});
    entry = ConstantStruct::get(
        elemTy, {F, annoGV, fileGV,
                 ConstantInt::get(I32Ty, 0),
                 ConstantPointerNull::get(cast<PointerType>(PtrTy))});
  }

  // Extend (or create) llvm.global.annotations.
  // IMPORTANT: must set section "llvm.metadata" on the recreated GV.
  // The AsmPrinter checks this section to identify annotation globals and skip
  // their normal emission.  Without it, the AsmPrinter treats the GV as a
  // regular data global, reaches code that cannot handle AppendingLinkage
  // globals named "llvm.global.annotations" outside "llvm.metadata", and
  // calls llvm_unreachable("unknown special variable").
  if (existingGV) {
    auto *oldArr = cast<ConstantArray>(existingGV->getInitializer());
    SmallVector<Constant *, 16> elems;
    for (unsigned i = 0, e = oldArr->getNumOperands(); i < e; ++i)
      elems.push_back(cast<Constant>(oldArr->getOperand(i)));
    elems.push_back(entry);
    ArrayType *newTy = ArrayType::get(entry->getType(), elems.size());
    Constant *newArr = ConstantArray::get(newTy, elems);
    existingGV->eraseFromParent();
    auto *newGV = new GlobalVariable(M, newArr->getType(), /*isConstant=*/false,
                                     GlobalValue::AppendingLinkage, newArr,
                                     "llvm.global.annotations");
    newGV->setSection("llvm.metadata");
  } else {
    ArrayType *arrTy = ArrayType::get(entry->getType(), 1);
    Constant *arr = ConstantArray::get(arrTy, {entry});
    auto *newGV = new GlobalVariable(M, arr->getType(), /*isConstant=*/false,
                                     GlobalValue::AppendingLinkage, arr,
                                     "llvm.global.annotations");
    newGV->setSection("llvm.metadata");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// injectBcKey — store XOR key as @__armorcomp_vmp_key_<fname> constant i64
// ─────────────────────────────────────────────────────────────────────────────

GlobalVariable *VMPCodeGen::injectBcKey(Function &F, uint64_t key) {
  std::string name = keyGlobalName(F.getName().str());
  if (auto *old = M.getGlobalVariable(name))
    old->eraseFromParent();
  auto *GV = new GlobalVariable(M, Type::getInt64Ty(Ctx),
                                 /*isConstant=*/true,
                                 GlobalValue::WeakODRLinkage,
                                 ConstantInt::get(Type::getInt64Ty(Ctx), key),
                                 name);
  GV->setAlignment(Align(8));
  return GV;
}

// ─────────────────────────────────────────────────────────────────────────────
// injectBytecode — store bytecode as a [N x i8] global
// ─────────────────────────────────────────────────────────────────────────────

GlobalVariable *VMPCodeGen::injectBytecode(Function &F,
                                            const std::vector<uint8_t> &bc) {
  std::string name = bcGlobalName(F.getName().str());

  // Remove any existing GV with this name (idempotent)
  if (auto *old = M.getGlobalVariable(name))
    old->eraseFromParent();

  ArrayType *ArrTy =
      ArrayType::get(Type::getInt8Ty(Ctx), bc.size());
  Constant *Init = ConstantDataArray::get(Ctx, ArrayRef<uint8_t>(bc));

  auto *GV = new GlobalVariable(M, ArrTy,
                                 /*isConstant=*/true,
                                 GlobalValue::WeakODRLinkage,
                                 Init, name);
  GV->setAlignment(Align(1));
  return GV;
}

// ─────────────────────────────────────────────────────────────────────────────
// buildDispatcher — generate the VM fetch-decode-execute loop as LLVM IR
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// injectGVTable — build [N x ptr] companion global for MOV_GV
// ─────────────────────────────────────────────────────────────────────────────

GlobalVariable *VMPCodeGen::injectGVTable(Function &F,
                                           const std::vector<GlobalValue *> &gvTable) {
  if (gvTable.empty()) return nullptr;

  std::string name = gvtabName(F.getName().str());

  if (auto *old = M.getGlobalVariable(name))
    old->eraseFromParent();

  PointerType *PtrTy8 = Type::getInt8PtrTy(Ctx);
  ArrayType *ArrTy    = ArrayType::get(PtrTy8, gvTable.size());

  std::vector<Constant *> elems;
  elems.reserve(gvTable.size());
  for (GlobalValue *gv : gvTable)
    elems.push_back(ConstantExpr::getBitCast(gv, PtrTy8));

  Constant *init = ConstantArray::get(ArrTy, elems);
  auto *GV = new GlobalVariable(M, ArrTy, /*isConstant=*/true,
                                 GlobalValue::PrivateLinkage, init, name);
  GV->setAlignment(Align(8));
  return GV;
}

// ─────────────────────────────────────────────────────────────────────────────
// buildDispatcher — generate the VM fetch-decode-execute loop as LLVM IR
// ─────────────────────────────────────────────────────────────────────────────

Function *VMPCodeGen::buildDispatcher(Function &origF,
                                       GlobalVariable *bcGV,
                                       GlobalVariable *gvTabGV,
                                       const std::vector<uint8_t> &bc,
                                       const std::vector<Function *> &callTable,
                                       uint64_t bcKey,
                                       const armorcomp::vmp::OpcodeMap &opcodeMap) {
  // ── Create dispatcher function with same type as origF ──────────────────
  std::string dispName = dispatcherName(origF.getName().str());

  // Remove existing dispatcher if present (re-virtualization)
  if (auto *old = M.getFunction(dispName))
    old->eraseFromParent();

  Function *Disp = Function::Create(origF.getFunctionType(),
                                     GlobalValue::InternalLinkage,
                                     dispName, &M);
  Disp->addFnAttr(Attribute::NoInline);
  Disp->addFnAttr(Attribute::OptimizeNone);

  // ── Type shortcuts ───────────────────────────────────────────────────────
  Type *I8Ty   = Type::getInt8Ty(Ctx);
  Type *I16Ty  = Type::getInt16Ty(Ctx);
  Type *I32Ty  = Type::getInt32Ty(Ctx);
  Type *I64Ty  = Type::getInt64Ty(Ctx);
  Type *PtrTy  = Type::getInt8PtrTy(Ctx);
  ArrayType *RegFileTy = ArrayType::get(I64Ty, NUM_REGS);
  ArrayType *VMStkTy   = ArrayType::get(I8Ty, 4096);

  // ── Basic Blocks ─────────────────────────────────────────────────────────
  BasicBlock *entryBB   = BasicBlock::Create(Ctx, "vm.entry",    Disp);
  BasicBlock *decLoopBB = BasicBlock::Create(Ctx, "vm.dec.loop", Disp); // decrypt loop header
  BasicBlock *decBodyBB = BasicBlock::Create(Ctx, "vm.dec.body", Disp); // decrypt loop body
  BasicBlock *decDoneBB = BasicBlock::Create(Ctx, "vm.dec.done", Disp); // after decrypt: init pc/args
  BasicBlock *dispBB    = BasicBlock::Create(Ctx, "vm.dispatch", Disp);
  BasicBlock *retBB     = BasicBlock::Create(Ctx, "vm.ret",      Disp);
  BasicBlock *retVoidBB = BasicBlock::Create(Ctx, "vm.ret.void", Disp);
  BasicBlock *undefBB   = BasicBlock::Create(Ctx, "vm.undef",    Disp);

  // ── Entry: allocate register file, pc, alloca pool, decrypt buffer ───────
  IRBuilder<> B(entryBB);

  // ── Register file value canary ───────────────────────────────────────────
  // All values stored in the register file are XOR-obfuscated with regCanary.
  // This makes a runtime stack dump of vm.regs[] show scrambled values rather
  // than the actual computation state, defeating memory-pattern analysis.
  //
  // Canary derivation: take the low byte of bcKey, replicate 8 times.
  // Using a single-byte pattern allows CreateMemSet to initialise the whole
  // register file in one call (memset fills at byte granularity).
  //   Unwritten reg: stored = regByte × 8, getReg returns regCanary^regCanary = 0
  //   Written reg:   stored = val ^ regCanary, getReg returns val ^ regCanary ^ regCanary = val
  uint8_t regByte = static_cast<uint8_t>(bcKey & 0xFF);
  if (regByte == 0) regByte = 0xA5; // never use identity (0 XOR = no-op)
  uint64_t regCanary = static_cast<uint64_t>(regByte) * 0x0101010101010101ULL;
  Value *regCanaryV = ConstantInt::get(I64Ty, regCanary);

  // Register file: [64 x i64]
  AllocaInst *regs = B.CreateAlloca(RegFileTy, nullptr, "vm.regs");
  regs->setAlignment(Align(8));
  // Initialise each byte with regByte so every i64 register == regCanary.
  // Decrypted read of an unwritten register yields regCanary ^ regCanary = 0.
  B.CreateMemSet(regs, ConstantInt::get(I8Ty, regByte),
                 ConstantInt::get(I64Ty, NUM_REGS * 8), Align(8));

  // PC alloca: i8* (pointer to current bytecode position)
  AllocaInst *pcAlloc = B.CreateAlloca(PtrTy, nullptr, "vm.pc");
  pcAlloc->setAlignment(Align(8));

  // ALLOCA pool: [4096 x i8] for VM-level allocas
  AllocaInst *vmStk = B.CreateAlloca(VMStkTy, nullptr, "vm.stk");
  vmStk->setAlignment(Align(8));
  AllocaInst *vmStkBP = B.CreateAlloca(PtrTy, nullptr, "vm.stkbp");
  vmStkBP->setAlignment(Align(8));
  // Initialise bump pointer to start of pool
  Value *stkBase = B.CreateBitCast(vmStk, PtrTy, "vm.stkbase");
  B.CreateStore(stkBase, vmStkBP);

  // Decrypt buffer: [bcSize x i8] on stack — receives XOR-decrypted bytecode.
  // The encrypted bytecode global is never directly executed; decrypted here.
  uint64_t bcSize = static_cast<uint64_t>(bc.size());
  ArrayType *DecBufTy = ArrayType::get(I8Ty, bcSize);
  AllocaInst *decBuf = B.CreateAlloca(DecBufTy, nullptr, "vm.decbuf");
  decBuf->setAlignment(Align(1));
  Value *decBufPtr = B.CreateBitCast(decBuf, PtrTy, "vm.decbufptr");
  Value *bcGVPtr   = B.CreateBitCast(bcGV,   PtrTy, "vm.bcgvptr");

  // Branch to decrypt loop header
  B.CreateBr(decLoopBB);

  // ── vm.dec.loop: loop header with PHI for i ───────────────────────────────
  PHINode *decI;
  {
    IRBuilder<> Ldec(decLoopBB);
    decI = Ldec.CreatePHI(I64Ty, 2, "vm.dec.i");
    decI->addIncoming(ConstantInt::get(I64Ty, 0), entryBB); // loop init
    Value *done = Ldec.CreateICmpEQ(decI, ConstantInt::get(I64Ty, bcSize), "dec.done");
    Ldec.CreateCondBr(done, decDoneBB, decBodyBB);
  }

  // ── vm.dec.body: decrypt one byte at position i ──────────────────────────
  {
    IRBuilder<> Lbody(decBodyBB);
    // Load encrypted byte from bytecode global
    Value *srcPtr = Lbody.CreateGEP(I8Ty, bcGVPtr, decI, "dec.src");
    Value *encByte = Lbody.CreateLoad(I8Ty, srcPtr, "dec.enc");
    // key byte = (KEY >> ((i % 8) * 8)) & 0xFF — compile-time constant i64
    Value *iMod8   = Lbody.CreateAnd(decI, ConstantInt::get(I64Ty, 7));
    Value *shift   = Lbody.CreateMul(iMod8, ConstantInt::get(I64Ty, 8));
    Value *keyVal  = ConstantInt::get(I64Ty, bcKey);
    Value *keyShr  = Lbody.CreateLShr(keyVal, shift);
    Value *keyByte = Lbody.CreateTrunc(keyShr, I8Ty, "dec.keybyte");
    Value *decByte = Lbody.CreateXor(encByte, keyByte, "dec.byte");
    // Store decrypted byte to decBuf
    Value *dstPtr  = Lbody.CreateGEP(I8Ty, decBufPtr, decI, "dec.dst");
    Lbody.CreateStore(decByte, dstPtr);
    // Advance loop counter and back-edge
    Value *iNext = Lbody.CreateAdd(decI, ConstantInt::get(I64Ty, 1), "dec.i.next");
    decI->addIncoming(iNext, decBodyBB); // close back-edge
    Lbody.CreateBr(decLoopBB);
  }

  // ── vm.dec.done: initialise pc = decBufPtr, load args ────────────────────
  {
    IRBuilder<> Bdone(decDoneBB);
    // pc starts at decrypted buffer — NOT the encrypted global
    Bdone.CreateStore(decBufPtr, pcAlloc);

    // Initialise arg registers: regs[i] = (i64) argN
    unsigned argIdx = 0;
    for (auto &Arg : Disp->args()) {
      if (argIdx >= MAX_CALL_ARGS) break;
      Value *argVal;
      if (Arg.getType()->isIntegerTy()) {
        argVal = Bdone.CreateZExtOrBitCast(&Arg, I64Ty);
      } else if (Arg.getType()->isPointerTy()) {
        argVal = Bdone.CreatePtrToInt(&Arg, I64Ty);
      } else {
        argVal = ConstantInt::get(I64Ty, 0);
      }
      Value *regPtr = Bdone.CreateGEP(
          RegFileTy, regs,
          {ConstantInt::get(I32Ty, 0), ConstantInt::get(I32Ty, argIdx)},
          "arg_reg_ptr");
      // Encrypt with regCanary so getReg(Ri) returns the correct plaintext.
      Value *encArg = Bdone.CreateXor(argVal, regCanaryV, "arg.enc");
      Bdone.CreateStore(encArg, regPtr);
      ++argIdx;
    }

    Bdone.CreateBr(dispBB);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Helper lambdas used inside handler BBs
  // ─────────────────────────────────────────────────────────────────────────

  // readByte: load one byte from *pcAlloc, advance pc by 1.
  auto readByte = [&](IRBuilder<> &bldr) -> Value * {
    Value *pc   = bldr.CreateLoad(PtrTy, pcAlloc, "pc");
    Value *byte = bldr.CreateLoad(I8Ty, pc, "byte");
    Value *next = bldr.CreateGEP(I8Ty, pc, ConstantInt::get(I64Ty, 1), "pc.next");
    bldr.CreateStore(next, pcAlloc);
    return byte;
  };

  // readU16: read 2 bytes little-endian, advance pc by 2.
  auto readU16 = [&](IRBuilder<> &bldr) -> Value * {
    Value *pc  = bldr.CreateLoad(PtrTy, pcAlloc, "pc");
    Value *b0  = bldr.CreateLoad(I8Ty, pc);
    Value *p1  = bldr.CreateGEP(I8Ty, pc, ConstantInt::get(I64Ty, 1));
    Value *b1  = bldr.CreateLoad(I8Ty, p1);
    Value *p2  = bldr.CreateGEP(I8Ty, pc, ConstantInt::get(I64Ty, 2));
    bldr.CreateStore(p2, pcAlloc);
    Value *e0  = bldr.CreateZExt(b0, I16Ty);
    Value *e1  = bldr.CreateZExt(b1, I16Ty);
    Value *s1  = bldr.CreateShl(e1, ConstantInt::get(I16Ty, 8));
    return bldr.CreateOr(e0, s1, "u16");
  };

  // readU32: read 4 bytes little-endian, advance pc by 4.
  auto readU32 = [&](IRBuilder<> &bldr) -> Value * {
    Value *pc = bldr.CreateLoad(PtrTy, pcAlloc, "pc");
    std::array<Value*, 4> bytes;
    for (int i = 0; i < 4; ++i) {
      Value *p = (i == 0) ? pc
                           : bldr.CreateGEP(I8Ty, pc, ConstantInt::get(I64Ty, i));
      bytes[i] = bldr.CreateLoad(I8Ty, p);
    }
    Value *end = bldr.CreateGEP(I8Ty, pc, ConstantInt::get(I64Ty, 4));
    bldr.CreateStore(end, pcAlloc);
    Value *acc = bldr.CreateZExt(bytes[0], I32Ty);
    for (int i = 1; i < 4; ++i) {
      Value *ext = bldr.CreateZExt(bytes[i], I32Ty);
      Value *shl = bldr.CreateShl(ext, ConstantInt::get(I32Ty, i * 8));
      acc = bldr.CreateOr(acc, shl);
    }
    return acc;
  };

  // readI32: same as readU32 but result is signed (still i32 IR type).
  auto readI32 = [&](IRBuilder<> &bldr) -> Value * {
    return readU32(bldr); // same bits, just interpreted as signed
  };

  // getReg: load regs[idx], decrypt with regCanary, return plaintext i64.
  auto getReg = [&](IRBuilder<> &bldr, Value *idxI8) -> Value * {
    Value *idx64  = bldr.CreateZExt(idxI8, I32Ty);
    Value *ptr    = bldr.CreateGEP(
        RegFileTy, regs,
        {ConstantInt::get(I32Ty, 0), idx64}, "reg_ptr");
    Value *stored = bldr.CreateLoad(I64Ty, ptr, "reg.enc");
    return bldr.CreateXor(stored, regCanaryV, "reg");
  };

  // setReg: encrypt val with regCanary, store into regs[idx].
  auto setReg = [&](IRBuilder<> &bldr, Value *idxI8, Value *val) {
    Value *enc   = bldr.CreateXor(val, regCanaryV, "reg.enc");
    Value *idx64 = bldr.CreateZExt(idxI8, I32Ty);
    Value *ptr   = bldr.CreateGEP(
        RegFileTy, regs,
        {ConstantInt::get(I32Ty, 0), idx64}, "reg_ptr");
    bldr.CreateStore(enc, ptr);
  };

  // ─────────────────────────────────────────────────────────────────────────
  // Dispatch BB: fetch opcode, advance pc, switch
  // ─────────────────────────────────────────────────────────────────────────
  {
    IRBuilder<> B2(dispBB);
    Value *pc  = B2.CreateLoad(PtrTy, pcAlloc, "pc");
    Value *opc = B2.CreateLoad(I8Ty, pc, "opcode");
    Value *pc1 = B2.CreateGEP(I8Ty, pc, ConstantInt::get(I64Ty, 1), "pc.after.opc");
    B2.CreateStore(pc1, pcAlloc);

    SwitchInst *sw = B2.CreateSwitch(opc, undefBB, 48);

    // addCase: maps semantic opcode → physical (scrambled) byte value before
    // inserting into the switch.  All call sites pass semantic Opcode enum values;
    // the physical mapping (unique per function) is applied here automatically.
    // ConstantInt::get(IntegerType*, uint64_t) returns ConstantInt* —
    // must use IntegerType* overload, not Type* overload (which returns Constant*).
    IntegerType *I8ITy = cast<IntegerType>(I8Ty);
    auto addCase = [&](uint8_t sem_opc, BasicBlock *target) {
      uint8_t phys_opc = opcodeMap.phys[sem_opc]; // semantic → physical
      sw->addCase(ConstantInt::get(I8ITy, static_cast<uint64_t>(phys_opc), false),
                  target);
    };

    // ─────────────────────────────────────────────────────────────────────
    // Handler factory: create a BB, populate it, branch back to dispatch.
    // Returns the newly created BasicBlock.
    // ─────────────────────────────────────────────────────────────────────
    auto mkHandler = [&](const std::string &name,
                         std::function<void(IRBuilder<> &)> body)
        -> BasicBlock * {
      BasicBlock *bb = BasicBlock::Create(Ctx, "h_" + name, Disp);
      IRBuilder<> hb(bb);
      body(hb);
      if (!bb->getTerminator())
        hb.CreateBr(dispBB);
      return bb;
    };

    // ── NOP ──────────────────────────────────────────────────────────────
    addCase(NOP, mkHandler("nop", [&](IRBuilder<> &) {}));

    // ── MOV_I8: dst = zext imm8 to i64 ───────────────────────────────────
    addCase(MOV_I8, mkHandler("mov_i8", [&](IRBuilder<> &h) {
      Value *dst  = readByte(h);
      Value *imm  = readByte(h);
      Value *ext  = h.CreateZExt(imm, I64Ty);
      setReg(h, dst, ext);
    }));

    // ── MOV_I16 ──────────────────────────────────────────────────────────
    addCase(MOV_I16, mkHandler("mov_i16", [&](IRBuilder<> &h) {
      Value *dst = readByte(h);
      Value *imm = readU16(h);
      Value *ext = h.CreateZExt(imm, I64Ty);
      setReg(h, dst, ext);
    }));

    // ── MOV_I32 ──────────────────────────────────────────────────────────
    addCase(MOV_I32, mkHandler("mov_i32", [&](IRBuilder<> &h) {
      Value *dst = readByte(h);
      Value *imm = readU32(h);
      Value *ext = h.CreateZExt(imm, I64Ty);
      setReg(h, dst, ext);
    }));

    // ── MOV_I64: read 8 bytes ─────────────────────────────────────────────
    addCase(MOV_I64, mkHandler("mov_i64", [&](IRBuilder<> &h) {
      Value *dst  = readByte(h);
      // Read 8 bytes little-endian
      Value *pc   = h.CreateLoad(PtrTy, pcAlloc, "pc");
      Value *acc  = ConstantInt::get(I64Ty, 0);
      for (int i = 0; i < 8; ++i) {
        Value *p    = h.CreateGEP(I8Ty, pc, ConstantInt::get(I64Ty, i));
        Value *byte = h.CreateLoad(I8Ty, p);
        Value *ext  = h.CreateZExt(byte, I64Ty);
        Value *shl  = h.CreateShl(ext, ConstantInt::get(I64Ty, i * 8));
        acc = h.CreateOr(acc, shl);
      }
      Value *end = h.CreateGEP(I8Ty, pc, ConstantInt::get(I64Ty, 8));
      h.CreateStore(end, pcAlloc);
      setReg(h, dst, acc);
    }));

    // ── MOV_RR ───────────────────────────────────────────────────────────
    addCase(MOV_RR, mkHandler("mov_rr", [&](IRBuilder<> &h) {
      Value *dst = readByte(h);
      Value *src = readByte(h);
      setReg(h, dst, getReg(h, src));
    }));

    // ── MOV_GV: load runtime address of a GlobalValue from gvtab ─────────
    if (gvTabGV) {
      ArrayType *gvArrTy = cast<ArrayType>(gvTabGV->getValueType());
      addCase(MOV_GV, mkHandler("mov_gv", [&, gvArrTy](IRBuilder<> &h) {
        Value *dst   = readByte(h);
        Value *idx16 = readU16(h);
        Value *idx32 = h.CreateZExt(idx16, I32Ty);
        Value *elemPtr = h.CreateGEP(gvArrTy, gvTabGV,
                             {ConstantInt::get(I32Ty, 0), idx32}, "gvtab.elem");
        Value *gvPtr   = h.CreateLoad(PtrTy, elemPtr, "gv.ptr");
        Value *gvInt   = h.CreatePtrToInt(gvPtr, I64Ty, "gv.int");
        setReg(h, dst, gvInt);
      }));
    }

    // ── Binary arithmetic ops (3R) ────────────────────────────────────────
    auto mkBinOp = [&](uint8_t opc_val, const std::string &nm,
                       std::function<Value*(IRBuilder<>&, Value*, Value*)> opFn) {
      addCase(opc_val, mkHandler(nm, [&, opFn](IRBuilder<> &h) mutable {
        Value *dst = readByte(h);
        Value *lhs = getReg(h, readByte(h));
        Value *rhs = getReg(h, readByte(h));
        setReg(h, dst, opFn(h, lhs, rhs));
      }));
    };

    mkBinOp(ADD,  "add",  [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateAdd(l,r); });
    mkBinOp(SUB,  "sub",  [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateSub(l,r); });
    mkBinOp(MUL,  "mul",  [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateMul(l,r); });
    mkBinOp(UDIV, "udiv", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateUDiv(l,r); });
    mkBinOp(SDIV, "sdiv", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateSDiv(l,r); });
    mkBinOp(UREM, "urem", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateURem(l,r); });
    mkBinOp(SREM, "srem", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateSRem(l,r); });
    mkBinOp(AND,  "and",  [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateAnd(l,r); });
    mkBinOp(OR,   "or",   [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateOr(l,r); });
    mkBinOp(XOR,  "xor",  [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateXor(l,r); });
    mkBinOp(SHL,  "shl",  [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateShl(l,r); });
    mkBinOp(LSHR, "lshr", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateLShr(l,r); });
    mkBinOp(ASHR, "ashr", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateAShr(l,r); });

    // ── NOT / NEG ─────────────────────────────────────────────────────────
    addCase(NOT, mkHandler("not", [&](IRBuilder<> &h) {
      Value *dst = readByte(h);
      Value *src = getReg(h, readByte(h));
      setReg(h, dst, h.CreateNot(src));
    }));
    addCase(NEG, mkHandler("neg", [&](IRBuilder<> &h) {
      Value *dst = readByte(h);
      Value *src = getReg(h, readByte(h));
      setReg(h, dst, h.CreateNeg(src));
    }));

    // ── ICmp ops ─────────────────────────────────────────────────────────
    auto mkCmp = [&](uint8_t opc_val, const std::string &nm,
                     ICmpInst::Predicate pred) {
      addCase(opc_val, mkHandler(nm, [&, pred](IRBuilder<> &h) mutable {
        Value *dst = readByte(h);
        Value *lhs = getReg(h, readByte(h));
        Value *rhs = getReg(h, readByte(h));
        Value *cmp = h.CreateICmp(pred, lhs, rhs);
        Value *ext = h.CreateZExt(cmp, I64Ty);
        setReg(h, dst, ext);
      }));
    };

    mkCmp(ICMP_EQ,  "icmp.eq",  ICmpInst::ICMP_EQ);
    mkCmp(ICMP_NE,  "icmp.ne",  ICmpInst::ICMP_NE);
    mkCmp(ICMP_SLT, "icmp.slt", ICmpInst::ICMP_SLT);
    mkCmp(ICMP_SLE, "icmp.sle", ICmpInst::ICMP_SLE);
    mkCmp(ICMP_SGT, "icmp.sgt", ICmpInst::ICMP_SGT);
    mkCmp(ICMP_SGE, "icmp.sge", ICmpInst::ICMP_SGE);
    mkCmp(ICMP_ULT, "icmp.ult", ICmpInst::ICMP_ULT);
    mkCmp(ICMP_ULE, "icmp.ule", ICmpInst::ICMP_ULE);
    mkCmp(ICMP_UGT, "icmp.ugt", ICmpInst::ICMP_UGT);
    mkCmp(ICMP_UGE, "icmp.uge", ICmpInst::ICMP_UGE);

    // ── JMP: offset32, relative to instruction end ─────────────────────────
    addCase(JMP, mkHandler("jmp", [&](IRBuilder<> &h) {
      Value *off32 = readI32(h); // advances pc past the 4-byte offset
      // pc (already points after offset) += sign-extended offset
      Value *pc_cur = h.CreateLoad(PtrTy, pcAlloc, "pc.after.jmp");
      Value *off64  = h.CreateSExt(off32, I64Ty);
      Value *new_pc = h.CreateGEP(I8Ty, pc_cur, off64, "pc.jmp.dest");
      h.CreateStore(new_pc, pcAlloc);
    }));

    // ── JCC: REG offset32_true offset32_false ──────────────────────────────
    addCase(JCC, mkHandler("jcc", [&](IRBuilder<> &h) {
      Value *condReg = readByte(h);
      Value *offT32  = readI32(h);
      Value *offF32  = readI32(h);
      Value *pc_base = h.CreateLoad(PtrTy, pcAlloc, "pc.after.jcc");
      Value *condVal = getReg(h, condReg);
      Value *cond    = h.CreateICmpNE(condVal, ConstantInt::get(I64Ty, 0));
      Value *offT64  = h.CreateSExt(offT32, I64Ty);
      Value *offF64  = h.CreateSExt(offF32, I64Ty);
      Value *off64   = h.CreateSelect(cond, offT64, offF64);
      Value *new_pc  = h.CreateGEP(I8Ty, pc_base, off64, "pc.jcc.dest");
      h.CreateStore(new_pc, pcAlloc);
    }));

    // ── LOAD_8/16/32/64 ──────────────────────────────────────────────────
    auto mkLoad = [&](uint8_t opc_val, const std::string &nm,
                      Type *loadTy) {
      addCase(opc_val, mkHandler(nm, [&, loadTy](IRBuilder<> &h) mutable {
        Value *dst    = readByte(h);
        Value *ptrReg = readByte(h);
        Value *ptr64  = getReg(h, ptrReg);
        Value *ptr    = h.CreateIntToPtr(ptr64, loadTy->getPointerTo());
        Value *val    = h.CreateLoad(loadTy, ptr);
        Value *ext    = h.CreateZExt(val, I64Ty);
        setReg(h, dst, ext);
      }));
    };

    mkLoad(LOAD_8,  "load8",  I8Ty);
    mkLoad(LOAD_16, "load16", I16Ty);
    mkLoad(LOAD_32, "load32", I32Ty);
    mkLoad(LOAD_64, "load64", I64Ty);

    // ── STORE_8/16/32/64 ─────────────────────────────────────────────────
    auto mkStore = [&](uint8_t opc_val, const std::string &nm,
                       Type *storeTy, unsigned bits) {
      addCase(opc_val, mkHandler(nm, [&, storeTy, bits](IRBuilder<> &h) mutable {
        Value *valReg = readByte(h);
        Value *ptrReg = readByte(h);
        Value *val64  = getReg(h, valReg);
        Value *ptr64  = getReg(h, ptrReg);
        Value *val    = h.CreateTrunc(val64, storeTy);
        Value *ptr    = h.CreateIntToPtr(ptr64, storeTy->getPointerTo());
        h.CreateStore(val, ptr);
        (void)bits;
      }));
    };

    mkStore(STORE_8,  "store8",  I8Ty,  8);
    mkStore(STORE_16, "store16", I16Ty, 16);
    mkStore(STORE_32, "store32", I32Ty, 32);
    mkStore(STORE_64, "store64", I64Ty, 64);

    // ── ALLOCA: bump-pointer allocation ───────────────────────────────────
    addCase(ALLOCA, mkHandler("alloca", [&](IRBuilder<> &h) {
      Value *dst   = readByte(h);
      Value *sz32  = readU32(h);
      Value *sz64  = h.CreateZExt(sz32, I64Ty);
      Value *bp    = h.CreateLoad(PtrTy, vmStkBP, "bp");
      Value *nbp   = h.CreateGEP(I8Ty, bp, sz64, "nbp");
      h.CreateStore(nbp, vmStkBP);
      Value *ptr64 = h.CreatePtrToInt(bp, I64Ty);
      setReg(h, dst, ptr64);
    }));

    // ── GEP8 ─────────────────────────────────────────────────────────────
    addCase(GEP8, mkHandler("gep8", [&](IRBuilder<> &h) {
      Value *dst   = readByte(h);
      Value *base  = getReg(h, readByte(h));
      Value *idx   = getReg(h, readByte(h));
      Value *baseP = h.CreateIntToPtr(base, PtrTy);
      Value *gepP  = h.CreateGEP(I8Ty, baseP, idx);
      Value *res   = h.CreatePtrToInt(gepP, I64Ty);
      setReg(h, dst, res);
    }));

    // ── ZEXT / SEXT / TRUNC ──────────────────────────────────────────────
    addCase(ZEXT, mkHandler("zext", [&](IRBuilder<> &h) {
      Value *dst   = readByte(h);
      Value *src   = getReg(h, readByte(h));
      Value *width = readByte(h);
      // Mask to the source width, then zero-extend to 64 bits
      // width is a constant like 1, 8, 16, 32, 64
      // We load it as a runtime byte, but compute mask dynamically:
      //   mask = (1 << width) - 1  for width < 64
      //   mask = 0xFFFFFFFFFFFFFFFF for width == 64
      Value *w64   = h.CreateZExt(width, I64Ty);
      Value *one   = ConstantInt::get(I64Ty, 1);
      Value *mask  = h.CreateSub(h.CreateShl(one, w64), one);
      Value *res   = h.CreateAnd(src, mask);
      setReg(h, dst, res);
    }));

    addCase(SEXT, mkHandler("sext", [&](IRBuilder<> &h) {
      Value *dst   = readByte(h);
      Value *src   = getReg(h, readByte(h));
      Value *width = readByte(h);
      // Sign-extend: shift left to put sign bit at bit 63, then arithmetic shift right
      Value *w64   = h.CreateZExt(width, I64Ty);
      Value *shamt = h.CreateSub(ConstantInt::get(I64Ty, 64), w64);
      Value *sl    = h.CreateShl(src, shamt);
      Value *res   = h.CreateAShr(sl, shamt);
      setReg(h, dst, res);
    }));

    addCase(TRUNC, mkHandler("trunc", [&](IRBuilder<> &h) {
      Value *dst   = readByte(h);
      Value *src   = getReg(h, readByte(h));
      Value *width = readByte(h);
      Value *w64   = h.CreateZExt(width, I64Ty);
      Value *one   = ConstantInt::get(I64Ty, 1);
      Value *mask  = h.CreateSub(h.CreateShl(one, w64), one);
      Value *res   = h.CreateAnd(src, mask);
      setReg(h, dst, res);
    }));

    // ── PTRTOINT / INTTOPTR ───────────────────────────────────────────────
    // In the VM, all values are i64 — these are effectively no-ops.
    addCase(PTRTOINT, mkHandler("ptrtoint", [&](IRBuilder<> &h) {
      Value *dst = readByte(h);
      setReg(h, dst, getReg(h, readByte(h)));
    }));
    addCase(INTTOPTR, mkHandler("inttoptr", [&](IRBuilder<> &h) {
      Value *dst = readByte(h);
      setReg(h, dst, getReg(h, readByte(h)));
    }));

    // ── SELECT ────────────────────────────────────────────────────────────
    addCase(SELECT, mkHandler("select", [&](IRBuilder<> &h) {
      Value *dst   = readByte(h);
      Value *cond  = readByte(h);
      Value *rTrue = readByte(h);
      Value *rFalse= readByte(h);
      Value *cv    = getReg(h, cond);
      Value *tv    = getReg(h, rTrue);
      Value *fv    = getReg(h, rFalse);
      Value *b     = h.CreateICmpNE(cv, ConstantInt::get(I64Ty, 0));
      setReg(h, dst, h.CreateSelect(b, tv, fv));
    }));

    // ── CALL_D: typed direct call via per-callee case BBs ────────────────
    if (!callTable.empty()) {
      // h_call_d: read dst and callIdx, then switch to per-callee BB.
      BasicBlock *callDBB = BasicBlock::Create(Ctx, "h_call_d", Disp);
      addCase(CALL_D, callDBB);

      IRBuilder<> hcd(callDBB);
      Value *dstReg  = readByte(hcd);
      Value *callIdx = readU16(hcd);
      Value *callIdx32 = hcd.CreateZExt(callIdx, I32Ty);

      // Default case loops back to dispatch (should never fire for valid bc)
      SwitchInst *callSw = hcd.CreateSwitch(callIdx32, dispBB,
                                             static_cast<unsigned>(callTable.size()));

      for (unsigned ci = 0; ci < callTable.size(); ++ci) {
        Function *callee = callTable[ci];
        std::string caseName = "call_d." + callee->getName().str();
        BasicBlock *caseBB = BasicBlock::Create(Ctx, caseName, Disp);
        callSw->addCase(ConstantInt::get(cast<IntegerType>(I32Ty), ci), caseBB);

        IRBuilder<> hc(caseBB);
        // Consume nargs byte from bytecode stream (we trust callee->arg_size())
        Value *_nargsV = readByte(hc);
        (void)_nargsV;

        // Read argument registers and coerce to callee param types
        std::vector<Value *> callArgs;
        for (auto &param : callee->args()) {
          Value *argReg   = readByte(hc);
          Value *argVal64 = getReg(hc, argReg);
          Type  *paramTy  = param.getType();
          Value *coerced;
          if (paramTy->isIntegerTy())
            coerced = hc.CreateTruncOrBitCast(argVal64, paramTy);
          else if (paramTy->isPointerTy())
            coerced = hc.CreateIntToPtr(argVal64, paramTy);
          else
            coerced = hc.CreateTruncOrBitCast(argVal64, paramTy);
          callArgs.push_back(coerced);
        }

        // Make the typed IR call
        CallInst *callI = hc.CreateCall(callee->getFunctionType(), callee, callArgs);

        // Coerce return value to i64 and write into dst register
        Type *retTy = callee->getReturnType();
        Value *retVal64;
        if (retTy->isVoidTy())
          retVal64 = ConstantInt::get(I64Ty, 0);
        else if (retTy->isIntegerTy())
          retVal64 = hc.CreateZExtOrBitCast(callI, I64Ty);
        else if (retTy->isPointerTy())
          retVal64 = hc.CreatePtrToInt(callI, I64Ty);
        else
          retVal64 = ConstantInt::get(I64Ty, 0);

        setReg(hc, dstReg, retVal64);
        hc.CreateBr(dispBB);
      }
    }

    // ── CALL: indirect function-pointer call ─────────────────────────────
    // Encoding: opcode dst fnReg nargs_byte arg0..argN [pad to MAX_CALL_ARGS]
    // The bytecode always has exactly MAX_CALL_ARGS arg-register bytes after
    // the nargs byte, so the dispatcher reads unconditionally (no IR loop).
    // All args are passed as i64; callee ignores extra register-argument slots.
    // Return type is assumed i64 (void callees leave x0 undefined; the dst
    // register is never read by subsequent bytecode for void-typed calls).
    addCase(CALL, mkHandler("call", [&](IRBuilder<> &h) {
      Value *dstReg  = readByte(h);      // destination register index
      Value *fnRegV  = readByte(h);      // register holding function pointer (i64)
      Value *_nargs  = readByte(h);      // actual arg count — informational only
      (void)_nargs;

      // Read all MAX_CALL_ARGS argument register bytes unconditionally.
      SmallVector<Value *, 8> callArgs;
      for (int i = 0; i < MAX_CALL_ARGS; ++i) {
        Value *argRegByte = readByte(h);
        callArgs.push_back(getReg(h, argRegByte));
      }

      // Build a fixed-8-arg i64 function type and call through the pointer.
      // Extra args in x0-x7 beyond the callee's actual arity are ignored.
      SmallVector<Type *, 8> paramTys(MAX_CALL_ARGS, I64Ty);
      FunctionType *callFT = FunctionType::get(I64Ty, paramTys, false);

      Value *fnPtrInt = getReg(h, fnRegV);
      Value *fnPtr    = h.CreateIntToPtr(fnPtrInt, callFT->getPointerTo());
      CallInst *callI = h.CreateCall(callFT, fnPtr, callArgs);

      // Store the i64 return value (possibly garbage for void callees, but
      // the dst register is only used by subsequent bytecode for non-void calls).
      setReg(h, dstReg, callI);
    }));

    // ── RET: set R0, jump to retBB ────────────────────────────────────────
    {
      BasicBlock *retHandler = BasicBlock::Create(Ctx, "h_ret", Disp);
      IRBuilder<> h(retHandler);
      Value *valReg = readByte(h);
      Value *rv     = getReg(h, valReg);
      // Store return value into R0
      setReg(h, ConstantInt::get(I8Ty, REG_RETVAL), rv);
      h.CreateBr(retBB);
      addCase(RET, retHandler);
    }

    // ── RET_VOID: jump directly to retVoidBB ─────────────────────────────
    {
      BasicBlock *rvHandler = BasicBlock::Create(Ctx, "h_ret_void", Disp);
      IRBuilder<> h(rvHandler);
      h.CreateBr(retVoidBB);
      addCase(RET_VOID, rvHandler);
    }
  } // end dispatch BB scope

  // ─────────────────────────────────────────────────────────────────────────
  // retBB: read R0 (decrypt from register file) and return it
  // ─────────────────────────────────────────────────────────────────────────
  {
    IRBuilder<> B3(retBB);
    // Use getReg to apply the XOR-decryption; the raw load would return the
    // encrypted value (val ^ regCanary) and produce a wrong return value.
    Value *r0 = getReg(B3, ConstantInt::get(I8Ty, REG_RETVAL));

    Type *retTy = origF.getReturnType();
    if (retTy->isVoidTy()) {
      B3.CreateRetVoid();
    } else {
      Value *retVal;
      if (retTy->isIntegerTy()) {
        retVal = B3.CreateTruncOrBitCast(r0, retTy);
      } else if (retTy->isPointerTy()) {
        retVal = B3.CreateIntToPtr(r0, retTy);
      } else {
        // Fallback: bitcast (may be wrong for floats, but keeps IR valid)
        retVal = B3.CreateTruncOrBitCast(r0, retTy);
      }
      B3.CreateRet(retVal);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // retVoidBB: void return
  // ─────────────────────────────────────────────────────────────────────────
  {
    IRBuilder<> B4(retVoidBB);
    if (origF.getReturnType()->isVoidTy()) {
      B4.CreateRetVoid();
    } else {
      // Non-void function with RET_VOID — return zero
      Value *zero = Constant::getNullValue(origF.getReturnType());
      B4.CreateRet(zero);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // undefBB: unreachable (hit unknown opcode)
  // ─────────────────────────────────────────────────────────────────────────
  {
    IRBuilder<> B5(undefBB);
    B5.CreateUnreachable();
  }

  return Disp;
}

// ─────────────────────────────────────────────────────────────────────────────
// replaceWithThunk — clear original function body, replace with
//   ret dispatcher(args...)
// ─────────────────────────────────────────────────────────────────────────────

void VMPCodeGen::replaceWithThunk(Function &F, Function *dispatcher) {
  // Drop all instruction operand references BEFORE erasing any BasicBlock.
  // Erasing BBs one-by-one without this step leaves later BBs holding uses
  // of Values defined in already-erased BBs, triggering dangling-pointer
  // writes inside Use::set() / removeFromList() and corrupting the heap.
  for (auto &BB : F)
    BB.dropAllReferences();

  // Now safe to remove: no cross-BB uses remain.
  while (!F.empty())
    F.front().eraseFromParent();

  // Build a single-BB thunk that tail-calls the dispatcher
  BasicBlock *bb = BasicBlock::Create(Ctx, "thunk", &F);
  IRBuilder<> B(bb);

  // Forward all arguments
  std::vector<Value *> args;
  for (auto &Arg : F.args())
    args.push_back(&Arg);

  CallInst *call = B.CreateCall(dispatcher->getFunctionType(), dispatcher, args);
  call->setTailCallKind(CallInst::TCK_MustTail);

  if (F.getReturnType()->isVoidTy()) {
    B.CreateRetVoid();
  } else {
    B.CreateRet(call);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// virtualize — public entry point
// ─────────────────────────────────────────────────────────────────────────────

bool VMPCodeGen::virtualize(Function &F,
                             const std::vector<uint8_t> &bc,
                             const std::vector<GlobalValue *> &gvTable,
                             const std::vector<Function *> &callTable,
                             uint64_t bcKey,
                             const armorcomp::vmp::OpcodeMap &opcodeMap) {
  if (bc.empty()) return false;

  GlobalVariable *bcGV    = injectBytecode(F, bc);
  (void)injectBcKey(F, bcKey);                           // store key as module GV
  GlobalVariable *gvTabGV = injectGVTable(F, gvTable);
  Function *dispatcher    = buildDispatcher(F, bcGV, gvTabGV, bc, callTable,
                                            bcKey, opcodeMap);

  if (!dispatcher) return false;

  // Inject "sub" and "mba" annotations for the dispatcher so downstream passes
  // (SubPass, MBAPass) that check llvm.global.annotations automatically process
  // it.  VMP runs before Sub/MBA in the pipeline (see HelloPass.cpp), so these
  // entries are visible when those passes scan the module for annotated functions.
  // Inject "sub" and "mba" so downstream passes automatically process the
  // dispatcher function.  The struct type mirrors existing annotation entries.
  addAnnotationToFunction(M, Ctx, dispatcher, "sub");
  addAnnotationToFunction(M, Ctx, dispatcher, "mba");

  replaceWithThunk(F, dispatcher);
  return true;
}
