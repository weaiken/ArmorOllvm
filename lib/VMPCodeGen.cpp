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
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
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
                                       const armorcomp::vmp::XTEAKey &xteaKey,
                                       const armorcomp::vmp::OpcodeMap &opcodeMap,
                                       uint64_t bcHash) {
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
  Type *I8Ty     = Type::getInt8Ty(Ctx);
  Type *I16Ty    = Type::getInt16Ty(Ctx);
  Type *I32Ty    = Type::getInt32Ty(Ctx);
  Type *I64Ty    = Type::getInt64Ty(Ctx);
  Type *PtrTy    = Type::getInt8PtrTy(Ctx);
  Type *FloatTy  = Type::getFloatTy(Ctx);
  Type *DoubleTy = Type::getDoubleTy(Ctx);
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
  // Canary derivation: take the low byte of xteaKey.k[0], replicate 8 times.
  // Using a single-byte pattern allows CreateMemSet to initialise the whole
  // register file in one call (memset fills at byte granularity).
  uint8_t regByte = static_cast<uint8_t>(xteaKey.k[0] & 0xFF);
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
  // Compute end-of-pool for bounds checking in ALLOCA handler
  Value *stkEnd = B.CreateGEP(I8Ty, stkBase,
                              ConstantInt::get(I64Ty, 4096), "vm.stkend");

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

  // ── vm.dec.loop: XTEA-CTR decryption (8-byte blocks) ─────────────────────
  PHINode *decI;
  {
    IRBuilder<> Ldec(decLoopBB);
    decI = Ldec.CreatePHI(I64Ty, 2, "vm.dec.i");
    decI->addIncoming(ConstantInt::get(I64Ty, 0), entryBB);
    Value *done = Ldec.CreateICmpUGE(decI, ConstantInt::get(I64Ty, bcSize), "dec.done");
    Ldec.CreateCondBr(done, decDoneBB, decBodyBB);
  }

  // ── vm.dec.body: XTEA-CTR decrypt one 8-byte block ──────────────────────
  {
    IRBuilder<> Lb(decBodyBB);
    // Block index = i / 8  (counter value for CTR mode)
    Value *blockIdx = Lb.CreateLShr(decI, ConstantInt::get(I64Ty, 3));
    Value *blockIdx32 = Lb.CreateTrunc(blockIdx, I32Ty);

    // XTEA encrypt counter: v0=blockIdx, v1=0, 32 rounds fully unrolled
    Value *v0 = blockIdx32;
    Value *v1 = ConstantInt::get(I32Ty, 0);
    Constant *keys[4] = {
      ConstantInt::get(I32Ty, xteaKey.k[0]),
      ConstantInt::get(I32Ty, xteaKey.k[1]),
      ConstantInt::get(I32Ty, xteaKey.k[2]),
      ConstantInt::get(I32Ty, xteaKey.k[3])
    };

    for (int round = 0; round < 32; ++round) {
      uint32_t sumVal = static_cast<uint32_t>(round) * 0x9E3779B9U;
      // v0 += (((v1<<4)^(v1>>5)) + v1) ^ (sum + key[sum & 3])
      Value *a = Lb.CreateXor(Lb.CreateShl(v1, ConstantInt::get(I32Ty, 4)),
                               Lb.CreateLShr(v1, ConstantInt::get(I32Ty, 5)));
      Value *b = Lb.CreateAdd(a, v1);
      Value *c = Lb.CreateAdd(ConstantInt::get(I32Ty, sumVal), keys[sumVal & 3]);
      v0 = Lb.CreateAdd(v0, Lb.CreateXor(b, c));

      uint32_t newSum = sumVal + 0x9E3779B9U;
      // v1 += (((v0<<4)^(v0>>5)) + v0) ^ (sum + key[(sum>>11) & 3])
      Value *d = Lb.CreateXor(Lb.CreateShl(v0, ConstantInt::get(I32Ty, 4)),
                               Lb.CreateLShr(v0, ConstantInt::get(I32Ty, 5)));
      Value *e = Lb.CreateAdd(d, v0);
      Value *f = Lb.CreateAdd(ConstantInt::get(I32Ty, newSum),
                               keys[(newSum >> 11) & 3]);
      v1 = Lb.CreateAdd(v1, Lb.CreateXor(e, f));
    }

    // XOR each of 8 keystream bytes with encrypted bytecode
    // Extend v0,v1 to i64 for byte extraction
    Value *v0_64 = Lb.CreateZExt(v0, I64Ty);
    Value *v1_64 = Lb.CreateZExt(v1, I64Ty);
    // Combine into a single 64-bit keystream: v0 is low 32 bits, v1 is high
    Value *ks64 = Lb.CreateOr(v0_64, Lb.CreateShl(v1_64, ConstantInt::get(I64Ty, 32)));

    for (int j = 0; j < 8; ++j) {
      Value *byteIdx = Lb.CreateAdd(decI, ConstantInt::get(I64Ty, j));
      Value *inBounds = Lb.CreateICmpULT(byteIdx, ConstantInt::get(I64Ty, bcSize));

      // Keystream byte
      Value *ksByte = Lb.CreateTrunc(
          Lb.CreateLShr(ks64, ConstantInt::get(I64Ty, j * 8)), I8Ty);

      Value *srcPtr = Lb.CreateGEP(I8Ty, bcGVPtr, byteIdx);
      Value *dstPtr = Lb.CreateGEP(I8Ty, decBufPtr, byteIdx);

      // Conditional decrypt (skip if past bytecode end)
      BasicBlock *doDecBB = BasicBlock::Create(Ctx, "dec.do", Disp);
      BasicBlock *contBB  = BasicBlock::Create(Ctx, "dec.cont", Disp);
      Lb.CreateCondBr(inBounds, doDecBB, contBB);

      {
        IRBuilder<> Ld(doDecBB);
        Value *enc = Ld.CreateLoad(I8Ty, srcPtr);
        Ld.CreateStore(Ld.CreateXor(enc, ksByte), dstPtr);
        Ld.CreateBr(contBB);
      }

      Lb.SetInsertPoint(contBB);
    }

    // Advance loop counter by 8 and back-edge
    Value *iNext = Lb.CreateAdd(decI, ConstantInt::get(I64Ty, 8), "dec.i.next");
    decI->addIncoming(iNext, Lb.GetInsertBlock());
    Lb.CreateBr(decLoopBB);
  }

  // ── vm.dec.done: integrity check then initialise pc & args ───────────────
  {
    IRBuilder<> Bdone(decDoneBB);

    // FNV-1a integrity check over decrypted bytecode
    BasicBlock *hashLoopBB = BasicBlock::Create(Ctx, "vm.hash.loop", Disp);
    BasicBlock *hashBodyBB = BasicBlock::Create(Ctx, "vm.hash.body", Disp);
    BasicBlock *hashDoneBB = BasicBlock::Create(Ctx, "vm.hash.done", Disp);
    BasicBlock *hashFailBB = BasicBlock::Create(Ctx, "vm.hash.fail", Disp);
    BasicBlock *hashPassBB = BasicBlock::Create(Ctx, "vm.hash.pass", Disp);
    Bdone.CreateBr(hashLoopBB);

    PHINode *hI, *hHash;
    {
      IRBuilder<> Hl(hashLoopBB);
      hI = Hl.CreatePHI(I64Ty, 2, "h.i");
      hHash = Hl.CreatePHI(I64Ty, 2, "h.hash");
      hI->addIncoming(ConstantInt::get(I64Ty, 0), decDoneBB);
      hHash->addIncoming(ConstantInt::get(I64Ty, 14695981039346656037ULL), decDoneBB);
      Value *hDone = Hl.CreateICmpEQ(hI, ConstantInt::get(I64Ty, bcSize));
      Hl.CreateCondBr(hDone, hashDoneBB, hashBodyBB);
    }
    {
      IRBuilder<> Hb(hashBodyBB);
      Value *bPtr = Hb.CreateGEP(I8Ty, decBufPtr, hI);
      Value *bVal = Hb.CreateLoad(I8Ty, bPtr);
      Value *bExt = Hb.CreateZExt(bVal, I64Ty);
      Value *hXor = Hb.CreateXor(hHash, bExt);
      Value *hMul = Hb.CreateMul(hXor, ConstantInt::get(I64Ty, 1099511628211ULL));
      Value *hINext = Hb.CreateAdd(hI, ConstantInt::get(I64Ty, 1));
      hI->addIncoming(hINext, hashBodyBB);
      hHash->addIncoming(hMul, hashBodyBB);
      Hb.CreateBr(hashLoopBB);
    }
    {
      IRBuilder<> Hd(hashDoneBB);
      Value *expected = ConstantInt::get(I64Ty, bcHash);
      Value *match = Hd.CreateICmpEQ(hHash, expected, "hash.match");
      Hd.CreateCondBr(match, hashPassBB, hashFailBB);
    }
    {
      IRBuilder<> Hf(hashFailBB);
      Function *trapFn = Intrinsic::getDeclaration(&M, Intrinsic::trap);
      Hf.CreateCall(trapFn);
      Hf.CreateUnreachable();
    }

    // hashPassBB: pc + args initialisation
    IRBuilder<> Bp(hashPassBB);
    Bp.CreateStore(decBufPtr, pcAlloc);

    // Initialise arg registers: regs[i] = (i64) argN
    unsigned argIdx = 0;
    for (auto &Arg : Disp->args()) {
      if (argIdx >= MAX_CALL_ARGS) break;
      Value *argVal;
      if (Arg.getType()->isIntegerTy()) {
        argVal = Bp.CreateZExtOrBitCast(&Arg, I64Ty);
      } else if (Arg.getType()->isPointerTy()) {
        argVal = Bp.CreatePtrToInt(&Arg, I64Ty);
      } else if (Arg.getType()->isFloatTy()) {
        Value *asI32 = Bp.CreateBitCast(&Arg, I32Ty);
        argVal = Bp.CreateZExt(asI32, I64Ty);
      } else if (Arg.getType()->isDoubleTy()) {
        argVal = Bp.CreateBitCast(&Arg, I64Ty);
      } else {
        argVal = ConstantInt::get(I64Ty, 0);
      }
      Value *regPtr = Bp.CreateGEP(
          RegFileTy, regs,
          {ConstantInt::get(I32Ty, 0), ConstantInt::get(I32Ty, argIdx)},
          "arg_reg_ptr");
      Value *encArg = Bp.CreateXor(argVal, regCanaryV, "arg.enc");
      Bp.CreateStore(encArg, regPtr);
      ++argIdx;
    }

    Bp.CreateBr(dispBB);
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

    // ── Handler polymorphism ──────────────────────────────────────────
    // Deterministic LCG seeded from bcKey: each function gets different
    // MBA variants, but the same function always gets the same choice.
    uint64_t polyRng = (static_cast<uint64_t>(xteaKey.k[1]) << 32)
                     | static_cast<uint64_t>(xteaKey.k[0]);
    auto polyChoice = [&]() -> bool {
      polyRng = polyRng * 6364136223846793005ULL + 1442695040888963407ULL;
      return (polyRng >> 32) & 1;
    };

    // ── NOP / Variable-length NOPs ─────────────────────────────────────
    addCase(NOP, mkHandler("nop", [&](IRBuilder<> &) {}));
    addCase(NOP2, mkHandler("nop2", [&](IRBuilder<> &h) {
      readByte(h); // skip 1 padding byte
    }));
    addCase(NOP3, mkHandler("nop3", [&](IRBuilder<> &h) {
      readByte(h); readByte(h); // skip 2 padding bytes
    }));
    addCase(NOP4, mkHandler("nop4", [&](IRBuilder<> &h) {
      readByte(h); readByte(h); readByte(h); // skip 3 padding bytes
    }));

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

    // ── Polymorphic binary ops: 50% chance of MBA-equivalent expression ──
    // ADD: a+b or (a^b) + 2*(a&b)  [carry-add decomposition]
    if (polyChoice()) {
      mkBinOp(ADD, "add", [](IRBuilder<> &h, Value *l, Value *r) {
        Value *x = h.CreateXor(l, r);
        Value *a = h.CreateAnd(l, r);
        Value *tw = h.CreateShl(a, ConstantInt::get(l->getType(), 1));
        return h.CreateAdd(x, tw);
      });
    } else {
      mkBinOp(ADD, "add", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateAdd(l,r); });
    }

    // SUB: a-b or a + (~b) + 1  [two's complement negation]
    if (polyChoice()) {
      mkBinOp(SUB, "sub", [](IRBuilder<> &h, Value *l, Value *r) {
        Value *nb = h.CreateNot(r);
        Value *s = h.CreateAdd(l, nb);
        return h.CreateAdd(s, ConstantInt::get(l->getType(), 1));
      });
    } else {
      mkBinOp(SUB, "sub", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateSub(l,r); });
    }

    mkBinOp(MUL,  "mul",  [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateMul(l,r); });
    mkBinOp(UDIV, "udiv", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateUDiv(l,r); });
    mkBinOp(SDIV, "sdiv", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateSDiv(l,r); });
    mkBinOp(UREM, "urem", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateURem(l,r); });
    mkBinOp(SREM, "srem", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateSRem(l,r); });

    // AND: a&b or ~(~a | ~b)  [De Morgan's law]
    if (polyChoice()) {
      mkBinOp(AND, "and", [](IRBuilder<> &h, Value *l, Value *r) {
        return h.CreateNot(h.CreateOr(h.CreateNot(l), h.CreateNot(r)));
      });
    } else {
      mkBinOp(AND, "and", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateAnd(l,r); });
    }

    // OR: a|b or ~(~a & ~b)  [De Morgan's law]
    if (polyChoice()) {
      mkBinOp(OR, "or", [](IRBuilder<> &h, Value *l, Value *r) {
        return h.CreateNot(h.CreateAnd(h.CreateNot(l), h.CreateNot(r)));
      });
    } else {
      mkBinOp(OR, "or", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateOr(l,r); });
    }

    // XOR: a^b or (a|b) - (a&b)  [set-difference identity]
    if (polyChoice()) {
      mkBinOp(XOR, "xor", [](IRBuilder<> &h, Value *l, Value *r) {
        return h.CreateSub(h.CreateOr(l, r), h.CreateAnd(l, r));
      });
    } else {
      mkBinOp(XOR, "xor", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateXor(l,r); });
    }

    mkBinOp(SHL,  "shl",  [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateShl(l,r); });
    mkBinOp(LSHR, "lshr", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateLShr(l,r); });
    mkBinOp(ASHR, "ashr", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateAShr(l,r); });

    // ── NOT / NEG (NOT is polymorphic) ────────────────────────────────────
    // NOT: ~a or (-a) - 1  [identity: -a = ~a + 1, so ~a = -a - 1]
    if (polyChoice()) {
      addCase(NOT, mkHandler("not", [&](IRBuilder<> &h) {
        Value *dst = readByte(h);
        Value *src = getReg(h, readByte(h));
        Value *neg = h.CreateNeg(src);
        setReg(h, dst, h.CreateSub(neg, ConstantInt::get(I64Ty, 1)));
      }));
    } else {
      addCase(NOT, mkHandler("not", [&](IRBuilder<> &h) {
        Value *dst = readByte(h);
        Value *src = getReg(h, readByte(h));
        setReg(h, dst, h.CreateNot(src));
      }));
    }
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

    // ── Float binary arithmetic (condBr split: f32 / f64) ───────────────────
    auto mkFBinOp = [&](uint8_t opc_val, const std::string &nm,
        std::function<Value*(IRBuilder<>&, Value*, Value*)> opFn) {
      BasicBlock *eBB = BasicBlock::Create(Ctx, "h_" + nm, Disp);
      addCase(opc_val, eBB);
      IRBuilder<> he(eBB);
      Value *dst   = readByte(he);
      Value *lhs64 = getReg(he, readByte(he));
      Value *rhs64 = getReg(he, readByte(he));
      Value *fpW   = readByte(he);
      Value *isF32 = he.CreateICmpEQ(fpW, ConstantInt::get(I8Ty, 32));

      BasicBlock *f32BB = BasicBlock::Create(Ctx, nm + ".f32", Disp);
      {
        IRBuilder<> h32(f32BB);
        Value *lf  = h32.CreateBitCast(h32.CreateTrunc(lhs64, I32Ty), FloatTy);
        Value *rf  = h32.CreateBitCast(h32.CreateTrunc(rhs64, I32Ty), FloatTy);
        Value *r32 = opFn(h32, lf, rf);
        Value *ri  = h32.CreateZExt(h32.CreateBitCast(r32, I32Ty), I64Ty);
        setReg(h32, dst, ri);
        h32.CreateBr(dispBB);
      }

      BasicBlock *f64BB = BasicBlock::Create(Ctx, nm + ".f64", Disp);
      {
        IRBuilder<> h64(f64BB);
        Value *ld  = h64.CreateBitCast(lhs64, DoubleTy);
        Value *rd  = h64.CreateBitCast(rhs64, DoubleTy);
        Value *r64 = opFn(h64, ld, rd);
        Value *ri  = h64.CreateBitCast(r64, I64Ty);
        setReg(h64, dst, ri);
        h64.CreateBr(dispBB);
      }

      he.CreateCondBr(isF32, f32BB, f64BB);
    };

    mkFBinOp(FADD, "fadd", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateFAdd(l,r); });
    mkFBinOp(FSUB, "fsub", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateFSub(l,r); });
    mkFBinOp(FMUL, "fmul", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateFMul(l,r); });
    mkFBinOp(FDIV, "fdiv", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateFDiv(l,r); });
    mkFBinOp(FREM, "frem", [](IRBuilder<> &h, Value *l, Value *r){ return h.CreateFRem(l,r); });

    // ── FNEG (condBr split) ─────────────────────────────────────────────────
    {
      BasicBlock *eBB = BasicBlock::Create(Ctx, "h_fneg", Disp);
      addCase(FNEG, eBB);
      IRBuilder<> he(eBB);
      Value *dst   = readByte(he);
      Value *src64 = getReg(he, readByte(he));
      Value *fpW   = readByte(he);
      Value *isF32 = he.CreateICmpEQ(fpW, ConstantInt::get(I8Ty, 32));

      BasicBlock *f32BB = BasicBlock::Create(Ctx, "fneg.f32", Disp);
      {
        IRBuilder<> h32(f32BB);
        Value *fv  = h32.CreateBitCast(h32.CreateTrunc(src64, I32Ty), FloatTy);
        Value *neg = h32.CreateFNeg(fv);
        Value *ri  = h32.CreateZExt(h32.CreateBitCast(neg, I32Ty), I64Ty);
        setReg(h32, dst, ri);
        h32.CreateBr(dispBB);
      }

      BasicBlock *f64BB = BasicBlock::Create(Ctx, "fneg.f64", Disp);
      {
        IRBuilder<> h64(f64BB);
        Value *dv  = h64.CreateBitCast(src64, DoubleTy);
        Value *neg = h64.CreateFNeg(dv);
        Value *ri  = h64.CreateBitCast(neg, I64Ty);
        setReg(h64, dst, ri);
        h64.CreateBr(dispBB);
      }

      he.CreateCondBr(isF32, f32BB, f64BB);
    }

    // ── FCmp ops (condBr split: f32 / f64) ──────────────────────────────────
    auto mkFCmp = [&](uint8_t opc_val, const std::string &nm,
                      FCmpInst::Predicate pred) {
      BasicBlock *eBB = BasicBlock::Create(Ctx, "h_" + nm, Disp);
      addCase(opc_val, eBB);
      IRBuilder<> he(eBB);
      Value *dst   = readByte(he);
      Value *lhs64 = getReg(he, readByte(he));
      Value *rhs64 = getReg(he, readByte(he));
      Value *fpW   = readByte(he);
      Value *isF32 = he.CreateICmpEQ(fpW, ConstantInt::get(I8Ty, 32));

      BasicBlock *f32BB = BasicBlock::Create(Ctx, nm + ".f32", Disp);
      {
        IRBuilder<> h32(f32BB);
        Value *lf  = h32.CreateBitCast(h32.CreateTrunc(lhs64, I32Ty), FloatTy);
        Value *rf  = h32.CreateBitCast(h32.CreateTrunc(rhs64, I32Ty), FloatTy);
        Value *cmp = h32.CreateFCmp(pred, lf, rf);
        setReg(h32, dst, h32.CreateZExt(cmp, I64Ty));
        h32.CreateBr(dispBB);
      }

      BasicBlock *f64BB = BasicBlock::Create(Ctx, nm + ".f64", Disp);
      {
        IRBuilder<> h64(f64BB);
        Value *ld  = h64.CreateBitCast(lhs64, DoubleTy);
        Value *rd  = h64.CreateBitCast(rhs64, DoubleTy);
        Value *cmp = h64.CreateFCmp(pred, ld, rd);
        setReg(h64, dst, h64.CreateZExt(cmp, I64Ty));
        h64.CreateBr(dispBB);
      }

      he.CreateCondBr(isF32, f32BB, f64BB);
    };

    mkFCmp(FCMP_OEQ, "fcmp.oeq", FCmpInst::FCMP_OEQ);
    mkFCmp(FCMP_ONE, "fcmp.one", FCmpInst::FCMP_ONE);
    mkFCmp(FCMP_OLT, "fcmp.olt", FCmpInst::FCMP_OLT);
    mkFCmp(FCMP_OLE, "fcmp.ole", FCmpInst::FCMP_OLE);
    mkFCmp(FCMP_OGT, "fcmp.ogt", FCmpInst::FCMP_OGT);
    mkFCmp(FCMP_OGE, "fcmp.oge", FCmpInst::FCMP_OGE);
    mkFCmp(FCMP_UEQ, "fcmp.ueq", FCmpInst::FCMP_UEQ);
    mkFCmp(FCMP_UNE, "fcmp.une", FCmpInst::FCMP_UNE);
    mkFCmp(FCMP_ULT, "fcmp.ult", FCmpInst::FCMP_ULT);
    mkFCmp(FCMP_ULE, "fcmp.ule", FCmpInst::FCMP_ULE);
    mkFCmp(FCMP_UGT, "fcmp.ugt", FCmpInst::FCMP_UGT);
    mkFCmp(FCMP_UGE, "fcmp.uge", FCmpInst::FCMP_UGE);
    mkFCmp(FCMP_ORD, "fcmp.ord", FCmpInst::FCMP_ORD);
    mkFCmp(FCMP_UNO, "fcmp.uno", FCmpInst::FCMP_UNO);

    // ── FPEXT: float → double (fixed direction) ─────────────────────────────
    addCase(FPEXT, mkHandler("fpext", [&](IRBuilder<> &h) {
      Value *dst   = readByte(h);
      Value *src64 = getReg(h, readByte(h));
      Value *i32v  = h.CreateTrunc(src64, I32Ty);
      Value *fv    = h.CreateBitCast(i32v, FloatTy);
      Value *dv    = h.CreateFPExt(fv, DoubleTy);
      Value *res   = h.CreateBitCast(dv, I64Ty);
      setReg(h, dst, res);
    }));

    // ── FPTRUNC: double → float (fixed direction) ───────────────────────────
    addCase(FPTRUNC, mkHandler("fptrunc", [&](IRBuilder<> &h) {
      Value *dst   = readByte(h);
      Value *src64 = getReg(h, readByte(h));
      Value *dv    = h.CreateBitCast(src64, DoubleTy);
      Value *fv    = h.CreateFPTrunc(dv, FloatTy);
      Value *i32v  = h.CreateBitCast(fv, I32Ty);
      Value *res   = h.CreateZExt(i32v, I64Ty);
      setReg(h, dst, res);
    }));

    // ── FPTOSI: float/double → signed i64 (condBr split) ───────────────────
    {
      BasicBlock *eBB = BasicBlock::Create(Ctx, "h_fptosi", Disp);
      addCase(FPTOSI, eBB);
      IRBuilder<> he(eBB);
      Value *dst   = readByte(he);
      Value *src64 = getReg(he, readByte(he));
      Value *fpW   = readByte(he);
      Value *isF32 = he.CreateICmpEQ(fpW, ConstantInt::get(I8Ty, 32));

      BasicBlock *f32BB = BasicBlock::Create(Ctx, "fptosi.f32", Disp);
      {
        IRBuilder<> h32(f32BB);
        Value *fv  = h32.CreateBitCast(h32.CreateTrunc(src64, I32Ty), FloatTy);
        Value *res = h32.CreateFPToSI(fv, I64Ty);
        setReg(h32, dst, res);
        h32.CreateBr(dispBB);
      }
      BasicBlock *f64BB = BasicBlock::Create(Ctx, "fptosi.f64", Disp);
      {
        IRBuilder<> h64(f64BB);
        Value *dv  = h64.CreateBitCast(src64, DoubleTy);
        Value *res = h64.CreateFPToSI(dv, I64Ty);
        setReg(h64, dst, res);
        h64.CreateBr(dispBB);
      }
      he.CreateCondBr(isF32, f32BB, f64BB);
    }

    // ── FPTOUI: float/double → unsigned i64 (condBr split) ──────────────────
    {
      BasicBlock *eBB = BasicBlock::Create(Ctx, "h_fptoui", Disp);
      addCase(FPTOUI, eBB);
      IRBuilder<> he(eBB);
      Value *dst   = readByte(he);
      Value *src64 = getReg(he, readByte(he));
      Value *fpW   = readByte(he);
      Value *isF32 = he.CreateICmpEQ(fpW, ConstantInt::get(I8Ty, 32));

      BasicBlock *f32BB = BasicBlock::Create(Ctx, "fptoui.f32", Disp);
      {
        IRBuilder<> h32(f32BB);
        Value *fv  = h32.CreateBitCast(h32.CreateTrunc(src64, I32Ty), FloatTy);
        Value *res = h32.CreateFPToUI(fv, I64Ty);
        setReg(h32, dst, res);
        h32.CreateBr(dispBB);
      }
      BasicBlock *f64BB = BasicBlock::Create(Ctx, "fptoui.f64", Disp);
      {
        IRBuilder<> h64(f64BB);
        Value *dv  = h64.CreateBitCast(src64, DoubleTy);
        Value *res = h64.CreateFPToUI(dv, I64Ty);
        setReg(h64, dst, res);
        h64.CreateBr(dispBB);
      }
      he.CreateCondBr(isF32, f32BB, f64BB);
    }

    // ── SITOFP: signed i64 → float/double (condBr split) ────────────────────
    {
      BasicBlock *eBB = BasicBlock::Create(Ctx, "h_sitofp", Disp);
      addCase(SITOFP, eBB);
      IRBuilder<> he(eBB);
      Value *dst   = readByte(he);
      Value *src64 = getReg(he, readByte(he));
      Value *fpW   = readByte(he);
      Value *isF32 = he.CreateICmpEQ(fpW, ConstantInt::get(I8Ty, 32));

      BasicBlock *f32BB = BasicBlock::Create(Ctx, "sitofp.f32", Disp);
      {
        IRBuilder<> h32(f32BB);
        Value *fv  = h32.CreateSIToFP(src64, FloatTy);
        Value *ri  = h32.CreateZExt(h32.CreateBitCast(fv, I32Ty), I64Ty);
        setReg(h32, dst, ri);
        h32.CreateBr(dispBB);
      }
      BasicBlock *f64BB = BasicBlock::Create(Ctx, "sitofp.f64", Disp);
      {
        IRBuilder<> h64(f64BB);
        Value *dv  = h64.CreateSIToFP(src64, DoubleTy);
        Value *ri  = h64.CreateBitCast(dv, I64Ty);
        setReg(h64, dst, ri);
        h64.CreateBr(dispBB);
      }
      he.CreateCondBr(isF32, f32BB, f64BB);
    }

    // ── UITOFP: unsigned i64 → float/double (condBr split) ──────────────────
    {
      BasicBlock *eBB = BasicBlock::Create(Ctx, "h_uitofp", Disp);
      addCase(UITOFP, eBB);
      IRBuilder<> he(eBB);
      Value *dst   = readByte(he);
      Value *src64 = getReg(he, readByte(he));
      Value *fpW   = readByte(he);
      Value *isF32 = he.CreateICmpEQ(fpW, ConstantInt::get(I8Ty, 32));

      BasicBlock *f32BB = BasicBlock::Create(Ctx, "uitofp.f32", Disp);
      {
        IRBuilder<> h32(f32BB);
        Value *fv  = h32.CreateUIToFP(src64, FloatTy);
        Value *ri  = h32.CreateZExt(h32.CreateBitCast(fv, I32Ty), I64Ty);
        setReg(h32, dst, ri);
        h32.CreateBr(dispBB);
      }
      BasicBlock *f64BB = BasicBlock::Create(Ctx, "uitofp.f64", Disp);
      {
        IRBuilder<> h64(f64BB);
        Value *dv  = h64.CreateUIToFP(src64, DoubleTy);
        Value *ri  = h64.CreateBitCast(dv, I64Ty);
        setReg(h64, dst, ri);
        h64.CreateBr(dispBB);
      }
      he.CreateCondBr(isF32, f32BB, f64BB);
    }

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

    // ── ALLOCA: bump-pointer allocation with bounds check ─────────────────
    addCase(ALLOCA, mkHandler("alloca", [&](IRBuilder<> &h) {
      Value *dst   = readByte(h);
      Value *sz32  = readU32(h);
      Value *sz64  = h.CreateZExt(sz32, I64Ty);
      Value *bp    = h.CreateLoad(PtrTy, vmStkBP, "bp");
      Value *nbp   = h.CreateGEP(I8Ty, bp, sz64, "nbp");
      // Bounds check: if nbp > stkEnd, overflow — clamp to bp (no-op alloca)
      Value *overflow = h.CreateICmpUGT(nbp, stkEnd, "alloca.ovf");
      Value *safeNbp  = h.CreateSelect(overflow, bp, nbp);
      h.CreateStore(safeNbp, vmStkBP);
      // On overflow return null (0); otherwise return allocated base
      Value *ptr64   = h.CreatePtrToInt(bp, I64Ty);
      Value *safePtr = h.CreateSelect(overflow,
                                      ConstantInt::get(I64Ty, 0), ptr64);
      setReg(h, dst, safePtr);
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
          else if (paramTy->isFloatTy()) {
            Value *asI32 = hc.CreateTrunc(argVal64, I32Ty);
            coerced = hc.CreateBitCast(asI32, FloatTy);
          } else if (paramTy->isDoubleTy())
            coerced = hc.CreateBitCast(argVal64, DoubleTy);
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
        else if (retTy->isFloatTy()) {
          Value *asI32 = hc.CreateBitCast(callI, I32Ty);
          retVal64 = hc.CreateZExt(asI32, I64Ty);
        } else if (retTy->isDoubleTy())
          retVal64 = hc.CreateBitCast(callI, I64Ty);
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

    // ── ADD_I32: Rdst = Rsrc + sext(imm32) ─────────────────────────────
    addCase(ADD_I32, mkHandler("add_i32", [&](IRBuilder<> &h) {
      Value *dst = readByte(h);
      Value *src = readByte(h);
      Value *imm = readI32(h);
      Value *immExt = h.CreateSExt(imm, I64Ty);
      Value *v = getReg(h, src);
      setReg(h, dst, h.CreateAdd(v, immExt));
    }));

    // ── SUB_I32: Rdst = Rsrc - sext(imm32) ─────────────────────────────
    addCase(SUB_I32, mkHandler("sub_i32", [&](IRBuilder<> &h) {
      Value *dst = readByte(h);
      Value *src = readByte(h);
      Value *imm = readI32(h);
      Value *immExt = h.CreateSExt(imm, I64Ty);
      Value *v = getReg(h, src);
      setReg(h, dst, h.CreateSub(v, immExt));
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
    // ── Dead Handler Injection ─────────────────────────────────────────
    // 16 fake unreachable handlers using 4 templates.  These BBs look
    // like real handlers to IDA but are never reached (the lifter never
    // emits these semantic opcodes, and Fisher-Yates scramble hides the
    // mapping).  Increases handler count from ~48 → ~64.
    {
      static const uint8_t fakeOpcodes[] = {
        0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
        0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E
      };
      for (unsigned fi = 0; fi < 16; ++fi) {
        uint8_t fakeOpc = fakeOpcodes[fi];
        std::string fn = "op" + std::to_string((int)fakeOpc);
        switch (fi % 4) {
        case 0: // Fake Binary: readByte×3 → add → setReg
          addCase(fakeOpc, mkHandler(fn, [&](IRBuilder<> &h) {
            Value *d = readByte(h); Value *a = getReg(h, readByte(h));
            Value *b = getReg(h, readByte(h));
            setReg(h, d, h.CreateAdd(a, b));
          }));
          break;
        case 1: // Fake Load: readByte×2 → load i64 → setReg
          addCase(fakeOpc, mkHandler(fn, [&](IRBuilder<> &h) {
            Value *d = readByte(h); Value *p = getReg(h, readByte(h));
            Value *ptr = h.CreateIntToPtr(p, I64Ty->getPointerTo());
            setReg(h, d, h.CreateLoad(I64Ty, ptr));
          }));
          break;
        case 2: // Fake Compare: readByte×3 → icmp slt → setReg
          addCase(fakeOpc, mkHandler(fn, [&](IRBuilder<> &h) {
            Value *d = readByte(h); Value *a = getReg(h, readByte(h));
            Value *b = getReg(h, readByte(h));
            Value *c = h.CreateICmpSLT(a, b);
            setReg(h, d, h.CreateZExt(c, I64Ty));
          }));
          break;
        case 3: // Fake Jump: readByte → readI32 → branch back (no-op)
          addCase(fakeOpc, mkHandler(fn, [&](IRBuilder<> &h) {
            (void)readByte(h); (void)readI32(h);
            // handler body does nothing useful, loops back to dispatch
          }));
          break;
        }
      }
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
      } else if (retTy->isFloatTy()) {
        Value *asI32 = B3.CreateTrunc(r0, I32Ty);
        retVal = B3.CreateBitCast(asI32, retTy);
      } else if (retTy->isDoubleTy()) {
        retVal = B3.CreateBitCast(r0, retTy);
      } else {
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
                             const armorcomp::vmp::XTEAKey &xteaKey,
                             const armorcomp::vmp::OpcodeMap &opcodeMap,
                             uint64_t bcHash) {
  if (bc.empty()) return false;

  // Derive a 64-bit key for the bcKey GV (backward-compat with key global).
  uint64_t bcKeyLegacy = (static_cast<uint64_t>(xteaKey.k[1]) << 32)
                        | static_cast<uint64_t>(xteaKey.k[0]);
  GlobalVariable *bcGV    = injectBytecode(F, bc);
  (void)injectBcKey(F, bcKeyLegacy);
  GlobalVariable *gvTabGV = injectGVTable(F, gvTable);
  Function *dispatcher    = buildDispatcher(F, bcGV, gvTabGV, bc, callTable,
                                            xteaKey, opcodeMap, bcHash);

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
