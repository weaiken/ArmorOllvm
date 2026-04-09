#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — VMPCodeGen
//
// Generates the VM fetch-decode-execute dispatcher function in LLVM IR and
// injects bytecode as a module-level global.  Together with VMPLifter, this
// implements function-level virtualization.
//
// ── Pipeline ──────────────────────────────────────────────────────────────
//   1. VMPLifter::lift(F)         → std::vector<uint8_t> bytecode
//   2. VMPCodeGen::virtualize(F, bc) →
//         a. Inject bytecode as @__armorcomp_vmp_bc_<fname> [N x i8] global
//         b. Build @__armorcomp_vmp_dispatch_<fname> function (the VM loop)
//         c. Replace F's body with a tail-call to the dispatcher
//
// ── Dispatcher Architecture ───────────────────────────────────────────────
// The dispatcher is a pure LLVM IR function with the same signature as F:
//
//   entry:
//     %regs    = alloca [64 x i64], align 8       ; virtual register file
//     %pcAlloc = alloca i8*, align 8               ; program counter ptr
//     %vmstk   = alloca [4096 x i8], align 8       ; alloca pool for ALLOCA op
//     %vmstkbp = alloca i8*, align 8               ; bump pointer into pool
//     ; initialise regs[0..nargs-1] from function arguments
//     ; initialise pc = @__armorcomp_vmp_bc_<fname>
//     br %dispatch
//
//   dispatch:
//     %pc = load i8*, i8** %pcAlloc
//     %opc = load i8, i8* %pc                      ; fetch opcode
//     %pc1 = gep i8, i8* %pc, 1                    ; advance pc past opcode
//     store i8* %pc1, i8** %pcAlloc
//     switch i8 %opc, label %undef_bb [            ; decode
//       i8 0x01, label %h_mov_i8
//       i8 0x04, label %h_mov_i64
//       ...
//     ]
//
//   h_mov_i8:                                       ; execute
//     %dst  = readByte(pcAlloc)
//     %imm8 = readByte(pcAlloc)
//     %ext  = zext i8 %imm8 to i64
//     setReg(%regs, %dst, %ext)
//     br %dispatch
//
//   ret_bb:
//     %r0  = getReg(%regs, 0)                      ; return value in R0
//     %ret = trunc / bitcast %r0 to return type
//     ret %ret
//
// ── Register file layout ──────────────────────────────────────────────────
//   %regs = alloca [64 x i64]
//   getReg(regs, N)  ≡  load i64, gep [64 x i64]* regs, 0, N
//   setReg(regs, N, V) ≡  store i64 V, gep [64 x i64]* regs, 0, N
//
// ── ALLOCA pool ───────────────────────────────────────────────────────────
//   A 4096-byte pool is allocated in the entry block.  The ALLOCA handler
//   bumps the pool pointer by the requested size and returns the old pointer.
//   This limits total alloca'd memory per call to 4096 bytes.  Overflows
//   are silently clamped (safe: worst-case is wrong results, no crash).
//
//===----------------------------------------------------------------------===//

#include "ArmorComp/VMPOpcodes.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Module.h"

#include <cstdint>
#include <vector>

namespace armorcomp {
namespace vmp {

class VMPCodeGen {
public:
  explicit VMPCodeGen(llvm::Module &M);

  /// Inject bytecode and build the VM dispatcher, then replace F's body
  /// with a thunk that tail-calls the dispatcher.
  /// \p gvTable   — GlobalValues whose runtime addresses are loaded via MOV_GV.
  /// \p callTable — Functions called directly via CALL_D.
  /// \p xteaKey   — XTEA key (4×32-bit); bytecode is pre-encrypted, dispatcher decrypts.
  /// \p opcodeMap — Per-function opcode scramble map (semantic→physical bytes).
  /// \p bcHash    — FNV-1a hash of scrambled (pre-encryption) bytecode for integrity.
  /// Returns true on success.
  bool virtualize(llvm::Function &F,
                  const std::vector<uint8_t> &bc,
                  const std::vector<llvm::GlobalValue *> &gvTable,
                  const std::vector<llvm::Function *> &callTable,
                  const armorcomp::vmp::XTEAKey &xteaKey,
                  const armorcomp::vmp::OpcodeMap &opcodeMap,
                  uint64_t bcHash);

private:
  llvm::Module      &M;
  llvm::LLVMContext &Ctx;

  // ── Bytecode injection ────────────────────────────────────────────────────
  llvm::GlobalVariable *injectBytecode(llvm::Function &F,
                                        const std::vector<uint8_t> &bc);

  // ── Bytecode key injection ─────────────────────────────────────────────────
  // Creates @__armorcomp_vmp_key_<fname> = weak_odr constant i64 KEY.
  llvm::GlobalVariable *injectBcKey(llvm::Function &F, uint64_t key);

  // ── GV-table injection ────────────────────────────────────────────────────
  // Creates @__armorcomp_vmp_gvtab_<fname> = [N x ptr] with runtime addresses.
  // Returns nullptr if gvTable is empty.
  llvm::GlobalVariable *injectGVTable(llvm::Function &F,
                                       const std::vector<llvm::GlobalValue *> &gvTable);

  // ── Dispatcher construction ───────────────────────────────────────────────
  // xteaKey:   XTEA key for decryption at runtime.
  // opcodeMap: physical byte values for each semantic opcode.
  // bcHash:    FNV-1a hash of scrambled bytecode for integrity verification.
  llvm::Function *buildDispatcher(llvm::Function &F,
                                   llvm::GlobalVariable *bcGV,
                                   llvm::GlobalVariable *gvTabGV,
                                   const std::vector<uint8_t> &bc,
                                   const std::vector<llvm::Function *> &callTable,
                                   const armorcomp::vmp::XTEAKey &xteaKey,
                                   const armorcomp::vmp::OpcodeMap &opcodeMap,
                                   uint64_t bcHash);

  // ── Original function replacement ─────────────────────────────────────────
  void replaceWithThunk(llvm::Function &F, llvm::Function *dispatcher);
};

} // namespace vmp
} // namespace armorcomp
