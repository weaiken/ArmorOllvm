#pragma once
//===----------------------------------------------------------------------===//
// ArmorComp — VMPLifter
//
// Translates LLVM IR functions into VMP bytecode (see VMPOpcodes.h).
//
// ── Overview ──────────────────────────────────────────────────────────────
// VMPLifter::lift(F) performs a single-pass linearization of F's CFG:
//
//   1. Collect all BBs in a stable order (RPO / reverse post-order).
//   2. For each BB:
//      a. Record its bytecode offset in bbOffset[].
//      b. Handle PHI nodes: for each PHI in this BB, we lower it by
//         inserting MOV instructions at the END of each predecessor BB.
//         (Handled via a pre-pass that builds a phi_mov table.)
//      c. For each non-PHI instruction, call emitInstr().
//   3. After all BBs are emitted, patch forward references (JMP / JCC targets
//      that were emitted before the target BB's offset was known).
//
// ── PHI Lowering ──────────────────────────────────────────────────────────
// PHI nodes are the only SSA construct that does not map to a single VM
// instruction.  Strategy:
//   - In a pre-pass, scan all PHI nodes in each BB.
//   - Build a map: predBB → list of (Rdst, Rsrc) MOV pairs to insert.
//   - When emitting a predecessor BB's terminator, first flush those MOVs,
//     then emit the terminator (JMP / JCC).
//
// ── Unsupported Instructions ──────────────────────────────────────────────
// If the lifter encounters an instruction it cannot translate (e.g. LLVM
// intrinsics, GEP with non-constant multi-level indices, FCMP, etc.), it
// returns std::nullopt.  VMPPass then skips the function and logs a warning.
//
// Supported instructions:
//   BinaryOperator (add/sub/mul/udiv/sdiv/urem/srem/and/or/xor/shl/lshr/ashr)
//   ICmpInst       (eq/ne/slt/sle/sgt/sge/ult/ule/ugt/uge)
//   BranchInst     (unconditional + conditional)
//   PHINode        (lowered via pre-pass)
//   LoadInst       (i8/i16/i32/i64, non-volatile only — volatile kills DCE)
//   StoreInst      (i8/i16/i32/i64)
//   AllocaInst     (i8/i16/i32/i64/ptr sized, constant size only)
//   ReturnInst     (void + non-void)
//   CallInst       (direct calls to known functions, up to 8 args)
//   ZExtInst / SExtInst / TruncInst
//   PtrToIntInst / IntToPtrInst
//   BitCastInst    (type-pun, treated as MOV_RR)
//   SelectInst     (ternary)
//   GetElementPtrInst (single-level, byte-granularity via GEP8)
//   UnaryOperator  (fneg → unsupported; but int neg via sub 0,x is supported)
//
//===----------------------------------------------------------------------===//

#include "ArmorComp/VMPOpcodes.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Value.h"

#include <cstdint>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace armorcomp {
namespace vmp {

class VMPLifter {
public:
  /// Translate \p F to VMP bytecode.
  /// Returns the bytecode on success, std::nullopt if F contains
  /// instructions that the lifter cannot handle.
  std::optional<std::vector<uint8_t>> lift(llvm::Function &F);

  /// After a successful lift(), returns the number of virtual instructions
  /// emitted (useful for logging).
  unsigned virtualInstrCount() const { return virtInstrCount; }

  /// Table of GlobalValues referenced by the bytecode (populated by lift()).
  /// VMPCodeGen uses this to build the runtime gvtab companion global.
  const std::vector<llvm::GlobalValue *> &getGVTable() const { return gvTable; }

  /// Table of directly-called Functions referenced by the bytecode (populated
  /// by lift()).  VMPCodeGen uses this to build typed CALL_D case BBs.
  const std::vector<llvm::Function *> &getCallTable() const { return callTable; }

private:
  // ── Virtual register allocation ─────────────────────────────────────────
  // Each LLVM SSA Value is assigned a unique 8-bit virtual register index.
  std::unordered_map<llvm::Value *, uint8_t> vregMap;
  uint8_t nextVReg = 0;

  // Allocate or look up the virtual register for V.
  uint8_t allocVReg(llvm::Value *V);
  // Look up a previously allocated virtual register. Asserts if not found.
  uint8_t getVReg(llvm::Value *V);
  // True if V already has a virtual register assigned.
  bool hasVReg(llvm::Value *V) const;

  // ── BB offset table + forward reference patching ─────────────────────────
  std::unordered_map<llvm::BasicBlock *, uint32_t> bbOffset;

  // Each entry: (position_in_bc_of_offset32_field, target_BB).
  // After all BBs are emitted, we fill in the actual relative offset.
  struct FwdRef {
    uint32_t patchPos;          // position of the offset32 field to patch
    uint32_t instrEndPos;       // position immediately after the instruction
    llvm::BasicBlock *targetBB;
  };
  std::vector<FwdRef> fwdRefs;

  // ── PHI lowering: predBB → (Rdst, Rsrc) pairs ────────────────────────────
  // Populated by lowerPHIs() before the main emission pass.
  // phiMovs: temporary scratch (unused after lowerPHIs completes).
  std::unordered_map<llvm::BasicBlock *,
                     std::vector<std::pair<uint8_t, uint8_t>>> phiMovs;
  // phiMovsValues: predBB → vector<(dstReg, incomingValue*)>
  // Used by emitPhiMovs() to materialise constants at emit time.
  std::unordered_map<llvm::BasicBlock *,
                     std::vector<std::pair<uint8_t, llvm::Value *>>>
      phiMovsValues;

  // ── GlobalValue table ────────────────────────────────────────────────────
  // GVs referenced by MOV_GV instructions; index = IDX16 operand.
  std::vector<llvm::GlobalValue *> gvTable;
  // Look up or insert a GlobalValue; returns its uint16_t index.
  uint16_t lookupGV(llvm::GlobalValue *GV);

  // ── Call table ───────────────────────────────────────────────────────────
  // Direct callees referenced by CALL_D instructions; index = IDX16 operand.
  std::vector<llvm::Function *> callTable;
  // Look up or insert a callee Function; returns its uint16_t index.
  uint16_t lookupCall(llvm::Function *F);

  // ── DataLayout pointer (set at the start of lift()) ──────────────────────
  const llvm::DataLayout *DLPtr = nullptr;

  // ── Stats ────────────────────────────────────────────────────────────────
  unsigned virtInstrCount = 0;

  // ── Junk bytecode injection ───────────────────────────────────────────────
  // Deterministic RNG state for injecting dead JMP+NOP blocks before each BB.
  // Seeded from the function name so each function gets unique junk patterns.
  uint64_t junkRng = 0;

  // ── Internal helpers ─────────────────────────────────────────────────────

  // Pre-pass: build phiMovs table from all PHI nodes in F.
  // Assigns virtual registers to all PHI dests and their incoming values.
  // Returns false if any PHI incoming value is an unhandled constant type.
  bool lowerPHIs(llvm::Function &F, std::vector<uint8_t> &bc);

  // Materialise a Value into a virtual register.
  // If V is a ConstantInt, emits a MOV_Ixxx instruction.
  // If V is a pointer-typed ConstantExpr (null), emits MOV_I64 0.
  // Otherwise looks up vregMap.
  // Returns the virtual register holding the value.
  // Returns UINT8_MAX on failure (unsupported constant type).
  uint8_t materialise(std::vector<uint8_t> &bc, llvm::Value *V);

  // Emit the phi-MOV pairs for predecessor predBB (called before terminator).
  void emitPhiMovs(std::vector<uint8_t> &bc, llvm::BasicBlock *predBB);

  // Emit phi-MOV pairs only for the (predBB → succBB) edge.
  // Used by conditional-branch trampoline generation.
  void emitPhiMovsForEdge(std::vector<uint8_t> &bc,
                           llvm::BasicBlock *predBB, llvm::BasicBlock *succBB);

  // Returns true if the (predBB → succBB) edge has any phi nodes to satisfy.
  bool edgeHasPhiMovs(llvm::BasicBlock *predBB, llvm::BasicBlock *succBB);

  // Emit a JMP or JCC for BranchInst.
  void emitBranch(std::vector<uint8_t> &bc, llvm::BranchInst &BI,
                  llvm::BasicBlock *curBB);

  // Handle LLVM intrinsic calls:
  //   - no-op intrinsics (lifetime, dbg, assume) → skip, return true
  //   - memory intrinsics (memcpy/memmove/memset) → lower to CALL_D
  //   - other intrinsics → return false (unsupported)
  bool handleIntrinsic(std::vector<uint8_t> &bc, llvm::CallInst &CI);

  // Emit a single non-PHI, non-terminator instruction.
  // Returns false if the instruction is unsupported.
  bool emitInstr(std::vector<uint8_t> &bc, llvm::Instruction &I);

  // Patch all forward references recorded in fwdRefs[].
  // Called after all BBs have been emitted.
  void patchForwardRefs(std::vector<uint8_t> &bc);

  // Record a forward reference at the current end of bc.
  // The offset32 field will be written at patchPos.
  // instrEndPos is the position of the byte immediately after the instruction.
  void addFwdRef(uint32_t patchPos, uint32_t instrEndPos,
                 llvm::BasicBlock *targetBB) {
    fwdRefs.push_back({patchPos, instrEndPos, targetBB});
  }

  // Get bit-width of an LLVM Type (returns 0 for unsupported).
  uint8_t getBitWidth(llvm::Type *T) const;

  // Reset all state for a fresh lift.
  void reset();
};

} // namespace vmp
} // namespace armorcomp
