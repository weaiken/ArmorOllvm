//===----------------------------------------------------------------------===//
// ArmorComp — VMPLifter
// Translates LLVM IR functions into VMP bytecode.
// See include/ArmorComp/VMPLifter.h for design documentation.
//===----------------------------------------------------------------------===//

#include "ArmorComp/VMPLifter.h"
#include "ArmorComp/VMPOpcodes.h"

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/Support/raw_ostream.h"

#include <cassert>
#include <cstring>

using namespace llvm;
using namespace armorcomp::vmp;

// ─────────────────────────────────────────────────────────────────────────────
// Register allocation helpers
// ─────────────────────────────────────────────────────────────────────────────

void VMPLifter::reset() {
  vregMap.clear();
  bbOffset.clear();
  fwdRefs.clear();
  phiMovs.clear();
  phiMovsValues.clear();
  gvTable.clear();
  callTable.clear();
  nextVReg = 0;
  virtInstrCount = 0;
  junkRng = 0;
}

uint8_t VMPLifter::allocVReg(Value *V) {
  auto it = vregMap.find(V);
  if (it != vregMap.end()) return it->second;
  assert(nextVReg < NUM_REGS && "VMP: ran out of virtual registers");
  uint8_t r = nextVReg++;
  vregMap[V] = r;
  return r;
}

uint8_t VMPLifter::getVReg(Value *V) {
  auto it = vregMap.find(V);
  assert(it != vregMap.end() && "VMP: value has no virtual register");
  return it->second;
}

bool VMPLifter::hasVReg(Value *V) const {
  return vregMap.count(V) > 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// getBitWidth — map LLVM Type → bit width for ZEXT/SEXT/TRUNC / LOAD/STORE
// ─────────────────────────────────────────────────────────────────────────────

uint8_t VMPLifter::getBitWidth(Type *T) const {
  if (auto *IT = dyn_cast<IntegerType>(T))
    return static_cast<uint8_t>(IT->getBitWidth());
  if (T->isPointerTy())
    return DLPtr ? static_cast<uint8_t>(DLPtr->getPointerSizeInBits()) : 64;
  return 0;    // unsupported
}

// ─────────────────────────────────────────────────────────────────────────────
// materialise — get a virtual register holding the given Value, emitting
// a load-immediate instruction if V is a constant.
// Returns UINT8_MAX on failure.
// ─────────────────────────────────────────────────────────────────────────────

uint8_t VMPLifter::materialise(std::vector<uint8_t> &bc, Value *V) {
  // Already in a register?
  if (hasVReg(V)) return getVReg(V);

  // ConstantInt: emit MOV_Ixxx, optionally obfuscated via NOT-chain.
  // For non-zero constants (50% probability), instead of:
  //   MOV_IMM dst, K
  // emit:
  //   MOV_IMM tmp, ~K    ; bytecode stores ~K, not K
  //   NOT     dst, tmp   ; dst = ~~K = K
  // A static bytecode analyser sees ~K in the immediate field and must know
  // the NOT-chain rule to recover the original value.
  if (auto *CI = dyn_cast<ConstantInt>(V)) {
    uint64_t imm64 = CI->getZExtValue();
    uint8_t r = allocVReg(V);
    xorshift64step(junkRng);
    bool useNOT = (imm64 != 0) && (junkRng & 1) && (nextVReg < NUM_REGS - 1);
    if (useNOT) {
      uint8_t tmp = nextVReg++; // anonymous scratch register (not in vregMap)
      emitMOV_IMM(bc, tmp, ~imm64);
      emit2R(bc, NOT, r, tmp);
      virtInstrCount += 2;
    } else {
      emitMOV_IMM(bc, r, imm64);
      ++virtInstrCount;
    }
    return r;
  }

  // ConstantPointerNull: treat as 0
  if (isa<ConstantPointerNull>(V)) {
    uint8_t r = allocVReg(V);
    emitMOV_I8(bc, r, 0);
    ++virtInstrCount;
    return r;
  }

  // UndefValue / PoisonValue: materialise as 0 (safe no-op for our purposes)
  if (isa<UndefValue>(V) || isa<PoisonValue>(V)) {
    uint8_t r = allocVReg(V);
    emitMOV_I8(bc, r, 0);
    ++virtInstrCount;
    return r;
  }

  // GlobalValue (global variable, function) — runtime address via gvtab
  if (auto *GV = dyn_cast<GlobalValue>(V)) {
    uint16_t idx = lookupGV(GV);
    uint8_t dst = allocVReg(V);
    emitMOV_GV(bc, dst, idx);
    ++virtInstrCount;
    return dst;
  }

  // ConstantExpr — handle common cases that wrap a GlobalValue
  if (auto *CE = dyn_cast<ConstantExpr>(V)) {
    unsigned op = CE->getOpcode();
    // BitCast / PtrToInt / IntToPtr over a GV — alias the underlying register
    if (op == Instruction::BitCast ||
        op == Instruction::PtrToInt ||
        op == Instruction::IntToPtr) {
      uint8_t src = materialise(bc, CE->getOperand(0));
      if (src == UINT8_MAX) return UINT8_MAX;
      vregMap[V] = src; // reuse the same register
      return src;
    }
    // GEP over a constant GlobalValue base with all-constant indices
    if (op == Instruction::GetElementPtr) {
      auto *GEPop = cast<GEPOperator>(CE);
      APInt byteOffset(64, 0);
      if (!DLPtr || !GEPop->accumulateConstantOffset(*DLPtr, byteOffset))
        return UINT8_MAX;
      auto *baseGV = dyn_cast<GlobalValue>(
          GEPop->getPointerOperand()->stripPointerCasts());
      if (!baseGV) return UINT8_MAX;
      uint16_t gvIdx = lookupGV(baseGV);
      uint8_t dst = allocVReg(V);
      if (byteOffset.isZero()) {
        emitMOV_GV(bc, dst, gvIdx);
        ++virtInstrCount;
      } else {
        uint8_t baseReg = nextVReg++; assert(baseReg < NUM_REGS);
        uint8_t offReg  = nextVReg++; assert(offReg < NUM_REGS);
        emitMOV_GV(bc, baseReg, gvIdx);
        emitMOV_IMM(bc, offReg, byteOffset.getZExtValue());
        emitGEP8(bc, dst, baseReg, offReg);
        virtInstrCount += 3;
      }
      return dst;
    }
    return UINT8_MAX; // unsupported ConstantExpr kind
  }

  return UINT8_MAX; // unsupported constant kind
}

// ── lookupGV / lookupCall ─────────────────────────────────────────────────────

uint16_t VMPLifter::lookupGV(GlobalValue *GV) {
  for (uint16_t i = 0; i < static_cast<uint16_t>(gvTable.size()); ++i)
    if (gvTable[i] == GV) return i;
  uint16_t idx = static_cast<uint16_t>(gvTable.size());
  gvTable.push_back(GV);
  return idx;
}

uint16_t VMPLifter::lookupCall(Function *F) {
  for (uint16_t i = 0; i < static_cast<uint16_t>(callTable.size()); ++i)
    if (callTable[i] == F) return i;
  uint16_t idx = static_cast<uint16_t>(callTable.size());
  callTable.push_back(F);
  return idx;
}

// ─────────────────────────────────────────────────────────────────────────────
// PHI lowering — pre-pass
// ─────────────────────────────────────────────────────────────────────────────

bool VMPLifter::lowerPHIs(Function &F, std::vector<uint8_t> & /*bc unused*/) {
  for (auto &BB : F) {
    for (auto &I : BB) {
      auto *PN = dyn_cast<PHINode>(&I);
      if (!PN) break; // PHIs always come first in a BB

      uint8_t dst = allocVReg(PN);

      for (unsigned i = 0, e = PN->getNumIncomingValues(); i < e; ++i) {
        Value *inVal = PN->getIncomingValue(i);
        BasicBlock *inBB = PN->getIncomingBlock(i);

        // Pre-allocate a register for the incoming value.
        // Constants will be materialised during emitPhiMovs().
        if (auto *CI = dyn_cast<ConstantInt>(inVal)) {
          // Reserve a fresh register; materialise will fill it in.
          (void)CI; // We'll handle this in emitPhiMovs via materialise().
          // Don't pre-allocate — let materialise() pick the register.
        } else if (isa<UndefValue>(inVal) || isa<PoisonValue>(inVal)) {
          // Will materialise as 0.
        } else {
          // SSA value — must already exist in vregMap before we reach
          // this phi mov emission (we emit phi movs right before the
          // terminator of the predecessor). This is guaranteed by
          // RPO traversal: the predecessor is processed before us.
          // (Exception: back-edges in loops — handled by allocVReg.)
          allocVReg(inVal);
        }

        phiMovs[inBB].push_back({dst, UINT8_MAX}); // UINT8_MAX → patch later
      }
    }
  }

  // Clear phiMovs (we rebuilt it per-BB below with the correct src regs).
  // We only needed the register pre-allocation step above.
  phiMovs.clear();

  // Second micro-pass: build the actual (dst, src) pairs per predecessor.
  for (auto &BB : F) {
    for (auto &I : BB) {
      auto *PN = dyn_cast<PHINode>(&I);
      if (!PN) break;

      uint8_t dst = getVReg(PN);
      for (unsigned i = 0, e = PN->getNumIncomingValues(); i < e; ++i) {
        Value *inVal = PN->getIncomingValue(i);
        BasicBlock *inBB = PN->getIncomingBlock(i);

        // src = UINT8_MAX means "constant — materialise at emit time"
        uint8_t src = hasVReg(inVal) ? getVReg(inVal) : UINT8_MAX;

        // Store the incoming value pointer in a parallel table so we can
        // materialise constants at emit time.
        (void)src;

        // We store a (dst, incomingValue*) pair instead so emitPhiMovs can
        // call materialise().  We overload the phiMovs map slightly:
        // the src field of the pair is used as a temporary index into
        // a per-predBB incomingValues vector.
        phiMovs[inBB].push_back({dst, static_cast<uint8_t>(i)});
      }
    }
  }

  // We need a separate map: predBB → vector<(dstReg, incomingValue*)>
  // Rebuild more cleanly:
  phiMovs.clear();
  phiMovsValues.clear();

  for (auto &BB : F) {
    for (auto &I : BB) {
      auto *PN = dyn_cast<PHINode>(&I);
      if (!PN) break;

      uint8_t dst = getVReg(PN);
      for (unsigned i = 0, e = PN->getNumIncomingValues(); i < e; ++i) {
        Value *inVal = PN->getIncomingValue(i);
        BasicBlock *inBB = PN->getIncomingBlock(i);
        phiMovsValues[inBB].push_back({dst, inVal});
      }
    }
  }

  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// emitPhiMovs — called before emitting the terminator of predBB
// ─────────────────────────────────────────────────────────────────────────────

void VMPLifter::emitPhiMovs(std::vector<uint8_t> &bc, BasicBlock *predBB) {
  auto it = phiMovsValues.find(predBB);
  if (it == phiMovsValues.end()) return;

  for (auto &[dst, inVal] : it->second) {
    uint8_t src = materialise(bc, inVal);
    if (src == UINT8_MAX) {
      // Unsupported constant — emit MOV_I8 0 as fallback
      emitMOV_I8(bc, dst, 0);
    } else {
      emitMOV_RR(bc, dst, src);
    }
    ++virtInstrCount;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// emitPhiMovsForEdge — emit phi-MOV pairs only for one (pred → succ) edge
// ─────────────────────────────────────────────────────────────────────────────

void VMPLifter::emitPhiMovsForEdge(std::vector<uint8_t> &bc,
                                    BasicBlock *predBB, BasicBlock *succBB) {
  for (auto &I : *succBB) {
    auto *PN = dyn_cast<PHINode>(&I);
    if (!PN) break; // PHIs are always first in a BB
    int idx = PN->getBasicBlockIndex(predBB);
    if (idx < 0) continue; // this pred is not an incoming edge for this PHI
    if (!vregMap.count(PN)) continue; // PHI not yet allocated (shouldn't happen)
    uint8_t dst = vregMap.at(PN); // allocated by lowerPHIs
    uint8_t src = materialise(bc, PN->getIncomingValue(idx));
    if (src == UINT8_MAX) {
      emitMOV_I8(bc, dst, 0); // fallback for unsupported constants
    } else {
      emitMOV_RR(bc, dst, src);
    }
    ++virtInstrCount;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// edgeHasPhiMovs — true if (predBB → succBB) has any PHI nodes to satisfy
// ─────────────────────────────────────────────────────────────────────────────

bool VMPLifter::edgeHasPhiMovs(BasicBlock *predBB, BasicBlock *succBB) {
  for (auto &I : *succBB) {
    auto *PN = dyn_cast<PHINode>(&I);
    if (!PN) break;
    if (PN->getBasicBlockIndex(predBB) >= 0) return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// emitBranch — handle BranchInst (unconditional or conditional)
// ─────────────────────────────────────────────────────────────────────────────

void VMPLifter::emitBranch(std::vector<uint8_t> &bc, BranchInst &BI,
                           BasicBlock *curBB) {
  if (BI.isUnconditional()) {
    // emit phi movs for successor before the jump
    emitPhiMovs(bc, curBB);

    BasicBlock *succ = BI.getSuccessor(0);
    uint32_t patchPos   = static_cast<uint32_t>(bc.size()) + 1; // after opcode
    uint32_t instrEnd   = static_cast<uint32_t>(bc.size()) + 5; // JMP is 5 bytes
    emitJMP(bc, 0); // placeholder
    ++virtInstrCount;

    auto it = bbOffset.find(succ);
    if (it != bbOffset.end()) {
      // Target already emitted — patch immediately
      int32_t off = static_cast<int32_t>(it->second) -
                    static_cast<int32_t>(instrEnd);
      patch32(bc, patchPos, off);
    } else {
      addFwdRef(patchPos, instrEnd, succ);
    }
  } else {
    // Conditional branch: JCC Rcond offset_true offset_false
    //
    // When a successor has PHI nodes satisfied by this edge, we cannot
    // branch directly to it — we need to emit the PHI movs first.  We
    // accomplish this with inline "trampoline" sequences:
    //
    //   [JCC cond, trueOff, falseOff]
    //   [trampoline_true:  <phi movs for trueSucc edge>  JMP trueSucc ]  ← if needed
    //   [trampoline_false: <phi movs for falseSucc edge> JMP falseSucc]  ← if needed
    //
    // All offsets are relative to instrEnd (byte after the JCC).

    uint8_t condReg = materialise(bc, BI.getCondition());

    BasicBlock *trueSucc  = BI.getSuccessor(0);
    BasicBlock *falseSucc = BI.getSuccessor(1);
    bool needTrueTramp  = edgeHasPhiMovs(curBB, trueSucc);
    bool needFalseTramp = edgeHasPhiMovs(curBB, falseSucc);

    uint32_t jccStart   = static_cast<uint32_t>(bc.size());
    uint32_t instrEnd   = jccStart + 10; // JCC is 10 bytes (opc+reg+off32+off32)
    uint32_t patchTrue  = jccStart + 2;
    uint32_t patchFalse = jccStart + 6;
    emitJCC(bc, condReg, 0, 0); // placeholders
    ++virtInstrCount;

    // ── True edge ──────────────────────────────────────────────────────────
    if (needTrueTramp) {
      // Trampoline starts right here (immediately after JCC).
      int32_t trampOff = static_cast<int32_t>(bc.size()) -
                         static_cast<int32_t>(instrEnd);
      patch32(bc, patchTrue, trampOff);
      emitPhiMovsForEdge(bc, curBB, trueSucc);
      // JMP to trueSucc
      uint32_t jmpPatch = static_cast<uint32_t>(bc.size()) + 1;
      uint32_t jmpEnd   = static_cast<uint32_t>(bc.size()) + 5;
      emitJMP(bc, 0);
      ++virtInstrCount;
      auto it = bbOffset.find(trueSucc);
      if (it != bbOffset.end()) {
        patch32(bc, jmpPatch, static_cast<int32_t>(it->second) -
                              static_cast<int32_t>(jmpEnd));
      } else {
        addFwdRef(jmpPatch, jmpEnd, trueSucc);
      }
    } else {
      auto it = bbOffset.find(trueSucc);
      if (it != bbOffset.end()) {
        patch32(bc, patchTrue, static_cast<int32_t>(it->second) -
                               static_cast<int32_t>(instrEnd));
      } else {
        addFwdRef(patchTrue, instrEnd, trueSucc);
      }
    }

    // ── False edge ─────────────────────────────────────────────────────────
    if (needFalseTramp) {
      int32_t trampOff = static_cast<int32_t>(bc.size()) -
                         static_cast<int32_t>(instrEnd);
      patch32(bc, patchFalse, trampOff);
      emitPhiMovsForEdge(bc, curBB, falseSucc);
      uint32_t jmpPatch = static_cast<uint32_t>(bc.size()) + 1;
      uint32_t jmpEnd   = static_cast<uint32_t>(bc.size()) + 5;
      emitJMP(bc, 0);
      ++virtInstrCount;
      auto it = bbOffset.find(falseSucc);
      if (it != bbOffset.end()) {
        patch32(bc, jmpPatch, static_cast<int32_t>(it->second) -
                              static_cast<int32_t>(jmpEnd));
      } else {
        addFwdRef(jmpPatch, jmpEnd, falseSucc);
      }
    } else {
      auto it = bbOffset.find(falseSucc);
      if (it != bbOffset.end()) {
        patch32(bc, patchFalse, static_cast<int32_t>(it->second) -
                                static_cast<int32_t>(instrEnd));
      } else {
        addFwdRef(patchFalse, instrEnd, falseSucc);
      }
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// emitInstr — emit a single non-PHI instruction
// Returns false if the instruction cannot be handled.
// ─────────────────────────────────────────────────────────────────────────────

bool VMPLifter::emitInstr(std::vector<uint8_t> &bc, Instruction &I) {
  // ── BinaryOperator ────────────────────────────────────────────────────────
  if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
    uint8_t lhs = materialise(bc, BO->getOperand(0));
    uint8_t rhs = materialise(bc, BO->getOperand(1));
    if (lhs == UINT8_MAX || rhs == UINT8_MAX) return false;

    uint8_t dst = allocVReg(BO);
    Opcode op;
    switch (BO->getOpcode()) {
      case Instruction::Add:  op = ADD;  break;
      case Instruction::Sub:  op = SUB;  break;
      case Instruction::Mul:  op = MUL;  break;
      case Instruction::UDiv: op = UDIV; break;
      case Instruction::SDiv: op = SDIV; break;
      case Instruction::URem: op = UREM; break;
      case Instruction::SRem: op = SREM; break;
      case Instruction::And:  op = AND;  break;
      case Instruction::Or:   op = OR;   break;
      case Instruction::Xor:  op = XOR;  break;
      case Instruction::Shl:  op = SHL;  break;
      case Instruction::LShr: op = LSHR; break;
      case Instruction::AShr: op = ASHR; break;
      default: return false;
    }
    emit3R(bc, op, dst, lhs, rhs);
    ++virtInstrCount;
    return true;
  }

  // ── ICmpInst ─────────────────────────────────────────────────────────────
  if (auto *IC = dyn_cast<ICmpInst>(&I)) {
    uint8_t lhs = materialise(bc, IC->getOperand(0));
    uint8_t rhs = materialise(bc, IC->getOperand(1));
    if (lhs == UINT8_MAX || rhs == UINT8_MAX) return false;

    // For signed predicates on sub-64-bit types, the VM's LOAD_8/16/32 handlers
    // zero-extend loaded values to i64.  A 32-bit -5 becomes 0x00000000FFFFFFFB,
    // which is positive as a signed i64 — causing wrong results for SLT/SGT/etc.
    // Fix: emit SEXT for both operands before the comparison so the sign bit is
    // replicated to bit 63 (e.g., -5 i32 → 0xFFFFFFFFFFFFFFFB i64).
    ICmpInst::Predicate pred = IC->getPredicate();
    bool isSigned = (pred == ICmpInst::ICMP_SLT || pred == ICmpInst::ICMP_SLE ||
                     pred == ICmpInst::ICMP_SGT || pred == ICmpInst::ICMP_SGE);
    if (isSigned) {
      uint8_t w = getBitWidth(IC->getOperand(0)->getType());
      if (w > 0 && w < 64) {
        uint8_t sl = nextVReg++;
        if (sl >= NUM_REGS) return false;
        emitSEXT(bc, sl, lhs, w);
        lhs = sl;
        ++virtInstrCount;
        uint8_t sr = nextVReg++;
        if (sr >= NUM_REGS) return false;
        emitSEXT(bc, sr, rhs, w);
        rhs = sr;
        ++virtInstrCount;
      }
    }

    uint8_t dst = allocVReg(IC);
    Opcode op;
    switch (IC->getPredicate()) {
      case ICmpInst::ICMP_EQ:  op = ICMP_EQ;  break;
      case ICmpInst::ICMP_NE:  op = ICMP_NE;  break;
      case ICmpInst::ICMP_SLT: op = ICMP_SLT; break;
      case ICmpInst::ICMP_SLE: op = ICMP_SLE; break;
      case ICmpInst::ICMP_SGT: op = ICMP_SGT; break;
      case ICmpInst::ICMP_SGE: op = ICMP_SGE; break;
      case ICmpInst::ICMP_ULT: op = ICMP_ULT; break;
      case ICmpInst::ICMP_ULE: op = ICMP_ULE; break;
      case ICmpInst::ICMP_UGT: op = ICMP_UGT; break;
      case ICmpInst::ICMP_UGE: op = ICMP_UGE; break;
      default: return false;
    }
    emit3R(bc, op, dst, lhs, rhs);
    ++virtInstrCount;
    return true;
  }

  // ── ZExtInst ─────────────────────────────────────────────────────────────
  if (auto *ZE = dyn_cast<ZExtInst>(&I)) {
    uint8_t src = materialise(bc, ZE->getOperand(0));
    if (src == UINT8_MAX) return false;
    uint8_t w = getBitWidth(ZE->getSrcTy());
    if (w == 0) return false;
    uint8_t dst = allocVReg(ZE);
    emitZEXT(bc, dst, src, w);
    ++virtInstrCount;
    return true;
  }

  // ── SExtInst ─────────────────────────────────────────────────────────────
  if (auto *SE = dyn_cast<SExtInst>(&I)) {
    uint8_t src = materialise(bc, SE->getOperand(0));
    if (src == UINT8_MAX) return false;
    uint8_t w = getBitWidth(SE->getSrcTy());
    if (w == 0) return false;
    uint8_t dst = allocVReg(SE);
    emitSEXT(bc, dst, src, w);
    ++virtInstrCount;
    return true;
  }

  // ── TruncInst ────────────────────────────────────────────────────────────
  if (auto *TR = dyn_cast<TruncInst>(&I)) {
    uint8_t src = materialise(bc, TR->getOperand(0));
    if (src == UINT8_MAX) return false;
    uint8_t w = getBitWidth(TR->getDestTy());
    if (w == 0) return false;
    uint8_t dst = allocVReg(TR);
    emitTRUNC(bc, dst, src, w);
    ++virtInstrCount;
    return true;
  }

  // ── PtrToIntInst ─────────────────────────────────────────────────────────
  if (auto *PI = dyn_cast<PtrToIntInst>(&I)) {
    uint8_t src = materialise(bc, PI->getOperand(0));
    if (src == UINT8_MAX) return false;
    uint8_t dst = allocVReg(PI);
    emit2R(bc, PTRTOINT, dst, src);
    ++virtInstrCount;
    return true;
  }

  // ── IntToPtrInst ─────────────────────────────────────────────────────────
  if (auto *IP = dyn_cast<IntToPtrInst>(&I)) {
    uint8_t src = materialise(bc, IP->getOperand(0));
    if (src == UINT8_MAX) return false;
    uint8_t dst = allocVReg(IP);
    emit2R(bc, INTTOPTR, dst, src);
    ++virtInstrCount;
    return true;
  }

  // ── BitCastInst — type pun, treat as MOV_RR ──────────────────────────────
  if (auto *BC = dyn_cast<BitCastInst>(&I)) {
    uint8_t src = materialise(bc, BC->getOperand(0));
    if (src == UINT8_MAX) return false;
    uint8_t dst = allocVReg(BC);
    emitMOV_RR(bc, dst, src);
    ++virtInstrCount;
    return true;
  }

  // ── SelectInst ───────────────────────────────────────────────────────────
  if (auto *SI = dyn_cast<SelectInst>(&I)) {
    uint8_t cond  = materialise(bc, SI->getCondition());
    uint8_t rTrue = materialise(bc, SI->getTrueValue());
    uint8_t rFalse= materialise(bc, SI->getFalseValue());
    if (cond == UINT8_MAX || rTrue == UINT8_MAX || rFalse == UINT8_MAX)
      return false;
    uint8_t dst = allocVReg(SI);
    emitSELECT(bc, dst, cond, rTrue, rFalse);
    ++virtInstrCount;
    return true;
  }

  // ── AllocaInst ───────────────────────────────────────────────────────────
  if (auto *AI = dyn_cast<AllocaInst>(&I)) {
    // Only support constant-size allocas.
    if (!AI->isStaticAlloca()) return false;
    Type *allocTy = AI->getAllocatedType();
    const DataLayout &DL = AI->getModule()->getDataLayout();
    uint64_t sz = DL.getTypeAllocSize(allocTy);
    uint64_t count = 1;
    if (auto *CI = dyn_cast<ConstantInt>(AI->getArraySize()))
      count = CI->getZExtValue();
    uint64_t totalSz = sz * count;
    if (totalSz > UINT32_MAX) return false;
    uint8_t dst = allocVReg(AI);
    emitALLOCA(bc, dst, static_cast<uint32_t>(totalSz));
    ++virtInstrCount;
    return true;
  }

  // ── LoadInst ─────────────────────────────────────────────────────────────
  if (auto *LI = dyn_cast<LoadInst>(&I)) {
    if (LI->isVolatile()) return false; // volatile loads — skip
    uint8_t ptr = materialise(bc, LI->getPointerOperand());
    if (ptr == UINT8_MAX) return false;
    uint8_t w = getBitWidth(LI->getType());
    if (w == 0) return false;
    uint8_t dst = allocVReg(LI);
    emitLOAD(bc, w, dst, ptr);
    ++virtInstrCount;
    return true;
  }

  // ── StoreInst ────────────────────────────────────────────────────────────
  if (auto *ST = dyn_cast<StoreInst>(&I)) {
    if (ST->isVolatile()) return false;
    uint8_t val = materialise(bc, ST->getValueOperand());
    uint8_t ptr = materialise(bc, ST->getPointerOperand());
    if (val == UINT8_MAX || ptr == UINT8_MAX) return false;
    uint8_t w = getBitWidth(ST->getValueOperand()->getType());
    if (w == 0) return false;
    emitSTORE(bc, w, val, ptr);
    ++virtInstrCount;
    return true;
  }

  // ── GetElementPtrInst ─────────────────────────────────────────────────────
  if (auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
    const DataLayout &DL = GEP->getModule()->getDataLayout();
    uint8_t base = materialise(bc, GEP->getPointerOperand());
    if (base == UINT8_MAX) return false;
    uint8_t dst = allocVReg(GEP);

    // Multi-level constant GEP (e.g. struct field: gep %S, 0, field_idx).
    // accumulateConstantOffset collapses all indices into a single byte
    // offset, handling struct field padding and nested array strides.
    if (GEP->getNumIndices() > 1 && GEP->hasAllConstantIndices()) {
      APInt byteOff(64, 0);
      if (GEP->accumulateConstantOffset(DL, byteOff)) {
        uint8_t offReg = nextVReg++;
        assert(offReg < NUM_REGS);
        emitMOV_IMM(bc, offReg, byteOff.getZExtValue());
        emitGEP8(bc, dst, base, offReg);
        virtInstrCount += 2; // MOV_IMM + GEP8
        return true;
      }
      // Fall through to single-index path only if accumulate fails
      // (non-constant base layer), which shouldn't normally happen here.
      return false;
    }

    // Single-index GEP (array element access).
    if (GEP->getNumIndices() != 1) return false;
    uint8_t idx = materialise(bc, *GEP->idx_begin());
    if (idx == UINT8_MAX) return false;

    // Compute element size; for GEP8 we need byte offset.
    Type *srcElemTy = GEP->getSourceElementType();
    uint64_t elemSz = DL.getTypeAllocSize(srcElemTy);

    if (elemSz == 1) {
      emitGEP8(bc, dst, base, idx);
    } else {
      // Multiply index by element size, then add to base.
      uint8_t szReg = nextVReg++;
      assert(szReg < NUM_REGS);
      emitMOV_IMM(bc, szReg, elemSz);
      uint8_t byteIdxReg = nextVReg++;
      assert(byteIdxReg < NUM_REGS);
      emit3R(bc, MUL, byteIdxReg, idx, szReg);
      emitGEP8(bc, dst, base, byteIdxReg);
      virtInstrCount += 2;
    }
    ++virtInstrCount;
    return true;
  }

  // ── CallInst ─────────────────────────────────────────────────────────────
  if (auto *CI = dyn_cast<CallInst>(&I)) {
    Function *callee = CI->getCalledFunction();

    // ── Indirect call: function pointer in a virtual register ────────────
    if (!callee) {
      // calledOperand is the function pointer value (ptr-typed SSA value).
      // materialise() handles: vregMap lookups, GlobalValue→MOV_GV,
      // ConstantExpr(BitCast of fn)→reuse src reg.
      Value *calledOp = CI->getCalledOperand();
      uint8_t fnPtrReg = materialise(bc, calledOp);
      if (fnPtrReg == UINT8_MAX) return false;

      unsigned nargs = CI->arg_size();
      if (nargs > MAX_CALL_ARGS) return false;

      // Only integer/pointer arg types.
      for (unsigned k = 0; k < nargs; ++k) {
        Type *t = CI->getArgOperand(k)->getType();
        if (!t->isIntegerTy() && !t->isPointerTy()) return false;
      }
      // Return type must be void, integer, or pointer.
      Type *retTy = CI->getType();
      if (!retTy->isVoidTy() && !retTy->isIntegerTy() && !retTy->isPointerTy())
        return false;

      std::vector<uint8_t> argRegs;
      argRegs.reserve(nargs);
      for (unsigned k = 0; k < nargs; ++k) {
        uint8_t r = materialise(bc, CI->getArgOperand(k));
        if (r == UINT8_MAX) return false;
        argRegs.push_back(r);
      }

      // Allocate a destination vreg even for void calls (value unused).
      uint8_t dst = allocVReg(CI);
      emitCALL(bc, dst, fnPtrReg, argRegs); // fixed-width: pads to MAX_CALL_ARGS
      ++virtInstrCount;
      return true;
    }

    // Route LLVM intrinsics through dedicated handler.
    if (callee->isIntrinsic())
      return handleIntrinsic(bc, *CI);

    if (callee->isVarArg()) return false;

    unsigned nargs = CI->arg_size();
    if (nargs > MAX_CALL_ARGS) return false;

    // Only integer / pointer arg types and return type.
    for (unsigned k = 0; k < nargs; ++k) {
      Type *t = CI->getArgOperand(k)->getType();
      if (!t->isIntegerTy() && !t->isPointerTy()) return false;
    }
    Type *retTy = CI->getType();
    if (!retTy->isVoidTy() && !retTy->isIntegerTy() && !retTy->isPointerTy())
      return false;

    // Materialise all arguments into virtual registers.
    std::vector<uint8_t> argRegs;
    argRegs.reserve(nargs);
    for (unsigned k = 0; k < nargs; ++k) {
      uint8_t r = materialise(bc, CI->getArgOperand(k));
      if (r == UINT8_MAX) return false;
      argRegs.push_back(r);
    }

    uint8_t dst = allocVReg(CI);
    uint16_t callIdx = lookupCall(callee);
    emitCALL_D(bc, dst, callIdx, argRegs);
    ++virtInstrCount;
    return true;
  }

  // ── ReturnInst ───────────────────────────────────────────────────────────
  // (Handled in the main BB loop after phi movs, not here.)
  if (isa<ReturnInst>(&I)) {
    // Should not reach here; the main loop handles ReturnInst separately.
    return false;
  }

  // ── BranchInst ───────────────────────────────────────────────────────────
  // (Handled in the main BB loop, not here.)
  if (isa<BranchInst>(&I)) {
    return false;
  }

  // ── Unhandled ─────────────────────────────────────────────────────────────
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// handleIntrinsic — lower LLVM intrinsics to no-op or CALL_D
// ─────────────────────────────────────────────────────────────────────────────

bool VMPLifter::handleIntrinsic(std::vector<uint8_t> &bc, CallInst &CI) {
  Function *callee = CI.getCalledFunction();
  Intrinsic::ID iid = callee->getIntrinsicID();

  // ── No-op intrinsics (optimizer hints, debug metadata) ─────────────────
  // These have no observable runtime effect; skip them silently.
  switch (iid) {
    case Intrinsic::lifetime_start:
    case Intrinsic::lifetime_end:
    case Intrinsic::dbg_declare:
    case Intrinsic::dbg_value:
    case Intrinsic::dbg_label:
    case Intrinsic::assume:
      return true; // emit nothing
    default:
      break;
  }

  // ── Memory intrinsics → lower to libc CALL_D ───────────────────────────
  // llvm.memcpy / llvm.memmove / llvm.memset all have the form:
  //   (ptr dst, ptr src_or_i8val, i64 len, i1 isvolatile)
  // We pass the first 3 args to the corresponding C library function.
  StringRef libcName;
  switch (iid) {
    case Intrinsic::memcpy:   libcName = "memcpy";  break;
    case Intrinsic::memmove:  libcName = "memmove"; break;
    case Intrinsic::memset:   libcName = "memset";  break;
    default:
      return false; // unsupported intrinsic
  }

  if (CI.arg_size() < 3) return false;

  Module *M = CI.getModule();
  LLVMContext &Ctx = M->getContext();
  Type *PtrTy  = Type::getInt8PtrTy(Ctx);
  Type *I32Ty  = Type::getInt32Ty(Ctx);
  Type *SizeTy = M->getDataLayout().getIntPtrType(Ctx);

  FunctionType *FT;
  if (libcName != "memset")
    FT = FunctionType::get(PtrTy, {PtrTy, PtrTy, SizeTy}, false);
  else
    FT = FunctionType::get(PtrTy, {PtrTy, I32Ty, SizeTy}, false);

  FunctionCallee FC = M->getOrInsertFunction(libcName, FT);
  Function *libcFn  = dyn_cast<Function>(FC.getCallee());
  if (!libcFn) return false;

  uint16_t callIdx = lookupCall(libcFn);

  // Materialise first 3 args; skip arg[3] (isvolatile flag).
  std::vector<uint8_t> argRegs;
  for (unsigned k = 0; k < 3; ++k) {
    uint8_t r = materialise(bc, CI.getArgOperand(k));
    if (r == UINT8_MAX) return false;
    argRegs.push_back(r);
  }

  // llvm.memcpy returns void; C memcpy returns void* — discard result.
  uint8_t dst = UINT8_MAX;

  emitCALL_D(bc, dst, callIdx, argRegs);
  ++virtInstrCount;
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// patchForwardRefs — fill in all outstanding jump offsets
// ─────────────────────────────────────────────────────────────────────────────

void VMPLifter::patchForwardRefs(std::vector<uint8_t> &bc) {
  for (auto &ref : fwdRefs) {
    auto it = bbOffset.find(ref.targetBB);
    assert(it != bbOffset.end() &&
           "VMP: target BB was never emitted — forward ref unresolvable");
    int32_t off = static_cast<int32_t>(it->second) -
                  static_cast<int32_t>(ref.instrEndPos);
    patch32(bc, ref.patchPos, off);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// lift — main entry point
// ─────────────────────────────────────────────────────────────────────────────

std::optional<std::vector<uint8_t>> VMPLifter::lift(Function &F) {
  if (F.isDeclaration() || F.empty()) return std::nullopt;

  DLPtr = &F.getParent()->getDataLayout();
  reset();
  // Per-function deterministic junk seed
  junkRng = vmFnv1a(F.getName().str() + "_junk");

  std::vector<uint8_t> bc;
  bc.reserve(256);

  // ── Assign argument registers ────────────────────────────────────────────
  unsigned argIdx = 0;
  for (auto &Arg : F.args()) {
    if (argIdx >= MAX_CALL_ARGS) break;
    vregMap[&Arg] = static_cast<uint8_t>(REG_ARG_FIRST + argIdx);
    ++argIdx;
  }
  nextVReg = REG_GP_FIRST; // GP registers start at R8

  // If there were fewer than MAX_CALL_ARGS args we still start GP at R8.
  if (nextVReg < REG_GP_FIRST) nextVReg = REG_GP_FIRST;

  // ── PHI lowering pre-pass ────────────────────────────────────────────────
  if (!lowerPHIs(F, bc)) return std::nullopt;

  // Conditional branches with PHI nodes on successor edges are now handled
  // via per-edge trampolines in emitBranch().  No pre-scan rejection needed.

  // ── Main emission loop — RPO traversal ───────────────────────────────────
  ReversePostOrderTraversal<Function *> RPOT(&F);

  for (BasicBlock *BB : RPOT) {
    // ── Junk bytecode injection ──────────────────────────────────────────
    // Emit JMP+N_NOPs before each BB.  bbOffset[BB] is recorded AFTER the
    // junk, so all forward references (JMP/JCC targets) correctly skip it.
    // The dispatcher starts at byte 0 (the first BB's JMP), which it executes,
    // jumping to the real first instruction.  All other junk blocks are in
    // dead space — no JMP/JCC target points inside the junk region.
    xorshift64step(junkRng);
    uint8_t junkLen = static_cast<uint8_t>((junkRng % 7) + 1); // 1..7 NOPs
    emitJMP(bc, static_cast<int32_t>(junkLen));
    for (uint8_t j = 0; j < junkLen; ++j)
      emitNOP(bc); // 0x00 — instrSize(NOP)=1, safe for scrambleBytecode

    // Record this BB's bytecode offset (AFTER junk, BEFORE real instructions)
    bbOffset[BB] = static_cast<uint32_t>(bc.size());

    for (auto &I : *BB) {
      // ── PHI nodes: already handled by pre-pass ────────────────────────
      if (isa<PHINode>(&I)) continue;

      // ── Terminators ───────────────────────────────────────────────────
      if (auto *BI = dyn_cast<BranchInst>(&I)) {
        emitBranch(bc, *BI, BB);
        continue;
      }
      if (auto *RI = dyn_cast<ReturnInst>(&I)) {
        // Phi movs for return BB — not needed (no successors)
        if (RI->getReturnValue() == nullptr) {
          emitRET_VOID(bc);
        } else {
          uint8_t retReg = materialise(bc, RI->getReturnValue());
          if (retReg == UINT8_MAX) return std::nullopt;
          emitRET(bc, retReg);
        }
        ++virtInstrCount;
        continue;
      }

      // ── Regular instructions ───────────────────────────────────────────
      if (!emitInstr(bc, I)) return std::nullopt;
    }
  }

  // ── Patch all forward jump references ────────────────────────────────────
  patchForwardRefs(bc);

  return bc;
}
