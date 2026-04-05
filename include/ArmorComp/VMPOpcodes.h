#pragma once
#include <cassert>
//===----------------------------------------------------------------------===//
// ArmorComp — VMP ISA (Virtual Machine Protection)
//
// Defines the bytecode instruction set, encoding format, register conventions,
// and VMState layout for the ArmorComp virtual machine.
//
// ── Overview ──────────────────────────────────────────────────────────────
// VMPPass lifts annotated LLVM IR functions into this custom bytecode and
// replaces the original function body with a fetch-decode-execute dispatcher
// generated in LLVM IR.  At runtime, the protected function executes entirely
// inside the VM loop — the original IR instruction sequence never appears in
// the binary, defeating static analysis and signature-based decompilation.
//
// ── Register File ─────────────────────────────────────────────────────────
//   64 virtual registers, each 64 bits wide (uint64_t).
//
//   R0        : return value (written by RET, read by dispatcher on exit)
//   R0 – R7   : function arguments (R0 = arg0, R1 = arg1, …, R7 = arg7)
//   R8 – R63  : general purpose; allocated by VMPLifter for SSA temporaries
//
// ── Instruction Encoding ──────────────────────────────────────────────────
// All instructions are variable-length byte sequences.  The first byte is
// always the opcode.  Operand types and sizes are fixed per opcode:
//
//   REG        1 byte   (0–63, identifies a virtual register)
//   IMM8       1 byte   (unsigned, zero-extended to 64 bits)
//   IMM16      2 bytes  (unsigned, little-endian, zero-extended)
//   IMM32      4 bytes  (unsigned, little-endian, zero-extended)
//   IMM64      8 bytes  (unsigned/signed, little-endian)
//   OFFSET32   4 bytes  (signed, little-endian, relative to NEXT instruction)
//   WIDTH1     1 byte   (bit-width: 1, 8, 16, 32, or 64)
//   NARGS1     1 byte   (number of register arguments that follow)
//
// ── Instruction Table ─────────────────────────────────────────────────────
//   Mnemonic        Encoding (bytes after opcode)      Size  Description
//   ─────────────── ─────────────────────────────────  ────  ────────────
//   NOP             —                                     1   no operation
//   MOV_I8          REG imm8                              3   Rdst = imm8
//   MOV_I16         REG imm16(2B)                         4   Rdst = imm16
//   MOV_I32         REG imm32(4B)                         6   Rdst = imm32
//   MOV_I64         REG imm64(8B)                        10   Rdst = imm64
//   MOV_RR          REG REG                               3   Rdst = Rsrc
//   ADD             REG REG REG                           4   Rdst = Rl + Rr
//   SUB             REG REG REG                           4   Rdst = Rl - Rr
//   MUL             REG REG REG                           4   Rdst = Rl * Rr
//   UDIV            REG REG REG                           4   Rdst = Rl /u Rr
//   SDIV            REG REG REG                           4   Rdst = Rl /s Rr
//   UREM            REG REG REG                           4   Rdst = Rl %u Rr
//   SREM            REG REG REG                           4   Rdst = Rl %s Rr
//   AND             REG REG REG                           4   Rdst = Rl & Rr
//   OR              REG REG REG                           4   Rdst = Rl | Rr
//   XOR             REG REG REG                           4   Rdst = Rl ^ Rr
//   SHL             REG REG REG                           4   Rdst = Rl << Rr
//   LSHR            REG REG REG                           4   Rdst = Rl >>u Rr
//   ASHR            REG REG REG                           4   Rdst = Rl >>s Rr
//   NOT             REG REG                               3   Rdst = ~Rsrc
//   NEG             REG REG                               3   Rdst = -Rsrc
//   ICMP_EQ         REG REG REG                           4   Rdst = Rl == Rr
//   ICMP_NE         REG REG REG                           4   Rdst = Rl != Rr
//   ICMP_SLT        REG REG REG                           4   Rdst = Rl <s  Rr
//   ICMP_SLE        REG REG REG                           4   Rdst = Rl <=s Rr
//   ICMP_SGT        REG REG REG                           4   Rdst = Rl >s  Rr
//   ICMP_SGE        REG REG REG                           4   Rdst = Rl >=s Rr
//   ICMP_ULT        REG REG REG                           4   Rdst = Rl <u  Rr
//   ICMP_ULE        REG REG REG                           4   Rdst = Rl <=u Rr
//   ICMP_UGT        REG REG REG                           4   Rdst = Rl >u  Rr
//   ICMP_UGE        REG REG REG                           4   Rdst = Rl >=u Rr
//   JMP             offset32(4B)                          5   pc += offset
//   JCC             REG offset32(4B) offset32(4B)        10   if Rcond: pc+=ofT else pc+=ofF
//   LOAD_8          REG REG                               3   Rdst = *(uint8_t *)Rptr
//   LOAD_16         REG REG                               3   Rdst = *(uint16_t *)Rptr
//   LOAD_32         REG REG                               3   Rdst = *(uint32_t *)Rptr
//   LOAD_64         REG REG                               3   Rdst = *(uint64_t *)Rptr
//   STORE_8         REG REG                               3   *(uint8_t *)Rptr = Rval
//   STORE_16        REG REG                               3   *(uint16_t *)Rptr = Rval
//   STORE_32        REG REG                               3   *(uint32_t *)Rptr = Rval
//   STORE_64        REG REG                               3   *(uint64_t *)Rptr = Rval
//   ALLOCA          REG imm32(4B)                         6   Rdst = stack_alloc(imm32 bytes)
//   GEP8            REG REG REG                           4   Rdst = (uint8_t*)Rbase + Ridx
//   ZEXT            REG REG WIDTH1                        4   Rdst = zext Rsrc to 64 bits
//   SEXT            REG REG WIDTH1                        4   Rdst = sext Rsrc to 64 bits
//   TRUNC           REG REG WIDTH1                        4   Rdst = Rsrc & mask(WIDTH1)
//   PTRTOINT        REG REG                               3   Rdst = (uint64_t)Rptr
//   INTTOPTR        REG REG                               3   Rdst = (ptr)Rint
//   SELECT          REG REG REG REG                       5   Rdst = Rcond ? Rtrue : Rfalse
//   CALL            REG REG NARGS1 REG...          3+nargs   Rdst = ((fn*)Rfn)(Rarg0,...)
//   RET             REG                                   2   R0 = Rval; return
//   RET_VOID        —                                     1   return (void)
//
// ── Jump Offsets ──────────────────────────────────────────────────────────
// OFFSET32 is a signed 32-bit displacement relative to the byte AFTER the
// current instruction (i.e., after the last byte of the current instruction).
//
//   new_pc = (pc_of_next_instr) + offset32
//
// For JCC:
//   if (regs[Rcond] != 0):  new_pc += offset32_true
//   else:                   new_pc += offset32_false
//
// ── Width Encoding (ZEXT / SEXT / TRUNC) ─────────────────────────────────
// WIDTH1 byte values:
//   1  → 1-bit  (boolean, mask = 0x1)
//   8  → 8-bit  (i8,  mask = 0xFF)
//   16 → 16-bit (i16, mask = 0xFFFF)
//   32 → 32-bit (i32, mask = 0xFFFFFFFF)
//   64 → 64-bit (i64, no-op truncation / identity zext/sext)
//
// ── Bytecode Global Naming ────────────────────────────────────────────────
// Each virtualized function "fname" gets a module-level bytecode global:
//   @__armorcomp_vmp_bc_<fname> = weak_odr constant [N x i8] ...
//
// An optional XOR-encryption key global may follow:
//   @__armorcomp_vmp_key_<fname> = weak_odr constant i64 ...
//
// ── Annotation ────────────────────────────────────────────────────────────
//   __attribute__((annotate("vmp")))
//   -passes= name : armorcomp-vmp  /  armorcomp-vmp-all
//
//===----------------------------------------------------------------------===//

#include <cstdint>
#include <vector>

namespace armorcomp {
namespace vmp {

// ─────────────────────────────────────────────────────────────────────────────
// Opcode enumeration
// ─────────────────────────────────────────────────────────────────────────────

enum Opcode : uint8_t {
  // ── Misc ────────────────────────────────────────────────────────────────
  NOP        = 0x00,

  // ── Immediate loads ─────────────────────────────────────────────────────
  MOV_I8     = 0x01,   // REG imm8         → Rdst = (uint64_t)imm8
  MOV_I16    = 0x02,   // REG imm16        → Rdst = (uint64_t)imm16
  MOV_I32    = 0x03,   // REG imm32        → Rdst = (uint64_t)imm32
  MOV_I64    = 0x04,   // REG imm64        → Rdst = imm64
  MOV_RR     = 0x05,   // REG REG          → Rdst = Rsrc
  MOV_GV     = 0x06,   // REG IDX16(2B)    → Rdst = (uint64_t) gv_table[IDX16]

  // ── Arithmetic ──────────────────────────────────────────────────────────
  ADD        = 0x10,   // REG REG REG
  SUB        = 0x11,   // REG REG REG
  MUL        = 0x12,   // REG REG REG
  UDIV       = 0x13,   // REG REG REG  (unsigned)
  SDIV       = 0x14,   // REG REG REG  (signed)
  UREM       = 0x15,   // REG REG REG  (unsigned remainder)
  SREM       = 0x16,   // REG REG REG  (signed remainder)

  // ── Bitwise ─────────────────────────────────────────────────────────────
  AND        = 0x20,   // REG REG REG
  OR         = 0x21,   // REG REG REG
  XOR        = 0x22,   // REG REG REG
  SHL        = 0x23,   // REG REG REG
  LSHR       = 0x24,   // REG REG REG  (logical shift right)
  ASHR       = 0x25,   // REG REG REG  (arithmetic shift right)
  NOT        = 0x26,   // REG REG      (bitwise NOT)
  NEG        = 0x27,   // REG REG      (arithmetic negate)

  // ── Integer comparison → boolean (0 or 1) ───────────────────────────────
  ICMP_EQ    = 0x30,   // REG REG REG
  ICMP_NE    = 0x31,   // REG REG REG
  ICMP_SLT   = 0x32,   // REG REG REG  (signed less-than)
  ICMP_SLE   = 0x33,   // REG REG REG
  ICMP_SGT   = 0x34,   // REG REG REG
  ICMP_SGE   = 0x35,   // REG REG REG
  ICMP_ULT   = 0x36,   // REG REG REG  (unsigned less-than)
  ICMP_ULE   = 0x37,   // REG REG REG
  ICMP_UGT   = 0x38,   // REG REG REG
  ICMP_UGE   = 0x39,   // REG REG REG

  // ── Control flow ────────────────────────────────────────────────────────
  JMP        = 0x40,   // offset32   (signed, relative to next instruction)
  JCC        = 0x41,   // REG offset32_true offset32_false
  RET        = 0x42,   // REG        (R0 = Rval, then exit)
  RET_VOID   = 0x43,   // —          (void return)

  // ── Memory ──────────────────────────────────────────────────────────────
  LOAD_8     = 0x50,   // REG REG    (Rdst = *(uint8_t *)Rptr, zero-extended)
  LOAD_16    = 0x51,   // REG REG    (Rdst = *(uint16_t *)Rptr, zero-extended)
  LOAD_32    = 0x52,   // REG REG    (Rdst = *(uint32_t *)Rptr, zero-extended)
  LOAD_64    = 0x53,   // REG REG    (Rdst = *(uint64_t *)Rptr)
  STORE_8    = 0x54,   // REG REG    (*(uint8_t *)Rptr = (uint8_t)Rval)
  STORE_16   = 0x55,   // REG REG    (*(uint16_t *)Rptr = (uint16_t)Rval)
  STORE_32   = 0x56,   // REG REG    (*(uint32_t *)Rptr = (uint32_t)Rval)
  STORE_64   = 0x57,   // REG REG    (*(uint64_t *)Rptr = Rval)
  ALLOCA     = 0x58,   // REG imm32  (Rdst = alloca(imm32 bytes); stack bump)
  GEP8       = 0x59,   // REG REG REG (Rdst = (uint8_t*)Rbase + Ridx)

  // ── Type conversion ─────────────────────────────────────────────────────
  ZEXT       = 0x60,   // REG REG WIDTH1  (zero-extend Rsrc[0:width] to 64b)
  SEXT       = 0x61,   // REG REG WIDTH1  (sign-extend Rsrc[0:width] to 64b)
  TRUNC      = 0x62,   // REG REG WIDTH1  (Rdst = Rsrc & mask(width))
  PTRTOINT   = 0x63,   // REG REG         (Rdst = (uint64_t)Rptr)
  INTTOPTR   = 0x64,   // REG REG         (Rdst = (ptr)Rint)

  // ── Ternary / misc ───────────────────────────────────────────────────────
  SELECT     = 0x70,   // REG REG REG REG (Rdst = Rcond ? Rtrue : Rfalse)
  CALL       = 0x71,   // REG REG NARGS1 REG... (Rdst = (*Rfn)(args...))
  CALL_D     = 0x72,   // REG IDX16(2B) NARGS1 REG... (direct call: calltab[IDX16](args...))
};

// ─────────────────────────────────────────────────────────────────────────────
// Register constants
// ─────────────────────────────────────────────────────────────────────────────

static constexpr uint8_t NUM_REGS        = 64;
static constexpr uint8_t REG_RETVAL      = 0;   // R0 — return value
static constexpr uint8_t REG_ARG_FIRST   = 0;   // R0–R7 — arguments
static constexpr uint8_t REG_ARG_LAST    = 7;
static constexpr uint8_t REG_GP_FIRST    = 8;   // R8–R63 — general purpose
static constexpr uint8_t REG_GP_LAST     = 63;
static constexpr uint8_t MAX_CALL_ARGS   = 8;   // matches REG_ARG_LAST - REG_ARG_FIRST + 1

// Width values used in ZEXT / SEXT / TRUNC
static constexpr uint8_t WIDTH_1  = 1;
static constexpr uint8_t WIDTH_8  = 8;
static constexpr uint8_t WIDTH_16 = 16;
static constexpr uint8_t WIDTH_32 = 32;
static constexpr uint8_t WIDTH_64 = 64;

// ─────────────────────────────────────────────────────────────────────────────
// VMState — layout of the virtual machine's execution context
//
// In the LLVM IR dispatcher:
//   - regs[] is modelled as a single [64 x i64] alloca
//   - pc is an i8* alloca (or kept in a local variable between iterations)
//   - bc_base is the pointer to the bytecode ConstantDataArray global
//
// In a hypothetical C reference implementation:
//   struct VMState { uint64_t regs[64]; const uint8_t *pc; const uint8_t *bc_base; };
// ─────────────────────────────────────────────────────────────────────────────

struct VMState {
  uint64_t        regs[NUM_REGS];
  const uint8_t  *pc;
  const uint8_t  *bc_base;
};

// ─────────────────────────────────────────────────────────────────────────────
// Bytecode builder helpers — used by VMPLifter to assemble instructions
// ─────────────────────────────────────────────────────────────────────────────

// Emit a single byte.
inline void emit8(std::vector<uint8_t> &bc, uint8_t v) {
  bc.push_back(v);
}

// Emit a 16-bit value, little-endian.
inline void emit16(std::vector<uint8_t> &bc, uint16_t v) {
  bc.push_back(static_cast<uint8_t>(v & 0xFF));
  bc.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}

// Emit a 32-bit value, little-endian.
inline void emit32(std::vector<uint8_t> &bc, uint32_t v) {
  bc.push_back(static_cast<uint8_t>(v & 0xFF));
  bc.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  bc.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
  bc.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

// Emit a 64-bit value, little-endian.
inline void emit64(std::vector<uint8_t> &bc, uint64_t v) {
  for (int i = 0; i < 8; ++i)
    bc.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}

// Patch a 32-bit little-endian value at position `pos` in the bytecode.
// Used for forward-reference patching after all BB offsets are known.
inline void patch32(std::vector<uint8_t> &bc, uint32_t pos, int32_t v) {
  assert(pos + 3 < bc.size() && "patch32: out-of-bounds write!");
  bc[pos]     = static_cast<uint8_t>(v & 0xFF);
  bc[pos + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
  bc[pos + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
  bc[pos + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

// ── Instruction emitters ──────────────────────────────────────────────────

inline void emitNOP(std::vector<uint8_t> &bc) {
  emit8(bc, NOP);
}

inline void emitMOV_I8(std::vector<uint8_t> &bc, uint8_t dst, uint8_t imm) {
  emit8(bc, MOV_I8); emit8(bc, dst); emit8(bc, imm);
}
inline void emitMOV_I16(std::vector<uint8_t> &bc, uint8_t dst, uint16_t imm) {
  emit8(bc, MOV_I16); emit8(bc, dst); emit16(bc, imm);
}
inline void emitMOV_I32(std::vector<uint8_t> &bc, uint8_t dst, uint32_t imm) {
  emit8(bc, MOV_I32); emit8(bc, dst); emit32(bc, imm);
}
inline void emitMOV_I64(std::vector<uint8_t> &bc, uint8_t dst, uint64_t imm) {
  emit8(bc, MOV_I64); emit8(bc, dst); emit64(bc, imm);
}
inline void emitMOV_RR(std::vector<uint8_t> &bc, uint8_t dst, uint8_t src) {
  emit8(bc, MOV_RR); emit8(bc, dst); emit8(bc, src);
}
inline void emitMOV_GV(std::vector<uint8_t> &bc, uint8_t dst, uint16_t gvIdx) {
  emit8(bc, MOV_GV); emit8(bc, dst); emit16(bc, gvIdx);
}

// Convenience: emit the smallest MOV_Ixxx that fits the value.
inline void emitMOV_IMM(std::vector<uint8_t> &bc, uint8_t dst, uint64_t imm) {
  if (imm <= 0xFF)
    emitMOV_I8(bc, dst, static_cast<uint8_t>(imm));
  else if (imm <= 0xFFFF)
    emitMOV_I16(bc, dst, static_cast<uint16_t>(imm));
  else if (imm <= 0xFFFFFFFF)
    emitMOV_I32(bc, dst, static_cast<uint32_t>(imm));
  else
    emitMOV_I64(bc, dst, imm);
}

// Three-register instructions (arithmetic, bitwise, comparison).
inline void emit3R(std::vector<uint8_t> &bc, Opcode op,
                   uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit8(bc, op); emit8(bc, dst); emit8(bc, lhs); emit8(bc, rhs);
}

// Two-register instructions (NOT, NEG, LOAD_*, STORE_*, PTRTOINT, INTTOPTR).
inline void emit2R(std::vector<uint8_t> &bc, Opcode op, uint8_t r0, uint8_t r1) {
  emit8(bc, op); emit8(bc, r0); emit8(bc, r1);
}

inline void emitJMP(std::vector<uint8_t> &bc, int32_t offset) {
  emit8(bc, JMP); emit32(bc, static_cast<uint32_t>(offset));
}
inline void emitJCC(std::vector<uint8_t> &bc, uint8_t cond,
                    int32_t offsetTrue, int32_t offsetFalse) {
  emit8(bc, JCC); emit8(bc, cond);
  emit32(bc, static_cast<uint32_t>(offsetTrue));
  emit32(bc, static_cast<uint32_t>(offsetFalse));
}

inline void emitRET(std::vector<uint8_t> &bc, uint8_t valReg) {
  emit8(bc, RET); emit8(bc, valReg);
}
inline void emitRET_VOID(std::vector<uint8_t> &bc) {
  emit8(bc, RET_VOID);
}

inline void emitLOAD(std::vector<uint8_t> &bc, uint8_t width,
                     uint8_t dst, uint8_t ptrReg) {
  Opcode op;
  switch (width) {
    case 8:  op = LOAD_8;  break;
    case 16: op = LOAD_16; break;
    case 32: op = LOAD_32; break;
    default: op = LOAD_64; break;
  }
  emit2R(bc, op, dst, ptrReg);
}
inline void emitSTORE(std::vector<uint8_t> &bc, uint8_t width,
                      uint8_t valReg, uint8_t ptrReg) {
  Opcode op;
  switch (width) {
    case 8:  op = STORE_8;  break;
    case 16: op = STORE_16; break;
    case 32: op = STORE_32; break;
    default: op = STORE_64; break;
  }
  emit2R(bc, op, valReg, ptrReg);
}

inline void emitALLOCA(std::vector<uint8_t> &bc, uint8_t dst, uint32_t size) {
  emit8(bc, ALLOCA); emit8(bc, dst); emit32(bc, size);
}
inline void emitGEP8(std::vector<uint8_t> &bc,
                     uint8_t dst, uint8_t base, uint8_t idx) {
  emit3R(bc, GEP8, dst, base, idx);
}

inline void emitZEXT(std::vector<uint8_t> &bc,
                     uint8_t dst, uint8_t src, uint8_t width) {
  emit8(bc, ZEXT); emit8(bc, dst); emit8(bc, src); emit8(bc, width);
}
inline void emitSEXT(std::vector<uint8_t> &bc,
                     uint8_t dst, uint8_t src, uint8_t width) {
  emit8(bc, SEXT); emit8(bc, dst); emit8(bc, src); emit8(bc, width);
}
inline void emitTRUNC(std::vector<uint8_t> &bc,
                      uint8_t dst, uint8_t src, uint8_t width) {
  emit8(bc, TRUNC); emit8(bc, dst); emit8(bc, src); emit8(bc, width);
}

inline void emitSELECT(std::vector<uint8_t> &bc,
                       uint8_t dst, uint8_t cond, uint8_t rTrue, uint8_t rFalse) {
  emit8(bc, SELECT);
  emit8(bc, dst); emit8(bc, cond); emit8(bc, rTrue); emit8(bc, rFalse);
}

// CALL: Rdst = (*Rfn)(Rarg0, Rarg1, ..., Rarg[nargs-1])
// Fixed-width encoding: always emits exactly MAX_CALL_ARGS argument register
// bytes (padding unused slots with 0x00).  The dispatcher reads all 8 bytes
// unconditionally; only the first `nargs` values are used by the callee.
// This avoids a runtime-length loop in the static IR dispatcher.
inline void emitCALL(std::vector<uint8_t> &bc,
                     uint8_t dst, uint8_t fnReg,
                     const std::vector<uint8_t> &argRegs) {
  emit8(bc, CALL);
  emit8(bc, dst);
  emit8(bc, fnReg);
  emit8(bc, static_cast<uint8_t>(argRegs.size()));
  for (uint8_t r : argRegs)
    emit8(bc, r);
  // Pad to fixed MAX_CALL_ARGS bytes so dispatcher can read unconditionally
  for (size_t i = argRegs.size(); i < MAX_CALL_ARGS; ++i)
    emit8(bc, 0x00); // padding: R0 index, callee ignores extra registers
}

// CALL_D: Rdst = calltab[callIdx](Rarg0, ..., Rarg[nargs-1])  (typed direct call)
inline void emitCALL_D(std::vector<uint8_t> &bc,
                       uint8_t dst, uint16_t callIdx,
                       const std::vector<uint8_t> &argRegs) {
  emit8(bc, CALL_D);
  emit8(bc, dst);
  emit16(bc, callIdx);
  emit8(bc, static_cast<uint8_t>(argRegs.size()));
  for (uint8_t r : argRegs)
    emit8(bc, r);
}

// ─────────────────────────────────────────────────────────────────────────────
// Bytecode global naming helpers
// ─────────────────────────────────────────────────────────────────────────────

inline std::string bcGlobalName(const std::string &fnName) {
  return "__armorcomp_vmp_bc_" + fnName;
}
inline std::string keyGlobalName(const std::string &fnName) {
  return "__armorcomp_vmp_key_" + fnName;
}
inline std::string dispatcherName(const std::string &fnName) {
  return "__armorcomp_vmp_dispatch_" + fnName;
}
inline std::string gvtabName(const std::string &fnName) {
  return "__armorcomp_vmp_gvtab_" + fnName;
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction-size helper — returns how many bytes an instruction occupies
// (opcode byte + operands).  Used by the lifter to compute relative offsets.
// ─────────────────────────────────────────────────────────────────────────────

inline uint32_t instrSize(Opcode op, uint8_t nargs = 0) {
  switch (op) {
    case NOP:      return 1;
    case MOV_I8:   return 3;
    case MOV_I16:  return 4;
    case MOV_I32:  return 6;
    case MOV_I64:  return 10;
    case MOV_RR:   return 3;
    case ADD: case SUB: case MUL: case UDIV: case SDIV:
    case UREM: case SREM:
    case AND: case OR: case XOR: case SHL: case LSHR: case ASHR:
    case ICMP_EQ: case ICMP_NE:
    case ICMP_SLT: case ICMP_SLE: case ICMP_SGT: case ICMP_SGE:
    case ICMP_ULT: case ICMP_ULE: case ICMP_UGT: case ICMP_UGE:
    case GEP8:
      return 4;  // opcode + 3 regs
    case NOT: case NEG:
    case LOAD_8: case LOAD_16: case LOAD_32: case LOAD_64:
    case STORE_8: case STORE_16: case STORE_32: case STORE_64:
    case PTRTOINT: case INTTOPTR:
      return 3;  // opcode + 2 regs
    case ALLOCA:
      return 6;  // opcode + reg + imm32
    case ZEXT: case SEXT: case TRUNC:
      return 4;  // opcode + 2 regs + width
    case JMP:
      return 5;  // opcode + offset32
    case JCC:
      return 10; // opcode + reg + offset32 + offset32
    case RET:
      return 2;  // opcode + reg
    case RET_VOID:
      return 1;
    case SELECT:
      return 5;  // opcode + 4 regs
    case MOV_GV:
      return 4;  // opcode + dstReg + idx16 (2B)
    case CALL:
      // Fixed-width: opcode(1) + dst(1) + fnReg(1) + nargs_byte(1) + MAX_CALL_ARGS arg regs
      return 4 + MAX_CALL_ARGS; // = 12 bytes total
    case CALL_D:
      return 5 + nargs; // opcode + dstReg + idx16 (2B) + nargs byte + nargs regs
    default:
      return 1;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// FNV-1a hash — deterministic seed for per-function key/map generation
// ─────────────────────────────────────────────────────────────────────────────

inline uint64_t vmFnv1a(const std::string &s) {
  uint64_t h = 14695981039346656037ULL;
  for (unsigned char c : s) {
    h ^= static_cast<uint64_t>(c);
    h *= 1099511628211ULL;
  }
  return h;
}

inline uint64_t xorshift64step(uint64_t &state) {
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return state;
}

// ─────────────────────────────────────────────────────────────────────────────
// Bytecode XOR encryption
//
// Key: 8-byte repeating XOR derived from fnName.
//   bc[i] ^= (key >> ((i % 8) * 8)) & 0xFF
//
// The key is injected as @__armorcomp_vmp_key_<fname> (constant i64).
// The dispatcher decrypts the bytecode into a stack buffer at runtime
// before starting the fetch-decode-execute loop, so static analysis of
// the bytecode global reveals only ciphertext.
// ─────────────────────────────────────────────────────────────────────────────

inline uint64_t genBcKey(const std::string &fnName) {
  uint64_t k = vmFnv1a(fnName + "_vmp_bckey");
  if (k == 0) k = 0xDEADBEEFCAFEBABEULL; // never zero
  return k;
}

// XOR-encrypt (or decrypt — same operation) bc in place.
inline void encryptBytecode(std::vector<uint8_t> &bc, uint64_t key) {
  for (size_t i = 0; i < bc.size(); ++i)
    bc[i] ^= static_cast<uint8_t>((key >> ((i % 8) * 8)) & 0xFF);
}

// ─────────────────────────────────────────────────────────────────────────────
// Opcode scrambling — per-function Fisher-Yates permutation
//
// OpcodeMap maps semantic Opcode enum byte → physical (wire) byte.
// Each function gets a unique bijection derived from its name:
//   - MOV_I8 in function "foo" might be physical byte 0xE3
//   - MOV_I8 in function "bar" might be physical byte 0x5A
// The dispatcher switch cases carry physical byte values, so a reverser
// examining the binary cannot infer ISA semantics without the key.
// ─────────────────────────────────────────────────────────────────────────────

struct OpcodeMap {
  uint8_t phys[256]; // semantic byte value → physical (wire) byte value
};

inline OpcodeMap genOpcodeMap(const std::string &fnName) {
  OpcodeMap m;
  for (int i = 0; i < 256; ++i) m.phys[i] = static_cast<uint8_t>(i);
  uint64_t state = vmFnv1a(fnName + "_vmp_opmap");
  for (int i = 255; i > 0; --i) {
    xorshift64step(state);
    int j = static_cast<int>(state % static_cast<uint64_t>(i + 1));
    std::swap(m.phys[i], m.phys[j]);
  }
  return m;
}

// Rewrite every opcode byte in a bytecode stream from semantic → physical.
// Must be called BEFORE encryptBytecode (XOR touches all bytes including opcodes).
// Uses instrSize() with the original semantic opcode to step over operand bytes.
inline void scrambleBytecode(std::vector<uint8_t> &bc, const OpcodeMap &m) {
  size_t pos = 0;
  while (pos < bc.size()) {
    uint8_t semByte = bc[pos];
    bc[pos] = m.phys[semByte];                  // semantic → physical opcode
    Opcode semOp = static_cast<Opcode>(semByte);
    // Variable-length instructions: peek nargs before advancing.
    // CALL is now fixed-width (always MAX_CALL_ARGS arg bytes); no peek needed.
    uint8_t nargs = 0;
    if (semOp == CALL_D && pos + 4 < bc.size())
      nargs = bc[pos + 4];                       // opc+dst+idx16+nargs+regs
    size_t sz = instrSize(semOp, nargs);
    if (sz == 0) sz = 1;                         // safety: never get stuck
    pos += sz;
  }
}

} // namespace vmp
} // namespace armorcomp
