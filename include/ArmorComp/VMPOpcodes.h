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
//   128 virtual registers, each 64 bits wide (uint64_t).
//
//   R0        : return value (written by RET, read by dispatcher on exit)
//   R0 – R7   : function arguments (R0 = arg0, R1 = arg1, …, R7 = arg7)
//   R8 – R127 : general purpose; allocated by VMPLifter for SSA temporaries
//
// ── Instruction Encoding ──────────────────────────────────────────────────
// All instructions are variable-length byte sequences.  The first byte is
// always the opcode.  Operand types and sizes are fixed per opcode:
//
//   REG        1 byte   (0–127, identifies a virtual register)
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

  // ── Super-instructions (fused immediate arithmetic) ────────────────────
  ADD_I32    = 0x44,   // REG REG imm32  → Rdst = Rsrc + sext(imm32)
  SUB_I32    = 0x45,   // REG REG imm32  → Rdst = Rsrc - sext(imm32)

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

  // ── Float arithmetic (0x80-0x85) ──────────────────────────────────────
  FADD       = 0x80,   // REG REG REG WIDTH1  (Rdst = Rlhs +f Rrhs, fpWidth)
  FSUB       = 0x81,   // REG REG REG WIDTH1
  FMUL       = 0x82,   // REG REG REG WIDTH1
  FDIV       = 0x83,   // REG REG REG WIDTH1
  FREM       = 0x84,   // REG REG REG WIDTH1
  FNEG       = 0x85,   // REG REG WIDTH1      (Rdst = -Rsrc, fpWidth)

  // ── Float comparison → boolean (0x88-0x8D ordered, 0x8E-0x93 unord.) ──
  FCMP_OEQ   = 0x88,   // REG REG REG WIDTH1  (ordered equal)
  FCMP_ONE   = 0x89,   // REG REG REG WIDTH1  (ordered not-equal)
  FCMP_OLT   = 0x8A,   // REG REG REG WIDTH1  (ordered less-than)
  FCMP_OLE   = 0x8B,   // REG REG REG WIDTH1  (ordered less-or-equal)
  FCMP_OGT   = 0x8C,   // REG REG REG WIDTH1  (ordered greater-than)
  FCMP_OGE   = 0x8D,   // REG REG REG WIDTH1  (ordered greater-or-equal)
  FCMP_UEQ   = 0x8E,   // REG REG REG WIDTH1  (unordered equal)
  FCMP_UNE   = 0x8F,   // REG REG REG WIDTH1  (unordered not-equal)
  FCMP_ULT   = 0x96,   // REG REG REG WIDTH1  (unordered less-than)
  FCMP_ULE   = 0x97,   // REG REG REG WIDTH1  (unordered less-or-equal)
  FCMP_UGT   = 0x98,   // REG REG REG WIDTH1  (unordered greater-than)
  FCMP_UGE   = 0x99,   // REG REG REG WIDTH1  (unordered greater-or-equal)
  FCMP_ORD   = 0x9A,   // REG REG REG WIDTH1  (ordered: both not NaN)
  FCMP_UNO   = 0x9B,   // REG REG REG WIDTH1  (unordered: either is NaN)

  // ── Variable-length NOPs (anti-pattern recognition) ──────────────────
  NOP2       = 0xF0,   // 2 bytes (opcode + 1 random pad byte)
  NOP3       = 0xF1,   // 3 bytes (opcode + 2 random pad bytes)
  NOP4       = 0xF2,   // 4 bytes (opcode + 3 random pad bytes)

  // ── Float ↔ Int conversions (0x90-0x95) ────────────────────────────────
  FPEXT      = 0x90,   // REG REG             (float → double)
  FPTRUNC    = 0x91,   // REG REG             (double → float)
  FPTOSI     = 0x92,   // REG REG WIDTH1      (float/double → signed i64; fpWidth)
  FPTOUI     = 0x93,   // REG REG WIDTH1      (float/double → unsigned i64; fpWidth)
  SITOFP     = 0x94,   // REG REG WIDTH1      (signed i64 → float/double; fpWidth)
  UITOFP     = 0x95,   // REG REG WIDTH1      (unsigned i64 → float/double; fpWidth)
};

// ─────────────────────────────────────────────────────────────────────────────
// Register constants
// ─────────────────────────────────────────────────────────────────────────────

static constexpr uint8_t NUM_REGS        = 128;
static constexpr uint8_t REG_RETVAL      = 0;   // R0 — return value
static constexpr uint8_t REG_ARG_FIRST   = 0;   // R0–R7 — arguments
static constexpr uint8_t REG_ARG_LAST    = 7;
static constexpr uint8_t REG_GP_FIRST    = 8;   // R8–R127 — general purpose
static constexpr uint8_t REG_GP_LAST     = 127;
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
//   - regs[] is modelled as a single [128 x i64] alloca
//   - pc is an i8* alloca (or kept in a local variable between iterations)
//   - bc_base is the pointer to the bytecode ConstantDataArray global
//
// In a hypothetical C reference implementation:
//   struct VMState { uint64_t regs[128]; const uint8_t *pc; const uint8_t *bc_base; };
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

// Three-register + trailing width byte (FADD, FSUB, ... FCMP_*).
inline void emit3R_W(std::vector<uint8_t> &bc, Opcode op,
                     uint8_t dst, uint8_t lhs, uint8_t rhs, uint8_t w) {
  emit3R(bc, op, dst, lhs, rhs);
  emit8(bc, w);
}

// Two-register + trailing width byte (FNEG, FPTOSI, FPTOUI, SITOFP, UITOFP).
inline void emit2R_W(std::vector<uint8_t> &bc, Opcode op,
                     uint8_t dst, uint8_t src, uint8_t w) {
  emit2R(bc, op, dst, src);
  emit8(bc, w);
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
    case NOP2:     return 2;
    case NOP3:     return 3;
    case NOP4:     return 4;
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
    case ADD_I32: case SUB_I32:
      return 7;  // opcode + dst + src + imm32(4)
    case SELECT:
      return 5;  // opcode + 4 regs
    case MOV_GV:
      return 4;  // opcode + dstReg + idx16 (2B)
    case CALL:
      // Fixed-width: opcode(1) + dst(1) + fnReg(1) + nargs_byte(1) + MAX_CALL_ARGS arg regs
      return 4 + MAX_CALL_ARGS; // = 12 bytes total
    case CALL_D:
      return 5 + nargs; // opcode + dstReg + idx16 (2B) + nargs byte + nargs regs

    // Float arithmetic (3R + fpWidth)
    case FADD: case FSUB: case FMUL: case FDIV: case FREM:
    case FCMP_OEQ: case FCMP_ONE: case FCMP_OLT:
    case FCMP_OLE: case FCMP_OGT: case FCMP_OGE:
    case FCMP_UEQ: case FCMP_UNE:
    case FCMP_ULT: case FCMP_ULE: case FCMP_UGT: case FCMP_UGE:
    case FCMP_ORD: case FCMP_UNO:
      return 5;  // opcode + 3 regs + fpWidth

    // Float unary / conversions with fpWidth
    case FNEG:
    case FPTOSI: case FPTOUI: case SITOFP: case UITOFP:
      return 4;  // opcode + 2 regs + fpWidth

    // Float conversions without fpWidth (fixed direction)
    case FPEXT: case FPTRUNC:
      return 3;  // opcode + 2 regs

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

// ── Super-instruction emitters ────────────────────────────────────────────

inline void emitADD_I32(std::vector<uint8_t> &bc, uint8_t dst, uint8_t src,
                         uint32_t imm) {
  emit8(bc, ADD_I32); emit8(bc, dst); emit8(bc, src); emit32(bc, imm);
}
inline void emitSUB_I32(std::vector<uint8_t> &bc, uint8_t dst, uint8_t src,
                         uint32_t imm) {
  emit8(bc, SUB_I32); emit8(bc, dst); emit8(bc, src); emit32(bc, imm);
}

// ─────────────────────────────────────────────────────────────────────────────
// Bytecode FNV-1a hash — for integrity verification at runtime
// ─────────────────────────────────────────────────────────────────────────────

inline uint64_t hashBytecode(const std::vector<uint8_t> &bc) {
  uint64_t h = 14695981039346656037ULL; // FNV-1a offset basis
  for (uint8_t b : bc) {
    h ^= static_cast<uint64_t>(b);
    h *= 1099511628211ULL;
  }
  return h;
}

// ─────────────────────────────────────────────────────────────────────────────
// XTEA encryption — replaces simple XOR for stronger bytecode protection
//
// XTEA-CTR mode: uses XTEA as a PRF to generate a keystream; XORs each byte
// of the bytecode with the keystream.  No padding needed (stream cipher).
// ─────────────────────────────────────────────────────────────────────────────

struct XTEAKey { uint32_t k[4]; };

inline XTEAKey genXTEAKey(const std::string &fnName) {
  uint64_t k0 = vmFnv1a(fnName + "_xtea_k0");
  uint64_t k1 = vmFnv1a(fnName + "_xtea_k1");
  return {{ static_cast<uint32_t>(k0), static_cast<uint32_t>(k0 >> 32),
            static_cast<uint32_t>(k1), static_cast<uint32_t>(k1 >> 32) }};
}

// XTEA encrypt a single 64-bit block (two 32-bit halves), 32 rounds.
inline void xteaEncryptBlock(uint32_t v[2], const uint32_t key[4]) {
  uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
  for (int i = 0; i < 32; i++) {
    v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    sum += delta;
    v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
  }
  v[0] = v0; v[1] = v1;
}

// Encrypt bytecode with XTEA-CTR mode (stream cipher, no padding needed).
inline void encryptBytecodeXTEA(std::vector<uint8_t> &bc, const XTEAKey &key) {
  for (size_t i = 0; i < bc.size(); i += 8) {
    uint32_t ctr[2] = { static_cast<uint32_t>(i / 8), 0 };
    xteaEncryptBlock(ctr, key.k);
    for (int j = 0; j < 8 && i + j < bc.size(); j++) {
      uint8_t ks = (j < 4) ? static_cast<uint8_t>(ctr[0] >> (j * 8))
                            : static_cast<uint8_t>(ctr[1] >> ((j - 4) * 8));
      bc[i + j] ^= ks;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bytecode disassembler — debug tool, activated via ARMORCOMP_VMP_DISASM env
// ─────────────────────────────────────────────────────────────────────────────

inline const char *opcodeName(Opcode op) {
  switch (op) {
    case NOP:      return "NOP";
    case NOP2:     return "NOP2";
    case NOP3:     return "NOP3";
    case NOP4:     return "NOP4";
    case MOV_I8:   return "MOV_I8";
    case MOV_I16:  return "MOV_I16";
    case MOV_I32:  return "MOV_I32";
    case MOV_I64:  return "MOV_I64";
    case MOV_RR:   return "MOV_RR";
    case MOV_GV:   return "MOV_GV";
    case ADD:      return "ADD";
    case SUB:      return "SUB";
    case MUL:      return "MUL";
    case UDIV:     return "UDIV";
    case SDIV:     return "SDIV";
    case UREM:     return "UREM";
    case SREM:     return "SREM";
    case AND:      return "AND";
    case OR:       return "OR";
    case XOR:      return "XOR";
    case SHL:      return "SHL";
    case LSHR:     return "LSHR";
    case ASHR:     return "ASHR";
    case NOT:      return "NOT";
    case NEG:      return "NEG";
    case ICMP_EQ:  return "ICMP_EQ";
    case ICMP_NE:  return "ICMP_NE";
    case ICMP_SLT: return "ICMP_SLT";
    case ICMP_SLE: return "ICMP_SLE";
    case ICMP_SGT: return "ICMP_SGT";
    case ICMP_SGE: return "ICMP_SGE";
    case ICMP_ULT: return "ICMP_ULT";
    case ICMP_ULE: return "ICMP_ULE";
    case ICMP_UGT: return "ICMP_UGT";
    case ICMP_UGE: return "ICMP_UGE";
    case JMP:      return "JMP";
    case JCC:      return "JCC";
    case RET:      return "RET";
    case RET_VOID: return "RET_VOID";
    case ADD_I32:  return "ADD_I32";
    case SUB_I32:  return "SUB_I32";
    case LOAD_8:   return "LOAD_8";
    case LOAD_16:  return "LOAD_16";
    case LOAD_32:  return "LOAD_32";
    case LOAD_64:  return "LOAD_64";
    case STORE_8:  return "STORE_8";
    case STORE_16: return "STORE_16";
    case STORE_32: return "STORE_32";
    case STORE_64: return "STORE_64";
    case ALLOCA:   return "ALLOCA";
    case GEP8:     return "GEP8";
    case ZEXT:     return "ZEXT";
    case SEXT:     return "SEXT";
    case TRUNC:    return "TRUNC";
    case PTRTOINT: return "PTRTOINT";
    case INTTOPTR: return "INTTOPTR";
    case SELECT:   return "SELECT";
    case CALL:     return "CALL";
    case CALL_D:   return "CALL_D";
    case FADD:     return "FADD";
    case FSUB:     return "FSUB";
    case FMUL:     return "FMUL";
    case FDIV:     return "FDIV";
    case FREM:     return "FREM";
    case FNEG:     return "FNEG";
    case FCMP_OEQ: return "FCMP_OEQ";
    case FCMP_ONE: return "FCMP_ONE";
    case FCMP_OLT: return "FCMP_OLT";
    case FCMP_OLE: return "FCMP_OLE";
    case FCMP_OGT: return "FCMP_OGT";
    case FCMP_OGE: return "FCMP_OGE";
    case FCMP_UEQ: return "FCMP_UEQ";
    case FCMP_UNE: return "FCMP_UNE";
    case FCMP_ULT: return "FCMP_ULT";
    case FCMP_ULE: return "FCMP_ULE";
    case FCMP_UGT: return "FCMP_UGT";
    case FCMP_UGE: return "FCMP_UGE";
    case FCMP_ORD: return "FCMP_ORD";
    case FCMP_UNO: return "FCMP_UNO";
    case FPEXT:    return "FPEXT";
    case FPTRUNC:  return "FPTRUNC";
    case FPTOSI:   return "FPTOSI";
    case FPTOUI:   return "FPTOUI";
    case SITOFP:   return "SITOFP";
    case UITOFP:   return "UITOFP";
    default:       return "???";
  }
}

inline void disassembleBytecode(const std::vector<uint8_t> &bc,
                                std::string &out) {
  size_t pos = 0;
  char buf[128];
  while (pos < bc.size()) {
    uint8_t opc = bc[pos];
    Opcode semOp = static_cast<Opcode>(opc);
    const char *name = opcodeName(semOp);
    int n = 0;

    switch (semOp) {
      case NOP: case RET_VOID:
        n = snprintf(buf, sizeof(buf), "  [%04x] %s\n", (unsigned)pos, name);
        break;
      case NOP2:
        n = snprintf(buf, sizeof(buf), "  [%04x] NOP2 pad=%02x\n",
                     (unsigned)pos, bc[pos+1]);
        break;
      case NOP3:
        n = snprintf(buf, sizeof(buf), "  [%04x] NOP3 pad=%02x%02x\n",
                     (unsigned)pos, bc[pos+1], bc[pos+2]);
        break;
      case NOP4:
        n = snprintf(buf, sizeof(buf), "  [%04x] NOP4 pad=%02x%02x%02x\n",
                     (unsigned)pos, bc[pos+1], bc[pos+2], bc[pos+3]);
        break;
      case MOV_I8:
        n = snprintf(buf, sizeof(buf), "  [%04x] MOV_I8  R%d, %d\n",
                     (unsigned)pos, bc[pos+1], bc[pos+2]);
        break;
      case MOV_I16: {
        uint16_t imm = bc[pos+2] | (bc[pos+3] << 8);
        n = snprintf(buf, sizeof(buf), "  [%04x] MOV_I16 R%d, %u\n",
                     (unsigned)pos, bc[pos+1], imm);
        break;
      }
      case MOV_I32: {
        uint32_t imm = bc[pos+2]|(bc[pos+3]<<8)|(bc[pos+4]<<16)|(bc[pos+5]<<24);
        n = snprintf(buf, sizeof(buf), "  [%04x] MOV_I32 R%d, %u\n",
                     (unsigned)pos, bc[pos+1], imm);
        break;
      }
      case MOV_I64: {
        uint64_t imm = 0;
        for (int i = 0; i < 8; ++i)
          imm |= (uint64_t)bc[pos+2+i] << (i*8);
        n = snprintf(buf, sizeof(buf), "  [%04x] MOV_I64 R%d, 0x%llx\n",
                     (unsigned)pos, bc[pos+1], (unsigned long long)imm);
        break;
      }
      case MOV_RR:
        n = snprintf(buf, sizeof(buf), "  [%04x] MOV_RR  R%d, R%d\n",
                     (unsigned)pos, bc[pos+1], bc[pos+2]);
        break;
      case MOV_GV: {
        uint16_t idx = bc[pos+2] | (bc[pos+3] << 8);
        n = snprintf(buf, sizeof(buf), "  [%04x] MOV_GV  R%d, gv[%u]\n",
                     (unsigned)pos, bc[pos+1], idx);
        break;
      }
      case RET:
        n = snprintf(buf, sizeof(buf), "  [%04x] RET     R%d\n",
                     (unsigned)pos, bc[pos+1]);
        break;
      case NOT: case NEG: case PTRTOINT: case INTTOPTR:
      case LOAD_8: case LOAD_16: case LOAD_32: case LOAD_64:
      case STORE_8: case STORE_16: case STORE_32: case STORE_64:
      case FPEXT: case FPTRUNC:
        n = snprintf(buf, sizeof(buf), "  [%04x] %-8s R%d, R%d\n",
                     (unsigned)pos, name, bc[pos+1], bc[pos+2]);
        break;
      case ADD: case SUB: case MUL: case UDIV: case SDIV: case UREM: case SREM:
      case AND: case OR: case XOR: case SHL: case LSHR: case ASHR:
      case ICMP_EQ: case ICMP_NE:
      case ICMP_SLT: case ICMP_SLE: case ICMP_SGT: case ICMP_SGE:
      case ICMP_ULT: case ICMP_ULE: case ICMP_UGT: case ICMP_UGE:
      case GEP8:
        n = snprintf(buf, sizeof(buf), "  [%04x] %-8s R%d, R%d, R%d\n",
                     (unsigned)pos, name, bc[pos+1], bc[pos+2], bc[pos+3]);
        break;
      case ZEXT: case SEXT: case TRUNC:
      case FNEG: case FPTOSI: case FPTOUI: case SITOFP: case UITOFP:
        n = snprintf(buf, sizeof(buf), "  [%04x] %-8s R%d, R%d, w%d\n",
                     (unsigned)pos, name, bc[pos+1], bc[pos+2], bc[pos+3]);
        break;
      case FADD: case FSUB: case FMUL: case FDIV: case FREM:
      case FCMP_OEQ: case FCMP_ONE: case FCMP_OLT: case FCMP_OLE:
      case FCMP_OGT: case FCMP_OGE:
      case FCMP_UEQ: case FCMP_UNE:
      case FCMP_ULT: case FCMP_ULE: case FCMP_UGT: case FCMP_UGE:
      case FCMP_ORD: case FCMP_UNO:
        n = snprintf(buf, sizeof(buf), "  [%04x] %-8s R%d, R%d, R%d, w%d\n",
                     (unsigned)pos, name, bc[pos+1], bc[pos+2], bc[pos+3], bc[pos+4]);
        break;
      case SELECT:
        n = snprintf(buf, sizeof(buf), "  [%04x] SELECT  R%d, R%d, R%d, R%d\n",
                     (unsigned)pos, bc[pos+1], bc[pos+2], bc[pos+3], bc[pos+4]);
        break;
      case JMP: {
        int32_t off = (int32_t)(bc[pos+1]|(bc[pos+2]<<8)|(bc[pos+3]<<16)|(bc[pos+4]<<24));
        n = snprintf(buf, sizeof(buf), "  [%04x] JMP     %+d\n",
                     (unsigned)pos, off);
        break;
      }
      case JCC: {
        int32_t ot = (int32_t)(bc[pos+2]|(bc[pos+3]<<8)|(bc[pos+4]<<16)|(bc[pos+5]<<24));
        int32_t of = (int32_t)(bc[pos+6]|(bc[pos+7]<<8)|(bc[pos+8]<<16)|(bc[pos+9]<<24));
        n = snprintf(buf, sizeof(buf), "  [%04x] JCC     R%d, t%+d, f%+d\n",
                     (unsigned)pos, bc[pos+1], ot, of);
        break;
      }
      case ALLOCA: {
        uint32_t sz = bc[pos+2]|(bc[pos+3]<<8)|(bc[pos+4]<<16)|(bc[pos+5]<<24);
        n = snprintf(buf, sizeof(buf), "  [%04x] ALLOCA  R%d, %u\n",
                     (unsigned)pos, bc[pos+1], sz);
        break;
      }
      case ADD_I32: case SUB_I32: {
        uint32_t imm = bc[pos+3]|(bc[pos+4]<<8)|(bc[pos+5]<<16)|(bc[pos+6]<<24);
        n = snprintf(buf, sizeof(buf), "  [%04x] %-8s R%d, R%d, %d\n",
                     (unsigned)pos, name, bc[pos+1], bc[pos+2], (int32_t)imm);
        break;
      }
      case CALL: {
        uint8_t nargs = bc[pos+3];
        n = snprintf(buf, sizeof(buf), "  [%04x] CALL    R%d, R%d, nargs=%d\n",
                     (unsigned)pos, bc[pos+1], bc[pos+2], nargs);
        break;
      }
      case CALL_D: {
        uint16_t idx = bc[pos+2] | (bc[pos+3] << 8);
        uint8_t nargs = bc[pos+4];
        n = snprintf(buf, sizeof(buf), "  [%04x] CALL_D  R%d, fn[%u], nargs=%d\n",
                     (unsigned)pos, bc[pos+1], idx, nargs);
        break;
      }
      default:
        n = snprintf(buf, sizeof(buf), "  [%04x] ??? 0x%02x\n",
                     (unsigned)pos, opc);
        break;
    }
    if (n > 0) out.append(buf, n);

    // For CALL_D, peek nargs for instrSize
    uint8_t nargs = 0;
    if (semOp == CALL_D && pos + 4 < bc.size())
      nargs = bc[pos + 4];
    size_t sz = instrSize(semOp, nargs);
    if (sz == 0) sz = 1;
    pos += sz;
  }
}

} // namespace vmp
} // namespace armorcomp
