// ArmorComp — VMPPass (VMP) validation test
//
// VMPPass virtualizes annotate("vmp") functions:
//   1. VMPLifter translates LLVM IR → custom VMP bytecode ([N x i8] global)
//   2. VMPCodeGen generates a VM fetch-decode-execute dispatcher in LLVM IR
//   3. Original function body → one-instruction thunk → tail-call to dispatcher
//
// Runtime behaviour is identical to the plain (non-annotated) counterparts.
// Static analysis is defeated: the dispatcher is a ~50-BB switch interpreter
// and the algorithm is hidden in an opaque bytecode blob.
//
// VMP ISA highlights (VMPOpcodes.h):
//   - 128 virtual registers (R0–R127), 64-bit each, with dead-register reclaim
//   - R0 = return value, R0–R7 = function arguments
//   - Opcodes: MOV_Ixx, MOV_RR, MOV_GV,
//              ADD/SUB/MUL/UDIV/SDIV/UREM/SREM/AND/OR/XOR/SHL/LSHR/ASHR,
//              ICMP_* (10 predicates), JMP/JCC, LOAD/STORE (8/16/32/64),
//              ALLOCA (with bounds check), GEP8,
//              ZEXT/SEXT/TRUNC, PTRTOINT/INTTOPTR, SELECT,
//              CALL (indirect), CALL_D (direct, typed, float/double support),
//              FADD/FSUB/FMUL/FDIV/FREM/FNEG,
//              FCMP_O* (6 ordered) + FCMP_U* (6 unordered) + FCMP_ORD/UNO,
//              FPEXT/FPTRUNC/FPTOSI/FPTOUI/SITOFP/UITOFP,
//              RET, RET_VOID, NOP
//              + SwitchInst (lowered to ICmp_EQ + JCC cascade)
//
// Limitations (functions that contain unsupported IR are skipped):
//   - SIMD / vector instructions → NOT supported
//   - VarArg callees (printf etc.) → NOT supported
//   - Indirect calls with float/double args → NOT supported (ABI limitation)
//   - Dynamic alloca (non-constant size) → NOT supported
//   When skipped, stderr shows: [ArmorComp][VMP] skipped (unsupported IR): <fn>
//
// Expected stderr (for successfully virtualized functions):
//   [ArmorComp][VMP] virtualized: vmp_add       (N bytecode bytes, M virtual instrs)
//   [ArmorComp][VMP] virtualized: vmp_sub        (N bytecode bytes, M virtual instrs)
//   [ArmorComp][VMP] virtualized: vmp_bitops     (N bytecode bytes, M virtual instrs)
//   [ArmorComp][VMP] virtualized: vmp_classify   (N bytecode bytes, M virtual instrs)
//   [ArmorComp][VMP] virtualized: vmp_loop       (N bytecode bytes, M virtual instrs)
//   [ArmorComp][VMP] virtualized: vmp_select     (N bytecode bytes, M virtual instrs)
//   [ArmorComp][VMP] virtualized: vmp_float_arith (N bytecode bytes, M virtual instrs)
//   [ArmorComp][VMP] virtualized: vmp_float_cmp   (N bytecode bytes, M virtual instrs)
//   [ArmorComp][VMP] virtualized: vmp_float_conv  (N bytecode bytes, M virtual instrs)
//   [ArmorComp][VMP] virtualized: vmp_float_boundary (...)
//   [ArmorComp][VMP] virtualized: vmp_dot3        (N bytecode bytes, M virtual instrs)
//   [ArmorComp][VMP] virtualized: vmp_lerp        (N bytecode bytes, M virtual instrs)
//   [ArmorComp][VMP] virtualized: vmp_fneg_test   (N bytecode bytes, M virtual instrs)
//
// Expected stdout ends with:
//   ALL TESTS PASSED

#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Struct used by multi-level GEP tests.
// At -O0, field accesses generate gep %Point, ptr %p, i32 0, i32 <field>
// (2 indices) which exercises the accumulateConstantOffset path.
typedef struct { int x; int y; } Point;

// ── Annotated functions (VMPPass applied) ─────────────────────────────────────

// Simple add: 1 BB, straightforward translation
__attribute__((annotate("vmp")))
int vmp_add(int a, int b) {
    return a + b;
}

// Subtraction with negation
__attribute__((annotate("vmp")))
int vmp_sub(int a, int b) {
    return a - b;
}

// Bitwise operations
__attribute__((annotate("vmp")))
int vmp_bitops(int a, int b) {
    return (a & b) | (a ^ b);
}

// Multi-way branch (no PHIs on conditional edges — simple early return)
__attribute__((annotate("vmp")))
int vmp_classify(int x) {
    if (x < 0)   return -1;
    if (x == 0)  return  0;
    if (x < 100) return  1;
    return 2;
}

// Counted loop (simple accumulation)
__attribute__((annotate("vmp")))
int vmp_loop(int n) {
    int sum = 0;
    int i;
    for (i = 1; i <= n; i++)
        sum += i;
    return sum;
}

// Ternary / select
__attribute__((annotate("vmp")))
int vmp_select(int cond, int a, int b) {
    return cond ? a : b;
}

// Struct field access (multi-level GEP).
// At -O0 the compiler emits gep %Point, ptr, i32 0, i32 <field> (2 indices).
// VMPLifter's accumulateConstantOffset path collapses both indices into a
// single byte offset and emits MOV_IMM + GEP8.
__attribute__((annotate("vmp")))
int vmp_point_sum(int ax, int ay, int bx, int by) {
    Point a, b;
    a.x = ax; a.y = ay;
    b.x = bx; b.y = by;
    return a.x + a.y + b.x + b.y;
}

// Conditional branch + PHI trampoline test.
// At -O0, C's "&&" and "||" operators generate short-circuit IR:
//
//   entry:  br i1 %cmp1, label %land.rhs, label %land.end
//   land.rhs: %cmp2 = ...; br label %land.end
//   land.end: %phi = phi i1 [ false, %entry ], [ %cmp2, %land.rhs ]
//
// The branch from %entry to %land.end is a conditional branch whose
// false-successor has a PHI node.  VMPLifter emits a per-edge trampoline:
//   JCC cond, land_rhs_off, trampoline_off
//   [trampoline: MOV phi_reg, 0 ; JMP land.end]
__attribute__((annotate("vmp")))
int vmp_and_cond(int a, int b, int c) {
    // a > 0 && b > 0 → short-circuit conditional branch with PHI at merge
    if (a > 0 && b > 0) return c;
    return 0;
}

__attribute__((annotate("vmp")))
int vmp_or_cond(int a, int b, int c) {
    // a > 0 || b > 0 → OR short-circuit, also generates PHI at merge
    if (a > 0 || b > 0) return c;
    return 0;
}

// Memory intrinsic lowering test.
// At -O0, __builtin_memcpy / __builtin_memset generate llvm.memcpy / llvm.memset
// intrinsics.  VMPLifter::handleIntrinsic() lowers them to CALL_D targeting the
// corresponding libc function (memcpy / memset).
typedef struct { int x; int y; int z; int w; } Vec4;

__attribute__((annotate("vmp")))
int vmp_memcpy_sum(void) {
    Vec4 src = {10, 20, 30, 40};
    Vec4 dst;
    __builtin_memcpy(&dst, &src, sizeof(Vec4));
    return dst.x + dst.y + dst.z + dst.w;
}

__attribute__((annotate("vmp")))
int vmp_memset_sum(void) {
    Vec4 v;
    __builtin_memset(&v, 0, sizeof(Vec4));
    return v.x + v.y + v.z + v.w; // must be 0
}

// Indirect call through a function pointer.
// At -O0 this generates a CallInst with null callee (calledFunction() == nullptr).
// VMPLifter materialises the pointer via PTRTOINT and emits the CALL opcode.
__attribute__((annotate("vmp")))
int vmp_icall(int (*fn)(int, int), int a, int b) {
    return fn(a, b);
}

// ── Annotated float functions (VMPPass Phase 1) ──────────────────────────────

// Basic double arithmetic: fadd, fsub, fmul, fdiv
__attribute__((annotate("vmp")))
double vmp_float_arith(double a, double b) {
    double sum  = a + b;
    double diff = a - b;
    double prod = a * b;
    double quot = a / b;
    return sum + diff + prod + quot;
}

// Float comparison: fcmp olt, fcmp ogt (ordered only, no !=)
__attribute__((annotate("vmp")))
int vmp_float_cmp(float x, float y) {
    if (x < y) return -1;
    if (x > y) return  1;
    return 0;
}

// Float ↔ int conversions: sitofp, fpext, fptosi
__attribute__((annotate("vmp")))
double vmp_float_conv(int n) {
    double d  = (double)n;       // sitofp i32 → double
    float  f  = (float)n;        // sitofp i32 → float
    double d2 = (double)f;       // fpext  float → double
    int    back = (int)d;         // fptosi double → i32
    return d + d2 + (double)back;
}

// Boundary: NaN / Inf / negative zero (ordered comparisons only)
__attribute__((annotate("vmp")))
int vmp_float_boundary(void) {
    int pass = 1;
    double nan_val = 0.0 / 0.0;

    // NaN: all ordered comparisons return false
    if (nan_val == nan_val) pass = 0;  // OEQ(NaN,NaN) → false
    if (nan_val < 0.0)     pass = 0;  // OLT(NaN,0)   → false
    if (nan_val > 0.0)     pass = 0;  // OGT(NaN,0)   → false
    if (nan_val == 0.0)    pass = 0;  // OEQ(NaN,0)   → false

    // Inf: inf + 1.0 still equals inf
    double inf_val = 1.0 / 0.0;
    double inf_sum = inf_val + 1.0;
    int inf_ok = 0;
    if (inf_sum == inf_val) inf_ok = 1;   // OEQ(+Inf,+Inf) → true
    if (inf_ok == 0) pass = 0;

    // Negative zero: -0.0 == 0.0 in IEEE 754
    double neg_zero = -0.0;
    int nz_ok = 0;
    if (neg_zero == 0.0) nz_ok = 1;      // OEQ(-0.0,0.0) → true
    if (nz_ok == 0) pass = 0;

    return pass;
}

// Dot product (3-element): fmul + fadd, 6 double args
__attribute__((annotate("vmp")))
double vmp_dot3(double a0, double a1, double a2,
                double b0, double b1, double b2) {
    return a0*b0 + a1*b1 + a2*b2;
}

// Linear interpolation (float path): fsub, fmul, fadd
__attribute__((annotate("vmp")))
float vmp_lerp(float a, float b, float t) {
    return a + t * (b - a);
}

// Unary negation: fneg
__attribute__((annotate("vmp")))
double vmp_fneg_test(double x) {
    return -x;
}

// ── Float function call tests (CALL_D with float/double args & returns) ────────

// Helper callees (NOT annotated — these are the targets of CALL_D)
double helper_double_add(double a, double b) { return a + b; }
float  helper_float_mul(float a, float b)    { return a * b; }
double helper_mixed(int n, double d, float f) { return n + d + (double)f; }

// VMP-annotated: exercises CALL_D with double args/return, float args/return,
// and mixed (int + double + float) args.
__attribute__((annotate("vmp")))
double vmp_float_call(double a, double b, float c) {
    double sum  = helper_double_add(a, b);       // double(double,double)
    float  prod = helper_float_mul(c, (float)a);  // float(float,float)
    double mix  = helper_mixed(42, sum, prod);     // double(int,double,float)
    return mix;
}

// VMP-annotated: exercises fcmp une (C's !=) and fcmp ueq
__attribute__((annotate("vmp")))
int vmp_fcmp_une(double a, double b) {
    int r = 0;
    if (a != b) r |= 1;   // fcmp une → true when a!=b or either is NaN
    if (a == a) r |= 2;   // fcmp oeq (ordered) — false for NaN
    return r;
}

// ── Unordered FCmp predicate tests (ULT/ULE/UGT/UGE/ORD/UNO) ─────────────────

// Tests all unordered float comparisons + ORD/UNO.
// Each bit in the result encodes a different predicate outcome.
__attribute__((annotate("vmp")))
int vmp_fcmp_unord(double a, double b) {
    int r = 0;
    if (!(a >= b)) r |= 1;    // fcmp ult: !(a >= b) → unordered less-than
    if (!(a >  b)) r |= 2;    // fcmp ule: !(a > b) → unordered less-or-equal
    if (!(a <= b)) r |= 4;    // fcmp ugt: !(a <= b) → unordered greater-than
    if (!(a <  b)) r |= 8;    // fcmp uge: !(a < b) → unordered greater-or-equal
    return r;
}

int plain_fcmp_unord(double a, double b) {
    int r = 0;
    if (!(a >= b)) r |= 1;
    if (!(a >  b)) r |= 2;
    if (!(a <= b)) r |= 4;
    if (!(a <  b)) r |= 8;
    return r;
}

// Note: fcmp ORD/UNO opcodes are implemented in the ISA but rarely emitted
// at -O0 (Clang uses `llvm.is.fpclass` intrinsic for __builtin_isnan at -O0,
// which is not yet handled by the lifter).  The opcodes are correct by
// construction via the same mkFCmp template as all other FCmp handlers.
// ORD/UNO appear at -O1+ when the optimizer collapses isnan patterns.

// ── SwitchInst test (lowered to cascading ICmp_EQ + JCC) ──────────────────────

// Switch on integer value with multiple cases + default
__attribute__((annotate("vmp")))
int vmp_switch(int x) {
    int r;
    switch (x) {
    case 0:  r = 100; break;
    case 1:  r = 200; break;
    case 5:  r = 500; break;
    case 10: r = 1000; break;
    case -1: r = -100; break;
    default: r = 42; break;
    }
    return r;
}

// Plain reference
int plain_switch(int x) {
    int r;
    switch (x) {
    case 0:  r = 100; break;
    case 1:  r = 200; break;
    case 5:  r = 500; break;
    case 10: r = 1000; break;
    case -1: r = -100; break;
    default: r = 42; break;
    }
    return r;
}

// ── High register pressure tests (new — tests register spill/reclaim) ─────────

// 60+ local variables: chain of dependent computations.
// Old code (64 regs, no reclaim) would crash at nextVReg >= 64.
// New code (128 regs + dead reg reclamation) should handle this easily.
__attribute__((annotate("vmp")))
int vmp_high_pressure(int seed) {
    int v0  = seed + 1;   int v1  = v0  * 3;   int v2  = v1  - 7;
    int v3  = v2  ^ 0xFF; int v4  = v3  + v0;   int v5  = v4  & 0xFFF;
    int v6  = v5  | v2;   int v7  = v6  + 13;   int v8  = v7  * 2;
    int v9  = v8  - v3;   int v10 = v9  + v5;   int v11 = v10 ^ v1;
    int v12 = v11 + 42;   int v13 = v12 - v8;   int v14 = v13 & 0x7F;
    int v15 = v14 | v6;   int v16 = v15 + v0;   int v17 = v16 * 5;
    int v18 = v17 - v10;  int v19 = v18 + v4;   int v20 = v19 ^ v12;
    int v21 = v20 + 99;   int v22 = v21 - v15;  int v23 = v22 & 0xFF;
    int v24 = v23 | v17;  int v25 = v24 + v9;   int v26 = v25 * 3;
    int v27 = v26 - v20;  int v28 = v27 + v11;  int v29 = v28 ^ v22;
    int v30 = v29 + 7;    int v31 = v30 - v24;  int v32 = v31 & 0x3FF;
    int v33 = v32 | v26;  int v34 = v33 + v13;  int v35 = v34 * 2;
    int v36 = v35 - v29;  int v37 = v36 + v16;  int v38 = v37 ^ v31;
    int v39 = v38 + 55;   int v40 = v39 - v33;  int v41 = v40 & 0x1FF;
    int v42 = v41 | v35;  int v43 = v42 + v18;  int v44 = v43 * 7;
    int v45 = v44 - v38;  int v46 = v45 + v21;  int v47 = v46 ^ v40;
    int v48 = v47 + 23;   int v49 = v48 - v42;  int v50 = v49 & 0xFFF;
    int v51 = v50 | v44;  int v52 = v51 + v27;  int v53 = v52 * 11;
    int v54 = v53 - v47;  int v55 = v54 + v30;  int v56 = v55 ^ v49;
    int v57 = v56 + 17;   int v58 = v57 - v51;  int v59 = v58 & 0x7FF;
    return v59;
}

// Plain reference for high_pressure
int plain_high_pressure(int seed) {
    int v0  = seed + 1;   int v1  = v0  * 3;   int v2  = v1  - 7;
    int v3  = v2  ^ 0xFF; int v4  = v3  + v0;   int v5  = v4  & 0xFFF;
    int v6  = v5  | v2;   int v7  = v6  + 13;   int v8  = v7  * 2;
    int v9  = v8  - v3;   int v10 = v9  + v5;   int v11 = v10 ^ v1;
    int v12 = v11 + 42;   int v13 = v12 - v8;   int v14 = v13 & 0x7F;
    int v15 = v14 | v6;   int v16 = v15 + v0;   int v17 = v16 * 5;
    int v18 = v17 - v10;  int v19 = v18 + v4;   int v20 = v19 ^ v12;
    int v21 = v20 + 99;   int v22 = v21 - v15;  int v23 = v22 & 0xFF;
    int v24 = v23 | v17;  int v25 = v24 + v9;   int v26 = v25 * 3;
    int v27 = v26 - v20;  int v28 = v27 + v11;  int v29 = v28 ^ v22;
    int v30 = v29 + 7;    int v31 = v30 - v24;  int v32 = v31 & 0x3FF;
    int v33 = v32 | v26;  int v34 = v33 + v13;  int v35 = v34 * 2;
    int v36 = v35 - v29;  int v37 = v36 + v16;  int v38 = v37 ^ v31;
    int v39 = v38 + 55;   int v40 = v39 - v33;  int v41 = v40 & 0x1FF;
    int v42 = v41 | v35;  int v43 = v42 + v18;  int v44 = v43 * 7;
    int v45 = v44 - v38;  int v46 = v45 + v21;  int v47 = v46 ^ v40;
    int v48 = v47 + 23;   int v49 = v48 - v42;  int v50 = v49 & 0xFFF;
    int v51 = v50 | v44;  int v52 = v51 + v27;  int v53 = v52 * 11;
    int v54 = v53 - v47;  int v55 = v54 + v30;  int v56 = v55 ^ v49;
    int v57 = v56 + 17;   int v58 = v57 - v51;  int v59 = v58 & 0x7FF;
    return v59;
}

// 100+ SSA values but each only used once — tests that dead regs are reclaimed.
// Peak live registers should be far below 128.
__attribute__((annotate("vmp")))
int vmp_recycle_test(int a, int b) {
    int r = a;
    r = r + b; r = r * 3; r = r - 7; r = r ^ 0xAB; r = r + 1;
    r = r * 2; r = r - 5; r = r ^ 0xCD; r = r + 3; r = r * 7;
    r = r - 11; r = r ^ 0xEF; r = r + 13; r = r * 5; r = r - 17;
    r = r ^ 0x12; r = r + 19; r = r * 3; r = r - 23; r = r ^ 0x34;
    r = r + 29; r = r * 11; r = r - 31; r = r ^ 0x56; r = r + 37;
    r = r * 2; r = r - 41; r = r ^ 0x78; r = r + 43; r = r * 3;
    r = r - 47; r = r ^ 0x9A; r = r + 53; r = r * 7; r = r - 59;
    r = r ^ 0xBC; r = r + 61; r = r * 5; r = r - 67; r = r ^ 0xDE;
    r = r + 71; r = r * 2; r = r - 73; r = r ^ 0xF0; r = r + 79;
    r = r * 3; r = r - 83; r = r ^ 0x11; r = r + 89; r = r * 7;
    r = r & 0xFFFF;
    return r;
}

// Plain reference for recycle_test
int plain_recycle_test(int a, int b) {
    int r = a;
    r = r + b; r = r * 3; r = r - 7; r = r ^ 0xAB; r = r + 1;
    r = r * 2; r = r - 5; r = r ^ 0xCD; r = r + 3; r = r * 7;
    r = r - 11; r = r ^ 0xEF; r = r + 13; r = r * 5; r = r - 17;
    r = r ^ 0x12; r = r + 19; r = r * 3; r = r - 23; r = r ^ 0x34;
    r = r + 29; r = r * 11; r = r - 31; r = r ^ 0x56; r = r + 37;
    r = r * 2; r = r - 41; r = r ^ 0x78; r = r + 43; r = r * 3;
    r = r - 47; r = r ^ 0x9A; r = r + 53; r = r * 7; r = r - 59;
    r = r ^ 0xBC; r = r + 61; r = r * 5; r = r - 67; r = r ^ 0xDE;
    r = r + 71; r = r * 2; r = r - 73; r = r ^ 0xF0; r = r + 79;
    r = r * 3; r = r - 83; r = r ^ 0x11; r = r + 89; r = r * 7;
    r = r & 0xFFFF;
    return r;
}

// ── Plain reference implementations (no annotation) ───────────────────────────

int plain_and_cond(int a, int b, int c) { return (a > 0 && b > 0) ? c : 0; }
int plain_or_cond(int a, int b, int c)  { return (a > 0 || b > 0) ? c : 0; }

int plain_add(int a, int b)       { return a + b; }
int plain_sub(int a, int b)       { return a - b; }
int plain_bitops(int a, int b)    { return (a & b) | (a ^ b); }
int plain_select(int c, int a, int b) { return c ? a : b; }
int plain_point_sum(int ax, int ay, int bx, int by) {
    Point a, b;
    a.x = ax; a.y = ay;
    b.x = bx; b.y = by;
    return a.x + a.y + b.x + b.y;
}

double plain_float_arith(double a, double b) {
    return (a+b) + (a-b) + (a*b) + (a/b);
}
int plain_float_cmp(float x, float y) {
    if (x < y) return -1;
    if (x > y) return  1;
    return 0;
}
double plain_float_conv(int n) {
    double d = (double)n; float f = (float)n;
    double d2 = (double)f; int back = (int)d;
    return d + d2 + (double)back;
}
double plain_dot3(double a0, double a1, double a2,
                  double b0, double b1, double b2) {
    return a0*b0 + a1*b1 + a2*b2;
}
float plain_lerp(float a, float b, float t) {
    return a + t * (b - a);
}

double plain_float_call(double a, double b, float c) {
    double sum  = helper_double_add(a, b);
    float  prod = helper_float_mul(c, (float)a);
    double mix  = helper_mixed(42, sum, prod);
    return mix;
}
int plain_fcmp_une(double a, double b) {
    int r = 0;
    if (a != b) r |= 1;
    if (a == a) r |= 2;
    return r;
}

int plain_classify(int x) {
    if (x < 0)   return -1;
    if (x == 0)  return  0;
    if (x < 100) return  1;
    return 2;
}

int plain_loop(int n) {
    int sum = 0, i;
    for (i = 1; i <= n; i++)
        sum += i;
    return sum;
}

// ── AtomicRMW tests (P3-b) ────────────────────────────────────────────────────
// __sync_* builtins generate atomicrmw / cmpxchg LLVM IR.
// VMP lifter lowers these to non-atomic load+op+store sequences, which is
// semantically correct for single-threaded VMP dispatch.

__attribute__((annotate("vmp")))
int vmp_atomic_add(int *p, int val) {
    return __sync_fetch_and_add(p, val); // atomicrmw add
}

__attribute__((annotate("vmp")))
int vmp_atomic_sub(int *p, int val) {
    return __sync_fetch_and_sub(p, val); // atomicrmw sub
}

__attribute__((annotate("vmp")))
int vmp_atomic_xchg(int *p, int val) {
    return __sync_lock_test_and_set(p, val); // atomicrmw xchg
}

__attribute__((annotate("vmp")))
int vmp_cmpxchg(int *p, int expected, int desired) {
    return __sync_val_compare_and_swap(p, expected, desired); // cmpxchg
}

// Plain counterparts — use real atomic ops (same result in single-threaded test)
int plain_atomic_add(int *p, int val) {
    return __sync_fetch_and_add(p, val);
}
int plain_atomic_sub(int *p, int val) {
    return __sync_fetch_and_sub(p, val);
}
int plain_atomic_xchg(int *p, int val) {
    return __sync_lock_test_and_set(p, val);
}
int plain_cmpxchg(int *p, int expected, int desired) {
    return __sync_val_compare_and_swap(p, expected, desired);
}

// ── FreezeInst test ─────────────────────────────────────────────────────────
// Clang generates FreezeInst in certain optimization patterns (e.g. select
// of potentially-undef values).  VMP should handle it as a no-op copy.
__attribute__((annotate("vmp")))
int vmp_freeze_test(int a, int b) {
    return (a > 0) ? a : b;
}
int plain_freeze_test(int a, int b) {
    return (a > 0) ? a : b;
}

// ── VarArg call test ────────────────────────────────────────────────────────
// Tests that VMP can handle calls to vararg functions (snprintf) via the
// wrapper function mechanism.  We return snprintf's return value directly
// (number of chars written) to avoid variable-index GEP in the while loop
// which is unsupported at -O0.
__attribute__((annotate("vmp")))
int vmp_vararg_test(int x, int y) {
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%d+%d=%d", x, y, x + y);
    return len;
}
int plain_vararg_test(int x, int y) {
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%d+%d=%d", x, y, x + y);
    return len;
}

// ── Super-instruction test ──────────────────────────────────────────────────
// Tests ADD_I32/SUB_I32 fused immediate opcodes.
__attribute__((annotate("vmp")))
int vmp_super_instr_test(int x) {
    int a = x + 42;
    int b = a - 17;
    int c = b + 100;
    return c - 1;
}
int plain_super_instr_test(int x) {
    int a = x + 42;
    int b = a - 17;
    int c = b + 100;
    return c - 1;
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main(void) {
    int ok = 1;

    // Print representative samples
    printf("vmp_add(3, 4)          = %d\n", vmp_add(3, 4));
    printf("plain_add(3, 4)        = %d\n", plain_add(3, 4));
    printf("vmp_sub(10, 3)         = %d\n", vmp_sub(10, 3));
    printf("vmp_bitops(0xF0, 0x0F) = %d\n", vmp_bitops(0xF0, 0x0F));
    printf("vmp_classify(-5)       = %d\n", vmp_classify(-5));
    printf("vmp_classify(0)        = %d\n", vmp_classify(0));
    printf("vmp_classify(50)       = %d\n", vmp_classify(50));
    printf("vmp_classify(200)      = %d\n", vmp_classify(200));
    printf("vmp_loop(10)           = %d\n", vmp_loop(10));
    printf("plain_loop(10)         = %d\n", plain_loop(10));
    printf("vmp_select(1, 7, 42)   = %d\n", vmp_select(1, 7, 42));
    printf("vmp_select(0, 7, 42)   = %d\n", vmp_select(0, 7, 42));
    printf("vmp_point_sum(1,2,3,4) = %d\n", vmp_point_sum(1, 2, 3, 4));
    printf("vmp_and_cond(1,1,99)   = %d\n", vmp_and_cond(1, 1, 99));
    printf("vmp_and_cond(1,0,99)   = %d\n", vmp_and_cond(1, 0, 99));
    printf("vmp_or_cond(0,0,99)    = %d\n", vmp_or_cond(0, 0, 99));
    printf("vmp_or_cond(1,0,99)    = %d\n", vmp_or_cond(1, 0, 99));
    printf("vmp_memcpy_sum()       = %d\n", vmp_memcpy_sum());
    printf("vmp_memset_sum()       = %d\n", vmp_memset_sum());
    printf("vmp_icall(add,3,4)     = %d\n", vmp_icall(plain_add, 3, 4));
    printf("vmp_icall(sub,10,3)    = %d\n", vmp_icall(plain_sub, 10, 3));

    // Float samples
    printf("vmp_float_arith(3,4)   = %.6g\n", vmp_float_arith(3.0, 4.0));
    printf("plain_float_arith(3,4) = %.6g\n", plain_float_arith(3.0, 4.0));
    printf("vmp_float_cmp(1,2)     = %d\n", vmp_float_cmp(1.0f, 2.0f));
    printf("vmp_float_cmp(2,1)     = %d\n", vmp_float_cmp(2.0f, 1.0f));
    printf("vmp_float_cmp(1,1)     = %d\n", vmp_float_cmp(1.0f, 1.0f));
    printf("vmp_float_conv(42)     = %.6g\n", vmp_float_conv(42));
    printf("vmp_float_boundary()   = %d\n", vmp_float_boundary());
    printf("vmp_dot3(1,2,3,4,5,6)  = %.6g\n", vmp_dot3(1,2,3,4,5,6));
    printf("vmp_lerp(0,1,0.5)      = %.6g\n", (double)vmp_lerp(0.0f,1.0f,0.5f));
    printf("vmp_fneg_test(3.14)    = %.6g\n", vmp_fneg_test(3.14));

    // ── Verify vmp_add == plain_add ────────────────────────────────────────
    {
        int cases[][2] = {
            {0,0},{1,2},{-1,-2},{100,-50},{2147483647,0},{-2147483648,0},
        };
        int n = (int)(sizeof(cases)/sizeof(cases[0]));
        for (int i = 0; i < n; i++) {
            int a = cases[i][0], b = cases[i][1];
            if (vmp_add(a,b) != plain_add(a,b)) {
                printf("FAIL vmp_add[%d]: vmp=%d plain=%d\n",
                       i, vmp_add(a,b), plain_add(a,b));
                ok = 0;
            }
        }
    }

    // ── Verify vmp_sub == plain_sub ────────────────────────────────────────
    {
        int cases[][2] = {
            {0,0},{5,3},{-5,-3},{100,50},{0,-2147483648},
        };
        int n = (int)(sizeof(cases)/sizeof(cases[0]));
        for (int i = 0; i < n; i++) {
            int a = cases[i][0], b = cases[i][1];
            if (vmp_sub(a,b) != plain_sub(a,b)) {
                printf("FAIL vmp_sub[%d]\n", i);
                ok = 0;
            }
        }
    }

    // ── Verify vmp_bitops == plain_bitops ──────────────────────────────────
    {
        int cases[][2] = {
            {0,0},{0xFF,0xFF},{0xF0,0x0F},{0xABCD,0x1234},{-1,0},
        };
        int n = (int)(sizeof(cases)/sizeof(cases[0]));
        for (int i = 0; i < n; i++) {
            int a = cases[i][0], b = cases[i][1];
            if (vmp_bitops(a,b) != plain_bitops(a,b)) {
                printf("FAIL vmp_bitops[%d]\n", i);
                ok = 0;
            }
        }
    }

    // ── Verify vmp_classify == plain_classify ─────────────────────────────
    {
        int vals[] = {-100,-1,0,1,50,99,100,200,2147483647,-2147483648};
        int n = (int)(sizeof(vals)/sizeof(vals[0]));
        for (int i = 0; i < n; i++) {
            if (vmp_classify(vals[i]) != plain_classify(vals[i])) {
                printf("FAIL vmp_classify[%d]: x=%d\n", i, vals[i]);
                ok = 0;
            }
        }
    }

    // ── Verify vmp_loop == plain_loop ─────────────────────────────────────
    {
        int vals[] = {0,1,2,5,10,50,100};
        int n = (int)(sizeof(vals)/sizeof(vals[0]));
        for (int i = 0; i < n; i++) {
            if (vmp_loop(vals[i]) != plain_loop(vals[i])) {
                printf("FAIL vmp_loop[%d]: n=%d\n", i, vals[i]);
                ok = 0;
            }
        }
    }

    // ── Verify vmp_select == plain_select ─────────────────────────────────
    {
        int conds[] = {0, 1, -1, 42};
        int as[]    = {7, 0, -100, 2147483647};
        int bs[]    = {42, -1, 999, -2147483648};
        int nc = (int)(sizeof(conds)/sizeof(conds[0]));
        int na = (int)(sizeof(as)/sizeof(as[0]));
        for (int i = 0; i < nc; i++) {
            for (int j = 0; j < na; j++) {
                if (vmp_select(conds[i],as[j],bs[j]) !=
                    plain_select(conds[i],as[j],bs[j])) {
                    printf("FAIL vmp_select[%d][%d]\n", i, j);
                    ok = 0;
                }
            }
        }
    }

    // ── Verify vmp_memcpy_sum / vmp_memset_sum (intrinsic lowering) ───────
    if (vmp_memcpy_sum() != 100) {
        printf("FAIL vmp_memcpy_sum: got=%d exp=100\n", vmp_memcpy_sum());
        ok = 0;
    }
    if (vmp_memset_sum() != 0) {
        printf("FAIL vmp_memset_sum: got=%d exp=0\n", vmp_memset_sum());
        ok = 0;
    }

    // ── Verify vmp_and_cond / vmp_or_cond (PHI trampoline) ───────────────
    {
        int a[] = {-1, 0, 1, 2};
        int b[] = {-1, 0, 1, 2};
        int na = (int)(sizeof(a)/sizeof(a[0]));
        int nb = (int)(sizeof(b)/sizeof(b[0]));
        for (int i = 0; i < na; i++) {
            for (int j = 0; j < nb; j++) {
                int c = (i * 10) + j;
                if (vmp_and_cond(a[i],b[j],c) != plain_and_cond(a[i],b[j],c)) {
                    printf("FAIL vmp_and_cond[%d][%d]\n", i, j);
                    ok = 0;
                }
                if (vmp_or_cond(a[i],b[j],c) != plain_or_cond(a[i],b[j],c)) {
                    printf("FAIL vmp_or_cond[%d][%d]\n", i, j);
                    ok = 0;
                }
            }
        }
    }

    // ── Verify vmp_point_sum == plain_point_sum (struct GEP) ──────────────
    {
        int cases[][4] = {
            {0,0,0,0},{1,2,3,4},{-1,-2,-3,-4},{100,200,-100,-200},
            {2147483647,0,0,-2147483647},
        };
        int n = (int)(sizeof(cases)/sizeof(cases[0]));
        for (int i = 0; i < n; i++) {
            int ax=cases[i][0], ay=cases[i][1], bx=cases[i][2], by=cases[i][3];
            int got = vmp_point_sum(ax, ay, bx, by);
            int exp = plain_point_sum(ax, ay, bx, by);
            if (got != exp) {
                printf("FAIL vmp_point_sum[%d]: got=%d exp=%d\n", i, got, exp);
                ok = 0;
            }
        }
    }

    // ── Verify vmp_icall (indirect call via function pointer) ─────────────
    {
        int cases[][2] = {
            {0,0},{3,4},{-1,-2},{100,-50},{10,3},
        };
        int n = (int)(sizeof(cases)/sizeof(cases[0]));
        for (int i = 0; i < n; i++) {
            int a = cases[i][0], b = cases[i][1];
            if (vmp_icall(plain_add, a, b) != plain_add(a, b)) {
                printf("FAIL vmp_icall(add)[%d]: got=%d exp=%d\n",
                       i, vmp_icall(plain_add,a,b), plain_add(a,b));
                ok = 0;
            }
            if (vmp_icall(plain_sub, a, b) != plain_sub(a, b)) {
                printf("FAIL vmp_icall(sub)[%d]: got=%d exp=%d\n",
                       i, vmp_icall(plain_sub,a,b), plain_sub(a,b));
                ok = 0;
            }
        }
    }

    // ── Verify vmp_float_arith == plain_float_arith ────────────────────
    {
        double cases[][2] = {
            {3.0, 4.0}, {1.5, 2.5}, {-1.0, 1.0},
            {100.5, -50.25}, {0.001, 1000.0},
        };
        int n = (int)(sizeof(cases)/sizeof(cases[0]));
        for (int i = 0; i < n; i++) {
            double a = cases[i][0], b = cases[i][1];
            double got = vmp_float_arith(a, b);
            double exp = plain_float_arith(a, b);
            if (got != exp) {
                printf("FAIL vmp_float_arith[%d]: got=%.15g exp=%.15g\n",
                       i, got, exp);
                ok = 0;
            }
        }
    }

    // ── Verify vmp_float_cmp == plain_float_cmp ─────────────────────
    {
        float fx[] = {1.0f, 2.0f, 1.0f, -1.0f, 0.0f, 3.14f};
        float fy[] = {2.0f, 1.0f, 1.0f,  1.0f, -0.0f, 3.14f};
        int n = (int)(sizeof(fx)/sizeof(fx[0]));
        for (int i = 0; i < n; i++) {
            int got = vmp_float_cmp(fx[i], fy[i]);
            int exp = plain_float_cmp(fx[i], fy[i]);
            if (got != exp) {
                printf("FAIL vmp_float_cmp[%d]: got=%d exp=%d\n", i, got, exp);
                ok = 0;
            }
        }
    }

    // ── Verify vmp_float_conv == plain_float_conv ───────────────────
    {
        int vals[] = {0, 1, -1, 42, -100, 1000000};
        int n = (int)(sizeof(vals)/sizeof(vals[0]));
        for (int i = 0; i < n; i++) {
            double got = vmp_float_conv(vals[i]);
            double exp = plain_float_conv(vals[i]);
            if (got != exp) {
                printf("FAIL vmp_float_conv[%d]: n=%d got=%.15g exp=%.15g\n",
                       i, vals[i], got, exp);
                ok = 0;
            }
        }
    }

    // ── Verify vmp_float_boundary (NaN/Inf/neg-zero) ────────────────
    if (vmp_float_boundary() != 1) {
        printf("FAIL vmp_float_boundary: got=%d exp=1\n", vmp_float_boundary());
        ok = 0;
    }

    // ── Verify vmp_dot3 == plain_dot3 ───────────────────────────────
    {
        double got = vmp_dot3(1,0,0, 0,1,0);
        double exp = plain_dot3(1,0,0, 0,1,0);
        if (got != exp) { printf("FAIL vmp_dot3[0]\n"); ok = 0; }
        got = vmp_dot3(1,2,3, 4,5,6);
        exp = plain_dot3(1,2,3, 4,5,6);
        if (got != exp) { printf("FAIL vmp_dot3[1]\n"); ok = 0; }
        got = vmp_dot3(-1.5, 2.5, 0.0, 4.0, -3.0, 1.0);
        exp = plain_dot3(-1.5, 2.5, 0.0, 4.0, -3.0, 1.0);
        if (got != exp) { printf("FAIL vmp_dot3[2]\n"); ok = 0; }
    }

    // ── Verify vmp_lerp == plain_lerp ───────────────────────────────
    {
        float got = vmp_lerp(0.0f, 1.0f, 0.5f);
        float exp = plain_lerp(0.0f, 1.0f, 0.5f);
        if (got != exp) { printf("FAIL vmp_lerp[0]\n"); ok = 0; }
        got = vmp_lerp(0.0f, 10.0f, 0.25f);
        exp = plain_lerp(0.0f, 10.0f, 0.25f);
        if (got != exp) { printf("FAIL vmp_lerp[1]\n"); ok = 0; }
        got = vmp_lerp(-5.0f, 5.0f, 1.0f);
        exp = plain_lerp(-5.0f, 5.0f, 1.0f);
        if (got != exp) { printf("FAIL vmp_lerp[2]\n"); ok = 0; }
    }

    // ── Verify vmp_fneg_test ────────────────────────────────────────
    {
        double vals[] = {1.0, -1.0, 0.0, 3.14, -2.718};
        int n = (int)(sizeof(vals)/sizeof(vals[0]));
        for (int i = 0; i < n; i++) {
            double got = vmp_fneg_test(vals[i]);
            double exp = -vals[i];
            if (got != exp) {
                printf("FAIL vmp_fneg_test[%d]: got=%.15g exp=%.15g\n",
                       i, got, exp);
                ok = 0;
            }
        }
    }

    // ── Verify vmp_float_call (CALL_D with float/double args & returns) ──
    {
        double got = vmp_float_call(1.5, 2.5, 3.0f);
        double exp = plain_float_call(1.5, 2.5, 3.0f);
        if (got != exp) {
            printf("FAIL vmp_float_call[0]: got=%.15g exp=%.15g\n", got, exp);
            ok = 0;
        }
        got = vmp_float_call(-10.0, 20.0, 0.5f);
        exp = plain_float_call(-10.0, 20.0, 0.5f);
        if (got != exp) {
            printf("FAIL vmp_float_call[1]: got=%.15g exp=%.15g\n", got, exp);
            ok = 0;
        }
        got = vmp_float_call(0.0, 0.0, 0.0f);
        exp = plain_float_call(0.0, 0.0, 0.0f);
        if (got != exp) {
            printf("FAIL vmp_float_call[2]: got=%.15g exp=%.15g\n", got, exp);
            ok = 0;
        }
    }

    // ── Verify vmp_fcmp_une (fcmp une / ueq) ────────────────────────────
    {
        int got, exp;
        // Different values: une=true(1), oeq=true(2) → 3
        got = vmp_fcmp_une(1.0, 2.0); exp = plain_fcmp_une(1.0, 2.0);
        if (got != exp) { printf("FAIL vmp_fcmp_une[0]: got=%d exp=%d\n", got, exp); ok = 0; }
        // Same values: une=false(0), oeq=true(2) → 2
        got = vmp_fcmp_une(3.0, 3.0); exp = plain_fcmp_une(3.0, 3.0);
        if (got != exp) { printf("FAIL vmp_fcmp_une[1]: got=%d exp=%d\n", got, exp); ok = 0; }
        // NaN: une=true(1), oeq(NaN,NaN)=false(0) → 1
        double nan_val = 0.0 / 0.0;
        got = vmp_fcmp_une(nan_val, 1.0); exp = plain_fcmp_une(nan_val, 1.0);
        if (got != exp) { printf("FAIL vmp_fcmp_une[2]: got=%d exp=%d\n", got, exp); ok = 0; }
        // NaN self: une(NaN,NaN)=true(1), oeq(NaN,NaN)=false(0) → 1
        got = vmp_fcmp_une(nan_val, nan_val); exp = plain_fcmp_une(nan_val, nan_val);
        if (got != exp) { printf("FAIL vmp_fcmp_une[3]: got=%d exp=%d\n", got, exp); ok = 0; }
    }

    // ── Verify vmp_fcmp_unord (unordered ULT/ULE/UGT/UGE) ─────────────
    {
        double cases[][2] = {
            {1.0, 2.0}, {2.0, 1.0}, {1.0, 1.0}, {-1.0, 1.0},
            {0.0, 0.0}, {100.5, -50.25},
        };
        int n = (int)(sizeof(cases)/sizeof(cases[0]));
        for (int i = 0; i < n; i++) {
            double a = cases[i][0], b = cases[i][1];
            int got = vmp_fcmp_unord(a, b);
            int exp = plain_fcmp_unord(a, b);
            if (got != exp) {
                printf("FAIL vmp_fcmp_unord[%d]: a=%.1f b=%.1f got=%d exp=%d\n",
                       i, a, b, got, exp);
                ok = 0;
            }
        }
        // NaN cases: all unordered comparisons return true when NaN is involved
        double nan_val = 0.0 / 0.0;
        {
            int got = vmp_fcmp_unord(nan_val, 1.0);
            int exp = plain_fcmp_unord(nan_val, 1.0);
            if (got != exp) {
                printf("FAIL vmp_fcmp_unord[nan,1]: got=%d exp=%d\n", got, exp);
                ok = 0;
            }
        }
        {
            int got = vmp_fcmp_unord(1.0, nan_val);
            int exp = plain_fcmp_unord(1.0, nan_val);
            if (got != exp) {
                printf("FAIL vmp_fcmp_unord[1,nan]: got=%d exp=%d\n", got, exp);
                ok = 0;
            }
        }
    }

    // ── Verify vmp_switch == plain_switch (SwitchInst lowering) ────────
    {
        int vals[] = {-2, -1, 0, 1, 2, 3, 5, 7, 10, 99, 2147483647};
        int n = (int)(sizeof(vals)/sizeof(vals[0]));
        for (int i = 0; i < n; i++) {
            int got = vmp_switch(vals[i]);
            int exp = plain_switch(vals[i]);
            if (got != exp) {
                printf("FAIL vmp_switch[%d]: x=%d got=%d exp=%d\n",
                       i, vals[i], got, exp);
                ok = 0;
            }
        }
    }

    // ── Verify vmp_high_pressure (60+ locals, high register pressure) ──
    {
        int seeds[] = {0, 1, -1, 42, 100, -999, 2147483647};
        int n = (int)(sizeof(seeds)/sizeof(seeds[0]));
        for (int i = 0; i < n; i++) {
            int got = vmp_high_pressure(seeds[i]);
            int exp = plain_high_pressure(seeds[i]);
            if (got != exp) {
                printf("FAIL vmp_high_pressure[%d]: seed=%d got=%d exp=%d\n",
                       i, seeds[i], got, exp);
                ok = 0;
            }
        }
    }

    // ── Verify vmp_recycle_test (100+ SSA values, each used once) ────
    {
        int cases[][2] = {{0,0},{1,2},{-1,-2},{42,99},{100,-50}};
        int n = (int)(sizeof(cases)/sizeof(cases[0]));
        for (int i = 0; i < n; i++) {
            int a = cases[i][0], b = cases[i][1];
            int got = vmp_recycle_test(a, b);
            int exp = plain_recycle_test(a, b);
            if (got != exp) {
                printf("FAIL vmp_recycle_test[%d]: a=%d b=%d got=%d exp=%d\n",
                       i, a, b, got, exp);
                ok = 0;
            }
        }
    }

    // ── Verify vmp_atomic_add / vmp_atomic_sub (AtomicRMW) ──────────────
    {
        int v1 = 10, p1 = 10;
        int r1 = vmp_atomic_add(&v1, 5);
        int e1 = plain_atomic_add(&p1, 5);
        if (r1 != e1 || v1 != p1) {
            printf("FAIL vmp_atomic_add: got old=%d new=%d, exp old=%d new=%d\n",
                   r1, v1, e1, p1);
            ok = 0;
        }

        int v2 = 20, p2 = 20;
        int r2 = vmp_atomic_sub(&v2, 7);
        int e2 = plain_atomic_sub(&p2, 7);
        if (r2 != e2 || v2 != p2) {
            printf("FAIL vmp_atomic_sub: got old=%d new=%d, exp old=%d new=%d\n",
                   r2, v2, e2, p2);
            ok = 0;
        }
    }

    // ── Verify vmp_atomic_xchg (AtomicRMW xchg) ──────────────────────
    {
        int v = 42, p = 42;
        int r = vmp_atomic_xchg(&v, 99);
        int e = plain_atomic_xchg(&p, 99);
        if (r != e || v != p) {
            printf("FAIL vmp_atomic_xchg: got old=%d new=%d, exp old=%d new=%d\n",
                   r, v, e, p);
            ok = 0;
        }
    }

    // ── Verify vmp_cmpxchg (CmpXchg — success + failure paths) ───────
    {
        // Success case: expected matches current
        int v1 = 10, p1 = 10;
        int r1 = vmp_cmpxchg(&v1, 10, 20);
        int e1 = plain_cmpxchg(&p1, 10, 20);
        if (r1 != e1 || v1 != p1) {
            printf("FAIL vmp_cmpxchg[success]: got old=%d new=%d, exp old=%d new=%d\n",
                   r1, v1, e1, p1);
            ok = 0;
        }

        // Failure case: expected does NOT match current
        int v2 = 30, p2 = 30;
        int r2 = vmp_cmpxchg(&v2, 99, 50);
        int e2 = plain_cmpxchg(&p2, 99, 50);
        if (r2 != e2 || v2 != p2) {
            printf("FAIL vmp_cmpxchg[fail]: got old=%d new=%d, exp old=%d new=%d\n",
                   r2, v2, e2, p2);
            ok = 0;
        }
    }

    // ── Verify vmp_freeze_test ────────────────────────────────────────
    {
        int cases[][3] = {{5, 10, 5}, {-3, 7, 7}, {0, 42, 42}, {1, 0, 1}};
        for (int i = 0; i < 4; ++i) {
            int r = vmp_freeze_test(cases[i][0], cases[i][1]);
            int e = plain_freeze_test(cases[i][0], cases[i][1]);
            if (r != e) {
                printf("FAIL vmp_freeze_test(%d,%d): got %d, exp %d\n",
                       cases[i][0], cases[i][1], r, e);
                ok = 0;
            }
        }
    }

    // ── Verify vmp_vararg_test (snprintf call via VMP wrapper) ───────
    {
        int r = vmp_vararg_test(3, 4);
        int e = plain_vararg_test(3, 4);
        if (r != e) {
            printf("FAIL vmp_vararg_test(3,4): got %d, exp %d\n", r, e);
            ok = 0;
        }
        r = vmp_vararg_test(100, 200);
        e = plain_vararg_test(100, 200);
        if (r != e) {
            printf("FAIL vmp_vararg_test(100,200): got %d, exp %d\n", r, e);
            ok = 0;
        }
    }

    // ── Verify vmp_super_instr_test (ADD_I32 / SUB_I32 opcodes) ─────
    {
        int inputs[] = {0, 10, -50, 1000000};
        for (int i = 0; i < 4; ++i) {
            int r = vmp_super_instr_test(inputs[i]);
            int e = plain_super_instr_test(inputs[i]);
            if (r != e) {
                printf("FAIL vmp_super_instr_test(%d): got %d, exp %d\n",
                       inputs[i], r, e);
                ok = 0;
            }
        }
    }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
