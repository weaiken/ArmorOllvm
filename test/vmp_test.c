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
//   - 64 virtual registers (R0–R63), 64-bit each
//   - R0 = return value, R0–R7 = function arguments
//   - Opcodes: MOV_Ixx, MOV_RR, ADD/SUB/MUL/AND/OR/XOR/SHL/LSHR/ASHR,
//              ICMP_* (10 predicates), JMP/JCC, LOAD/STORE (8/16/32/64),
//              ALLOCA, GEP8, ZEXT/SEXT/TRUNC, PTRTOINT/INTTOPTR, SELECT,
//              RET, RET_VOID, NOP
//
// Limitations (functions that contain unsupported IR are skipped):
//   - Direct function calls → NOT supported (CallInst returns nullopt)
//   - Floating-point instructions → NOT supported
//   - SIMD / vector instructions → NOT supported
//   - Conditional branches with PHI nodes on both edges → NOT supported
//   When skipped, stderr shows: [ArmorComp][VMP] skipped (unsupported IR): <fn>
//
// Expected stderr (for successfully virtualized functions):
//   [ArmorComp][VMP] virtualized: vmp_add       (N bytecode bytes, M virtual instrs)
//   [ArmorComp][VMP] virtualized: vmp_sub        (N bytecode bytes, M virtual instrs)
//   [ArmorComp][VMP] virtualized: vmp_bitops     (N bytecode bytes, M virtual instrs)
//   [ArmorComp][VMP] virtualized: vmp_classify   (N bytecode bytes, M virtual instrs)
//   [ArmorComp][VMP] virtualized: vmp_loop       (N bytecode bytes, M virtual instrs)
//   [ArmorComp][VMP] virtualized: vmp_select     (N bytecode bytes, M virtual instrs)
//
// Expected stdout ends with:
//   ALL TESTS PASSED

#include <stdio.h>
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

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
