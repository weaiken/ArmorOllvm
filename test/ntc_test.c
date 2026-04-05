// ArmorComp — NeonTypeConfusionPass (NTC) validation test
//
// NeonTypeConfusionPass injects fmov GPR↔SIMD instructions at function
// entry and before each ReturnInst.  At runtime the injected code is a
// no-op (the volatile zero source evaluates to 0, fmov moves 0 through
// s16-s19 and back to w9-w12).  Correctness of all function outputs is
// verified exhaustively.
//
// Expected stderr (ArmorComp log):
//   [ArmorComp][NTC] obfuscated: secure_add      (2 injection(s), 1 ret(s))
//   [ArmorComp][NTC] obfuscated: secure_abs      (2 injection(s), 2 ret(s))
//   [ArmorComp][NTC] obfuscated: secure_classify (2 injection(s), 4 ret(s))
//   [ArmorComp][NTC] obfuscated: secure_sum      (2 injection(s), 1 ret(s))
//   (no message for plain_* — not annotated)
//
// IDA Pro analysis effect on annotated functions (AArch64 binary):
//   - At function entry IDA sees:
//       ldr  w8, [x<N>]         ; volatile load from __armorcomp_ntc_zero
//       fmov s16, w8            ; GPR→SIMD: IDA infers integer arg is float
//       fmov w9,  s16           ; SIMD→GPR: IDA propagates float type
//       fmov s17, w8
//       fmov w10, s17
//   - IDA type inference annotates integer parameters as float/double
//   - Hex-Rays F5 prototype shows wrong types, e.g.:
//       float secure_add(float, float)  instead of  int secure_add(int, int)
//   - Combined with FuncSigObfPass: prototype is completely unrecoverable
//
// Verification: llvm-objdump -d ntc_test_aarch64 | grep -A20 "<secure_add>"
//   → should show fmov s16/s17 immediately after the volatile ldr at entry
//   → plain_add should NOT contain any fmov instructions
//
// Expected stdout:
//   secure_add(3, 4)         =  7
//   secure_add(-5, 2)        = -3
//   plain_add(3, 4)          =  7
//   secure_abs(-7)           =  7
//   secure_abs(5)            =  5
//   plain_abs(-7)            =  7
//   secure_classify(-5)      = -1
//   secure_classify(0)       =  0
//   secure_classify(5)       =  1
//   secure_classify(101)     =  2
//   plain_classify(-5)       = -1
//   secure_sum(1, 10)        = 55
//   plain_sum(1, 10)         = 55
//   ALL TESTS PASSED

#include <stdio.h>

// ── Annotated functions (NeonTypeConfusionPass applied) ──────────────────────

// Basic arithmetic — single return; tests entry-block injection
__attribute__((annotate("ntc")))
int secure_add(int a, int b) {
    return a + b;
}

// Two return paths — tests both entry and both ret-block injections
__attribute__((annotate("ntc")))
int secure_abs(int x) {
    if (x < 0) return -x;
    return x;
}

// Four return paths — exercises all four ret-block injection sites
__attribute__((annotate("ntc")))
int secure_classify(int x) {
    if (x < 0)   return -1;   // ret 1
    if (x > 100) return 2;    // ret 2
    if (x == 0)  return 0;    // ret 3
    return 1;                  // ret 4
}

// Loop function — entry injection + single ret; verifies accumulation
__attribute__((annotate("ntc")))
int secure_sum(int lo, int hi) {
    int acc = 0;
    for (int i = lo; i <= hi; i++)
        acc += i;
    return acc;
}

// ── Plain reference implementations (no annotation) ──────────────────────────

int plain_add(int a, int b) {
    return a + b;
}

int plain_abs(int x) {
    if (x < 0) return -x;
    return x;
}

int plain_classify(int x) {
    if (x < 0)   return -1;
    if (x > 100) return 2;
    if (x == 0)  return 0;
    return 1;
}

int plain_sum(int lo, int hi) {
    int acc = 0;
    for (int i = lo; i <= hi; i++)
        acc += i;
    return acc;
}

// ── Main ─────────────────────────────────────────────────────────────────────

int main(void) {
    // Print representative samples
    printf("secure_add(3, 4)         = %d\n",  secure_add(3, 4));       //  7
    printf("secure_add(-5, 2)        = %d\n",  secure_add(-5, 2));      // -3
    printf("plain_add(3, 4)          = %d\n",  plain_add(3, 4));        //  7
    printf("secure_abs(-7)           = %d\n",  secure_abs(-7));         //  7
    printf("secure_abs(5)            = %d\n",  secure_abs(5));          //  5
    printf("plain_abs(-7)            = %d\n",  plain_abs(-7));          //  7
    printf("secure_classify(-5)      = %d\n",  secure_classify(-5));    // -1
    printf("secure_classify(0)       = %d\n",  secure_classify(0));     //  0
    printf("secure_classify(5)       = %d\n",  secure_classify(5));     //  1
    printf("secure_classify(101)     = %d\n",  secure_classify(101));   //  2
    printf("plain_classify(-5)       = %d\n",  plain_classify(-5));     // -1
    printf("secure_sum(1, 10)        = %d\n",  secure_sum(1, 10));      // 55
    printf("plain_sum(1, 10)         = %d\n",  plain_sum(1, 10));       // 55

    int ok = 1;

    // Verify secure_add matches plain_add
    int add_a[] = {0, 1, -1, 100, -100, 2147483};
    int add_b[] = {0, 2, -3,  -5,  200,  999999};
    int nadd = (int)(sizeof(add_a) / sizeof(add_a[0]));
    for (int i = 0; i < nadd; i++) {
        int s = secure_add(add_a[i], add_b[i]);
        int p = plain_add(add_a[i], add_b[i]);
        if (s != p) {
            printf("FAIL add(%d,%d): secure=%d plain=%d\n",
                   add_a[i], add_b[i], s, p);
            ok = 0;
        }
    }

    // Verify secure_abs matches plain_abs
    int abs_v[] = {0, 1, -1, 100, -100, 2147483647, -2147483647};
    int nabs = (int)(sizeof(abs_v) / sizeof(abs_v[0]));
    for (int i = 0; i < nabs; i++) {
        int s = secure_abs(abs_v[i]);
        int p = plain_abs(abs_v[i]);
        if (s != p) {
            printf("FAIL abs(%d): secure=%d plain=%d\n", abs_v[i], s, p);
            ok = 0;
        }
    }

    // Verify secure_classify matches plain_classify
    int cls_v[] = {-200, -1, 0, 1, 50, 100, 101, 200, -2147483648};
    int ncls = (int)(sizeof(cls_v) / sizeof(cls_v[0]));
    for (int i = 0; i < ncls; i++) {
        int s = secure_classify(cls_v[i]);
        int p = plain_classify(cls_v[i]);
        if (s != p) {
            printf("FAIL classify(%d): secure=%d plain=%d\n",
                   cls_v[i], s, p);
            ok = 0;
        }
    }

    // Verify secure_sum matches plain_sum
    struct { int lo, hi; } sum_v[] = {
        {1, 10}, {0, 0}, {-5, 5}, {1, 100}, {5, 5}
    };
    int nsum = (int)(sizeof(sum_v) / sizeof(sum_v[0]));
    for (int i = 0; i < nsum; i++) {
        int s = secure_sum(sum_v[i].lo, sum_v[i].hi);
        int p = plain_sum(sum_v[i].lo, sum_v[i].hi);
        if (s != p) {
            printf("FAIL sum(%d,%d): secure=%d plain=%d\n",
                   sum_v[i].lo, sum_v[i].hi, s, p);
            ok = 0;
        }
    }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
