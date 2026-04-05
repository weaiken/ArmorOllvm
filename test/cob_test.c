// ArmorComp — ConditionObfPass (COB) validation test
//
// ConditionObfPass transforms every ICmpInst in annotated functions by adding
// opaque noise (mul(volatile_zero, K) = 0 at runtime) to both operands:
//
//   Original:  icmp pred A, B
//   Obfuscated: icmp pred (A + noise_A), (B + noise_B)
//
// At runtime noise_A = noise_B = 0, so the comparison result is identical.
// To IDA Hex-Rays, noise_A/noise_B are non-zero unknowns loaded from a
// volatile global — the comparison condition cannot be resolved statically.
//
// Expected stderr (ArmorComp log):
//   [ArmorComp][COB] obfuscated: secure_classify  (N icmp(s))
//   [ArmorComp][COB] obfuscated: secure_max        (N icmp(s))
//   [ArmorComp][COB] obfuscated: secure_between    (N icmp(s))
//   [ArmorComp][COB] obfuscated: secure_mix        (N icmp(s))
//   (no message for plain_* — not annotated)
//
// IDA Pro analysis effect on annotated functions:
//   - If-conditions displayed as "(v4 + v2) < (v3 + v1)" instead of "x < 0"
//   - Decompiler cannot fold noise terms → condition expressions unresolvable
//   - Variable types and values harder to infer from comparison context
//
// Verification: llvm-objdump -d cob_test_aarch64 | grep -A40 "<secure_classify>"
//   → should show additional add/mul instructions before each cmp instruction
//   → e.g., "add w9, w0, w8" before "cmp w9, w10" (noisy operands)
//   → plain_classify should show bare "cmp w0, #0" without noise
//
// Expected stdout:
//   secure_classify(-5)      = -1
//   secure_classify(0)       =  0
//   secure_classify(5)       =  1
//   secure_classify(101)     =  2
//   plain_classify(-5)       = -1
//   secure_max(3, 7)         =  7
//   secure_max(5, 3)         =  5
//   plain_max(3, 7)          =  7
//   secure_between(5,1,10)   =  1
//   secure_between(0,1,10)   =  0
//   plain_between(5,1,10)    =  1
//   secure_mix(-3, 7, -1)    = 10
//   ALL TESTS PASSED

#include <stdio.h>

// ── Annotated functions (ConditionObfPass applied) ──────────────────────────

// signed comparisons: slt, sgt, eq
__attribute__((annotate("cob")))
int secure_classify(int x) {
    if (x < 0)   return -1;    // icmp slt x, 0
    if (x > 100) return 2;     // icmp sgt x, 100
    if (x == 0)  return 0;     // icmp eq  x, 0
    return 1;
}

// signed greater-than comparison
__attribute__((annotate("cob")))
int secure_max(int a, int b) {
    return (a > b) ? a : b;    // icmp sgt a, b
}

// signed range check: sge + sle
__attribute__((annotate("cob")))
int secure_between(int x, int lo, int hi) {
    return (x >= lo) && (x <= hi);   // icmp sge + icmp sle
}

// mixed: signed, unsigned, equality — exercises all predicate families
// a: signed value, b: non-negative, returns (|a|+b) if a != 0, else -1
__attribute__((annotate("cob")))
int secure_mix(int a, int b, int sentinel) {
    if (a == sentinel) return -1;     // icmp eq  (signed eq)
    int abs_a = (a < 0) ? -a : a;    // icmp slt (signed)
    if ((unsigned)b > 100u) b = 100; // icmp ugt (unsigned)
    return abs_a + b;
}

// ── Plain reference implementations (no annotation) ─────────────────────────

int plain_classify(int x) {
    if (x < 0)   return -1;
    if (x > 100) return 2;
    if (x == 0)  return 0;
    return 1;
}

int plain_max(int a, int b) {
    return (a > b) ? a : b;
}

int plain_between(int x, int lo, int hi) {
    return (x >= lo) && (x <= hi);
}

int plain_mix(int a, int b, int sentinel) {
    if (a == sentinel) return -1;
    int abs_a = (a < 0) ? -a : a;
    if ((unsigned)b > 100u) b = 100;
    return abs_a + b;
}

// ── Main ─────────────────────────────────────────────────────────────────────

int main(void) {
    printf("secure_classify(-5)      = %d\n",  secure_classify(-5));   // -1
    printf("secure_classify(0)       = %d\n",  secure_classify(0));    //  0
    printf("secure_classify(5)       = %d\n",  secure_classify(5));    //  1
    printf("secure_classify(101)     = %d\n",  secure_classify(101));  //  2
    printf("plain_classify(-5)       = %d\n",  plain_classify(-5));    // -1
    printf("secure_max(3, 7)         = %d\n",  secure_max(3, 7));      //  7
    printf("secure_max(5, 3)         = %d\n",  secure_max(5, 3));      //  5
    printf("plain_max(3, 7)          = %d\n",  plain_max(3, 7));       //  7
    printf("secure_between(5,1,10)   = %d\n",  secure_between(5,1,10)); // 1
    printf("secure_between(0,1,10)   = %d\n",  secure_between(0,1,10)); // 0
    printf("plain_between(5,1,10)    = %d\n",  plain_between(5,1,10)); // 1
    printf("secure_mix(-3, 7, -1)    = %d\n",  secure_mix(-3, 7, -1)); // 10

    int ok = 1;

    // Verify secure_classify matches plain_classify
    int cv[] = {-100, -1, 0, 1, 50, 100, 101, 200, -2147483648};
    int nc = (int)(sizeof(cv) / sizeof(cv[0]));
    for (int i = 0; i < nc; i++) {
        int s = secure_classify(cv[i]);
        int p = plain_classify(cv[i]);
        if (s != p) {
            printf("FAIL classify(%d): secure=%d plain=%d\n", cv[i], s, p);
            ok = 0;
        }
    }

    // Verify secure_max matches plain_max
    int as[] = {-10, 0,  5,  3,  7, -1};
    int bs[] = {  5, 0, -3,  7,  3,  1};
    int nm = (int)(sizeof(as) / sizeof(as[0]));
    for (int i = 0; i < nm; i++) {
        int s = secure_max(as[i], bs[i]);
        int p = plain_max(as[i], bs[i]);
        if (s != p) {
            printf("FAIL max(%d,%d): secure=%d plain=%d\n", as[i], bs[i], s, p);
            ok = 0;
        }
    }

    // Verify secure_between matches plain_between
    struct { int x, lo, hi; } bv[] = {
        {5, 1, 10}, {0, 1, 10}, {10, 1, 10}, {11, 1, 10},
        {1, 1, 10}, {-5, -10, 0}, {0, 0, 0}
    };
    int nb = (int)(sizeof(bv) / sizeof(bv[0]));
    for (int i = 0; i < nb; i++) {
        int s = secure_between(bv[i].x, bv[i].lo, bv[i].hi);
        int p = plain_between(bv[i].x, bv[i].lo, bv[i].hi);
        if (s != p) {
            printf("FAIL between(%d,%d,%d): secure=%d plain=%d\n",
                   bv[i].x, bv[i].lo, bv[i].hi, s, p);
            ok = 0;
        }
    }

    // Verify secure_mix matches plain_mix
    int mv_a[]  = { -3,   0,  5, -1,  50,  -50 };
    int mv_b[]  = {  7,   3, 10, 200,  50,  101 };
    int mv_s[]  = { -1,  -1, -1, -1,   5,    0 };
    int nv = (int)(sizeof(mv_a) / sizeof(mv_a[0]));
    for (int i = 0; i < nv; i++) {
        int s = secure_mix(mv_a[i], mv_b[i], mv_s[i]);
        int p = plain_mix(mv_a[i], mv_b[i], mv_s[i]);
        if (s != p) {
            printf("FAIL mix(%d,%d,%d): secure=%d plain=%d\n",
                   mv_a[i], mv_b[i], mv_s[i], s, p);
            ok = 0;
        }
    }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
