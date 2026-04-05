// ArmorComp — LoopObfuscationPass (LOB) validation test
//
// LoopObfuscationPass uses LoopAnalysis to find natural loops and injects:
//   1. Preheader junk: volatile_zero arithmetic chain → asm sideeffect sink
//   2. Header noise: volatile_zero + 0 → asm sideeffect sink
//   3. Fake invariant: dead alloca = volatile_zero * PRIME → asm sink
//
// This must run BEFORE BCF/CFF (step 7.5 in pipeline, after MBA).
// Loops must be visible in the IR — CFF destroys loop structure.
//
// Expected stderr:
//   [ArmorComp][LOB] obfuscated: secure_sum    (N loop(s))
//   [ArmorComp][LOB] obfuscated: secure_matrix (N loop(s))
//   (no LOB message for plain_* — not annotated)
//
// Verification (AArch64 disasm):
//   llvm-objdump -d lob_test_aarch64 | grep -A60 "<secure_sum>"
//   → loop preheader should show ldr x_,[@__armorcomp_lob_zero] + extra instructions
//   → loop header should show similar volatile load + arithmetic
//
// Expected stdout:
//   sum(10)        = 55
//   matrix 3x3 sum = 45
//   ALL TESTS PASSED

#include <stdio.h>

// ── Annotated functions ────────────────────────────────────────────────────

__attribute__((annotate("lob")))
int secure_sum(int n) {
    int sum = 0;
    for (int i = 1; i <= n; i++)
        sum += i;
    return sum;
}

// Nested loops test (LOB targets top-level loops)
__attribute__((annotate("lob")))
int secure_matrix_sum(int mat[3][3]) {
    int total = 0;
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            total += mat[i][j];
        }
    }
    return total;
}

// While loop test
__attribute__((annotate("lob")))
int secure_while(int n) {
    int prod = 1;
    while (n > 0) {
        prod *= n;
        n--;
    }
    return prod;
}

// ── Plain reference ────────────────────────────────────────────────────────

int plain_sum(int n) {
    int sum = 0;
    for (int i = 1; i <= n; i++)
        sum += i;
    return sum;
}

int plain_matrix_sum(int mat[3][3]) {
    int total = 0;
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++)
            total += mat[i][j];
    return total;
}

int plain_while(int n) {
    int prod = 1;
    while (n > 0) { prod *= n--; }
    return prod;
}

// ── Main ────────────────────────────────────────────────────────────────────

int main(void) {
    int mat[3][3] = { {1,2,3}, {4,5,6}, {7,8,9} };  // sum = 45

    printf("sum(10)        = %d\n", secure_sum(10));          // 55
    printf("matrix 3x3 sum = %d\n", secure_matrix_sum(mat));  // 45

    int ok = 1;

    // Test sum for various n
    int ns[] = {0, 1, 2, 5, 10, 20, 100};
    int nn = (int)(sizeof(ns) / sizeof(ns[0]));
    for (int i = 0; i < nn; i++) {
        int s = secure_sum(ns[i]);
        int p = plain_sum(ns[i]);
        if (s != p) {
            printf("FAIL sum(%d): secure=%d plain=%d\n", ns[i], s, p);
            ok = 0;
        }
    }

    // Test matrix sum
    int ms = secure_matrix_sum(mat);
    int mp = plain_matrix_sum(mat);
    if (ms != mp) { printf("FAIL matrix: secure=%d plain=%d\n", ms, mp); ok = 0; }

    // Test while loop (factorial-style)
    int ws[] = {0, 1, 2, 3, 4, 5};
    int nw = (int)(sizeof(ws) / sizeof(ws[0]));
    for (int i = 0; i < nw; i++) {
        int s = secure_while(ws[i]);
        int p = plain_while(ws[i]);
        if (s != p) {
            printf("FAIL while(%d): secure=%d plain=%d\n", ws[i], s, p);
            ok = 0;
        }
    }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
