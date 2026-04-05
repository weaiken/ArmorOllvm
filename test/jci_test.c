// ArmorComp — JunkCodePass (JCI) validation test
//
// JunkCodePass inserts dead arithmetic computation chains into each basic block
// of targeted functions.  Each chain:
//   1. volatile load @__armorcomp_jci_zero (= 0 at runtime)
//   2. 4–7 arithmetic/logic ops (xor/or/and/shl/lshr/mul/add/sub) with
//      PRNG-seeded constants (xorshift64 seeded by FNV-1a(fn+"_jci_"+bbIdx))
//   3. empty asm sideeffect sink "r,~{dirflag},~{fpsr},~{flags}"
//
// The chain is a provable no-op (0 op K = 0); the asm sink prevents DCE.
// Runtime behaviour is identical to the plain (non-annotated) versions.
//
// AArch64 disassembly (example: 3-op chain in a single BB):
//   ldr  x8, [__armorcomp_jci_zero]   ; volatile load = 0
//   eor  x8, x8, #0xdeadbeef...        ; jci.xor  — IDA: unknown chain
//   orr  x8, x8, #0x12345678...        ; jci.or
//   mul  x8, x8, x9                    ; jci.mul  — x9 = constant
//   ; no output for asm sink — value in x8 forced live, then freed
//
// IDA Hex-Rays F5 effect:
//   Annotated:  multiple extra local variables (v4, v5, v6, ...) in each BB
//   Plain:      no such variables
//
// Expected stderr (one line per obfuscated function):
//   [ArmorComp][JCI] injected: jci_add_multi   (N junk instr(s), M BB(s))
//   [ArmorComp][JCI] injected: jci_classify    (N junk instr(s), M BB(s))
//   [ArmorComp][JCI] injected: jci_loop        (N junk instr(s), M BB(s))
//   [ArmorComp][JCI] injected: jci_branch      (N junk instr(s), M BB(s))
//   (no message for plain_* or non-annotated functions)
//
// Expected stdout ends with:
//   ALL TESTS PASSED

#include <stdio.h>
#include <stdint.h>

// ── Annotated functions (JunkCodePass applied) ────────────────────────────────

// Simple add: 1 BB → 1 junk chain injected.
__attribute__((annotate("jci")))
int jci_add(int a, int b) {
    return a + b;
}

// Multi-BB add via early-return pattern: tests that ALL BBs get junk chains.
__attribute__((annotate("jci")))
int jci_add_multi(int a, int b, int abs_mode) {
    if (abs_mode) {
        if (a < 0) a = -a;
        if (b < 0) b = -b;
    }
    return a + b;
}

// Branch function: 5 BBs (entry + 4 if/else arms) → 5 junk chains.
__attribute__((annotate("jci")))
int jci_classify(int x) {
    if (x < 0)   return -1;
    if (x == 0)  return  0;
    if (x < 100) return  1;
    return 2;
}

// Loop function: entry + loop body + exit BBs → multiple junk chains.
__attribute__((annotate("jci")))
int jci_loop(int n) {
    int sum = 0;
    for (int i = 1; i <= n; i++)
        sum += i;
    return sum;
}

// Branch + arithmetic: tests mixed control flow with junk injected per-BB.
__attribute__((annotate("jci")))
long jci_branch(int x, int y) {
    long result;
    if (x >= 0) {
        result = (long)x * y;
    } else {
        result = -(long)x * y;
    }
    return result;
}

// ── Plain reference implementations (no annotation) ──────────────────────────

int plain_add(int a, int b) { return a + b; }

int plain_add_multi(int a, int b, int abs_mode) {
    if (abs_mode) {
        if (a < 0) a = -a;
        if (b < 0) b = -b;
    }
    return a + b;
}

int plain_classify(int x) {
    if (x < 0)   return -1;
    if (x == 0)  return  0;
    if (x < 100) return  1;
    return 2;
}

int plain_loop(int n) {
    int sum = 0;
    for (int i = 1; i <= n; i++)
        sum += i;
    return sum;
}

long plain_branch(int x, int y) {
    long result;
    if (x >= 0) {
        result = (long)x * y;
    } else {
        result = -(long)x * y;
    }
    return result;
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main(void) {
    int ok = 1;

    // Print representative samples
    printf("jci_add(3, 4)                = %d\n",   jci_add(3, 4));
    printf("plain_add(3, 4)              = %d\n",   plain_add(3, 4));
    printf("jci_classify(-5)             = %d\n",   jci_classify(-5));
    printf("jci_classify(0)              = %d\n",   jci_classify(0));
    printf("jci_classify(50)             = %d\n",   jci_classify(50));
    printf("jci_classify(200)            = %d\n",   jci_classify(200));
    printf("jci_loop(10)                 = %d\n",   jci_loop(10));
    printf("plain_loop(10)               = %d\n",   plain_loop(10));
    printf("jci_branch(3, 4)             = %ld\n",  jci_branch(3, 4));
    printf("jci_branch(-3, 4)            = %ld\n",  jci_branch(-3, 4));

    // ── Verify jci_add == plain_add ────────────────────────────────────────
    int add_cases[][2] = {
        {0, 0}, {1, 2}, {-1, -2}, {100, -50},
        {2147483647, 0}, {-2147483648, 0},
        {1000, -1000}, {5, -5},
    };
    int n_add = (int)(sizeof(add_cases) / sizeof(add_cases[0]));
    for (int i = 0; i < n_add; i++) {
        int a = add_cases[i][0], b = add_cases[i][1];
        if (jci_add(a, b) != plain_add(a, b)) {
            printf("FAIL jci_add[%d]: jci=%d plain=%d\n",
                   i, jci_add(a, b), plain_add(a, b));
            ok = 0;
        }
    }

    // ── Verify jci_add_multi == plain_add_multi ───────────────────────────
    int ams_cases[][3] = {
        {3, 4, 0}, {3, 4, 1}, {-3, -4, 1}, {-3, -4, 0},
        {0, 0, 1}, {-100, 200, 1}, {100, -200, 1},
    };
    int n_ams = (int)(sizeof(ams_cases) / sizeof(ams_cases[0]));
    for (int i = 0; i < n_ams; i++) {
        int a = ams_cases[i][0], b = ams_cases[i][1], m = ams_cases[i][2];
        if (jci_add_multi(a, b, m) != plain_add_multi(a, b, m)) {
            printf("FAIL jci_add_multi[%d]\n", i);
            ok = 0;
        }
    }

    // ── Verify jci_classify == plain_classify ─────────────────────────────
    int cls_vals[] = {-100, -1, 0, 1, 50, 99, 100, 200, 2147483647, -2147483648};
    int n_cls = (int)(sizeof(cls_vals) / sizeof(cls_vals[0]));
    for (int i = 0; i < n_cls; i++) {
        if (jci_classify(cls_vals[i]) != plain_classify(cls_vals[i])) {
            printf("FAIL jci_classify[%d]: x=%d\n", i, cls_vals[i]);
            ok = 0;
        }
    }

    // ── Verify jci_loop == plain_loop ─────────────────────────────────────
    int loop_vals[] = {0, 1, 2, 5, 10, 50, 100};
    int n_loop = (int)(sizeof(loop_vals) / sizeof(loop_vals[0]));
    for (int i = 0; i < n_loop; i++) {
        if (jci_loop(loop_vals[i]) != plain_loop(loop_vals[i])) {
            printf("FAIL jci_loop[%d]: n=%d\n", i, loop_vals[i]);
            ok = 0;
        }
    }

    // ── Verify jci_branch == plain_branch ─────────────────────────────────
    int branch_x[] = {0, 1, -1, 100, -100, 2147483647, -2147483648};
    int branch_y[] = {0, 1, 2, -3};
    int nx = (int)(sizeof(branch_x) / sizeof(branch_x[0]));
    int ny = (int)(sizeof(branch_y) / sizeof(branch_y[0]));
    for (int i = 0; i < nx; i++) {
        for (int j = 0; j < ny; j++) {
            if (jci_branch(branch_x[i], branch_y[j]) !=
                plain_branch(branch_x[i], branch_y[j])) {
                printf("FAIL jci_branch[%d][%d]\n", i, j);
                ok = 0;
            }
        }
    }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
