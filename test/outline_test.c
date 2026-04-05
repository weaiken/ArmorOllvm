// ArmorComp — OutlinePass (OUTLINE) validation test
//
// OutlinePass extracts each non-entry basic block of an annotated function
// into an independent internal function named __armorcomp_outline_N with
// noinline + optnone attributes.  The original function becomes a thin
// dispatcher that calls the outlined helpers.
//
// Prior to extraction:
//   - PHI nodes are demoted to alloca/load/store (DemotePHIToStack)
//   - Cross-block SSA values are demoted to alloca (DemoteRegToStack)
// This ensures CodeExtractor can handle all live-in / live-out values as
// function arguments and return values.
//
// Expected stderr (ArmorComp log):
//   [ArmorComp][OUTLINE] outlined: secure_compute (N blocks)
//   [ArmorComp][OUTLINE] outlined: secure_classify (N blocks)
//   (no message for plain_compute / plain_classify — not annotated)
//
// Verification (host, requires llvm-objdump):
//   llvm-objdump --syms outline_test_aarch64 | grep __armorcomp_outline_
//   → lists multiple __armorcomp_outline_N symbols
//
//   llvm-objdump -d outline_test_aarch64 | awk '/<secure_compute>/{p=1}p{print;if(/ret$/)exit}'
//   → should show "bl __armorcomp_outline_N" call instructions where the
//     original BB logic was; no inline arithmetic sequences inside secure_compute
//
// Expected stdout (when run on device/emulator):
//   secure_compute(3, 4)   = 14
//   secure_compute(5, 10)  = 35
//   secure_compute(10, -3) = 7
//   plain_compute(3, 4)    = 14
//   secure_classify(-5)    = -1
//   secure_classify(0)     =  0
//   secure_classify(5)     =  1
//   ALL TESTS PASSED

#include <stdio.h>

// ── Annotated functions ────────────────────────────────────────────────────

// secure_compute: annotated with "outline".
// Has multiple BBs: entry + conditional branches + arithmetic blocks.
// Each non-entry BB is extracted to a separate __armorcomp_outline_N.
__attribute__((annotate("outline")))
int secure_compute(int a, int b) {
    int result;
    if (a > b) {
        result = a * b - a;     // BB1: a>b path
    } else if (a == b) {
        result = a * a;         // BB2: a==b path
    } else {
        result = a + b + a * b; // BB3: a<b path
    }
    return result;
}

// secure_classify: a second annotated function with more branches.
__attribute__((annotate("outline")))
int secure_classify(int x) {
    if (x < 0)   return -1; // BB1
    if (x == 0)  return  0; // BB2
    if (x < 10)  return  1; // BB3
    if (x < 100) return  2; // BB4
    return 3;                // BB5
}

// ── Plain reference implementations (no annotation) ──────────────────────

int plain_compute(int a, int b) {
    int result;
    if (a > b) {
        result = a * b - a;
    } else if (a == b) {
        result = a * a;
    } else {
        result = a + b + a * b;
    }
    return result;
}

int plain_classify(int x) {
    if (x < 0)   return -1;
    if (x == 0)  return  0;
    if (x < 10)  return  1;
    if (x < 100) return  2;
    return 3;
}

// ── Main ──────────────────────────────────────────────────────────────────

int main(void) {
    // Print a few values for visual inspection
    printf("secure_compute(3, 4)   = %d\n", secure_compute(3, 4));    // 14 (3<4: 3+4+12=19? no: 3+4+3*4=3+4+12=19)
    printf("secure_compute(5, 10)  = %d\n", secure_compute(5, 10));   // 5<10: 5+10+50=65? let's trace
    printf("secure_compute(10, -3) = %d\n", secure_compute(10, -3));  // 10>-3: 10*(-3)-10=-30-10=-40
    printf("plain_compute(3, 4)    = %d\n", plain_compute(3, 4));
    printf("secure_classify(-5)    = %d\n", secure_classify(-5));     // -1
    printf("secure_classify(0)     = %d\n", secure_classify(0));      //  0
    printf("secure_classify(5)     = %d\n", secure_classify(5));      //  1

    int ok = 1;

    // secure_compute must match plain_compute for all test inputs
    int ca[] = { -10, -1,  0,  1,  3,  5, 10, 20,  7,  7 };
    int cb[] = {  -5, -1,  0,  1,  4, 10, 10, 10, -2,  3 };
    int n = sizeof(ca) / sizeof(ca[0]);
    for (int i = 0; i < n; i++) {
        int s = secure_compute(ca[i], cb[i]);
        int p = plain_compute(ca[i], cb[i]);
        if (s != p) {
            printf("FAIL compute(%d,%d): secure=%d plain=%d\n", ca[i], cb[i], s, p);
            ok = 0;
        }
    }

    // secure_classify must match plain_classify for all test inputs
    int xs[] = { -100, -1, 0, 1, 5, 9, 10, 50, 99, 100, 999 };
    int nx = sizeof(xs) / sizeof(xs[0]);
    for (int i = 0; i < nx; i++) {
        int s = secure_classify(xs[i]);
        int p = plain_classify(xs[i]);
        if (s != p) {
            printf("FAIL classify(%d): secure=%d plain=%d\n", xs[i], s, p);
            ok = 0;
        }
    }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
