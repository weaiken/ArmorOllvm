// ArmorComp — ArithmeticStatePass (ASP) validation test
//
// ArithmeticStatePass runs AFTER CFFPass and XOR-encodes CFF state variables:
//   - All "store i32 CONST, %state_var" → "store i32 (CONST XOR K)"
//   - All SwitchInst case constants → (case_val XOR K)
// This defeats d810/msynack which work by tracing constant state values.
//
// In this test: annotate("cff") + annotate("asp") on the same function.
// The pipeline runs CFF first (step 17), then ASP (step 17.5), so the
// state variable from CFF is visible when ASP runs.
//
// Expected stderr:
//   [ArmorComp][CFF] flattened:  secure_classify
//   [ArmorComp][CFF] flattened:  secure_loop
//   [ArmorComp][ASP] encoded:    secure_classify (N state var(s), M constant(s))
//   [ArmorComp][ASP] encoded:    secure_loop     (N state var(s), M constant(s))
//   (no CFF/ASP messages for plain_* — not annotated)
//
// Expected stdout:
//   classify(-5) = -1
//   classify(0)  =  0
//   classify(3)  =  1
//   loop(5)      = 15
//   ALL TESTS PASSED

#include <stdio.h>

// ── Annotated functions — CFF first, then ASP encodes the state variable ──

__attribute__((annotate("cff")))
__attribute__((annotate("asp")))
int secure_classify(int x) {
    if (x < 0)      return -1;
    else if (x == 0) return  0;
    else             return  1;
}

__attribute__((annotate("cff")))
__attribute__((annotate("asp")))
int secure_loop(int n) {
    int sum = 0;
    for (int i = 1; i <= n; i++)
        sum += i;
    return sum;
}

// ── Plain reference ────────────────────────────────────────────────────────

int plain_classify(int x) {
    if (x < 0)       return -1;
    else if (x == 0) return  0;
    else             return  1;
}

int plain_loop(int n) {
    int sum = 0;
    for (int i = 1; i <= n; i++)
        sum += i;
    return sum;
}

// ── Main ────────────────────────────────────────────────────────────────────

int main(void) {
    printf("classify(-5) = %d\n", secure_classify(-5));  // -1
    printf("classify(0)  = %d\n", secure_classify(0));   //  0
    printf("classify(3)  = %d\n", secure_classify(3));   //  1
    printf("loop(5)      = %d\n", secure_loop(5));       // 15

    int ok = 1;
    int vals[] = { -10, -3, -1, 0, 1, 2, 5, 10, 100 };
    int nv = (int)(sizeof(vals) / sizeof(vals[0]));
    for (int i = 0; i < nv; i++) {
        int s = secure_classify(vals[i]);
        int p = plain_classify(vals[i]);
        if (s != p) {
            printf("FAIL classify(%d): secure=%d plain=%d\n", vals[i], s, p);
            ok = 0;
        }
    }

    int ns[] = { 0, 1, 2, 5, 10, 20, 50, 100 };
    int nn = (int)(sizeof(ns) / sizeof(ns[0]));
    for (int i = 0; i < nn; i++) {
        int s = secure_loop(ns[i]);
        int p = plain_loop(ns[i]);
        if (s != p) {
            printf("FAIL loop(%d): secure=%d plain=%d\n", ns[i], s, p);
            ok = 0;
        }
    }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
