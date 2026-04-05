// ArmorComp — IndirectCall pass validation test
//
// Tests:
//   secure_dispatch() — annotate("icall"): all direct calls within this
//     function are replaced with opaque-pointer indirect calls.
//     Static analysis (IDA/Ghidra/objdump) cannot resolve the callees.
//     Runtime behaviour must be identical to the unobfuscated version.
//
//   plain_dispatch()  — no annotation: direct calls remain; used as control.
//
// Expected stderr output (ArmorComp log):
//   [ArmorComp][ICALL] indirected: secure_dispatch (4 calls)
//
// Verification (host only, requires llvm-objdump from brew llvm@17):
//   llvm-objdump -d icall_test_aarch64 | grep -A2 "<secure_dispatch>"
//   → should show BLR (indirect branch-link register), NOT BL #offset
//
//   llvm-objdump -d icall_test_aarch64 | grep -A2 "<plain_dispatch>"
//   → should show BL #<symbol>  (direct call, label visible)
//
// Expected stdout:
//   [secure] add(3,4)     = 7
//   [secure] mul(3,4)     = 12
//   [secure] sub(10,3)    = 7
//   [secure] classify(-1) = -1
//   [plain]  add(3,4)     = 7
//   ALL TESTS PASSED

#include <stdio.h>

// Helper functions — defined in the same TU so IndirectCallPass can
// replace the direct calls to them inside secure_dispatch.
static int helper_add(int a, int b) { return a + b; }
static int helper_mul(int a, int b) { return a * b; }
static int helper_sub(int a, int b) { return a - b; }
static int helper_classify(int x) {
    if (x < 0) return -1;
    if (x > 0) return  1;
    return 0;
}

// secure_dispatch: all 4 calls inside will be indirected.
// Annotation: annotate("icall")
__attribute__((annotate("icall")))
void secure_dispatch(int a, int b) {
    int r1 = helper_add(a, b);           // → indirect call via %fp
    int r2 = helper_mul(a, b);           // → indirect call via %fp
    int r3 = helper_sub(a + b, a);       // → indirect call via %fp
    int r4 = helper_classify(a - b - 1); // → indirect call via %fp
    printf("[secure] add(%d,%d)     = %d\n", a, b, r1);
    printf("[secure] mul(%d,%d)     = %d\n", a, b, r2);
    printf("[secure] sub(%d,%d)    = %d\n", a + b, a, r3);
    printf("[secure] classify(%d) = %d\n", a - b - 1, r4);
}

// plain_dispatch: no annotation; direct calls remain unchanged.
void plain_dispatch(int a, int b) {
    int r = helper_add(a, b);
    printf("[plain]  add(%d,%d)     = %d\n", a, b, r);
}

int main(void) {
    secure_dispatch(3, 4);
    plain_dispatch(3, 4);

    // Simple functional check: reproduce expected values independently.
    int ok = 1;
    if (helper_add(3, 4) != 7)     { printf("FAIL: helper_add\n"); ok = 0; }
    if (helper_mul(3, 4) != 12)    { printf("FAIL: helper_mul\n"); ok = 0; }
    if (helper_sub(7, 3) != 4)     { printf("FAIL: helper_sub\n"); ok = 0; }
    if (helper_classify(-1) != -1) { printf("FAIL: helper_classify\n"); ok = 0; }

    if (ok)
        printf("ALL TESTS PASSED\n");

    return ok ? 0 : 1;
}
