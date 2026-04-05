// ArmorComp — RetAddrObfPass (RAO) validation test
//
// RAOPass inserts "sub sp, sp, xN" before each call and "add sp, sp, xN"
// after each call in annotated functions.  xN is always 0 at runtime
// (volatile load from @__armorcomp_rao_zero = 0), but IDA's sp_delta tracker
// cannot prove this — every call site shows UNKNOWN sp_delta.
//
// Combined with SPOPass (function entry/exit sub/add), the annotated function
// is completely opaque to Hex-Rays F5 decompilation.
//
// Expected stderr (ArmorComp log):
//   [ArmorComp][RAO] obfuscated: secure_calls (3 calls)
//   (no message for plain_calls — not annotated)
//
// Verification (host, requires llvm-objdump):
//   llvm-objdump -d rao_test_aarch64 | awk '/<secure_calls>/{p=1}p{print;if(/ret/)exit}'
//   → should show pairs of:
//       ldr x8, [__armorcomp_rao_zero]
//       sub sp, sp, x8
//       bl helper_*
//       ldr x9, [__armorcomp_rao_zero]
//       add sp, sp, x9
//   (one pair around each of the 3 calls)
//
//   llvm-objdump -d rao_test_aarch64 | awk '/<plain_calls>/{p=1}p{print;if(/ret/)exit}'
//   → NO sub/add sp pairs (only standard function prologue/epilogue)
//
// Expected stdout:
//   secure_calls(3, 4)  = 14
//   secure_calls(5, 6)  = 22
//   plain_calls(3, 4)   = 14
//   ALL TESTS PASSED

#include <stdio.h>

// Three simple helpers that become the instrumented callees.
static int double_it(int x) { return x * 2; }
static int add_it(int a, int b) { return a + b; }
static int negate_it(int x) { return -x; }

// secure_calls: annotated with "rao" — all 3 calls get sub/add SP noise.
__attribute__((annotate("rao")))
int secure_calls(int x, int y) {
    int a = double_it(x);       // call 1
    int b = double_it(y);       // call 2
    int s = add_it(a, b);       // call 3
    (void)negate_it(0);         // call 4 — void result, tests void-call path
    return s;
}

// plain_calls: no annotation — direct calls, no sub/add SP noise.
int plain_calls(int x, int y) {
    int a = double_it(x);
    int b = double_it(y);
    return add_it(a, b);
}

int main(void) {
    // secure_calls(3,4): double(3)=6, double(4)=8, add(6,8)=14
    // secure_calls(5,6): double(5)=10, double(6)=12, add(10,12)=22
    printf("secure_calls(3, 4)  = %d\n", secure_calls(3, 4));   // 14
    printf("secure_calls(5, 6)  = %d\n", secure_calls(5, 6));   // 22
    printf("plain_calls(3, 4)   = %d\n", plain_calls(3, 4));    // 14

    int ok = 1;
    if (secure_calls(3, 4)   != plain_calls(3, 4))   { printf("FAIL: (3,4)\n");   ok = 0; }
    if (secure_calls(5, 6)   != plain_calls(5, 6))   { printf("FAIL: (5,6)\n");   ok = 0; }
    if (secure_calls(0, 0)   != plain_calls(0, 0))   { printf("FAIL: (0,0)\n");   ok = 0; }
    if (secure_calls(-1, -1) != plain_calls(-1, -1)) { printf("FAIL: (-1,-1)\n"); ok = 0; }
    if (secure_calls(100, 200) != plain_calls(100, 200)) { printf("FAIL: (100,200)\n"); ok = 0; }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
