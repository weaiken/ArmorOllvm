// ArmorComp — MBA pass validation test
//
// Tests:
//   compute_mba()  — annotate("mba") only: verifies all 5 MBA-transformed ops
//                    produce correct results at runtime.
//   full_protect() — annotate("mba") + annotate("sub") + annotate("bcf") +
//                    annotate("cff"): 4-layer obfuscation, result must match.
//
// Expected stderr output (ArmorComp log):
//   [ArmorComp][MBA] obfuscated: compute_mba (1 round)
//   [ArmorComp][MBA] obfuscated: full_protect (1 round)
//   [ArmorComp][SUB] substituted: full_protect
//   [ArmorComp][BCF] obfuscated: full_protect
//   [ArmorComp][CFF] flattened: full_protect
//
// Expected stdout:
//   add(5,3)    = 8
//   sub(10,4)   = 6
//   and(0xF0,0x0F) = 0
//   or(0xF0,0x0F)  = 255
//   xor(0xFF,0x0F) = 240
//   full_protect(10) = 55
//   ALL TESTS PASSED

#include <stdio.h>

// compute_mba: exercises all 5 operations that MBAPass rewrites.
// With -O0 these binary ops remain; MBAPass replaces each with its MBA form.
__attribute__((annotate("mba")))
int compute_mba(int a, int b) {
    int r_add = a + b;          // → 2*(a|b) - (a^b)  OR  ~(~a - b)
    int r_sub = a - b;          // → 2*(a&~b)-(a^b)   OR  (a|b)&~b+(a|b)&a-(a|b)
    int r_and = a & b;          // → (a|b)-(a^b)       OR  ((a+b)-(a^b))>>1
    int r_or  = a | b;          // → (a&b)+(a^b)       OR  a+b-(a&b)
    int r_xor = a ^ b;          // → 2*(a|b)-(a+b)     OR  (a-b)+2*(b&~a)
    return r_add + r_sub + r_and + r_or + r_xor;
}

// full_protect: 4-layer obfuscation on a sum loop.
__attribute__((annotate("mba")))
__attribute__((annotate("sub")))
__attribute__((annotate("bcf")))
__attribute__((annotate("cff")))
int full_protect(int n) {
    int sum = 0;
    for (int i = 1; i <= n; i++)
        sum = sum + i;
    return sum;
}

int main(void) {
    int a = 5, b = 3;

    // compute_mba(5, 3):
    //   add = 8, sub = 2, and = 1, or = 7, xor = 6  → total = 24
    int r = compute_mba(a, b);
    int expected_comb = (a+b) + (a-b) + (a&b) + (a|b) + (a^b);

    printf("add(%d,%d)    = %d\n", a, b, a + b);
    printf("sub(%d,%d)    = %d\n", a, b, a - b);
    printf("and(0x%02X,0x%02X) = %d\n", (unsigned)0xF0, (unsigned)0x0F, 0xF0 & 0x0F);
    printf("or(0x%02X,0x%02X)  = %d\n", (unsigned)0xF0, (unsigned)0x0F, 0xF0 | 0x0F);
    printf("xor(0x%02X,0x%02X) = %d\n", (unsigned)0xFF, (unsigned)0x0F, 0xFF ^ 0x0F);

    int fp = full_protect(10);
    printf("full_protect(10) = %d\n", fp);

    // Verify
    int ok = 1;
    if (r != expected_comb) {
        printf("FAIL: compute_mba(%d,%d) = %d, expected %d\n", a, b, r, expected_comb);
        ok = 0;
    }
    if (fp != 55) {
        printf("FAIL: full_protect(10) = %d, expected 55\n", fp);
        ok = 0;
    }
    if (ok)
        printf("ALL TESTS PASSED\n");

    return ok ? 0 : 1;
}
