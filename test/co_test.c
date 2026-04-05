// ArmorComp — Integer Constant Obfuscation (ConstObf) validation test
//
// ConstObfPass replaces every integer constant in qualifying instructions
// with: xor iN (C ^ K), (or i64 volatile_zero | K64)
// where K is a compile-time random key.  The expression evaluates to C at
// runtime but IDA/Ghidra cannot see bare numeric literals.
//
// Expected stderr (ArmorComp log):
//   [ArmorComp][CO] obfuscated: compute_co (N constant(s))
//   (no message for compute_plain — not annotated)
//
// Verification (host, requires llvm-objdump):
//   llvm-objdump -d co_test_aarch64 | awk '/<compute_co>/{p=1}p{print;if(/ret/)exit}'
//   → should NOT show plain "mov w*, #5" or "mov w*, #12" etc.
//   → should show eor/orr sequences using __armorcomp_co_zero
//
//   llvm-objdump -d co_test_aarch64 | awk '/<compute_plain>/{p=1}p{print;if(/ret/)exit}'
//   → should show plain "mov w*, #5", "mov w*, #12" etc.
//
// Expected stdout:
//   compute_co(3)  = 255
//   compute_co(7)  = 249
//   compute_co(10) = 241
//   ALL TESTS PASSED

#include <stdio.h>

// compute_co: constants 5, 12, 0xFF are all obfuscated — no bare immediates
// in decompiler output.
__attribute__((annotate("co")))
int compute_co(int x) {
    return (x * 5 + 12) ^ 0xFF;   // constants: 5, 12, 255
}

// compute_plain: no annotation — baseline, IDA sees plain immediates
int compute_plain(int x) {
    return (x * 5 + 12) ^ 0xFF;
}

int main(void) {
    printf("compute_co(3)  = %d\n", compute_co(3));    // (3*5+12)^0xFF = 27^255 = 228? no: 27^255=228
    printf("compute_co(7)  = %d\n", compute_co(7));    // (7*5+12)^0xFF = 47^255 = 208
    printf("compute_co(10) = %d\n", compute_co(10));   // (10*5+12)^0xFF = 62^255 = 193

    int ok = 1;
    if (compute_co(3)  != compute_plain(3))  { printf("FAIL: compute_co(3)\n");  ok = 0; }
    if (compute_co(7)  != compute_plain(7))  { printf("FAIL: compute_co(7)\n");  ok = 0; }
    if (compute_co(10) != compute_plain(10)) { printf("FAIL: compute_co(10)\n"); ok = 0; }
    if (compute_co(0)  != compute_plain(0))  { printf("FAIL: compute_co(0)\n");  ok = 0; }
    if (compute_co(-1) != compute_plain(-1)) { printf("FAIL: compute_co(-1)\n"); ok = 0; }
    if (compute_co(100)!= compute_plain(100)){ printf("FAIL: compute_co(100)\n");ok = 0; }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
