// ArmorComp — Stack Pointer Obfuscation (SPO) validation test
//
// SPOPass injects a volatile-loaded zero into:
//   - entry block: "sub sp, sp, xN"  (defeats IDA sp_delta analysis)
//   - each return:  "add sp, sp, xN"  (runtime no-op restore)
//
// Because xN is loaded from @__armorcomp_spo_zero via a volatile load, IDA
// cannot determine xN at analysis time, so sp_delta = UNKNOWN → Hex-Rays
// outputs "sp-analysis failed" and refuses to decompile compute_spo.
//
// At runtime, xN = 0 always, so the sub/add pair is a no-op and the function
// produces identical results to the unobfuscated version.
//
// Expected stderr (ArmorComp log):
//   [ArmorComp][SPO] obfuscated: compute_spo (2 ret(s))
//   (no message for compute_plain — no annotation)
//
// Verification (host, requires llvm-objdump):
//   llvm-objdump -d spo_test_aarch64 | awk '/<compute_spo>/{p=1}p{print; if(/ret/)exit}'
//   → should show "sub sp, sp, x<N>" after function prologue
//   → should show "add sp, sp, x<N>" before ret
//
// Expected stdout:
//   compute_spo(3, 4) = 7
//   compute_spo(5, 7) = 35
//   compute_spo(2, 3) = 5
//   ALL TESTS PASSED

#include <stdio.h>

// compute_spo: protected by SPO — IDA cannot decompile, runtime is correct
__attribute__((annotate("spo")))
int compute_spo(int x, int y) {
    int sum = x + y;
    int product = x * y;
    if (sum > 10) return product;   // one ret path
    return sum;                     // another ret path
}

// compute_plain: no annotation — baseline / control (IDA can decompile normally)
int compute_plain(int x, int y) {
    int sum = x + y;
    int product = x * y;
    if (sum > 10) return product;
    return sum;
}

int main(void) {
    // Show output for manual inspection on device
    printf("compute_spo(3, 4) = %d\n", compute_spo(3, 4));   // 3+4=7  <= 10 → 7
    printf("compute_spo(5, 7) = %d\n", compute_spo(5, 7));   // 5+7=12 > 10 → 35
    printf("compute_spo(2, 3) = %d\n", compute_spo(2, 3));   // 2+3=5  <= 10 → 5

    // Correctness check: SPO-protected and plain must produce identical results
    int ok = 1;
    if (compute_spo(3, 4) != compute_plain(3, 4)) {
        printf("FAIL: compute_spo(3, 4)\n"); ok = 0;
    }
    if (compute_spo(5, 7) != compute_plain(5, 7)) {
        printf("FAIL: compute_spo(5, 7)\n"); ok = 0;
    }
    if (compute_spo(2, 3) != compute_plain(2, 3)) {
        printf("FAIL: compute_spo(2, 3)\n"); ok = 0;
    }
    // Edge: both ret paths
    if (compute_spo(0, 0) != compute_plain(0, 0)) {
        printf("FAIL: compute_spo(0, 0)\n"); ok = 0;
    }
    if (compute_spo(100, 100) != compute_plain(100, 100)) {
        printf("FAIL: compute_spo(100, 100)\n"); ok = 0;
    }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
