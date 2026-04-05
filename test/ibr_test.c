// ArmorComp — IndirectBranch pass validation test
//
// Tests:
//   classify_ibr()    — annotate("ibr"): conditional + unconditional branches
//                       replaced by indirectbr; runtime result must be identical.
//   loop_ibr()        — annotate("ibr"): loop (conditional + back-edge branches)
//   classify_plain()  — no annotation: branches stay direct (control)
//
// Expected stderr (ArmorComp log):
//   [ArmorComp][IBR] indirected: classify_ibr  (N branches)
//   [ArmorComp][IBR] indirected: loop_ibr      (N branches)
//
// Verification (host, requires llvm-objdump from brew llvm@17):
//   llvm-objdump -d ibr_test_aarch64 | awk '/<classify_ibr>/{p=1} p{print; if(/ret/)exit}'
//   → should show "br x8" or "blr x8" (indirect), NOT "b.lt / b.gt" (direct cond branch)
//
//   llvm-objdump -d ibr_test_aarch64 | awk '/<classify_plain>/{p=1} p{print; if(/ret/)exit}'
//   → should show "b.lt / b.gt" (direct conditional branches)
//
// Expected stdout:
//   classify_ibr(-5) = -1
//   classify_ibr(0)  = 0
//   classify_ibr(3)  = 1
//   loop_ibr(5)      = 15
//   ALL TESTS PASSED

#include <stdio.h>

// classify_ibr: two conditional branches + two unconditional returns.
// IndirectBranchPass will convert all BranchInst terminators.
__attribute__((annotate("ibr")))
int classify_ibr(int x) {
    if (x < 0) return -1;
    if (x > 0) return  1;
    return 0;
}

// loop_ibr: loop with back-edge branch — tests unconditional and conditional.
__attribute__((annotate("ibr")))
int loop_ibr(int n) {
    int sum = 0;
    int i = 1;
    while (i <= n) {
        sum += i;
        i++;
    }
    return sum;
}

// classify_plain: identical logic, no annotation (baseline / control).
int classify_plain(int x) {
    if (x < 0) return -1;
    if (x > 0) return  1;
    return 0;
}

int main(void) {
    printf("classify_ibr(-5) = %d\n", classify_ibr(-5));
    printf("classify_ibr(0)  = %d\n", classify_ibr(0));
    printf("classify_ibr(3)  = %d\n", classify_ibr(3));
    printf("loop_ibr(5)      = %d\n", loop_ibr(5));

    int ok = 1;
    if (classify_ibr(-5) != -1) { printf("FAIL: classify_ibr(-5)\n"); ok=0; }
    if (classify_ibr( 0) !=  0) { printf("FAIL: classify_ibr(0)\n");  ok=0; }
    if (classify_ibr( 3) !=  1) { printf("FAIL: classify_ibr(3)\n");  ok=0; }
    if (loop_ibr(5)      != 15) { printf("FAIL: loop_ibr(5)\n");       ok=0; }
    // Sanity check: plain version must give same result
    if (classify_plain(-5) != -1) { printf("FAIL: classify_plain\n"); ok=0; }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
