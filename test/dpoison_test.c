// ArmorComp — DwarfPoisonPass (DPOISON) validation test
//
// DwarfPoisonPass injects self-contained .cfi_remember_state / fake-CFI /
// .cfi_restore_state inline-asm blocks at:
//   - Function entry (2x, after allocas)
//   - Before each non-entry BB terminator (1x per BB)
//   - Before each ret (1x extra)
//
// The injected blocks add misleading DWARF rows to .eh_frame:
//   PC=nop:  CFA=<huge/scratch>, x30=undefined, x29=undefined
//   PC=next: restored to correct CFA
//
// Expected stderr (ArmorComp log):
//   [ArmorComp][DPOISON] obfuscated: secure_compute   (N CFI poison injection(s), 1 ret(s))
//   [ArmorComp][DPOISON] obfuscated: secure_branch     (N CFI poison injection(s), 2 ret(s))
//   [ArmorComp][DPOISON] obfuscated: secure_loop       (N CFI poison injection(s), 1 ret(s))
//   (no message for plain_compute / plain_branch / plain_loop — not annotated)
//
// Verification (host, requires readelf or llvm-dwarfdump):
//
//   readelf --debug-dump=frames dpoison_test_aarch64 | grep -B2 -A30 "FDE.*secure_compute"
//   → should contain DW_CFA_def_cfa rows with huge offsets (e.g., sp+524288, sp+65536)
//     and/or DW_CFA_undefined entries for r30 (LR, x30) and r29 (FP, x29)
//
//   llvm-dwarfdump --eh-frame dpoison_test_aarch64 | grep -A40 "secure_compute"
//   → should show multiple CFA= lines alternating between:
//       CFA=x29+16 (correct, from function prologue)
//       CFA=sp+524288 (fake, from injected poison block)  ← IDA analysis fails here
//       CFA=x29+16 (restored, .cfi_restore_state)
//
// IDA Pro analysis effect:
//   - sp_delta shows UNKNOWN throughout all annotated functions
//   - Hex-Rays decompiler: "stack analysis failed" / wrong local-variable addresses
//   - Stack view shows inconsistent and impossible frame sizes
//   - IDA CFG may display "sp is not balanced" warnings on every BB
//
// Runtime correctness:
//   Each .cfi_restore_state reinstates the correct CFA record before the next
//   real instruction.  Fake DWARF rows cover only the single injected nop.
//   Exception handling and backtrace() can still unwind through annotated fns.
//
// Expected stdout:
//   secure_compute(3, 4)   = 14
//   secure_compute(2, 3)   = 7
//   plain_compute(3, 4)    = 14
//   secure_branch(-7)      = 7
//   secure_branch(5)       = 5
//   secure_loop(1, 10)     = 55
//   ALL TESTS PASSED

#include <stdio.h>

// ── Annotated functions (DwarfPoisonPass applied) ──────────────────────────

__attribute__((annotate("dpoison")))
int secure_compute(int a, int b) {
    // a=3, b=4: x=12, y=-1, result=14
    int x = a * b;
    int y = a - b;
    return x + y + a;
}

// Two-return-path function — exercises per-ret injection at both exits
__attribute__((annotate("dpoison")))
int secure_branch(int x) {
    if (x < 0) return -x;  // ret #1
    return x;               // ret #2
}

// Loop function — more basic blocks → more injection points → more DWARF rows
__attribute__((annotate("dpoison")))
long long secure_loop(int start, int end) {
    long long acc = 0;
    for (int i = start; i <= end; i++)
        acc += i;
    return acc;
}

// ── Plain reference implementations (no annotation) ───────────────────────

int plain_compute(int a, int b) {
    int x = a * b;
    int y = a - b;
    return x + y + a;
}

int plain_branch(int x) {
    return (x < 0) ? -x : x;
}

long long plain_loop(int start, int end) {
    long long acc = 0;
    for (int i = start; i <= end; i++)
        acc += i;
    return acc;
}

// ── Main ──────────────────────────────────────────────────────────────────

int main(void) {
    printf("secure_compute(3, 4)   = %d\n",   secure_compute(3, 4));   // 14
    printf("secure_compute(2, 3)   = %d\n",   secure_compute(2, 3));   // 7
    printf("plain_compute(3, 4)    = %d\n",   plain_compute(3, 4));    // 14
    printf("secure_branch(-7)      = %d\n",   secure_branch(-7));      // 7
    printf("secure_branch(5)       = %d\n",   secure_branch(5));       // 5
    printf("secure_loop(1, 10)     = %lld\n", secure_loop(1, 10));     // 55

    int ok = 1;

    // Verify secure_compute matches plain_compute across diverse inputs
    int as[] = {-10, -5, -1, 0, 1, 5, 10, 127, -128, 42};
    int bs[] = {  5,  5,  1, 0, 1, 3,  7,  -7,   50, 58};
    int nc = (int)(sizeof(as) / sizeof(as[0]));
    for (int i = 0; i < nc; i++) {
        int s = secure_compute(as[i], bs[i]);
        int p = plain_compute(as[i], bs[i]);
        if (s != p) {
            printf("FAIL compute(%d,%d): secure=%d plain=%d\n",
                   as[i], bs[i], s, p);
            ok = 0;
        }
    }

    // Verify secure_branch matches plain_branch
    int bvs[] = {-100, -1, 0, 1, 100, -2147483647};
    int nb = (int)(sizeof(bvs) / sizeof(bvs[0]));
    for (int i = 0; i < nb; i++) {
        int s = secure_branch(bvs[i]);
        int p = plain_branch(bvs[i]);
        if (s != p) {
            printf("FAIL branch(%d): secure=%d plain=%d\n", bvs[i], s, p);
            ok = 0;
        }
    }

    // Verify secure_loop matches plain_loop
    int sa[] = { 0,  1, -5,  3 };
    int ea[] = { 0, 10,  5, 100 };
    int ns = (int)(sizeof(sa) / sizeof(sa[0]));
    for (int i = 0; i < ns; i++) {
        long long s = secure_loop(sa[i], ea[i]);
        long long p = plain_loop(sa[i], ea[i]);
        if (s != p) {
            printf("FAIL loop(%d,%d): secure=%lld plain=%lld\n",
                   sa[i], ea[i], s, p);
            ok = 0;
        }
    }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
