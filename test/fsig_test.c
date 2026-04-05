// ArmorComp — FuncSigObfPass (FSIG) validation test
//
// FuncSigObfPass injects:
//   Entry: reads x1, x2, x3 via inline asm; OR-accumulates; volatile-stores
//          to __armorcomp_fsig_sink.  No runtime side effect.
//   Exit:  before each ret, writes volatile 0 to x1, x2 via inline asm.
//          No runtime side effect (x1/x2 are caller-saved; callers discard).
//
// Expected stderr (ArmorComp log):
//   [ArmorComp][FSIG] obfuscated: secure_add   (3 fake arg-reads at entry, 1 ret(s) with fake return-val writes)
//   [ArmorComp][FSIG] obfuscated: secure_abs   (3 fake arg-reads at entry, 2 ret(s) with fake return-val writes)
//   [ArmorComp][FSIG] obfuscated: secure_sum   (3 fake arg-reads at entry, 1 ret(s) with fake return-val writes)
//   (no message for plain_add / plain_abs — not annotated)
//
// Verification (host, requires llvm-objdump):
//   llvm-objdump -d fsig_test_aarch64 | grep -A30 "<secure_add>"
//   → near function entry: "mov  x9, x1" / "mov x10, x2" / "mov x11, x3"
//     followed by orr/eor chain then a volatile str to __armorcomp_fsig_sink
//   → near function exit: "mov  x1, x9" / "mov  x2, x9" immediately before ret
//     (x9 holds the volatile-zero value)
//
// IDA analysis effect:
//   - IDA prototype for secure_add: "__int64 secure_add(__int64 a0, __int64 a1,
//       __int64 a2, __int64 a3)" instead of "int secure_add(int, int)"
//   - IDA return type: may show struct or multiple return registers for x0+x1+x2
//   - Hex-Rays decompiles incorrect signature causing callers to look wrong
//
// Expected stdout:
//   secure_add(3, 4)   = 7
//   secure_add(-5, 2)  = -3
//   plain_add(3, 4)    = 7
//   secure_abs(-7)     = 7
//   secure_abs(5)      = 5
//   secure_sum(1, 10)  = 55
//   ALL TESTS PASSED

#include <stdio.h>

// ── Annotated functions (FuncSigObfPass applied) ──────────────────────────

__attribute__((annotate("fsig")))
int secure_add(int a, int b) {
    return a + b;
}

// Two-return-path function — exercises per-ret write injection
__attribute__((annotate("fsig")))
int secure_abs(int x) {
    if (x < 0) return -x;   // ret #1
    return x;                // ret #2
}

// Loop function — more complex body, but boundary obfuscation is the same
__attribute__((annotate("fsig")))
long long secure_sum(int start, int end) {
    long long acc = 0;
    for (int i = start; i <= end; i++)
        acc += i;
    return acc;
}

// ── Plain reference implementations (no annotation) ──────────────────────

int plain_add(int a, int b) {
    return a + b;
}

int plain_abs(int x) {
    return (x < 0) ? -x : x;
}

long long plain_sum(int start, int end) {
    long long acc = 0;
    for (int i = start; i <= end; i++)
        acc += i;
    return acc;
}

// ── Main ──────────────────────────────────────────────────────────────────

int main(void) {
    printf("secure_add(3, 4)   = %d\n",   secure_add(3, 4));    // 7
    printf("secure_add(-5, 2)  = %d\n",   secure_add(-5, 2));   // -3
    printf("plain_add(3, 4)    = %d\n",   plain_add(3, 4));     // 7
    printf("secure_abs(-7)     = %d\n",   secure_abs(-7));      // 7
    printf("secure_abs(5)      = %d\n",   secure_abs(5));       // 5
    printf("secure_sum(1, 10)  = %lld\n", secure_sum(1, 10));   // 55

    int ok = 1;

    // Verify secure_add matches plain_add across diverse inputs
    int xs[] = {-10, -5, -1, 0, 1, 5, 10, 127, -128, 42};
    int ys[] = {  5,  5,  1, 0, 1, 3,  7,  -7,   50, 58};
    int nc = (int)(sizeof(xs) / sizeof(xs[0]));
    for (int i = 0; i < nc; i++) {
        int s = secure_add(xs[i], ys[i]);
        int p = plain_add(xs[i], ys[i]);
        if (s != p) {
            printf("FAIL add(%d,%d): secure=%d plain=%d\n",
                   xs[i], ys[i], s, p);
            ok = 0;
        }
    }

    // Verify secure_abs matches plain_abs
    int avs[] = {-100, -1, 0, 1, 100, -2147483647};
    int na = (int)(sizeof(avs) / sizeof(avs[0]));
    for (int i = 0; i < na; i++) {
        int s = secure_abs(avs[i]);
        int p = plain_abs(avs[i]);
        if (s != p) {
            printf("FAIL abs(%d): secure=%d plain=%d\n", avs[i], s, p);
            ok = 0;
        }
    }

    // Verify secure_sum matches plain_sum
    int sa[] = { 0,  1, -5,  3 };
    int ea[] = { 0, 10,  5, 100 };
    int ns = (int)(sizeof(sa) / sizeof(sa[0]));
    for (int i = 0; i < ns; i++) {
        long long s = secure_sum(sa[i], ea[i]);
        long long p = plain_sum(sa[i], ea[i]);
        if (s != p) {
            printf("FAIL sum(%d,%d): secure=%lld plain=%lld\n",
                   sa[i], ea[i], s, p);
            ok = 0;
        }
    }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
