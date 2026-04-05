// ArmorComp — FlattenDataFlowPass (DF) validation test
//
// FlattenDataFlowPass merges all statically-sized alloca instructions in a
// function's entry block into a single byte pool: alloca [N x i8].
// Each original local variable is accessed via an obfuscated GEP index:
//
//   pool  = alloca [N x i8]
//   z     = load volatile i64 @__armorcomp_df_zero   ; = 0 at runtime
//   idx   = xor i64 (O ^ KEY), (or i64 z, KEY)       ; = O at runtime
//   ptr   = gep i8, ptr pool, i64 idx                ; = pool + O
//
// Effect: IDA/Ghidra variable recovery fails because the decompiler cannot
// resolve the volatile GEP index to a constant, so it cannot determine the
// type or identity of each "variable" in the pool.
//
// Expected stderr (ArmorComp log):
//   [ArmorComp][DF] flattened: secure_compute (N alloca(s), M bytes)
//   [ArmorComp][DF] flattened: secure_mixed   (N alloca(s), M bytes)
//   (no message for plain_compute / plain_mixed — not annotated)
//
// Verification (host, requires llvm-objdump):
//   llvm-objdump -d df_test_aarch64 | awk '/<secure_compute>/{p=1}p{print;if(/ret$/)exit}'
//   → Should show "armorcomp.df.pool" alloca near the top of the function and
//     GEP-based pointer loads (no named [sp, #-4] / [sp, #-8] stack slots
//     at fixed offsets — instead they all compute via the pool base + eor/orr).
//
// Expected stdout:
//   secure_compute(3, 4)   = 6
//   secure_compute(5, 3)   = 42
//   plain_compute(3, 4)    = 6
//   secure_mixed(3, 4)     = 42
//   ALL TESTS PASSED

#include <stdio.h>

// ── Annotated functions ────────────────────────────────────────────────────

// secure_compute: annotated with "df".
// Has 4 integer allocas (a, b, c, d) — all merged into one [16 x i8] pool.
// Alignment: all i32 → pool aligned to 4 bytes, total = 16 bytes.
__attribute__((annotate("df")))
int secure_compute(int x, int y) {
    int a = x + y;
    int b = x - y;
    int c = a * b;
    int d = (c > 0) ? c : -c;      // abs(c)
    return (a + b + c + d) % 100;
}

// secure_mixed: mixed int + long long to exercise alignment handling.
// Allocas: x_copy (i32, align 4), acc (i64, align 8), step (i32, align 4).
// Pool layout (with alignment padding):
//   offset 0: x_copy  [4 bytes]
//   offset 4: (padding 4 bytes to align acc to 8)
//   offset 8: acc     [8 bytes]
//   offset 16: step   [4 bytes]
//   → pool = [20 x i8] (padded to maxAlign=8: 24 bytes)
__attribute__((annotate("df")))
long long secure_mixed(int n, int m) {
    int x_copy = n + m;
    long long acc = 0;
    int step = n * m;
    for (int i = 0; i < x_copy; i++)
        acc += step;
    return acc;
}

// ── Plain reference implementations (no annotation) ─────────────────────

int plain_compute(int x, int y) {
    int a = x + y;
    int b = x - y;
    int c = a * b;
    int d = (c > 0) ? c : -c;
    return (a + b + c + d) % 100;
}

long long plain_mixed(int n, int m) {
    int x_copy = n + m;
    long long acc = 0;
    int step = n * m;
    for (int i = 0; i < x_copy; i++)
        acc += step;
    return acc;
}

// ── Main ──────────────────────────────────────────────────────────────────

int main(void) {
    // Print a few values for visual inspection
    printf("secure_compute(3, 4)   = %d\n", secure_compute(3, 4));     // 6
    printf("secure_compute(5, 3)   = %d\n", secure_compute(5, 3));     // 42
    printf("plain_compute(3, 4)    = %d\n", plain_compute(3, 4));      // 6
    printf("secure_mixed(3, 4)     = %lld\n", secure_mixed(3, 4));     // 42

    int ok = 1;

    // secure_compute must match plain_compute for all test inputs
    int xs[] = { -10, -5, -1,  0,  1,  2,  3,  5,  7, 10, 20 };
    int ys[] = {  -3, -1,  1,  0, -1,  3,  4,  3, -2,  7, 15 };
    int n = sizeof(xs) / sizeof(xs[0]);
    for (int i = 0; i < n; i++) {
        int s = secure_compute(xs[i], ys[i]);
        int p = plain_compute(xs[i], ys[i]);
        if (s != p) {
            printf("FAIL compute(%d,%d): secure=%d plain=%d\n",
                   xs[i], ys[i], s, p);
            ok = 0;
        }
    }

    // secure_mixed must match plain_mixed for all test inputs
    int na[] = { 0, 1, 2,  3,  4,  5,  0, -1 };
    int ma[] = { 0, 1, 3, -1,  2,  5, 10,  0 };
    int nm = sizeof(na) / sizeof(na[0]);
    for (int i = 0; i < nm; i++) {
        long long s = secure_mixed(na[i], ma[i]);
        long long p = plain_mixed(na[i], ma[i]);
        if (s != p) {
            printf("FAIL mixed(%d,%d): secure=%lld plain=%lld\n",
                   na[i], ma[i], s, p);
            ok = 0;
        }
    }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
