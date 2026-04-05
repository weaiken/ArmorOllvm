// ArmorComp — DataEncodingPass (DENC) validation test
//
// DataEncodingPass wraps every direct load/store to eligible integer allocas
// (i8 / i16 / i32 / i64) with XOR encode/decode pairs:
//
//   store side:  %de.enc = xor iN val, K
//                store iN %de.enc, ptr %x
//
//   load  side:  %raw    = load iN, ptr %x
//                %de.dec = xor iN %raw, K
//                ; all uses of %raw replaced with %de.dec
//
//   K = xorshift64(FNV1a(fn_name + "_denc_" + alloca_index))
//
// Effect: stack memory always contains XOR-encoded values.  IDA/Ghidra
// sees eor sequences around every ldr/str pair instead of plain variable
// accesses; this hinders type recovery and value propagation at the
// source-variable level.
//
// Expected stderr (ArmorComp log):
//   [ArmorComp][DENC] encoded: secure_compute (N alloca(s))
//   [ArmorComp][DENC] encoded: secure_mixed   (N alloca(s))
//   (no message for plain_compute / plain_mixed — not annotated)
//
// Verification (host, requires llvm-objdump):
//   llvm-objdump -d denc_test_aarch64 | grep -A50 "<secure_compute>"
//   → every str should be preceded by an eor instruction (encode)
//   → every ldr should be followed by an eor instruction (decode)
//
// Expected stdout:
//   secure_compute(2, 3)   = 12
//   secure_compute(5, 2)   = 20
//   plain_compute(2, 3)    = 12
//   secure_mixed(4, 3)     = 7
//   ALL TESTS PASSED

#include <stdio.h>

// ── Annotated functions ────────────────────────────────────────────────────

// secure_compute: 4 integer locals (a, b, c, result).
// At -O0 clang also creates allocas for the x, y params → 6 allocas total.
// All i32 allocas: each gets its own deterministic XOR key.
// secure_compute(2,3): a=5, b=6, c=-1, result=1 → 1+5+6=12
// secure_compute(5,2): a=7, b=10, c=-3, result=3 → 3+7+10=20
__attribute__((annotate("denc")))
int secure_compute(int x, int y) {
    int a = x + y;
    int b = x * y;
    int c = a - b;
    int result = (c > 0) ? c : -c;   // abs(c)
    return result + a + b;
}

// secure_mixed: int and long long locals exercise two different type widths.
//   n_copy (i32), acc (i64), step (i32), loop counter i (i32)
//   Each alloca gets its own key sized to the alloca's type width.
// secure_mixed(4,3): n_copy=7, step=1, acc=1*7=7
__attribute__((annotate("denc")))
long long secure_mixed(int n, int m) {
    int n_copy = n + m;
    long long acc = 0;
    int step = n - m;
    for (int i = 0; i < n_copy; i++)
        acc += step;
    return acc;
}

// ── Plain reference implementations (no annotation) ─────────────────────

int plain_compute(int x, int y) {
    int a = x + y;
    int b = x * y;
    int c = a - b;
    int result = (c > 0) ? c : -c;
    return result + a + b;
}

long long plain_mixed(int n, int m) {
    int n_copy = n + m;
    long long acc = 0;
    int step = n - m;
    for (int i = 0; i < n_copy; i++)
        acc += step;
    return acc;
}

// ── Main ──────────────────────────────────────────────────────────────────

int main(void) {
    printf("secure_compute(2, 3)   = %d\n",   secure_compute(2, 3));   // 12
    printf("secure_compute(5, 2)   = %d\n",   secure_compute(5, 2));   // 20
    printf("plain_compute(2, 3)    = %d\n",   plain_compute(2, 3));    // 12
    printf("secure_mixed(4, 3)     = %lld\n", secure_mixed(4, 3));     // 7

    int ok = 1;

    // secure_compute must match plain_compute for all test inputs
    int xs[] = { -5, -2, -1,  0,  1,  2,  3,  5,  7, 10 };
    int ys[] = { -3,  1,  1,  0, -1,  3,  4,  2, -2,  5 };
    int ncases = (int)(sizeof(xs) / sizeof(xs[0]));
    for (int i = 0; i < ncases; i++) {
        int s = secure_compute(xs[i], ys[i]);
        int p = plain_compute(xs[i], ys[i]);
        if (s != p) {
            printf("FAIL compute(%d,%d): secure=%d plain=%d\n",
                   xs[i], ys[i], s, p);
            ok = 0;
        }
    }

    // secure_mixed must match plain_mixed for all test inputs
    int na[] = { 0, 1, 2,  4,  5,  0, -1,  3 };
    int ma[] = { 0, 1, 3,  3,  5, 10,  0, -1 };
    int nm = (int)(sizeof(na) / sizeof(na[0]));
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
