// ArmorComp — FakeAPICallPass (FAPI) validation test
//
// FakeAPICallPass injects real libc calls (getpid / getpagesize) before each
// BB's terminator.  The results are consumed by asm sideeffect sinks to
// prevent DCE.  Unlike JunkCodePass's arithmetic chains, these are genuine
// system calls that static analysis tools cannot prove are no-ops.
//
// Expected stderr:
//   [ArmorComp][FAPI] injected: secure_compute (N API call(s))
//   [ArmorComp][FAPI] injected: secure_mixed   (N API call(s))
//   (no message for plain_* — not annotated)
//
// Verification (AArch64 disasm):
//   llvm-objdump -d fapi_test_aarch64 | grep -A30 "<secure_compute>"
//   → should show "bl getpid" or "bl getpagesize" before each branch/ret
//
// Expected stdout:
//   secure_compute(2, 3)   = 12
//   secure_compute(5, 2)   = 20
//   plain_compute(2, 3)    = 12
//   secure_mixed(4, 3)     = 7
//   ALL TESTS PASSED

#include <stdio.h>

// ── Annotated functions ────────────────────────────────────────────────────

__attribute__((annotate("fapi")))
int secure_compute(int x, int y) {
    int a = x + y;
    int b = x * y;
    int c = a - b;
    int result = (c > 0) ? c : -c;
    return result + a + b;
}

__attribute__((annotate("fapi")))
long long secure_mixed(int n, int m) {
    int n_copy = n + m;
    long long acc = 0;
    int step = n - m;
    for (int i = 0; i < n_copy; i++)
        acc += step;
    return acc;
}

// ── Plain reference implementations ────────────────────────────────────────

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

// ── Main ────────────────────────────────────────────────────────────────────

int main(void) {
    printf("secure_compute(2, 3)   = %d\n",   secure_compute(2, 3));
    printf("secure_compute(5, 2)   = %d\n",   secure_compute(5, 2));
    printf("plain_compute(2, 3)    = %d\n",   plain_compute(2, 3));
    printf("secure_mixed(4, 3)     = %lld\n", secure_mixed(4, 3));

    int ok = 1;

    int xs[] = { -5, -2, -1, 0, 1, 2, 3, 5, 7, 10 };
    int ys[] = { -3,  1,  1, 0,-1, 3, 4, 2,-2,  5 };
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

    int na[] = { 0, 1, 2, 4, 5, 0, -1, 3 };
    int ma[] = { 0, 1, 3, 3, 5,10,  0,-1 };
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
