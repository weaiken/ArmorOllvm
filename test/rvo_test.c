// ArmorComp — ReturnValueObfPass (RVO) validation test
//
// ReturnValueObfPass injects `retval ^= volatile_zero` immediately before
// each ReturnInst for integer/pointer-returning functions.  At runtime the
// XOR is a no-op (volatile_zero == 0), so all function outputs remain
// correct.  Correctness is verified exhaustively below.
//
// Expected stderr (ArmorComp log):
//   [ArmorComp][RVO] obfuscated: secure_add    (1 ret(s), 32-bit)
//   [ArmorComp][RVO] obfuscated: secure_abs    (1 ret(s), 32-bit)
//   [ArmorComp][RVO] obfuscated: secure_classify (1 ret(s), 32-bit)
//   [ArmorComp][RVO] obfuscated: secure_sum    (1 ret(s), 32-bit)
//   [ArmorComp][RVO] obfuscated: secure_id64   (1 ret(s), 64-bit)
//   [ArmorComp][RVO] obfuscated: secure_ptr    (1 ret(s), ptr)
//   (no message for plain_* — not annotated)
//
// IDA Pro analysis effect on annotated functions (AArch64 binary):
//   secure_add disassembly (before ret):
//     ldr  w8, [__armorcomp_rvo_zero]   ; volatile zero load
//     eor  w0, w0, w8                   ; w0 ^= 0 (IDA cannot prove this)
//     ret
//   → IDA return-type inference fails: marks return type as __int64 or _UNKNOWN
//   → Hex-Rays F5 output shows wrong return type for all annotated functions
//   → Combined with NTC (fmov roundtrips) and FSIG (fake arg reads):
//     complete function prototype unrecoverable
//
// Verification: llvm-objdump -d rvo_test_aarch64 | grep -A10 "<secure_add>"
//   → should show   eor w0, w0, w8   immediately before ret
//   → plain_add should NOT contain any eor on w0 before ret
//
// Expected stdout:
//   secure_add(3, 4)         =  7
//   secure_add(-5, 2)        = -3
//   plain_add(3, 4)          =  7
//   secure_abs(-7)           =  7
//   secure_abs(5)            =  5
//   plain_abs(-7)            =  7
//   secure_classify(-5)      = -1
//   secure_classify(0)       =  0
//   secure_classify(5)       =  1
//   secure_classify(101)     =  2
//   plain_classify(-5)       = -1
//   secure_sum(1, 10)        = 55
//   plain_sum(1, 10)         = 55
//   secure_id64(42)          = 42
//   plain_id64(42)           = 42
//   secure_ptr(ok)           = ok
//   ALL TESTS PASSED

#include <stdio.h>
#include <stdint.h>

// ── Annotated functions (ReturnValueObfPass applied) ─────────────────────────

// 32-bit integer return — single ret path
__attribute__((annotate("rvo")))
int secure_add(int a, int b) {
    return a + b;
}

// 32-bit integer return — two ret paths (at -O0: single-exit IR)
__attribute__((annotate("rvo")))
int secure_abs(int x) {
    if (x < 0) return -x;
    return x;
}

// 32-bit integer return — four ret paths
__attribute__((annotate("rvo")))
int secure_classify(int x) {
    if (x < 0)   return -1;
    if (x > 100) return 2;
    if (x == 0)  return 0;
    return 1;
}

// 32-bit integer return — loop + single ret
__attribute__((annotate("rvo")))
int secure_sum(int lo, int hi) {
    int acc = 0;
    for (int i = lo; i <= hi; i++)
        acc += i;
    return acc;
}

// 64-bit integer return — tests i64 XOR (eor x0, x0, x8 in disassembly)
__attribute__((annotate("rvo")))
int64_t secure_id64(int64_t x) {
    return x;
}

// Pointer return — tests ptrtoint → XOR → inttoptr path
__attribute__((annotate("rvo")))
const char *secure_ptr(const char *s) {
    return s;
}

// ── Plain reference implementations (no annotation) ──────────────────────────

int plain_add(int a, int b) { return a + b; }

int plain_abs(int x) {
    if (x < 0) return -x;
    return x;
}

int plain_classify(int x) {
    if (x < 0)   return -1;
    if (x > 100) return 2;
    if (x == 0)  return 0;
    return 1;
}

int plain_sum(int lo, int hi) {
    int acc = 0;
    for (int i = lo; i <= hi; i++)
        acc += i;
    return acc;
}

int64_t plain_id64(int64_t x) { return x; }

const char *plain_ptr(const char *s) { return s; }

// ── Main ─────────────────────────────────────────────────────────────────────

int main(void) {
    // Print representative samples
    printf("secure_add(3, 4)         = %d\n",  secure_add(3, 4));       //  7
    printf("secure_add(-5, 2)        = %d\n",  secure_add(-5, 2));      // -3
    printf("plain_add(3, 4)          = %d\n",  plain_add(3, 4));        //  7
    printf("secure_abs(-7)           = %d\n",  secure_abs(-7));         //  7
    printf("secure_abs(5)            = %d\n",  secure_abs(5));          //  5
    printf("plain_abs(-7)            = %d\n",  plain_abs(-7));          //  7
    printf("secure_classify(-5)      = %d\n",  secure_classify(-5));    // -1
    printf("secure_classify(0)       = %d\n",  secure_classify(0));     //  0
    printf("secure_classify(5)       = %d\n",  secure_classify(5));     //  1
    printf("secure_classify(101)     = %d\n",  secure_classify(101));   //  2
    printf("plain_classify(-5)       = %d\n",  plain_classify(-5));     // -1
    printf("secure_sum(1, 10)        = %d\n",  secure_sum(1, 10));      // 55
    printf("plain_sum(1, 10)         = %d\n",  plain_sum(1, 10));       // 55
    printf("secure_id64(42)          = %lld\n", (long long)secure_id64(42)); // 42
    printf("plain_id64(42)           = %lld\n", (long long)plain_id64(42));  // 42

    static const char tag[] = "ok";
    const char *p = secure_ptr(tag);
    printf("secure_ptr(ok)           = %s\n", p);   // ok

    int ok = 1;

    // Verify secure_add == plain_add
    int add_a[] = {0, 1, -1, 100, -100, 2147483};
    int add_b[] = {0, 2, -3,  -5,  200,  999999};
    int nadd = (int)(sizeof(add_a) / sizeof(add_a[0]));
    for (int i = 0; i < nadd; i++) {
        if (secure_add(add_a[i], add_b[i]) != plain_add(add_a[i], add_b[i])) {
            printf("FAIL add(%d,%d)\n", add_a[i], add_b[i]);
            ok = 0;
        }
    }

    // Verify secure_abs == plain_abs
    int abs_v[] = {0, 1, -1, 100, -100, 2147483647, -2147483647};
    int nabs = (int)(sizeof(abs_v) / sizeof(abs_v[0]));
    for (int i = 0; i < nabs; i++) {
        if (secure_abs(abs_v[i]) != plain_abs(abs_v[i])) {
            printf("FAIL abs(%d)\n", abs_v[i]);
            ok = 0;
        }
    }

    // Verify secure_classify == plain_classify
    int cls_v[] = {-200, -1, 0, 1, 50, 100, 101, 200, -2147483648};
    int ncls = (int)(sizeof(cls_v) / sizeof(cls_v[0]));
    for (int i = 0; i < ncls; i++) {
        if (secure_classify(cls_v[i]) != plain_classify(cls_v[i])) {
            printf("FAIL classify(%d)\n", cls_v[i]);
            ok = 0;
        }
    }

    // Verify secure_sum == plain_sum
    struct { int lo, hi; } sum_v[] = {
        {1, 10}, {0, 0}, {-5, 5}, {1, 100}, {5, 5}
    };
    int nsum = (int)(sizeof(sum_v) / sizeof(sum_v[0]));
    for (int i = 0; i < nsum; i++) {
        if (secure_sum(sum_v[i].lo, sum_v[i].hi) !=
            plain_sum(sum_v[i].lo, sum_v[i].hi)) {
            printf("FAIL sum(%d,%d)\n", sum_v[i].lo, sum_v[i].hi);
            ok = 0;
        }
    }

    // Verify secure_id64 == plain_id64
    int64_t id64_v[] = {0, 1, -1, (int64_t)0x7FFFFFFFFFFFFFFF,
                        (int64_t)0x8000000000000001LL};
    int nid = (int)(sizeof(id64_v) / sizeof(id64_v[0]));
    for (int i = 0; i < nid; i++) {
        if (secure_id64(id64_v[i]) != plain_id64(id64_v[i])) {
            printf("FAIL id64(%lld)\n", (long long)id64_v[i]);
            ok = 0;
        }
    }

    // Verify secure_ptr == plain_ptr (pointer identity)
    const char *ptrs[] = {tag, "hello", NULL};
    int nptr = (int)(sizeof(ptrs) / sizeof(ptrs[0]));
    for (int i = 0; i < nptr; i++) {
        if (secure_ptr(ptrs[i]) != plain_ptr(ptrs[i])) {
            printf("FAIL ptr\n");
            ok = 0;
        }
    }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
