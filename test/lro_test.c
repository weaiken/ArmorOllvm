// ArmorComp — LRObfPass (LRO) validation test
//
// LRObfPass injects inline asm "eor x30, x30, <volatile_zero>" immediately
// before each ReturnInst in annotated AArch64 functions.  At runtime the XOR
// is a no-op (x30 ^ 0 == x30), so all function calls return to the correct
// caller address and all outputs remain correct.
//
// Expected stderr (ArmorComp log, one line per obfuscated function):
//   [ArmorComp][LRO] obfuscated: secure_add     (1 ret(s))
//   [ArmorComp][LRO] obfuscated: secure_classify (1 ret(s))
//   [ArmorComp][LRO] obfuscated: secure_sum     (1 ret(s))
//   [ArmorComp][LRO] obfuscated: secure_id64    (1 ret(s))
//   [ArmorComp][LRO] obfuscated: secure_ptr     (1 ret(s))
//   [ArmorComp][LRO] obfuscated: multi_ret      (1 ret(s))
//   (no message for plain_* — not annotated)
//
// IDA Pro analysis effect on annotated functions (AArch64 binary):
//   Before each ret:
//     ldr  x9, [__armorcomp_lro_zero]   ; volatile load of zero
//     eor  x30, x30, x9                 ; x30 ^= 0  (IDA cannot prove this)
//     ret
//   → IDA cannot determine the return address statically
//   → All caller xrefs from annotated functions become JUMPOUT()
//   → Function boundary detection may fail ("sp-analysis failed")
//   → Stack unwinding: .eh_frame-based sp_delta at ret becomes UNKNOWN
//
// Verification (disassembly check):
//   llvm-objdump -d lro_test_aarch64 | grep -A15 "<secure_add>"
//   Should show:
//     ldr  x9, [...]   ; load lro_zero
//     eor  x30, x30, x9
//     ret
//   plain_add should NOT contain any eor on x30.
//
// Expected stdout:
//   secure_add(3, 4)         =  7
//   secure_add(-5, 2)        = -3
//   plain_add(3, 4)          =  7
//   secure_classify(-5)      = -1
//   secure_classify(0)       =  0
//   secure_classify(5)       =  1
//   secure_sum(1, 10)        = 55
//   plain_sum(1, 10)         = 55
//   secure_id64(42)          = 42
//   plain_id64(42)           = 42
//   secure_ptr(ok)           = ok
//   multi_ret(-1)            = -1
//   multi_ret(0)             =  0
//   multi_ret(7)             =  1
//   ALL TESTS PASSED

#include <stdio.h>
#include <stdint.h>

// ── Annotated functions (LRObfPass applied) ───────────────────────────────────

// Simple arithmetic: single ret — tests basic LRO injection.
__attribute__((annotate("lro")))
int secure_add(int a, int b) {
    return a + b;
}

// Four ret paths: tests that each separate ReturnInst gets its own eor x30.
__attribute__((annotate("lro")))
int secure_classify(int x) {
    if (x < 0)   return -1;
    if (x > 100) return 2;
    if (x == 0)  return 0;
    return 1;
}

// Loop with accumulation: loop body does not contain ret, only the exit does.
// Ensures lro.zero load is inserted only before the single ReturnInst.
__attribute__((annotate("lro")))
int secure_sum(int lo, int hi) {
    int acc = 0;
    for (int i = lo; i <= hi; i++)
        acc += i;
    return acc;
}

// 64-bit integer return: ensures inline asm still receives correct i64 value.
__attribute__((annotate("lro")))
int64_t secure_id64(int64_t x) {
    return x;
}

// Pointer return: tests that LRO works for pointer-returning functions.
// The return VALUE is correct (x0 not touched); only x30 is XOR'd.
__attribute__((annotate("lro")))
const char *secure_ptr(const char *s) {
    return s;
}

// Three-way conditional: produces 3 separate ret paths in LLVM IR at -O0.
// Verifies the pass processes every ReturnInst in the function.
__attribute__((annotate("lro")))
int multi_ret(int x) {
    if (x < 0) return -1;
    if (x > 0) return 1;
    return 0;
}

// ── Plain reference implementations (no annotation) ──────────────────────────

int plain_add(int a, int b) { return a + b; }

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

int plain_multi_ret(int x) {
    if (x < 0) return -1;
    if (x > 0) return 1;
    return 0;
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main(void) {
    // Print representative samples
    printf("secure_add(3, 4)         = %d\n",  secure_add(3, 4));       //  7
    printf("secure_add(-5, 2)        = %d\n",  secure_add(-5, 2));      // -3
    printf("plain_add(3, 4)          = %d\n",  plain_add(3, 4));        //  7
    printf("secure_classify(-5)      = %d\n",  secure_classify(-5));    // -1
    printf("secure_classify(0)       = %d\n",  secure_classify(0));     //  0
    printf("secure_classify(5)       = %d\n",  secure_classify(5));     //  1
    printf("secure_sum(1, 10)        = %d\n",  secure_sum(1, 10));      // 55
    printf("plain_sum(1, 10)         = %d\n",  plain_sum(1, 10));       // 55
    printf("secure_id64(42)          = %lld\n", (long long)secure_id64(42)); // 42
    printf("plain_id64(42)           = %lld\n", (long long)plain_id64(42));  // 42

    static const char tag[] = "ok";
    const char *p = secure_ptr(tag);
    printf("secure_ptr(ok)           = %s\n",  p);                      // ok

    printf("multi_ret(-1)            = %d\n",  multi_ret(-1));          // -1
    printf("multi_ret(0)             = %d\n",  multi_ret(0));           //  0
    printf("multi_ret(7)             = %d\n",  multi_ret(7));           //  1

    int ok = 1;

    // ── Verify secure_add == plain_add ────────────────────────────────────
    int add_a[] = {0, 1, -1, 100, -100, 2147483};
    int add_b[] = {0, 2, -3,  -5,  200,  999999};
    int nadd = (int)(sizeof(add_a) / sizeof(add_a[0]));
    for (int i = 0; i < nadd; i++) {
        if (secure_add(add_a[i], add_b[i]) != plain_add(add_a[i], add_b[i])) {
            printf("FAIL add(%d,%d)\n", add_a[i], add_b[i]);
            ok = 0;
        }
    }

    // ── Verify secure_classify == plain_classify ──────────────────────────
    int cls_v[] = {-200, -1, 0, 1, 50, 100, 101, 200, -2147483648};
    int ncls = (int)(sizeof(cls_v) / sizeof(cls_v[0]));
    for (int i = 0; i < ncls; i++) {
        if (secure_classify(cls_v[i]) != plain_classify(cls_v[i])) {
            printf("FAIL classify(%d)\n", cls_v[i]);
            ok = 0;
        }
    }

    // ── Verify secure_sum == plain_sum ────────────────────────────────────
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

    // ── Verify secure_id64 == plain_id64 ─────────────────────────────────
    int64_t id64_v[] = {0, 1, -1, (int64_t)0x7FFFFFFFFFFFFFFF,
                        (int64_t)0x8000000000000001LL};
    int nid = (int)(sizeof(id64_v) / sizeof(id64_v[0]));
    for (int i = 0; i < nid; i++) {
        if (secure_id64(id64_v[i]) != plain_id64(id64_v[i])) {
            printf("FAIL id64(%lld)\n", (long long)id64_v[i]);
            ok = 0;
        }
    }

    // ── Verify secure_ptr == plain_ptr (pointer identity) ────────────────
    const char *ptrs[] = {tag, "hello", NULL};
    int nptr = (int)(sizeof(ptrs) / sizeof(ptrs[0]));
    for (int i = 0; i < nptr; i++) {
        if (secure_ptr(ptrs[i]) != plain_ptr(ptrs[i])) {
            printf("FAIL ptr\n");
            ok = 0;
        }
    }

    // ── Verify multi_ret == plain_multi_ret ──────────────────────────────
    int mr_v[] = {-100, -1, 0, 1, 100, -2147483648, 2147483647};
    int nmr = (int)(sizeof(mr_v) / sizeof(mr_v[0]));
    for (int i = 0; i < nmr; i++) {
        if (multi_ret(mr_v[i]) != plain_multi_ret(mr_v[i])) {
            printf("FAIL multi_ret(%d)\n", mr_v[i]);
            ok = 0;
        }
    }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
