// ArmorComp — GEPObfPass (GEPO) validation test
//
// GEPObfPass converts constant-offset GEPs to raw i8-pointer byte-offset GEPs
// using DataLayout to fold all indices into a single signed byte offset, then
// XOR-obfuscates that offset with a volatile-zero load:
//
//   Original: getelementptr %S, ptr base, i64 0, i32 K  (struct field K)
//   → byte_offset = DataLayout::getOffset(field K in %S)
//   → %gepo.zero = load volatile i64, @__armorcomp_gepo_zero
//   → %gepo.off  = xor i64 byte_offset, %gepo.zero
//   → %gepo.ptr  = getelementptr i8, ptr base, i64 %gepo.off
//
// WHY i8 GEP (not per-index XOR)?
//   LLVM requires struct field indices to be ConstantInt; per-index XOR would
//   create non-constant struct indices and crash IRTranslator.  The i8 byte-
//   offset approach is legal and achieves the same IDA confusion effect.
//
// IDA Pro analysis effect:
//   Without GEPO:  ldr w0, [x0, #4]  → IDA: struct field at byte offset 4
//   With GEPO:     adr x9, gepo_zero
//                  ldr x10, [x9]         ; volatile load = 0
//                  mov x9, #4            ; byte offset constant
//                  eor x9, x9, x10       ; 4 XOR 0 = 4 at runtime
//                  ldr w0, [x8, x9]      ; IDA: unknown offset → struct recovery fails
//
// Expected stderr (one line per obfuscated function):
//   [ArmorComp][GEPO] obfuscated: get_field_b    (N GEP(s))
//   [ArmorComp][GEPO] obfuscated: get_nested     (N GEP(s))
//   [ArmorComp][GEPO] obfuscated: array_elem     (N GEP(s))
//   [ArmorComp][GEPO] obfuscated: multi_field    (N GEP(s))
//   [ArmorComp][GEPO] obfuscated: mixed_access   (N GEP(s))
//   (no message for plain_* or non-annotated functions)
//
// Disassembly verification:
//   llvm-objdump -d gepo_test_aarch64 | grep -A15 "<get_field_b>"
//   Should show (field b at byte offset 4 in Simple):
//     mov  x9, #4                        ; byte offset of Simple.b
//     eor  x9, x9, x10                   ; 4 XOR 0 = 4 at runtime; IDA can't fold
//     ldr  w0, [x8, x9]                  ; struct access — offset unknown to IDA
//   plain_get_field_b should show:
//     ldr  w0, [x8, #0x4]                ; direct constant offset visible to IDA
//
//   array_elem shows byte offset 12 (= arr[3] = 3 * sizeof(int)):
//     mov  x9, #0xc                      ; 3 * 4 = 12
//     eor  x9, x9, x10
//
// Expected stdout ends with:
//   ALL TESTS PASSED

#include <stdio.h>
#include <stdint.h>
#include <string.h>

// ── Test data structures ─────────────────────────────────────────────────────

// Simple struct: tests field access via constant GEP indices.
typedef struct {
    int  a;     // offset 0
    int  b;     // offset 4
    int  c;     // offset 8
    long d;     // offset 16 (after alignment padding)
} Simple;

// Nested struct: tests multi-level GEP with nested constant indices.
typedef struct {
    int  x;
    Simple inner;  // inner.b is at base+offsetof(inner)+4
} Nested;

// Pair struct for testing two-field return.
typedef struct {
    int lo;
    int hi;
} Pair;

// ── Annotated functions (GEPObfPass applied) ──────────────────────────────────

// Single struct field access: produces 1 GEP with constant field index.
__attribute__((annotate("gepo")))
int get_field_b(const Simple *s) {
    return s->b;   // GEP: [i64 0, i32 1] — field index 1 obfuscated
}

// Nested struct field access: two-level GEP.
__attribute__((annotate("gepo")))
int get_nested(const Nested *n) {
    return n->inner.c;  // GEP: [i64 0, i32 1] → inner; [i64 0, i32 2] → inner.c
}

// Fixed array element with constant index: tests array GEP.
// arr[3] → getelementptr T, ptr arr, i64 3  (non-zero first index obfuscated)
__attribute__((annotate("gepo")))
int array_elem(const int arr[10]) {
    return arr[3];  // GEP: [i64 3] — first index is non-zero → obfuscated
}

// Multiple field accesses in one function: tests that each GEP is processed.
__attribute__((annotate("gepo")))
Pair multi_field(const Simple *s) {
    Pair p;
    p.lo = s->a;   // GEP: field index 0 (skipped if outer 0, but inner is i32 0)
    p.hi = s->c;   // GEP: field index 2 — obfuscated
    return p;
}

// Mix of struct access and arithmetic: tests that only GEP indices change.
__attribute__((annotate("gepo")))
long mixed_access(const Simple *s, int k) {
    // s->d is at a non-zero field index → obfuscated GEP
    // The arithmetic on the result is normal
    return s->d + k * 2L;
}

// ── Plain reference implementations (no annotation) ──────────────────────────

int plain_get_field_b(const Simple *s) { return s->b; }

int plain_get_nested(const Nested *n) { return n->inner.c; }

int plain_array_elem(const int arr[10]) { return arr[3]; }

Pair plain_multi_field(const Simple *s) {
    Pair p;
    p.lo = s->a;
    p.hi = s->c;
    return p;
}

long plain_mixed_access(const Simple *s, int k) {
    return s->d + k * 2L;
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main(void) {
    // Set up test data
    Simple s = { 10, 20, 30, 40LL };
    Nested n;
    n.x = 1;
    n.inner = s;

    int arr[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

    // Print representative samples
    printf("get_field_b(s)          = %d\n",  get_field_b(&s));     // 20
    printf("plain_get_field_b(s)    = %d\n",  plain_get_field_b(&s)); // 20
    printf("get_nested(n)           = %d\n",  get_nested(&n));       // 30
    printf("plain_get_nested(n)     = %d\n",  plain_get_nested(&n)); // 30
    printf("array_elem(arr)         = %d\n",  array_elem(arr));      // 3
    printf("plain_array_elem(arr)   = %d\n",  plain_array_elem(arr)); // 3
    {
        Pair p = multi_field(&s);
        printf("multi_field(s)          = {%d, %d}\n",  p.lo, p.hi); // {10, 30}
    }
    {
        Pair p = plain_multi_field(&s);
        printf("plain_multi_field(s)    = {%d, %d}\n",  p.lo, p.hi); // {10, 30}
    }
    printf("mixed_access(s, 5)      = %ld\n", mixed_access(&s, 5));        // 50
    printf("plain_mixed_access(s,5) = %ld\n", plain_mixed_access(&s, 5)); // 50

    int ok = 1;

    // ── Verify get_field_b == plain_get_field_b ────────────────────────────
    Simple sv[] = {
        {0,  0,  0,  0},
        {1,  2,  3,  4},
        {-1, -2, -3, -4},
        {2147483647, -2147483648, 100, 200},
    };
    int nsv = (int)(sizeof(sv) / sizeof(sv[0]));
    for (int i = 0; i < nsv; i++) {
        if (get_field_b(&sv[i]) != plain_get_field_b(&sv[i])) {
            printf("FAIL get_field_b[%d]\n", i);
            ok = 0;
        }
    }

    // ── Verify get_nested == plain_get_nested ──────────────────────────────
    for (int i = 0; i < nsv; i++) {
        Nested nv;
        nv.x = i;
        nv.inner = sv[i];
        if (get_nested(&nv) != plain_get_nested(&nv)) {
            printf("FAIL get_nested[%d]\n", i);
            ok = 0;
        }
    }

    // ── Verify array_elem == plain_array_elem ──────────────────────────────
    int arrs[4][10] = {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
        {-1, -2, -3, -4, -5, -6, -7, -8, -9, -10},
        {2147483647, 100, 200, -2147483648, 5, 6, 7, 8, 9, 10},
    };
    int narr = (int)(sizeof(arrs) / sizeof(arrs[0]));
    for (int i = 0; i < narr; i++) {
        if (array_elem(arrs[i]) != plain_array_elem(arrs[i])) {
            printf("FAIL array_elem[%d]\n", i);
            ok = 0;
        }
    }

    // ── Verify multi_field == plain_multi_field ────────────────────────────
    for (int i = 0; i < nsv; i++) {
        Pair p1 = multi_field(&sv[i]);
        Pair p2 = plain_multi_field(&sv[i]);
        if (p1.lo != p2.lo || p1.hi != p2.hi) {
            printf("FAIL multi_field[%d]: {%d,%d} vs {%d,%d}\n",
                   i, p1.lo, p1.hi, p2.lo, p2.hi);
            ok = 0;
        }
    }

    // ── Verify mixed_access == plain_mixed_access ──────────────────────────
    int kvals[] = {0, 1, -1, 100, -100, 2147483};
    int nk = (int)(sizeof(kvals) / sizeof(kvals[0]));
    for (int i = 0; i < nsv; i++) {
        for (int j = 0; j < nk; j++) {
            if (mixed_access(&sv[i], kvals[j]) !=
                plain_mixed_access(&sv[i], kvals[j])) {
                printf("FAIL mixed_access[%d][%d]\n", i, j);
                ok = 0;
            }
        }
    }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
