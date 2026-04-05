// ArmorComp — PointerXorPass (PXOR) validation test
//
// PointerXorPass XOR-encodes pointer-typed alloca slots:
//   store: ptrtoint(%val) XOR K → inttoptr → store into alloca
//   load:  load from alloca → ptrtoint → XOR K → inttoptr → result
//
// K = xorshift64(FNV1a(fn_name + "_pxor_" + alloca_index))
//
// Expected stderr:
//   [ArmorComp][PXOR] encoded: secure_ptr_ops (N pointer alloca(s))
//   (no message for plain_ptr_ops — not annotated)
//
// Verification (AArch64 disasm):
//   llvm-objdump -d pxor_test_aarch64 | grep -A40 "<secure_ptr_ops>"
//   → pointer stores should be preceded by an eor instruction (encode)
//   → pointer loads should be followed by an eor instruction (decode)
//
// Expected stdout:
//   sum via ptr  = 55
//   chain result = 6
//   ALL TESTS PASSED

#include <stdio.h>
#include <stdlib.h>

// ── Annotated functions ────────────────────────────────────────────────────

// Uses a pointer local to iterate through an array
__attribute__((annotate("pxor")))
int secure_ptr_ops(int *arr, int n) {
    int *p = arr;      // ptr alloca (p is stored on stack, XOR-encoded)
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += *p;
        p++;           // pointer arithmetic on XOR-encoded stack slot
    }
    return sum;
}

// Pointer swapping — tests store and load on pointer allocas
__attribute__((annotate("pxor")))
int secure_ptr_swap(int *a, int *b) {
    int *tmp = a;    // ptr alloca tmp is XOR-encoded
    a = b;           // ptr alloca a  is XOR-encoded
    b = tmp;         // ptr alloca b  is XOR-encoded (after swap)
    return *a + *b;  // loads from XOR-encoded ptrs → decode → deref
}

// ── Plain reference implementations ────────────────────────────────────────

int plain_ptr_ops(int *arr, int n) {
    int *p = arr;
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += *p;
        p++;
    }
    return sum;
}

int plain_ptr_swap(int *a, int *b) {
    int *tmp = a;
    a = b;
    b = tmp;
    return *a + *b;
}

// ── Main ────────────────────────────────────────────────────────────────────

int main(void) {
    int arr[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    int n = 10;

    int s_sum = secure_ptr_ops(arr, n);
    int p_sum = plain_ptr_ops(arr, n);
    printf("sum via ptr  = %d\n", s_sum);   // should be 55

    int x = 2, y = 4;
    int s_sw = secure_ptr_swap(&x, &y);
    int ax = 2, ay = 4;
    int p_sw = plain_ptr_swap(&ax, &ay);
    printf("chain result = %d\n", s_sw);    // 2+4=6

    int ok = 1;
    if (s_sum != 55) { printf("FAIL sum: got %d\n", s_sum); ok = 0; }
    if (s_sum != p_sum) { printf("FAIL sum mismatch: s=%d p=%d\n", s_sum, p_sum); ok = 0; }
    if (s_sw != 6) { printf("FAIL swap: got %d\n", s_sw); ok = 0; }
    if (s_sw != p_sw) { printf("FAIL swap mismatch: s=%d p=%d\n", s_sw, p_sw); ok = 0; }

    // Larger stress test
    int big[100];
    for (int i = 0; i < 100; i++) big[i] = i;
    int expected = 4950; // 0+1+...+99
    int got_s = secure_ptr_ops(big, 100);
    int got_p = plain_ptr_ops(big, 100);
    if (got_s != expected) { printf("FAIL big sum: got %d\n", got_s); ok = 0; }
    if (got_s != got_p) { printf("FAIL big mismatch: s=%d p=%d\n", got_s, got_p); ok = 0; }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
