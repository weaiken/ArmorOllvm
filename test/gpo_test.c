// ArmorComp — GlobalPointerObfuscationPass (GPO) validation test
//
// GlobalPointerObfuscationPass encrypts function-pointer globals:
//   - @fn_ptr_global initializer → null  (in binary)
//   - @__armorcomp_gpo_enc_N = ptrtoint(@target_fn) XOR K  (companion global)
//   - __armorcomp_gpo_init ctor: load enc → xor K → inttoptr → store to @fn_ptr_global
//
// The ctor runs before main() via @llvm.global_ctors.
//
// Expected stderr:
//   [ArmorComp][GPO] encrypted: N function pointer global(s)
//   (only when any function in the module has annotate("gpo"))
//
// Verification (AArch64 disasm):
//   llvm-objdump -d gpo_test_aarch64 | grep "__armorcomp_gpo"
//   → should show encrypted companion globals and the ctor function
//   readelf -S gpo_test_aarch64 | grep ".data"
//   → @compute_fn, @process_fn land in .data as null, decoded by ctor
//
// Expected stdout:
//   result1 = 12
//   result2 = 20
//   via ptr  = 7
//   ALL TESTS PASSED

#include <stdio.h>

// ── Function pointer globals (targeted by GPO) ────────────────────────────

typedef int (*compute_fn_t)(int, int);

static int add_fn(int a, int b) { return a + b; }
static int mul_fn(int a, int b) { return a * b; }
static int sub_fn(int a, int b) { return a - b; }

// These globals are encrypted by GPO: initializer → null in binary,
// decoded by the generated ctor at startup.
compute_fn_t compute_fn  = add_fn;
compute_fn_t process_fn  = mul_fn;
compute_fn_t transform_fn = sub_fn;

// ── Annotated function — triggers GPO for this module ─────────────────────

// annotate("gpo") on any function triggers GPO encryption for the whole module.
__attribute__((annotate("gpo")))
int secure_dispatch(int x, int y) {
    return compute_fn(x, y);   // uses global function pointer
}

__attribute__((annotate("gpo")))
int secure_process(int x, int y) {
    return process_fn(x, y);
}

// ── Plain function (no annotation, still uses the globals) ─────────────────

int plain_via_ptr(int x, int y) {
    return transform_fn(x, y);
}

// ── Main ────────────────────────────────────────────────────────────────────

int main(void) {
    // After GPO ctor: compute_fn = add_fn, process_fn = mul_fn, transform_fn = sub_fn
    int r1 = secure_dispatch(5, 7);     // add: 5+7=12
    int r2 = secure_process(4, 5);      // mul: 4*5=20
    int r3 = plain_via_ptr(10, 3);      // sub: 10-3=7

    printf("result1 = %d\n", r1);       // 12
    printf("result2 = %d\n", r2);       // 20
    printf("via ptr  = %d\n", r3);      //  7

    int ok = 1;
    if (r1 != 12) { printf("FAIL dispatch: %d != 12\n", r1); ok = 0; }
    if (r2 != 20) { printf("FAIL process: %d != 20\n", r2); ok = 0; }
    if (r3 !=  7) { printf("FAIL plain:   %d != 7\n",  r3); ok = 0; }

    // Verify the function pointers still work after GPO decode
    if (compute_fn(3, 4) != 7)   { printf("FAIL fn ptr add\n");  ok = 0; }
    if (process_fn(3, 4) != 12)  { printf("FAIL fn ptr mul\n");  ok = 0; }
    if (transform_fn(7, 3) != 4) { printf("FAIL fn ptr sub\n");  ok = 0; }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
