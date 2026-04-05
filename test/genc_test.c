// ArmorComp — GlobalEncPass (GENC) validation test
//
// GlobalEncPass XOR-encrypts the ConstantInt initializer of each integer
// global variable used by annotate("genc") functions.  A generated
// __armorcomp_genc_init constructor decrypts them at program startup.
//
// Key derivation (per GV, deterministic):
//   K = xorshift64(FNV1a(gv_name)) & type_mask     (never zero)
//   stored_initializer = original ^ K
//   ctor: volatile_load ^ K → store (restores original)
//
// Expected stderr (ArmorComp log):
//   [ArmorComp][GENC] encrypted: g_key   (i32, key=0x...)
//   [ArmorComp][GENC] encrypted: g_magic (i64, key=0x...)
//   [ArmorComp][GENC] injected constructor: __armorcomp_genc_init (2 global(s))
//   (no message for g_plain — not referenced by any annotate("genc") function)
//
// Verification (host):
//   llvm-objdump -d genc_test_aarch64 | grep -A30 "<__armorcomp_genc_init>"
//     → should show: ldr (volatile), eor (key), str pattern for g_key and g_magic
//
//   llvm-objdump -s --section=.data genc_test_aarch64
//     → bytes for g_key and g_magic differ from the C source values below
//     → g_plain is NOT in the list (remains in .rodata or shows original value)
//
// Expected stdout:
//   verify_key(1000)  = 1
//   verify_key(9999)  = 0
//   read_magic()      = 3735928559
//   plain_value()     = 42
//   ALL TESTS PASSED

#include <stdio.h>
#include <stdint.h>

// ── Globals that should be encrypted (used by annotate("genc") functions) ─────

// i32 global: license key threshold
static int g_key = 1234;

// i64 global: magic constant (0xDEADBEEF = 3735928559)
static long long g_magic = 3735928559LL;

// ── Global that must NOT be encrypted (used only by plain function) ─────────

// i32 global: a plain constant (no annotation on using function)
static int g_plain = 42;

// ── Annotated functions ──────────────────────────────────────────────────────

// verify_key: uses g_key — should be encrypted in binary.
__attribute__((annotate("genc")))
int verify_key(int input) {
    return input >= g_key ? 1 : 0;
}

// read_magic: uses g_magic — should be encrypted in binary.
__attribute__((annotate("genc")))
long long read_magic(void) {
    return g_magic;
}

// ── Plain reference implementations (no annotation) ─────────────────────────

// plain_value: uses g_plain — g_plain must NOT be encrypted.
int plain_value(void) {
    return g_plain;
}

// ── Main ─────────────────────────────────────────────────────────────────────

int main(void) {
    // Print values for visual inspection
    printf("verify_key(1000)  = %d\n", verify_key(1000));   // 0: 1000 < 1234
    printf("verify_key(9999)  = %d\n", verify_key(9999));   // 1: 9999 >= 1234
    printf("read_magic()      = %lld\n", read_magic());     // 3735928559
    printf("plain_value()     = %d\n", plain_value());      // 42

    int ok = 1;

    // verify_key must return 0 for inputs below g_key (1234)
    int below[] = { 0, 1, 100, 500, 1000, 1233 };
    for (int i = 0; i < (int)(sizeof(below)/sizeof(below[0])); i++) {
        if (verify_key(below[i]) != 0) {
            printf("FAIL verify_key(%d): expected 0, got %d\n",
                   below[i], verify_key(below[i]));
            ok = 0;
        }
    }

    // verify_key must return 1 for inputs at or above g_key (1234)
    int above[] = { 1234, 1235, 5000, 9999, 100000 };
    for (int i = 0; i < (int)(sizeof(above)/sizeof(above[0])); i++) {
        if (verify_key(above[i]) != 1) {
            printf("FAIL verify_key(%d): expected 1, got %d\n",
                   above[i], verify_key(above[i]));
            ok = 0;
        }
    }

    // read_magic must return the original g_magic value (not the ciphertext)
    if (read_magic() != 3735928559LL) {
        printf("FAIL read_magic(): expected 3735928559, got %lld\n",
               read_magic());
        ok = 0;
    }

    // plain_value must still return 42 (g_plain is not encrypted)
    if (plain_value() != 42) {
        printf("FAIL plain_value(): expected 42, got %d\n", plain_value());
        ok = 0;
    }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
