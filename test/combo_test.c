// ArmorComp — Full Pass Compatibility Test
//
// Tests that ALL 33 passes can be applied simultaneously without crashing
// or producing incorrect runtime results.
//
// Two test functions:
//
//   1. all_passes_combo() — every NON-VMP pass (29 function-level + 3 module)
//      Exercises: loops, switch, conditions, struct fields, pointers, globals,
//      function calls, arithmetic — giving every pass something to transform.
//
//   2. vmp_combo() — VMP + all AArch64 passes (8 annotations)
//      Tests musttail thunk compatibility with SPO/RAO/DPOISON/LRO/FSIG/NTC/RVO.
//
// Expected stderr should show all passes processing these functions.
// Expected stdout ends with: ALL TESTS PASSED

#include <stdio.h>
#include <stdint.h>

// ── Globals for module-level passes ──────────────────────────────────────────

// GENC encrypts this integer global; STRENC encrypts string constants
static int g_combo_val = 42;

// Function pointer global for GPO encryption
typedef int (*combo_fn_t)(int, int);

// ── Helper functions (NOT annotated — these are callees) ─────────────────────

int combo_helper_add(int x, int y) { return x + y; }
int combo_helper_mul(int x, int y) { return x * y; }

// Function pointer target (GPO encrypts this)
static combo_fn_t g_combo_fn = combo_helper_add;

// ── Struct for GEP (GEPO) ───────────────────────────────────────────────────

typedef struct { int a; int b; int c; } Triple;

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: ALL non-VMP passes (32 annotations)
//
// Pipeline processes this function in order:
//   STRENC (module) → GENC (module) → GPO (module) →
//   SOB → SPLIT → SUB → MBA → LOB → COB → DENC → PXOR → JCI → FAPI →
//   CO → GEPO → DF → OUTLINE → BCF → OP → CFF → ASP → RAO → ICALL →
//   IBR → IGV → FW → FSIG → SPO → NTC → RVO → LRO → DPOISON
// ─────────────────────────────────────────────────────────────────────────────
__attribute__((
    annotate("cff"),     // Control Flow Flattening
    annotate("bcf"),     // Bogus Control Flow
    annotate("mba"),     // Mixed Boolean-Arithmetic
    annotate("sub"),     // Instruction Substitution
    annotate("split"),   // Basic Block Splitting
    annotate("sob"),     // Switch Obfuscation
    annotate("lob"),     // Loop Obfuscation
    annotate("cob"),     // Condition Obfuscation
    annotate("denc"),    // Data Encoding (integer allocas)
    annotate("pxor"),    // Pointer XOR (pointer allocas)
    annotate("jci"),     // Junk Code Injection
    annotate("fapi"),    // Fake API Calls
    annotate("co"),      // Constant Obfuscation
    annotate("gepo"),    // GEP Obfuscation
    annotate("df"),      // Data Flow Flattening
    annotate("outline"), // BB Outlining
    annotate("op"),      // Opaque Predicates
    annotate("asp"),     // Arithmetic State (post-CFF)
    annotate("rao"),     // Return Address Obfuscation (AArch64)
    annotate("icall"),   // Indirect Call
    annotate("ibr"),     // Indirect Branch
    annotate("igv"),     // Indirect Global Variable
    annotate("fw"),      // Function Wrapper
    annotate("fsig"),    // Function Signature (AArch64)
    annotate("spo"),     // Stack Pointer Obfuscation (AArch64)
    annotate("ntc"),     // NEON Type Confusion (AArch64)
    annotate("rvo"),     // Return Value XOR (AArch64)
    annotate("lro"),     // Link Register Obfuscation (AArch64)
    annotate("dpoison"), // DWARF CFI Poison (AArch64)
    annotate("strenc"),  // String Encryption (module)
    annotate("genc"),    // Global Encryption (module)
    annotate("gpo")      // Global Pointer Obfuscation (module)
))
int all_passes_combo(int a, int b) {
    int sum = 0;
    int i;

    // ── Loop: exercises LOB (loop header junk), BCF (bogus branches) ──
    for (i = 0; i < (a & 0xF); i++) {
        sum += i * 2 + 1;   // SUB transforms add/mul; MBA transforms bitwise ops
    }

    // ── Switch: exercises SOB (jump-table + indirectbr) ──────────────
    switch (b & 3) {
    case 0: sum += 10; break;
    case 1: sum += 20; break;
    case 2: sum += 30; break;
    default: sum += b; break;
    }

    // ── Condition: exercises COB, BCF ───────────────────────────────
    if (sum > 50) {
        sum = sum - 10;
    } else {
        sum = sum + 5;
    }

    // ── Second condition: more BBs for SPLIT, OUTLINE ────────────────
    if ((sum & 1) == 0) {
        sum = (sum >> 1) + b;
    } else {
        sum = (sum * 3) + 1;
    }

    // ── Struct field access: exercises GEPO ──────────────────────────
    Triple t;
    t.a = sum;
    t.b = b;
    t.c = t.a + t.b;
    sum = t.c;

    // ── Pointer usage: exercises PXOR ───────────────────────────────
    int val = 100;
    int *p = &val;
    *p = sum + g_combo_val;   // IGV accesses global; CO obfuscates constants
    sum = *p;

    // ── Direct function call: FW wraps, then ICALL makes indirect ────
    sum = combo_helper_add(sum, b);

    // ── Function pointer call: GPO encrypts g_combo_fn ──────────────
    sum = g_combo_fn(sum, 1);

    // ── String constant: STRENC encrypts this literal ────────────────
    // Manual strlen avoids vararg printf / library call issues
    const char *s = "ArmorComp-Combo-Test";
    int slen = 0;
    while (s[slen]) slen++;
    sum += slen;   // 20 chars

    return sum;   // RVO XOR-obfuscates return value
}

// ── Plain reference (no annotations) ────────────────────────────────────────
int plain_all_passes_combo(int a, int b) {
    int sum = 0;
    int i;

    for (i = 0; i < (a & 0xF); i++) {
        sum += i * 2 + 1;
    }

    switch (b & 3) {
    case 0: sum += 10; break;
    case 1: sum += 20; break;
    case 2: sum += 30; break;
    default: sum += b; break;
    }

    if (sum > 50) {
        sum = sum - 10;
    } else {
        sum = sum + 5;
    }

    if ((sum & 1) == 0) {
        sum = (sum >> 1) + b;
    } else {
        sum = (sum * 3) + 1;
    }

    Triple t;
    t.a = sum;
    t.b = b;
    t.c = t.a + t.b;
    sum = t.c;

    int val = 100;
    int *p = &val;
    *p = sum + g_combo_val;
    sum = *p;

    sum = combo_helper_add(sum, b);
    sum = g_combo_fn(sum, 1);

    const char *s = "ArmorComp-Combo-Test";
    int slen = 0;
    while (s[slen]) slen++;
    sum += slen;

    return sum;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: VMP + all AArch64 passes (8 annotations)
//
// VMP runs first → replaces function with musttail thunk + dispatcher.
// SPO/RAO/DPOISON have musttail guards → skip thunk ret (safe).
// VMP dispatcher auto-gets SUB + MBA annotations.
// ─────────────────────────────────────────────────────────────────────────────
__attribute__((
    annotate("vmp"),      // Virtual Machine Protection
    annotate("spo"),      // Stack Pointer Obfuscation (AArch64)
    annotate("rao"),      // Return Address Obfuscation (AArch64)
    annotate("dpoison"),  // DWARF CFI Poison (AArch64)
    annotate("rvo"),      // Return Value XOR
    annotate("lro"),      // Link Register Obfuscation (AArch64)
    annotate("fsig"),     // Function Signature (AArch64)
    annotate("ntc")       // NEON Type Confusion (AArch64)
))
int vmp_combo(int a, int b) {
    int sum = 0;
    int i;

    // Loop
    for (i = 0; i < (a & 0xF); i++)
        sum += i;

    // Condition
    if (sum > 50) sum = sum / 2;
    else          sum = sum * 3;

    return sum + b;
}

int plain_vmp_combo(int a, int b) {
    int sum = 0;
    int i;
    for (i = 0; i < (a & 0xF); i++)
        sum += i;
    if (sum > 50) sum = sum / 2;
    else          sum = sum * 3;
    return sum + b;
}

// ── Main ────────────────────────────────────────────────────────────────────

int main(void) {
    int ok = 1;

    // ── Test all_passes_combo vs plain ──────────────────────────────────
    printf("=== All-Pass Combo (32 annotations) ===\n");
    {
        int cases[][2] = {
            {0, 0}, {1, 1}, {5, 2}, {10, 3}, {15, 0},
            {-1, -1}, {100, 1}, {255, 3}, {7, 2},
        };
        int n = (int)(sizeof(cases)/sizeof(cases[0]));
        for (int i = 0; i < n; i++) {
            int a = cases[i][0], b = cases[i][1];
            int got = all_passes_combo(a, b);
            int exp = plain_all_passes_combo(a, b);
            printf("  combo(%d, %d) = %d (exp %d) %s\n",
                   a, b, got, exp, got == exp ? "OK" : "FAIL");
            if (got != exp) ok = 0;
        }
    }

    // ── Test vmp_combo vs plain ─────────────────────────────────────────
    printf("=== VMP Combo (VMP + 7 AArch64 passes) ===\n");
    {
        int cases[][2] = {
            {0, 0}, {1, 5}, {5, 10}, {10, -3}, {15, 0},
            {-1, 100}, {100, -50}, {255, 42}, {7, 7},
        };
        int n = (int)(sizeof(cases)/sizeof(cases[0]));
        for (int i = 0; i < n; i++) {
            int a = cases[i][0], b = cases[i][1];
            int got = vmp_combo(a, b);
            int exp = plain_vmp_combo(a, b);
            printf("  vmp_combo(%d, %d) = %d (exp %d) %s\n",
                   a, b, got, exp, got == exp ? "OK" : "FAIL");
            if (got != exp) ok = 0;
        }
    }

    if (ok) printf("ALL TESTS PASSED\n");
    else    printf("SOME TESTS FAILED\n");
    return ok ? 0 : 1;
}
