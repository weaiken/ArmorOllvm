// ArmorComp — IndirectGlobalVariable pass validation test
//
// Tests:
//   get_stats_igv()  — annotate("igv"): load and store to multiple global vars;
//                      all GV operands become volatile proxy-pointer loads.
//   get_stats_plain()— no annotation: direct GV accesses (control).
//
// Expected stderr (ArmorComp log):
//   [ArmorComp][IGV] indirected: get_stats_igv (N accesses, M globals)
//
// Verification (host, requires llvm-objdump):
//   llvm-objdump -d igv_test_aarch64 | awk '/<get_stats_igv>/{p=1}p{print; if(/ret/)exit}'
//   → should access __armorcomp_igv_g_counter / __armorcomp_igv_g_total via
//     a double-dereference (load ptr, then load/store i32), NOT a direct adrp+ldr.
//
//   llvm-objdump -d igv_test_aarch64 | awk '/<get_stats_plain>/{p=1}p{print; if(/ret/)exit}'
//   → should access g_counter / g_total directly (single adrp+ldr/str sequence).
//
// Expected stdout:
//   [igv] counter=3 total=6
//   [plain] counter=3 total=6
//   ALL TESTS PASSED

#include <stdio.h>

// Globals that will be proxied by IGV
int g_counter = 0;
int g_total   = 0;

// get_stats_igv: all accesses to g_counter and g_total become indirect.
__attribute__((annotate("igv")))
void get_stats_igv(int v) {
    g_counter++;           // store to g_counter → proxy load + indirect store
    g_total += v;          // load+store g_total  → proxy load + indirect load/store
}

// get_stats_plain: direct access (no annotation, no proxy)
void get_stats_plain(int v) {
    g_counter++;
    g_total += v;
}

int main(void) {
    // Reset globals
    g_counter = 0;
    g_total   = 0;

    // Call igv-protected version 3 times
    get_stats_igv(1);
    get_stats_igv(2);
    get_stats_igv(3);
    printf("[igv] counter=%d total=%d\n", g_counter, g_total);

    // Reset and call plain version for same result
    g_counter = 0;
    g_total   = 0;
    get_stats_plain(1);
    get_stats_plain(2);
    get_stats_plain(3);
    printf("[plain] counter=%d total=%d\n", g_counter, g_total);

    // Verify both produce the same result
    int ok = 1;
    if (g_counter != 3) { printf("FAIL: counter=%d expected 3\n", g_counter); ok=0; }
    if (g_total   != 6) { printf("FAIL: total=%d expected 6\n",   g_total);   ok=0; }

    // Re-run igv version and compare
    g_counter = 0; g_total = 0;
    get_stats_igv(1); get_stats_igv(2); get_stats_igv(3);
    if (g_counter != 3) { printf("FAIL: igv counter=%d\n", g_counter); ok=0; }
    if (g_total   != 6) { printf("FAIL: igv total=%d\n",   g_total);   ok=0; }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
