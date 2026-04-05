// ArmorComp — YAML config file validation test
//
// Tests config-driven obfuscation WITHOUT any __attribute__((annotate(...))).
// Pass selection is entirely driven by config_test.yaml.
//
// config_test.yaml selects config_classify for: cff, bcf, igv, spo
// config_plain is NOT selected by any rule (baseline / control).
//
// Expected stderr (ArmorComp log):
//   [ArmorComp][Config] loaded 3 rule(s) from "config_test.yaml"
//   [ArmorComp][BCF] obfuscated: config_classify
//   [ArmorComp][CFF] flattened:  config_classify
//   [ArmorComp][IGV] indirected: config_classify (N accesses, M globals)
//   [ArmorComp][SPO] obfuscated: config_classify (1 ret(s))
//   (NO messages for config_plain — not covered by any rule)
//
// Verification (host, requires llvm-objdump):
//   llvm-objdump -d config_test_aarch64 | awk '/<config_classify>/{p=1}p{print; if(/ret/)exit}'
//   → should show indirect branch pattern (br x8 / no b.lt / b.gt)
//   → should show proxy-load pattern for any global variable accesses
//
//   llvm-objdump -d config_test_aarch64 | awk '/<config_plain>/{p=1}p{print; if(/ret/)exit}'
//   → should show direct branch pattern (b.lt / b.gt / cbnz)
//
// Expected stdout:
//   config_classify(-5) = -1
//   config_classify(0)  =  0
//   config_classify(3)  =  1
//   ALL TESTS PASSED

#include <stdio.h>

// config_classify: selected by config rule (name: "config_classify")
// No source annotation — obfuscation applied via YAML config only.
int config_classify(int x) {
    if (x < 0) return -1;
    if (x > 0) return  1;
    return 0;
}

// config_plain: NOT selected by any config rule (baseline / control)
int config_plain(int x) {
    if (x < 0) return -1;
    if (x > 0) return  1;
    return 0;
}

int main(void) {
    printf("config_classify(-5) = %d\n", config_classify(-5));
    printf("config_classify(0)  = %d\n", config_classify(0));
    printf("config_classify(3)  = %d\n", config_classify(3));

    int ok = 1;
    if (config_classify(-5) != -1) { printf("FAIL: config_classify(-5)\n"); ok = 0; }
    if (config_classify( 0) !=  0) { printf("FAIL: config_classify(0)\n");  ok = 0; }
    if (config_classify( 3) !=  1) { printf("FAIL: config_classify(3)\n");  ok = 0; }

    // Sanity: plain version must give same results
    if (config_plain(-5) != -1) { printf("FAIL: config_plain(-5)\n"); ok = 0; }
    if (config_plain( 0) !=  0) { printf("FAIL: config_plain(0)\n");  ok = 0; }
    if (config_plain( 3) !=  1) { printf("FAIL: config_plain(3)\n");  ok = 0; }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
