// ArmorComp — SwitchObfPass (SOB) validation test
//
// SwitchObfPass replaces every SwitchInst with:
//   dense jump-table + volatile table load + ptrtoint/XOR/inttoptr + indirectbr
// IDA Pro's switch pattern matcher sees "ldr + ldr + eor + br" and cannot
// reconstruct the original switch → all case paths show as JUMPOUT().
//
// Expected stderr (ArmorComp log, one line per obfuscated function):
//   [ArmorComp][SOB] obfuscated: classify_dir   (1 switch)
//   [ArmorComp][SOB] obfuscated: classify_neg   (1 switch)
//   [ArmorComp][SOB] obfuscated: classify_gap   (1 switch)
//   [ArmorComp][SOB] obfuscated: grade           (1 switch)
//   [ArmorComp][SOB] obfuscated: multi_switch    (2 switches)
//   (no message for plain_* — not annotated)
//
// Verification (disassembly check):
//   llvm-objdump -d sob_test_aarch64 | grep -A30 "<classify_dir>"
//   Should show:
//     ldr  x8, [sob_table_0, ...]     ; table load
//     ldr  x9, [__armorcomp_sob_zero] ; volatile zero
//     eor  x8, x8, x9                 ; XOR (IDA cannot constant-fold)
//     br   x8                         ; indirect jump — no switch reconstruction
//
// Expected stdout:
//   classify_dir(0)    = zero
//   classify_dir(1)    = one
//   classify_dir(2)    = two
//   classify_dir(99)   = other
//   classify_neg(-1)   = minus_one
//   classify_neg(0)    = zero
//   classify_neg(1)    = plus_one
//   classify_neg(99)   = far_positive
//   grade(90)          = A
//   grade(80)          = B
//   grade(70)          = C
//   grade(60)          = D
//   grade(50)          = F
//   multi_switch(1,0)  = (1+0)=1
//   multi_switch(2,3)  = (2*3)=6
//   ALL TESTS PASSED

#include <stdio.h>
#include <stdint.h>

// ── String-return helpers (no annotation) ────────────────────────────────────
static const char *str_val(const char *s) { return s; }

// ── Annotated functions (SwitchObfPass applied) ───────────────────────────────

// Basic consecutive switch: cases 0, 1, 2 with default.
// Dense table size = (2 - 0 + 2) = 4 entries.
__attribute__((annotate("sob")))
const char *classify_dir(int x) {
    switch (x) {
        case 0: return "zero";
        case 1: return "one";
        case 2: return "two";
        default: return "other";
    }
}

// Switch with negative and positive cases: -1, 0, 1 and far positive 99.
// The 99 case would make the table huge — but wait, minCase=-1, maxCase=99 → range=100.
// That's fine (≤ 1023), table size = 102 entries.
__attribute__((annotate("sob")))
const char *classify_neg(int x) {
    switch (x) {
        case -1: return "minus_one";
        case  0: return "zero";
        case  1: return "plus_one";
        case 99: return "far_positive";
        default: return "other";
    }
}

// Switch with gaps: cases 0, 2, 4.  Indices 1 and 3 map to default.
// Dense table: [0→case0, 1→default, 2→case2, 3→default, 4→case4, 5→default]
__attribute__((annotate("sob")))
const char *classify_gap(int x) {
    switch (x) {
        case 0: return "even_zero";
        case 2: return "even_two";
        case 4: return "even_four";
        default: return "odd_or_out";
    }
}

// Grade function: tests string output for multiple enum-like values.
// Cases 60..90 (step 10), range = 30 → table size 32.
__attribute__((annotate("sob")))
const char *grade(int score) {
    switch (score / 10) {
        case 9:  return "A";
        case 8:  return "B";
        case 7:  return "C";
        case 6:  return "D";
        default: return "F";
    }
}

// Two switches in one function: verifies both are independently obfuscated.
__attribute__((annotate("sob")))
int multi_switch(int op, int x) {
    int base;
    switch (op) {
        case 1:  base = x + 0; break;
        case 2:  base = x * 3; break;
        case 3:  base = x - 1; break;
        default: base = 0;     break;
    }
    int modifier;
    switch (x % 4) {
        case 0:  modifier = 0; break;
        case 1:  modifier = 0; break;  // same dest, deduplication test
        case 2:  modifier = 0; break;
        case 3:  modifier = 0; break;
        default: modifier = 0; break;
    }
    return base + modifier;
}

// ── Plain reference implementations (no annotation) ──────────────────────────

const char *plain_classify_dir(int x) {
    switch (x) {
        case 0: return "zero";
        case 1: return "one";
        case 2: return "two";
        default: return "other";
    }
}

const char *plain_classify_neg(int x) {
    switch (x) {
        case -1: return "minus_one";
        case  0: return "zero";
        case  1: return "plus_one";
        case 99: return "far_positive";
        default: return "other";
    }
}

const char *plain_classify_gap(int x) {
    switch (x) {
        case 0: return "even_zero";
        case 2: return "even_two";
        case 4: return "even_four";
        default: return "odd_or_out";
    }
}

const char *plain_grade(int score) {
    switch (score / 10) {
        case 9:  return "A";
        case 8:  return "B";
        case 7:  return "C";
        case 6:  return "D";
        default: return "F";
    }
}

int plain_multi_switch(int op, int x) {
    int base;
    switch (op) {
        case 1:  base = x + 0; break;
        case 2:  base = x * 3; break;
        case 3:  base = x - 1; break;
        default: base = 0;     break;
    }
    return base;
}

// ── Main ──────────────────────────────────────────────────────────────────────

// String equality helper
static int streq(const char *a, const char *b) {
    while (*a && *b) {
        if (*a++ != *b++) return 0;
    }
    return *a == *b;
}

int main(void) {
    // Print representative samples
    printf("classify_dir(0)    = %s\n",  classify_dir(0));    // zero
    printf("classify_dir(1)    = %s\n",  classify_dir(1));    // one
    printf("classify_dir(2)    = %s\n",  classify_dir(2));    // two
    printf("classify_dir(99)   = %s\n",  classify_dir(99));   // other

    printf("classify_neg(-1)   = %s\n",  classify_neg(-1));   // minus_one
    printf("classify_neg(0)    = %s\n",  classify_neg(0));    // zero
    printf("classify_neg(1)    = %s\n",  classify_neg(1));    // plus_one
    printf("classify_neg(99)   = %s\n",  classify_neg(99));   // far_positive

    printf("grade(90)          = %s\n",  grade(90));           // A
    printf("grade(80)          = %s\n",  grade(80));           // B
    printf("grade(70)          = %s\n",  grade(70));           // C
    printf("grade(60)          = %s\n",  grade(60));           // D
    printf("grade(50)          = %s\n",  grade(50));           // F

    printf("multi_switch(1,0)  = (1+0)=%d\n",  multi_switch(1, 0));  // 1
    printf("multi_switch(2,3)  = (2*3)=%d\n",  multi_switch(2, 3));  // 6

    int ok = 1;

    // ── Verify classify_dir == plain_classify_dir ──────────────────────────
    int dir_vals[] = {0, 1, 2, -1, 3, 100, -100, 2147483647};
    int ndir = (int)(sizeof(dir_vals) / sizeof(dir_vals[0]));
    for (int i = 0; i < ndir; i++) {
        if (!streq(classify_dir(dir_vals[i]),
                   plain_classify_dir(dir_vals[i]))) {
            printf("FAIL classify_dir(%d)\n", dir_vals[i]);
            ok = 0;
        }
    }

    // ── Verify classify_neg == plain_classify_neg ──────────────────────────
    int neg_vals[] = {-2, -1, 0, 1, 2, 98, 99, 100, -100, -2147483648};
    int nneg = (int)(sizeof(neg_vals) / sizeof(neg_vals[0]));
    for (int i = 0; i < nneg; i++) {
        if (!streq(classify_neg(neg_vals[i]),
                   plain_classify_neg(neg_vals[i]))) {
            printf("FAIL classify_neg(%d)\n", neg_vals[i]);
            ok = 0;
        }
    }

    // ── Verify classify_gap ───────────────────────────────────────────────
    int gap_vals[] = {-1, 0, 1, 2, 3, 4, 5, 100};
    int ngap = (int)(sizeof(gap_vals) / sizeof(gap_vals[0]));
    for (int i = 0; i < ngap; i++) {
        if (!streq(classify_gap(gap_vals[i]),
                   plain_classify_gap(gap_vals[i]))) {
            printf("FAIL classify_gap(%d)\n", gap_vals[i]);
            ok = 0;
        }
    }

    // ── Verify grade ──────────────────────────────────────────────────────
    int grade_vals[] = {0, 10, 59, 60, 61, 69, 70, 79, 80, 89, 90, 99, 100};
    int ngrade = (int)(sizeof(grade_vals) / sizeof(grade_vals[0]));
    for (int i = 0; i < ngrade; i++) {
        if (!streq(grade(grade_vals[i]), plain_grade(grade_vals[i]))) {
            printf("FAIL grade(%d)\n", grade_vals[i]);
            ok = 0;
        }
    }

    // ── Verify multi_switch ───────────────────────────────────────────────
    int ops[]  = {0, 1, 2, 3, 4, -1};
    int args[] = {0, 1, 5, 10, -3, 7};
    int nmulti = (int)(sizeof(ops) / sizeof(ops[0]));
    for (int i = 0; i < nmulti; i++) {
        if (multi_switch(ops[i], args[i]) != plain_multi_switch(ops[i], args[i])) {
            printf("FAIL multi_switch(%d,%d)\n", ops[i], args[i]);
            ok = 0;
        }
    }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
