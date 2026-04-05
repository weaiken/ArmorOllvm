// ArmorComp — OpaquePredicatePass (OP) validation test
//
// OPPass splits each non-entry BB into head + tail.  The head evaluates one
// of 6 opaque predicate formulas (3 always-true, 3 always-false), then
// branches to the real tail or a dead-end block.  The dead block contains
// junk volatile arithmetic and a ret of the null return value — it is never
// executed at runtime.
//
// Expected stderr (ArmorComp log):
//   [ArmorComp][OP] obfuscated: secure_classify (N predicates)
//   (no message for plain_classify — not annotated)
//
// Verification (host, requires llvm-objdump):
//   llvm-objdump -d op_test_aarch64 | awk '/<secure_classify>/{p=1}p{print;if(/ret$/)exit}'
//   → Should contain multiple dead-end "op.dead" blocks ending with "ret"
//     interleaved with the real conditional branch chain.
//   → The dead blocks contain "0x4f50" (ASCII "OP") as a marker constant.
//
//   llvm-objdump -d op_test_aarch64 | awk '/<plain_classify>/{p=1}p{print;if(/ret$/)exit}'
//   → Compact straight-line branches, no dead blocks.
//
// Expected stdout:
//   secure_classify(-5) = -1
//   secure_classify(0)  =  0
//   secure_classify(5)  =  1
//   secure_classify(50) =  2
//   secure_classify(100) = 3
//   plain_classify(-5)  = -1
//   ALL TESTS PASSED

#include <stdio.h>

// secure_classify: annotated with "op" — OPP inserts opaque-predicate dead
// branches at each non-entry basic block.  The function must still produce
// the correct result because the always-true/false predicates route execution
// through the real tail at runtime.
__attribute__((annotate("op")))
int secure_classify(int x) {
    if (x < 0)   return -1;
    if (x == 0)  return  0;
    if (x < 10)  return  1;
    if (x < 100) return  2;
    return 3;
}

// plain_classify: no annotation — unobfuscated reference implementation.
int plain_classify(int x) {
    if (x < 0)   return -1;
    if (x == 0)  return  0;
    if (x < 10)  return  1;
    if (x < 100) return  2;
    return 3;
}

// secure_arith: a second annotated function with arithmetic BBs to exercise
// more predicate formulas (xorshift advances once per non-entry BB, cycling
// through all 6 formulas across the two functions).
__attribute__((annotate("op")))
int secure_arith(int a, int b) {
    int s = a + b;
    int p = a * b;
    if (s > p)  return s - p;
    if (s == p) return 0;
    return p - s;
}

int plain_arith(int a, int b) {
    int s = a + b;
    int p = a * b;
    if (s > p)  return s - p;
    if (s == p) return 0;
    return p - s;
}

int main(void) {
    // Print a few values for visual inspection
    printf("secure_classify(-5)  = %d\n", secure_classify(-5));   // -1
    printf("secure_classify(0)   = %d\n", secure_classify(0));    //  0
    printf("secure_classify(5)   = %d\n", secure_classify(5));    //  1
    printf("secure_classify(50)  = %d\n", secure_classify(50));   //  2
    printf("secure_classify(100) = %d\n", secure_classify(100));  //  3
    printf("plain_classify(-5)   = %d\n", plain_classify(-5));    // -1

    int ok = 1;

    // secure_classify must match plain_classify for all test inputs
    int cls_tests[] = { -100, -1, 0, 1, 5, 9, 10, 50, 99, 100, 999 };
    int ncls = sizeof(cls_tests) / sizeof(cls_tests[0]);
    for (int i = 0; i < ncls; i++) {
        int x = cls_tests[i];
        int s = secure_classify(x);
        int p = plain_classify(x);
        if (s != p) {
            printf("FAIL classify(%d): secure=%d plain=%d\n", x, s, p);
            ok = 0;
        }
    }

    // secure_arith must match plain_arith
    int arith_a[] = { 0, 1, 3, 5,  7, -1, -3,  10 };
    int arith_b[] = { 0, 1, 4, 5, -2,  2,  3, -10 };
    int narith = sizeof(arith_a) / sizeof(arith_a[0]);
    for (int i = 0; i < narith; i++) {
        int a = arith_a[i], b = arith_b[i];
        int s = secure_arith(a, b);
        int p = plain_arith(a, b);
        if (s != p) {
            printf("FAIL arith(%d,%d): secure=%d plain=%d\n", a, b, s, p);
            ok = 0;
        }
    }

    if (ok) printf("ALL TESTS PASSED\n");
    return ok ? 0 : 1;
}
