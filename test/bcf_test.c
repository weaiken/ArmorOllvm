// test/bcf_test.c
// 验证 BCF (Bogus Control Flow) pass:
//   - classify_bcf:    annotate("bcf") — 纯 BCF，添加虚假分支
//   - protect_both:    annotate("bcf") + annotate("cff") — BCF + CFF 叠加
//   - helper:          无注解 — 不应被修改
//
// 编译时 stderr 应看到:
//   [ArmorComp][BCF] obfuscated: classify_bcf
//   [ArmorComp][BCF] obfuscated: protect_both
//   [ArmorComp][CFF] flattened:  protect_both   (两个 pass 都作用于它)
//
// 期望运行时输出:
//   classify_bcf(-3) = -1
//   classify_bcf(0)  =  0
//   classify_bcf(5)  =  1
//   protect_both(10) = 55
//   helper(7)        =  7

#include <stdio.h>

// ── BCF only ─────────────────────────────────────────────────────────────
// BCF 会在每个 BB 前插入一个条件分支:
//   if ((n*(n+1))&1 == 0)  →  real_block
//   else                   →  bogus_clone  →  loop back (never reached)
__attribute__((annotate("bcf")))
int classify_bcf(int n) {
    if (n < 0)  return -1;
    if (n == 0) return  0;
    return  1;
}

// ── BCF + CFF combined ────────────────────────────────────────────────────
// BCF 先添加虚假分支，CFF 再平坦化整个 CFG（包含虚假分支）。
// 反编译器看到的是：一个带有随机 ID dispatch 的 switch，其中既有真实 case
// 也有虚假 case，无法区分。
__attribute__((annotate("bcf")))
__attribute__((annotate("cff")))
int protect_both(int n) {
    int s = 0;
    for (int i = 1; i <= n; i++)
        s += i;
    return s;
}

// ── No annotation ─────────────────────────────────────────────────────────
int helper(int x) { return x; }

int main(void) {
    printf("classify_bcf(-3) = %d\n", classify_bcf(-3));  // -1
    printf("classify_bcf(0)  = %d\n", classify_bcf(0));   //  0
    printf("classify_bcf(5)  = %d\n", classify_bcf(5));   //  1
    printf("protect_both(10) = %d\n", protect_both(10));  // 55
    printf("helper(7)        = %d\n", helper(7));         //  7
    return 0;
}
