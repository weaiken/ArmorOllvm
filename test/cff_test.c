// test/cff_test.c
// 验证 CFF (Control Flow Flattening) pass 的三种控制流模式：
//   1. 顺序执行    — classify()  中的 if/else if/else 链
//   2. if/else    — same
//   3. 循环        — sum_to_n()
//
// 编译时 stderr 应看到：
//   [ArmorComp][CFF] flattened: classify
//   [ArmorComp][CFF] flattened: sum_to_n
//   (注意: add() 无 cff 注解，不应出现在上面的输出中)
//
// 期望运行时输出：
//   classify(-5) = -1
//   classify(0)  =  0
//   classify(3)  =  1
//   sum_to_n(10) = 55
//   add(3,4)     =  7

#include <stdio.h>

// ── 顺序 + if/else 控制流 ────────────────────────────────────────────────
//
// 编译后 IR 大约有 4 个 BB：entry, if.then1, if.then2, if.else
// CFF 会将其平坦化为 entry → dispatch → {cases...}
__attribute__((annotate("cff")))
int classify(int n) {
    if (n < 0)  return -1;
    if (n == 0) return  0;
    return  1;
}

// ── 循环控制流 ───────────────────────────────────────────────────────────
//
// 循环产生的 PHI 节点（累加器 s，循环变量 i）会先被 DemotePHIToStack
// demote 到内存，再进行平坦化。
__attribute__((annotate("cff")))
int sum_to_n(int n) {
    int s = 0;
    for (int i = 1; i <= n; i++)
        s += i;
    return s;
}

// ── 非注解函数（不应被平坦化）───────────────────────────────────────────
int add(int a, int b) { return a + b; }

int main(void) {
    printf("classify(-5) = %d\n", classify(-5));   // expected: -1
    printf("classify(0)  = %d\n", classify(0));    // expected:  0
    printf("classify(3)  = %d\n", classify(3));    // expected:  1
    printf("sum_to_n(10) = %d\n", sum_to_n(10));   // expected: 55
    printf("add(3,4)     = %d\n", add(3, 4));      // expected:  7
    return 0;
}
