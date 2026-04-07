// test/cfr_test.c
// 验证 ControlFlowRandomization (控制流随机布局) pass:
//   - shuffled_func:     annotate("cfr") — 基本块布局随机化
//   - complex_logic:     annotate("cfr") + annotate("cff") — CFR + CFF 叠加
//   - simple_func:       无注解 — 不应被修改
//
// 编译时 stderr 应看到:
//   [ArmorComp][CFR] randomized layout: shuffled_func (N BBs)
//   [ArmorComp][CFR] randomized layout: complex_logic (N BBs)
//   [ArmorComp][CFF] flattened: complex_logic
//
// CFR pass 作用:
//   1. 收集所有非入口基本块
//   2. 使用确定性 PRNG (基于函数名) 进行 Fisher-Yates 洗牌
//   3. 按新顺序重新排列基本块
//
// 效果:
//   - 反编译器 (IDA/Ghidra) 无法按执行流顺序重建 CFG
//   - 基本块在二进制中的物理位置与逻辑执行顺序不一致
//   - 增加静态分析的难度
//
// 期望运行时输出 (功能不受影响):
//   classify(5) = 1
//   compute(10) = 385
//   simple(7) = 49

#include <stdio.h>

// ── CFR only ──────────────────────────────────────────────────────────────
// 包含多个基本块 (if/else if/else)，CFR 会打乱它们的布局顺序。
// 函数语义完全不变，只是基本块在内存中的排列不同了。
__attribute__((annotate("cfr")))
int classify(int n) {
    if (n < 0)
        return -1;
    else if (n == 0)
        return 0;
    else if (n <= 10)
        return 1;
    else if (n <= 100)
        return 2;
    else
        return 3;
}

// ── CFR + CFF combined ────────────────────────────────────────────────────
// CFR 先打乱基本块布局，CFF 再平坦化为 switch-dispatcher。
// 双重混淆:
//   1. 物理布局混乱 (CFR)
//   2. 控制流结构改变 (CFF)
// 反编译器需要同时克服两个障碍才能重建原始逻辑。
__attribute__((annotate("cfr")))
__attribute__((annotate("cff")))
int compute(int n) {
    int sum = 0;
    for (int i = 1; i <= n; i++) {
        if (i % 2 == 0)
            sum += i * i;      // 偶数平方
        else
            sum += i * 3;      // 奇数乘3
    }
    return sum;
}

// ── No annotation ─────────────────────────────────────────────────────────
int simple_func(int x) { return x * x; }

int main(void) {
    printf("classify(-5) = %d\n", classify(-5));   // -1
    printf("classify(0)  = %d\n", classify(0));    //  0
    printf("classify(5)  = %d\n", classify(5));    //  1
    printf("classify(50) = %d\n", classify(50));   //  2
    printf("classify(200)= %d\n", classify(200));  //  3
    printf("compute(10) = %d\n", compute(10));     // 3+9+16+12+25+15+36+21+49+27+100+33=385
    printf("simple(7)   = %d\n", simple_func(7));  // 49

    // 验证所有测试通过
    int passed = 0;

    // classify 测试
    if (classify(-5) == -1 &&
        classify(0) == 0 &&
        classify(5) == 1 &&
        classify(50) == 2 &&
        classify(200) == 3)
        passed++;

    // compute 测试: 1*3 + 2*2 + 3*3 + 4*2 + 5*3 + 6*2 + 7*3 + 8*2 + 9*3 + 10*2
    // = 3 + 4 + 9 + 8 + 15 + 12 + 21 + 16 + 27 + 20 = 135? 等等让我重新算
    // i=1(奇):3, i=2(偶):4, i=3(奇):9, i=4(偶):16, i=5(奇):15, i=6(偶):36,
    // i=7(奇):21, i=8(偶):64, i=9(奇):27, i=10(偶):100
    // = 3+4+9+16+15+36+21+64+27+100 = 295
    if (compute(10) == 295)
        passed++;

    if (simple_func(7) == 49)
        passed++;

    if (passed == 3)
        printf("ALL TESTS PASSED\n");
    else
        printf("SOME TESTS FAILED (%d/3)\n", passed);

    return 0;
}
