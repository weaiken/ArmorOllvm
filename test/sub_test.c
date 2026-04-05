// test/sub_test.c
// 验证 SUB (Instruction Substitution) pass:
//   - calc_sub:    annotate("sub")                   — 纯指令替换
//   - protect_all: annotate("sub") + annotate("bcf") + annotate("cff") — 三层叠加
//   - plain_add:   无注解                             — 不应被修改
//
// 编译时 stderr 应看到:
//   [ArmorComp][SUB] substituted: calc_sub    (2 rounds)
//   [ArmorComp][SUB] substituted: protect_all (2 rounds)
//   [ArmorComp][BCF] obfuscated:  protect_all
//   [ArmorComp][CFF] flattened:   protect_all
//
// 期望运行时输出:
//   add(3, 4)         = 7
//   sub(10, 3)        = 7
//   and(0xF0, 0x0F)   = 0
//   or(0xF0, 0x0F)    = 255
//   xor(0xFF, 0x0F)   = 240
//   protect_all(10)   = 55
//   plain_add(3, 4)   = 7

#include <stdio.h>

// ── SUB only ──────────────────────────────────────────────────────────────────
// SubPass 会把每个 ADD/SUB/AND/OR/XOR 指令替换成等价但更复杂的指令序列。
// 经过 2 轮替换后，反编译器看到的是若干层 XOR/AND/OR/shift/sub 的嵌套，
// 而不是简单的算术运算。
__attribute__((annotate("sub")))
int calc_sub(int a, int b, int op) {
    if (op == 0) return a + b;    // ADD — 被替换成 (a^b)+((a&b)<<1) 之类
    if (op == 1) return a - b;    // SUB — 被替换成 a+(~b)+1 之类
    if (op == 2) return a & b;    // AND — 被替换成 ~(~a|~b) 之类
    if (op == 3) return a | b;    // OR  — 被替换成 ~(~a&~b) 之类
    return a ^ b;                 // XOR — 被替换成 (a&~b)|(~a&b) 之类
}

// ── SUB + BCF + CFF combined ─────────────────────────────────────────────────
// SubPass 先替换指令，BCFPass 再加虚假分支，CFFPass 最后平坦化 CFG。
// 反编译器看到：一个带 switch dispatch 的循环，case 中既有复杂替换指令，
// 又有虚假分支，且所有路径都经过 switch 中转，无法还原原始逻辑。
__attribute__((annotate("sub")))
__attribute__((annotate("bcf")))
__attribute__((annotate("cff")))
int protect_all(int n) {
    int s = 0;
    for (int i = 1; i <= n; i++)
        s += i;          // 内层 += 被 SUB 替换，循环结构被 BCF+CFF 打乱
    return s;
}

// ── No annotation ─────────────────────────────────────────────────────────────
int plain_add(int a, int b) { return a + b; }

int main(void) {
    // calc_sub: 所有操作码都测一遍，验证替换后语义不变
    printf("add(3, 4)         = %d\n", calc_sub(3, 4, 0));     // 7
    printf("sub(10, 3)        = %d\n", calc_sub(10, 3, 1));    // 7
    printf("and(0xF0, 0x0F)   = %d\n", calc_sub(0xF0, 0x0F, 2)); // 0
    printf("or(0xF0, 0x0F)    = %d\n", calc_sub(0xF0, 0x0F, 3)); // 255
    printf("xor(0xFF, 0x0F)   = %d\n", calc_sub(0xFF, 0x0F, 4)); // 240

    // protect_all: 三层混淆叠加，验证功能仍然正确
    printf("protect_all(10)   = %d\n", protect_all(10));       // 55

    // plain_add: 未注解函数，结果必须与原始相同
    printf("plain_add(3, 4)   = %d\n", plain_add(3, 4));       // 7

    return 0;
}
