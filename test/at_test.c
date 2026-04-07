// test/at_test.c
// 验证 AntiTamper (防篡改完整性校验) pass:
//   - protected_func:    annotate("at") — 注入 canary 完整性校验
//   - critical_section:  annotate("at") + annotate("adb") — 防篡改 + 反调试叠加
//   - normal_func:       无注解 — 不应被修改
//
// 编译时 stderr 应看到:
//   [ArmorComp][AT] integrity check injected: protected_func
//   [ArmorComp][AT] integrity check injected: critical_section
//   [ArmorComp][ADB] anti-debug checks injected: critical_section (N BB(s))
//
// AT pass 注入机制:
//   1. 函数入口: 存储 canary 值到 volatile global
//   2. 每个 return 前: 加载并比较 canary
//   3. 不匹配 → 调用 abort() 终止进程 (检测到篡改)
//
// 期望运行时输出:
//   result = 42
//   secret = 0xDEADBEEF
//   normal(10) = 100

#include <stdio.h>
#include <stdint.h>

// ── AntiTamper only ───────────────────────────────────────────────────────
// AT 注入 canary 守护:
//   - 入口: __armorcomp_at_canary_<func> = random_value
//   - 出口: if (__armorcomp_at_canary_<func> != expected) abort()
//
// 如果函数体被静态 patch 或运行时修改 → canary 不匹配 → 触发保护
__attribute__((annotate("at")))
int protected_func(int x, int y) {
    // 简单计算逻辑
    int result = x * y + 10;
    if (result > 100)
        result = 100;
    return result;
}

// ── AntiTamper + AntiDebug combined ────────────────────────────────────────
// 双重保护:
//   - AT: 检测代码是否被篡改
//   - ADB: 检测是否被调试器附加
//
// 适用于关键安全函数: 密钥派生、许可证验证、加密操作等
__attribute__((annotate("at")))
__attribute__((annotate("adb")))
uint32_t critical_section(uint32_t input) {
    // 模拟敏感操作: 密钥混合
    uint32_t key = 0xDEADBEEF;
    uint32_t result = input ^ key;
    result = (result << 7) | (result >> 25);  // 循环左移
    return result;
}

// ── No annotation ─────────────────────────────────────────────────────────
int normal_func(int x) { return x * x; }

int main(void) {
    printf("result = %d\n", protected_func(4, 8));           // 4*8+10=42
    printf("secret = 0x%08X\n", critical_section(0));        // ^DEADBEEF + rotate
    printf("normal(10) = %d\n", normal_func(10));             // 100

    // 验证所有测试通过
    int passed = 0;

    if (protected_func(4, 8) == 42 &&
        protected_func(20, 5) == 100)
        passed++;

    // critical_section 的输出是确定性的
    uint32_t expected = 0 ^ 0xDEADBEEF;
    expected = (expected << 7) | (expected >> 25);
    if (critical_section(0) == expected)
        passed++;

    if (normal_func(10) == 100)
        passed++;

    if (passed == 3)
        printf("ALL TESTS PASSED\n");
    else
        printf("SOME TESTS FAILED (%d/3)\n", passed);

    return 0;
}
