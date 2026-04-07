// test/adb_test.c
// 验证 AntiDebug (反调试检测) pass:
//   - secure_login:     annotate("adb") — 注入多层反调试检测
//   - verify_checksum:  annotate("adb") + annotate("at") — 反调试 + 防篡改叠加
//   - plain_func:       无注解 — 不应被修改
//
// 编译时 stderr 应看到:
//   [ArmorComp][ADB] anti-debug checks injected: secure_login (N BB(s))
//   [ArmorComp][ADB] anti-debug checks injected: verify_checksum (N BB(s))
//   [ArmorComp][AT] integrity check injected: verify_checksum
//
// 运行时行为:
//   - 正常执行: 函数应正常工作，输出正确结果
//   - 被调试器附加: 触发 abort() 终止进程
//
// 期望运行时输出 (正常模式):
//   login result = 1
//   checksum = 42
//   plain(5) = 25

#include <stdio.h>
#include <string.h>

// ── AntiDebug only ────────────────────────────────────────────────────────
// ADB 注入以下检测层:
//   1. ptrace(PTRACE_TRACEME) 自身附加检测
//   2. clock_gettime 时间差异检测 (反单步)
//   3. LD_PRELOAD / DYLD_INSERT_LIBRARIES 环境变量检测
//
// 如果任何一层检测到调试器 → 调用 abort() 终止进程
__attribute__((annotate("adb")))
int secure_login(const char *user, const char *pass) {
    // 模拟登录验证逻辑
    if (strcmp(user, "admin") == 0 && strcmp(pass, "secret123") == 0)
        return 1;  // 登录成功
    return 0;      // 登录失败
}

// ── AntiDebug + AntiTamper combined ────────────────────────────────────────
// ADB 先注入反调试代码，AT 再注入 canary 完整性校验。
// 形成双层保护:
//   - 外层: 检测是否被调试/分析
//   - 内层: 检测函数体是否被篡改
__attribute__((annotate("adb")))
__attribute__((annotate("at")))
int verify_checksum(int data) {
    // 简单的校验和计算
    int sum = 0;
    for (int i = 1; i <= data; i++)
        sum += i * i;
    return sum % 100;
}

// ── No annotation ─────────────────────────────────────────────────────────
int plain_func(int x) { return x * x; }

int main(void) {
    printf("login result = %d\n", secure_login("admin", "secret123"));  // 1
    printf("checksum = %d\n", verify_checksum(5));                       // 55%100=55
    printf("plain(5) = %d\n", plain_func(5));                            // 25

    // 验证所有测试通过
    int passed = 0;

    if (secure_login("admin", "secret123") == 1 &&
        secure_login("guest", "wrong") == 0)
        passed++;

    if (verify_checksum(5) == 55 &&  // 1+4+9+16+25=55
        plain_func(5) == 25)
        passed++;

    if (passed == 2)
        printf("ALL TESTS PASSED\n");
    else
        printf("SOME TESTS FAILED\n");

    return 0;
}
