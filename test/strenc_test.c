// test/strenc_test.c
// 验证 STRENC (String Encryption) + SPLIT (Basic Block Splitting) pass，
// 以及与 SUB + BCF + CFF 的五层叠加保护。
//
// 函数说明：
//   - secure_fn:   全部五个注解 → 完整 5 层保护
//   - plain_fn:    无注解        → 不应被修改（字符串也不应加密）
//
// 编译时 stderr 应包含：
//   [ArmorComp][STRENC] encrypted: .str      (SECRET_API_KEY 字符串)
//   [ArmorComp][STRENC] injected constructor: __armorcomp_str_init
//   [ArmorComp][SPLT]   split:   secure_fn   (BB 数量增加)
//   [ArmorComp][SUB]    substituted: secure_fn
//   [ArmorComp][BCF]    obfuscated:  secure_fn
//   [ArmorComp][CFF]    flattened:   secure_fn
//
// 期望运行时输出（正确时）：
//   key = SECRET_API_KEY
//   sum(5) = 15
//
// 关键验证：
//   1. StrEncPass: 运行 `strings strenc_test_aarch64` 不应看到 "SECRET_API_KEY"
//      （字符串在 ELF 中以密文存储，运行时才解密）
//   2. SplitPass:  secure_fn 的 BB 数量多于源代码直接计数
//   3. 功能正确：runtime 输出与 plain_fn 相同

#include <stdio.h>

// ── 全五层保护 ────────────────────────────────────────────────────────────────
// 每个注解激活对应的 pass:
//   strenc → StrEncPass: 加密此函数引用的字符串字面量
//   split  → SplitPass:  拆分基本块（在 BCF/CFF 之前扩大 CFG）
//   sub    → SubPass:    替换算术/逻辑指令
//   bcf    → BCFPass:    插入永远不执行的虚假分支
//   cff    → CFFPass:    平坦化所有基本块到 switch dispatch
__attribute__((annotate("strenc")))
__attribute__((annotate("split")))
__attribute__((annotate("sub")))
__attribute__((annotate("bcf")))
__attribute__((annotate("cff")))
void secure_fn(int n) {
    // 这个字符串字面量将被 StrEncPass 加密：
    //   - ELF 中存储密文，`strings` 工具看不到 "SECRET_API_KEY"
    //   - 运行时 __armorcomp_str_init 在 main() 之前解密
    const char *key = "SECRET_API_KEY";
    printf("key = %s\n", key);

    // 普通求和循环，会被 SPLIT+SUB+BCF+CFF 多层混淆
    int s = 0;
    for (int i = 1; i <= n; i++)
        s += i;
    printf("sum(%d) = %d\n", n, s);
}

// ── 无注解函数 ────────────────────────────────────────────────────────────────
// plain_fn 的字符串 "plain: %d" 不应被加密（该函数无 strenc 注解）
void plain_fn(int x) {
    printf("plain: %d\n", x);
}

int main(void) {
    secure_fn(5);  // 期望: "key = SECRET_API_KEY" + "sum(5) = 15"
    plain_fn(42);  // 期望: "plain: 42"
    return 0;
}
