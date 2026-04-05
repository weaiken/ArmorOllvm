// test/hello.c
// 用于验证 ArmorComp pass plugin 能正确加载并处理 Android ARM64 编译目标
// 预期输出（编译时 stderr）：
//   [ArmorComp] function: add (1 basic blocks)
//   [ArmorComp] function: main (1 basic blocks)

#include <stdio.h>

// 将来会加 __attribute__((annotate("vmp"))) 的目标函数
int add(int a, int b) {
    return a + b;
}

int main(void) {
    printf("add(3, 4) = %d\n", add(3, 4));
    return 0;
}
