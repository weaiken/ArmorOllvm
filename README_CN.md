# ArmorComp 中文文档

基于 LLVM 17 的 out-of-tree pass plugin 代码混淆框架，主要面向 Android NDK（arm64-v8a / armeabi-v7a）和 iOS。
无需修改 LLVM 源码 —— 构建后通过 `-fpass-plugin` 加载即可。

**33 个混淆 Pass** | 支持 arm64（完整 33 个） 和 arm32（IR 级 pass；6 个 AArch64 专属自动跳过）

---

## 目录

- [Pass 一览](#pass-一览)
- [Android Studio 集成指南](#android-studio-集成指南)
  - [前置要求](#前置要求)
  - [方案一：CMake 工具链文件（推荐）](#方案一cmake-工具链文件推荐)
  - [方案二：ndk-build 集成](#方案二ndk-build-集成)
  - [方案三：手动 clang wrapper](#方案三手动-clang-wrapper)
- [函数标注方式](#函数标注方式)
- [YAML 配置文件（无需改源码）](#yaml-配置文件无需改源码)
- [VMP 虚拟机保护](#vmp-虚拟机保护)
- [推荐 Pass 组合](#推荐-pass-组合)
- [常见问题](#常见问题)

---

## Pass 一览

| Pass | 标注 | 说明 |
|------|------|------|
| CFFPass | `cff` | 控制流平坦化 —— dispatch-switch 循环 |
| BCFPass | `bcf` | 虚假控制流 —— 不透明谓词死分支 |
| OpaquePredicatePass | `op` | 不透明谓词 —— 6 种公式（P0-P2 恒真 / P3-P5 恒假）|
| SubPass | `sub` | 指令替换 —— 13 种 ADD/SUB/AND/OR/XOR 等价模式 |
| MBAPass | `mba` | 混合布尔算术重写 —— 10 种公式 |
| SplitPass | `split` | 基本块拆分 —— 膨胀 CFG |
| StrEncPass | `strenc` | 字符串加密 —— XOR 密文 + 构造函数解密 |
| GlobalEncPass | `genc` | 全局整数变量加密 —— XOR 加密初始值 + ctor 解密 |
| IndirectCallPass | `icall` | 间接调用 —— 不透明指针隐藏调用目标 |
| IndirectBranchPass | `ibr` | 间接跳转 —— `indirectbr` 隐藏跳转目标 |
| IndirectGlobalVariablePass | `igv` | 间接全局变量 —— 代理指针隐藏全局变量引用 |
| SPOPass | `spo` | 栈指针混淆 —— TPIDR_EL0 双读 XOR 破坏 IDA sp_delta (AArch64) |
| ConstObfPass | `co` | 整数常量混淆 —— XOR-key 分裂隐藏所有数字字面量 |
| FuncWrapPass | `fw` | 函数包装混淆 —— 内部转发函数隐藏真实调用者 |
| RetAddrObfPass | `rao` | 返回地址混淆 —— TPIDR_EL0 双读 XOR sub/add SP (AArch64) |
| OutlinePass | `outline` | 基本块外提 —— 每个非入口 BB 提取为 `__armorcomp_outline_N` |
| FlattenDataFlowPass | `df` | 数据流平坦化 —— 所有 alloca 合并到单一 `[N x i8]` 池 |
| DataEncodingPass | `denc` | 局部变量内存编码 —— 每次 store/load 使用 XOR 编解码 |
| FuncSigObfPass | `fsig` | 函数签名混淆 —— 伪造参数读取 + 返回值写入 (AArch64) |
| DwarfPoisonPass | `dpoison` | DWARF CFI 表投毒 —— 破坏 IDA `.eh_frame` 分析 (AArch64) |
| ConditionObfPass | `cob` | 条件比较混淆 —— ICmpInst 操作数加噪 |
| NeonTypeConfusionPass | `ntc` | NEON/FP 类型混淆 —— `fmov` GPR↔SIMD 误导类型推断 (AArch64) |
| ReturnValueObfPass | `rvo` | 返回值混淆 —— `eor x0, x0, volatile_zero`（跨平台） |
| LRObfPass | `lro` | 链接寄存器混淆 —— `eor x30, x30, volatile_zero` (AArch64) |
| GEPObfPass | `gepo` | GEP 索引混淆 —— 破坏 IDA 结构体 / 数组识别 |
| SwitchObfPass | `sob` | Switch 混淆 —— 密集跳转表 + `indirectbr` |
| JunkCodePass | `jci` | 垃圾代码注入 —— 每个 BB 注入不可消除的算术链 |
| ArithmeticStatePass | `asp` | CFF 状态变量 XOR 编码 —— 防止 IDA 解析状态机 |
| PointerXorPass | `pxor` | 指针 alloca XOR —— ptrtoint/xor/inttoptr 包装 |
| FakeAPICallPass | `fapi` | 伪 API 调用注入 —— getpid/getpagesize 噪声 |
| GlobalPointerObfPass | `gpo` | 全局函数指针加密 —— ctor 双重 XOR 解密 |
| LoopObfuscationPass | `lob` | 循环混淆 —— 循环入口注入垃圾计算链 |
| VMPPass | `vmp` | 虚拟机保护 —— 128 寄存器字节码 VM + XTEA 加密 + 完整性校验 + 多态 handler |

---

## Android Studio 集成指南

### 前置要求

| 组件 | 版本要求 | 安装方式 |
|------|---------|---------|
| Android Studio | 任意版本（已测试 Hedgehog / Iguana / Jellyfish） | 官网下载 |
| Android NDK | r25+ (推荐 r26b) | Android Studio SDK Manager |
| LLVM 17 | Homebrew clang@17 (macOS) 或 clang-17 (Linux) | 见下文 |
| CMake | >= 3.22 | Android Studio SDK Manager |
| Ninja | 任意版本 | Android Studio 自带 |

#### 安装 LLVM 17

**macOS (Homebrew):**
```bash
brew install llvm@17
# 验证安装
/opt/homebrew/opt/llvm@17/bin/clang --version
```

**Linux (apt):**
```bash
sudo apt install clang-17 libclang-17-dev
```

> **为什么需要 brew clang@17？**
>
> NDK 自带的 clang 是**静态链接** LLVM 的，无法 `dlopen` 加载 pass plugin。
> ArmorComp 需要动态链接的 clang@17 来加载 `libArmorComp.dylib`。
> toolchain 中的 launcher 脚本会自动拦截 NDK clang 调用，替换为 brew clang@17 + plugin，
> 同时保留 NDK 的 `--sysroot`、`--target`、`-resource-dir` 等交叉编译参数。

---

### 方案一：CMake 工具链文件（推荐）

这是最简单的集成方式，适用于使用 CMake 构建 native 代码的 Android 项目。

#### 步骤 1：复制 toolchain 目录

将 ArmorComp 的 `toolchain/` 目录复制到你的 Android 项目中：

```
your-app/
├── app/
│   ├── src/
│   │   ├── main/
│   │   │   ├── cpp/
│   │   │   │   ├── CMakeLists.txt
│   │   │   │   └── native-lib.cpp
│   │   │   └── java/
│   │   └── ...
│   └── build.gradle
├── armorcomp/
│   └── toolchain/            ← 复制到这里
│       ├── bin/
│       ├── lib/
│       │   └── darwin-arm64/libArmorComp.dylib
│       ├── android.cmake     ← 核心工具链文件
│       └── ...
└── build.gradle
```

#### 步骤 2：修改 app/build.gradle

```groovy
android {
    // ...

    defaultConfig {
        // ...
        externalNativeBuild {
            cmake {
                // 指向 ArmorComp 的 android.cmake 工具链文件
                arguments "-DCMAKE_TOOLCHAIN_FILE=${rootDir}/armorcomp/toolchain/android.cmake"

                // arm64-v8a: 完整支持全部 33 个 pass
                // armeabi-v7a: 支持 IR 级 pass（6 个 AArch64 专属自动跳过）
                abiFilters "arm64-v8a"
            }
        }
    }

    externalNativeBuild {
        cmake {
            path "src/main/cpp/CMakeLists.txt"
            version "3.22.1"
        }
    }
}
```

> **Kotlin DSL (build.gradle.kts):**
> ```kotlin
> android {
>     defaultConfig {
>         externalNativeBuild {
>             cmake {
>                 arguments(
>                     "-DCMAKE_TOOLCHAIN_FILE=${rootDir}/armorcomp/toolchain/android.cmake"
>                 )
>                 abiFilters("arm64-v8a")
>             }
>         }
>     }
>     externalNativeBuild {
>         cmake {
>             path = file("src/main/cpp/CMakeLists.txt")
>             version = "3.22.1"
>         }
>     }
> }
> ```

#### 步骤 3：在 C/C++ 源码中添加标注

```c
// native-lib.c

#include <jni.h>
#include <string.h>

// 对核心算法启用 CFF + BCF + VMP 保护
__attribute__((annotate("cff")))
__attribute__((annotate("bcf")))
__attribute__((annotate("vmp")))
JNIEXPORT jint JNICALL
Java_com_example_myapp_MainActivity_verifyLicense(
    JNIEnv *env, jobject thiz, jstring key) {

    const char *nativeKey = (*env)->GetStringUTFChars(env, key, NULL);
    int result = 0;

    // 你的核心验证逻辑...
    if (strcmp(nativeKey, "VALID_KEY") == 0) {
        result = 1;
    }

    (*env)->ReleaseStringUTFChars(env, key, nativeKey);
    return result;
}

// 对字符串加密
__attribute__((annotate("strenc")))
JNIEXPORT jstring JNICALL
Java_com_example_myapp_MainActivity_getApiKey(
    JNIEnv *env, jobject thiz) {

    const char *secret = "sk-AbCdEfGh123456";  // 编译后此字符串会被加密
    return (*env)->NewStringUTF(env, secret);
}
```

#### 步骤 4：构建运行

在 Android Studio 中直接点击 **Run** 或 **Build > Make Project**。

构建日志（Build Output）中会看到 ArmorComp 的输出：

```
[ArmorComp] Plugin:   .../armorcomp/toolchain/lib/darwin-arm64/libArmorComp.dylib
[ArmorComp] Launcher: .../armorcomp/toolchain/bin/armorcomp-launcher
[ArmorComp] NDK:      .../Android/sdk/ndk/26.1.10909125

[ArmorComp][CFF] flattened: Java_com_example_myapp_MainActivity_verifyLicense
[ArmorComp][BCF] obfuscated: Java_com_example_myapp_MainActivity_verifyLicense
[ArmorComp][VMP] virtualized: Java_com_example_myapp_MainActivity_verifyLicense (N bytecode bytes, M virtual instrs)
[ArmorComp][StrEnc] encrypted 1 string(s) in module
```

#### 工作原理

```
Android Studio
    ↓
Gradle → CMake (使用 android.cmake 工具链文件)
    ↓
CMake 发现 CMAKE_TOOLCHAIN_FILE → 加载 android.cmake
    ↓
android.cmake:
  1. 定位 NDK toolchain → include(android.toolchain.cmake)
  2. 定位 libArmorComp.dylib
  3. 设置 CMAKE_C_COMPILER_LAUNCHER = armorcomp-launcher
    ↓
编译时 CMake 调用: armorcomp-launcher <NDK_CLANG> <FLAGS>
    ↓
armorcomp-launcher:
  1. 从 NDK clang 路径推导 resource-dir
  2. 丢弃 NDK clang，替换为 brew clang@17
  3. 注入 -fpass-plugin=libArmorComp.dylib
  4. 保留全部 NDK 编译参数 (--target, --sysroot, ...)
    ↓
brew clang@17 -fpass-plugin=libArmorComp.dylib --target=aarch64-linux-android21 ...
    ↓
LLVM 17 加载 ArmorComp → 运行各 pass → 输出混淆后的 .o
    ↓
NDK linker 链接 → libmynativelib.so (混淆后的 native library)
```

---

### 方案二：ndk-build 集成

适用于仍在使用 `Android.mk` / `ndk-build` 的旧项目。

#### Android.mk

```makefile
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE    := mynativelib
LOCAL_SRC_FILES := native-lib.cpp secure_logic.c

# 引入 ArmorComp 工具链
include $(LOCAL_PATH)/../../armorcomp/toolchain/armorcomp.mk

include $(BUILD_SHARED_LIBRARY)
```

#### Application.mk

```makefile
APP_ABI      := arm64-v8a
APP_PLATFORM := android-21
```

`armorcomp.mk` 会自动将 `TARGET_CC` / `TARGET_CXX` 替换为 ArmorComp 的 clang wrapper。

---

### 方案三：手动 clang wrapper

适用于不使用 CMake/ndk-build 的自定义构建系统，或需要精确控制编译参数的场景。

```bash
# 直接使用 armorcomp-clang 编译单个文件
./armorcomp/toolchain/bin/armorcomp-clang \
    --target=aarch64-linux-android21 \
    --sysroot=$ANDROID_NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot \
    -O0 \
    -c native-lib.c -o native-lib.o

# 链接（使用 NDK linker）
$ANDROID_NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/ld.lld \
    native-lib.o -o libmynativelib.so -shared \
    --sysroot=$ANDROID_NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot
```

---

## 函数标注方式

使用 `__attribute__((annotate("pass_name")))` 标记需要保护的函数：

```c
// 单个 pass
__attribute__((annotate("cff")))
int my_function(int x) { ... }

// 多个 pass —— 逐个叠加
__attribute__((annotate("cff")))
__attribute__((annotate("bcf")))
__attribute__((annotate("sub")))
__attribute__((annotate("mba")))
int highly_protected(int x) { ... }

// C++ 便捷宏
#define ARMORCOMP(...) __attribute__((annotate("cff"))) \
                       __attribute__((annotate("bcf"))) \
                       __attribute__((annotate("sub")))

ARMORCOMP()
int my_cpp_function(int x) { ... }
```

**可用标注值：**
`cff` `bcf` `op` `sub` `mba` `cob` `split` `strenc` `genc` `denc` `jci` `fapi` `icall` `ibr` `igv` `spo` `co` `gepo` `fw` `rao` `outline` `df` `fsig` `dpoison` `ntc` `rvo` `lro` `sob` `asp` `pxor` `gpo` `lob` `vmp`

---

## YAML 配置文件（无需改源码）

适用于保护第三方库或不方便修改源码的场景。

#### 激活方式

```bash
# 方式 1: 环境变量
export ARMORCOMP_CONFIG=/path/to/armorcomp.yaml

# 方式 2: 自动发现（工作目录下的 armorcomp.yaml）
# 在项目根目录放置 armorcomp.yaml 即可
```

在 Android Studio 中设置环境变量，可以在 `build.gradle` 中添加：

```groovy
android {
    defaultConfig {
        externalNativeBuild {
            cmake {
                arguments "-DCMAKE_TOOLCHAIN_FILE=${rootDir}/armorcomp/toolchain/android.cmake"
                abiFilters "arm64-v8a"
            }
        }
    }
}

// 设置 ArmorComp 配置文件环境变量
tasks.matching { it.name.contains("externalNativeBuild") }.configureEach {
    environment("ARMORCOMP_CONFIG", "${rootDir}/armorcomp.yaml")
}
```

#### 配置文件格式

```yaml
# armorcomp.yaml

functions:
  # 精确函数名匹配
  - name: "Java_com_example_Crypto_decrypt"
    passes: [cff, bcf, vmp, icall, ibr]

  # 正则模式 —— 保护所有 JNI 导出
  - pattern: "^Java_"
    passes: [cff, sub, co, mba]

  # 保护名字包含 "secure" 的函数
  - pattern: "secure"
    passes: [cff, bcf, op, mba, spo]
```

**规则说明：**
- 从上到下匹配，**首个匹配的规则生效**
- 配置与 `annotate()` 标注是**叠加**关系，任一触发即生效
- 无匹配且无标注的函数不受影响

---

## VMP 虚拟机保护

VMPPass 是保护强度最高的 pass。它将整个函数体转换为自定义字节码虚拟机：

```
LLVM IR → VMPLifter (字节码) → Opcode 置乱 → XTEA-CTR 加密 → VMPCodeGen (调度器)
```

### VM 指令集

- **128 个虚拟寄存器** (R0–R127)，64 位宽，支持死寄存器回收
- R0 = 返回值，R0–R7 = 函数参数
- **~50 个操作码**：算术、位运算、比较（10 ICmp + 14 FCmp）、控制流、内存访问（8/16/32/64）、类型转换、浮点、指针、原子操作、直接/间接调用
- **超级指令** ADD_I32/SUB_I32 —— 7 字节融合立即数算术

### 保护层级

| 层 | 机制 | 效果 |
|---|------|------|
| Opcode 置乱 | Fisher-Yates 全排列（每个函数独立种子）| 每个函数的 opcode 编码都不同 |
| XTEA-CTR 加密 | 32 轮 XTEA 分组密码 CTR 模式（每函数独立密钥）| 字节码静态加密，运行时解密 |
| 完整性校验 | FNV-1a 哈希 | 篡改检测 → `llvm.trap` |
| 寄存器 Canary | 寄存器读写 XOR 掩码 | 防止直接操纵寄存器文件 |
| Dead Handler | 16 个虚假 handler BB（4 种模板）| IDA 无法区分真假 handler |
| Handler 多态 | 6 个高频 handler 使用 MBA 等价表达式 | 每个函数使用不同 handler 实现 |
| VarArg 支持 | 自动生成 non-vararg wrapper | printf/snprintf 等可被虚拟化 |

### VMP 调试

设置环境变量查看字节码反汇编输出：

```bash
ARMORCOMP_VMP_DISASM=1 ./gradlew assembleDebug 2>&1 | grep -A 20 "Disassembly of"
```

输出示例：
```
[VMP] Disassembly of Java_com_example_Crypto_decrypt:
  [0000] JMP     +1
  [0005] NOP
  [0006] ALLOCA  R8, 4
  [000c] STORE_32 R0, R8
  [000f] LOAD_32  R9, R8
  [0012] ADD_I32  R8, R9, 42
  [0019] RET      R8
```

### VMP 限制

- SIMD / 向量指令 → 不支持（函数会被跳过）
- 带浮点参数的间接调用 → 不支持（ABI 限制）
- 动态大小 alloca → 不支持

---

## 推荐 Pass 组合

在 Android arm64-v8a 上测试验证通过：

| 目标 | 组合 | 效果 |
|------|------|------|
| 直接破坏 IDA F5 | `spo + rao + dpoison` | sp_delta = UNKNOWN → 反编译器失败 |
| F5 输出不可读 | `cff + bcf + mba` | 状态机迷宫，条件不可解析 |
| 最强保护 | `vmp + spo + dpoison` | 算法隐藏在 VM 中 + wrapper sp 被破坏 |
| 全栈 | `spo + rao + cff + bcf + mba + dpoison` | 所有反分析层叠加 |

> **注意：** VMP + CFF **不应组合** —— CFF 会二次展平 VMP 调度器的 switch，导致 `musttail` 不变式冲突。

---

## 自动执行顺序

当使用标注模式时，pass 的执行顺序为：

```
STRENC → GENC → GPO → VMP → SOB → SPLIT → SUB → MBA → LOB →
COB → DENC → PXOR → JCI → FAPI → CO → GEPO → DF → OUTLINE →
BCF → OP → CFF → ASP → RAO → ICALL → IBR → IGV → FW → FSIG →
SPO → NTC → RVO → LRO → DPOISON
```

每个 pass 还有 `-all` 变体（如 `armorcomp-cff-all`），无需标注即应用到所有函数。

---

## 常见问题

### Q: Android Studio 构建报错 "plugin not found"

**原因：** `toolchain/lib/darwin-arm64/libArmorComp.dylib` 不存在。

**解决：**
```bash
# 从源码构建
cd ArmorComp
cmake -B build -G Ninja
cmake --build build --target ArmorComp
cp build/libArmorComp.dylib toolchain/lib/darwin-arm64/
```

### Q: 报错 "no suitable clang found"

**原因：** 未安装 Homebrew LLVM 17。

**解决：**
```bash
brew install llvm@17
# 验证
/opt/homebrew/opt/llvm@17/bin/clang --version
```

### Q: 构建成功但没有混淆日志输出

**原因：**
1. 没有添加 `__attribute__((annotate(...)))` 标注
2. 也没有设置 YAML 配置文件

**解决：** 至少使用一种标注方式。如果使用 YAML，确保 `ARMORCOMP_CONFIG` 环境变量已设置。

### Q: 某些函数被 VMP 跳过 (skipped)

**原因：** 函数中包含 VMP 不支持的 IR 指令（SIMD 向量运算、动态 alloca 等）。

**解决：**
- 检查 stderr 中的 `[ArmorComp][VMP] skipped (unsupported IR): <函数名>`
- 对这些函数改用其他 pass（如 `cff + bcf + mba`）

### Q: macOS Intel (x86_64) 和 Linux 怎么使用？

toolchain 支持三种平台：

| 平台 | Plugin 路径 |
|------|------------|
| macOS Apple Silicon | `toolchain/lib/darwin-arm64/libArmorComp.dylib` |
| macOS Intel | `toolchain/lib/darwin-x86_64/libArmorComp.dylib` |
| Linux x86_64 | `toolchain/lib/linux-x86_64/libArmorComp.so` |

`android.cmake` 和 launcher 会自动检测当前平台并使用对应的 plugin 文件。

### Q: 能同时支持 arm64 和 arm32 吗？

可以。在 `build.gradle` 中设置：

```groovy
abiFilters "arm64-v8a", "armeabi-v7a"
```

arm32 编译时，6 个 AArch64 专属 pass（`spo` / `rao` / `ntc` / `lro` / `fsig` / `dpoison`）会自动跳过，其余 27 个 pass 正常工作。

### Q: 如何验证混淆效果？

1. **编译日志** —— 查看 stderr 中各 pass 的输出确认已生效
2. **反汇编对比** —— 用 IDA Pro / Ghidra 打开混淆前后的 `.so` 文件
3. **运行时测试** —— 确保混淆后功能不变（所有 pass 保证语义等价）
4. **VMP 反汇编器** —— `ARMORCOMP_VMP_DISASM=1` 查看字节码

### Q: 使用 ArmorComp 后 APK 体积增大了多少？

取决于使用的 pass 和标注的函数数量：
- 轻量级（`cff + sub + mba`）：通常增大 10-30%
- 中等级（`cff + bcf + op + mba + icall + ibr`）：增大 50-100%
- VMP：每个虚拟化函数生成 ~60 个 handler BB 的调度器，增大较多，建议只对核心函数使用

### Q: 能和 ProGuard / R8 一起使用吗？

可以。ProGuard/R8 只作用于 Java/Kotlin 字节码，ArmorComp 作用于 native C/C++ 代码，两者互不干扰。推荐同时使用以获得全栈保护。

---

## iOS 集成

### CMake 方式

```bash
cmake -DCMAKE_TOOLCHAIN_FILE=/path/to/toolchain/ios.cmake \
      -DIOS_PLATFORM=OS64 \
      -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 \
      ..
```

### Xcode (.xcconfig) 方式

1. 将 `ArmorComp.xcconfig` 添加到 Xcode 项目
2. 在 target 的 Build Settings → "Based on" 中选择 `ArmorComp`
3. 设置 `ARMORCOMP_TOOLCHAIN_DIR` 为 toolchain 目录的绝对路径

详见 `toolchain/ArmorComp.xcconfig` 文件中的注释。

---

## 从源码构建

```bash
git clone <repo>
cd ArmorComp
cmake -B build -G Ninja
cmake --build build --target ArmorComp
# 部署到 toolchain
cp build/libArmorComp.dylib toolchain/lib/darwin-arm64/
```

> **重要：** 修改 pass 源码后必须重新部署到 `toolchain/lib/` 目录，
> 因为 launcher 使用的是 `toolchain/lib/` 下的插件，不是 `build/` 下的。
