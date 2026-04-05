# ArmorComp v0.26.0 — 快速接入指南

> **交付物**：`armorcomp-toolchain-v0.26.0-darwin-arm64.tar.gz`（55 MB）
> **支持平台**：macOS（Apple Silicon / Intel）编译宿主机
> **目标平台**：Android arm64-v8a / armeabi-v7a、iOS arm64

---

## 一、包内容说明

解压后得到 `toolchain/` 目录，结构如下：

```
toolchain/
├── bin/
│   ├── armorcomp-clang          # macOS C 编译器包装脚本
│   ├── armorcomp-clang++        # macOS C++ 编译器包装脚本
│   ├── armorcomp-launcher       # Android NDK CMake 专用 launcher
│   ├── clang17                  # 内置 clang 17 可执行文件（已打包，无需 brew）
│   └── clang17++                # 内置 clang++ 17
├── lib/
│   └── darwin-arm64/
│       └── libArmorComp.dylib   # 混淆 pass 插件（Apple Silicon）
├── vendor/
│   ├── libLLVM.dylib            # LLVM 运行时（随 clang17 使用，已内置）
│   └── libclang-cpp.dylib       # Clang 运行时（随 clang17 使用，已内置）
├── android.cmake                # Android NDK CMake 工具链文件
├── ios.cmake                    # iOS CMake 工具链文件
├── ArmorComp.xcconfig           # Xcode Build Settings 集成文件
├── armorcomp.mk                 # ndk-build Android.mk 集成片段
└── README.md                    # 详细参考文档
```

> **无需安装 brew llvm@17**
> `vendor/` 目录已内置完整的 LLVM 17 运行时。解压后开箱即用，不依赖宿主机的 Homebrew 环境。

---

## 二、解压与放置

将 tar 包解压到您项目的任意目录，推荐与 `CMakeLists.txt` / `build.gradle` 同级：

```bash
# 解压
tar -xzf armorcomp-toolchain-v0.26.0-darwin-arm64.tar.gz

# 解压后得到 toolchain/ 目录
# 建议放置位置（以 Android 项目为例）：
#
#   MyApp/
#   ├── app/
#   │   └── src/main/cpp/CMakeLists.txt
#   ├── armorcomp/
#   │   └── toolchain/        ← 解压到这里
#   └── build.gradle
```

**路径可自由选择**，只需在后续步骤中替换 `/path/to/toolchain` 为实际路径。

---

## 三、Android 接入

### 方式 A：Gradle + CMake（推荐）

在 `app/build.gradle` 中添加工具链文件路径：

```groovy
android {
    defaultConfig {
        externalNativeBuild {
            cmake {
                // 替换为实际的 toolchain 路径
                arguments "-DCMAKE_TOOLCHAIN_FILE=${rootDir}/armorcomp/toolchain/android.cmake"
                // arm64-v8a: 完整支持所有 pass
                abiFilters "arm64-v8a"
                // armeabi-v7a: 同样支持；spo/rao/ntc/lro/fsig/dpoison 等 AArch64-only pass
                //              会自动跳过，其余 ~27 个 IR pass 正常运行
                // abiFilters "arm64-v8a", "armeabi-v7a"
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

> `abiFilters` 同时支持 `"arm64-v8a"` 和 `"armeabi-v7a"`。arm32 目标上，6 个 AArch64-only pass（`spo`/`rao`/`ntc`/`lro`/`fsig`/`dpoison`）会自动静默跳过，不影响其余 pass 运行。

无需其他改动，Sync Project 后正常编译即可。

---

### 方式 B：plain CMake 命令行

```bash
cmake \
    -DCMAKE_TOOLCHAIN_FILE=/path/to/toolchain/android.cmake \
    -DANDROID_ABI=arm64-v8a \          # 或 armeabi-v7a
    -DANDROID_PLATFORM=android-21 \
    -DANDROID_NDK=/path/to/ndk \
    -B build -S .

cmake --build build
```

`ANDROID_NDK` 若不传，会自动从以下位置探测：
- 环境变量 `ANDROID_NDK_ROOT` / `ANDROID_NDK_HOME` / `NDK_ROOT`
- `$HOME/Library/Android/sdk/ndk/` 下最新版本

---

### 方式 C：ndk-build

在 `Android.mk` 中添加一行 include：

```makefile
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE    := mynativelib
LOCAL_SRC_FILES := native.c

# 添加这一行，替换为实际路径
include /path/to/toolchain/armorcomp.mk

include $(BUILD_SHARED_LIBRARY)
```

`Application.mk` 设置：

```makefile
APP_ABI      := arm64-v8a armeabi-v7a   # armeabi-v7a 同样支持
APP_PLATFORM := android-21
```

---

## 四、iOS 接入

### 方式 A：CMake 命令行

```bash
cmake \
    -DCMAKE_TOOLCHAIN_FILE=/path/to/toolchain/ios.cmake \
    -DIOS_PLATFORM=OS64 \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 \
    -B build -S .

cmake --build build
```

产出为标准 arm64 Mach-O object 文件，直接与 Xcode 的 `ld` 链接，无格式兼容问题。

---

### 方式 B：Xcode xcconfig

1. 在 Xcode 中 **File → Add Files to Project**，选择 `toolchain/ArmorComp.xcconfig`
2. 打开 **Project → Info → Configurations**，将目标 Configuration 的 **Based on** 改为 `ArmorComp`
3. 在 `ArmorComp.xcconfig` 中（或 Xcode Build Settings 搜索 `ARMORCOMP_TOOLCHAIN_DIR`）设置路径：

```
ARMORCOMP_TOOLCHAIN_DIR = /absolute/path/to/toolchain
```

或通过命令行传入：

```bash
xcodebuild -DARMORCOMP_TOOLCHAIN_DIR=/absolute/path/to/toolchain
```

---

## 五、标注混淆函数

在 C / C++ 源文件中使用 `__attribute__((annotate("pass名称")))` 标注需要混淆的函数：

```c
// 单个 pass
__attribute__((annotate("cff")))
int secure_decrypt(const uint8_t *buf, int len) {
    // ...
}

// 叠加多个 pass（逐行堆叠）
__attribute__((annotate("cff")))
__attribute__((annotate("bcf")))
__attribute__((annotate("sub")))
__attribute__((annotate("vmp")))
int critical_keygen(int seed) {
    // ...
}
```

### 可用 Pass 一览

| 标注 | 功能 | 强度 |
|------|------|------|
| `cff`     | CFG 平坦化（控制流混淆）| ★★★★ |
| `bcf`     | 虚假控制流注入 | ★★★★ |
| `op`      | 不透明谓词插入 | ★★★ |
| `sub`     | 指令替换 | ★★ |
| `mba`     | 混合布尔算术替换 | ★★★ |
| `cob`     | 比较指令混淆 | ★★ |
| `sob`     | switch 语句混淆 | ★★★ |
| `split`   | 基本块拆分 | ★★ |
| `outline` | 基本块外联为独立函数 | ★★★ |
| `jci`     | 垃圾代码注入 | ★★ |
| `strenc`  | 字符串加密（模块级） | ★★★ |
| `genc`    | 全局整数变量加密 | ★★★ |
| `denc`    | 局部变量内存编码 | ★★ |
| `co`      | 整数常量混淆 | ★★ |
| `df`      | 数据流平坦化（栈池合并）| ★★★ |
| `icall`   | 间接调用混淆 | ★★★ |
| `ibr`     | 间接跳转混淆 | ★★★ |
| `igv`     | 全局变量间接访问 | ★★ |
| `fw`      | 函数包装混淆 | ★★ |
| `fsig`    | 函数签名混淆 | ★★★ |
| `gepo`    | GEP 索引混淆 | ★★ |
| `spo`     | 栈指针混淆（破坏 IDA sp-delta）| ★★★ |
| `rao`     | 返回地址 / 调用帧混淆 | ★★★ |
| `lro`     | 链接寄存器 XOR 混淆 | ★★★ |
| `rvo`     | 返回值 XOR 混淆 | ★★ |
| `ntc`     | NEON/FP 寄存器类型混淆 | ★★ |
| `dpoison` | DWARF CFI 表毒化 | ★★ |
| `vmp`     | 虚拟机保护（最强，性能损耗较高）| ★★★★★ |

---

## 六、YAML 配置（无需修改源代码）

如果不方便修改源码，可通过配置文件按函数名/正则批量启用 pass：

```bash
# 构建前设置环境变量
export ARMORCOMP_CONFIG="$(pwd)/armorcomp.yaml"
```

`armorcomp.yaml` 示例：

```yaml
functions:
  # 精确匹配函数名
  - name: "Java_com_example_Crypto_decrypt"
    passes: [cff, bcf, icall, ibr, vmp]

  # 正则匹配所有 JNI 函数
  - pattern: "^Java_"
    passes: [cff, sub, co, strenc]

  # 匹配所有 secure_ 前缀函数
  - pattern: "^secure_"
    passes: [cff, bcf, op, mba, spo]
```

- 第一条匹配的规则生效（顺序敏感）
- YAML 配置与 `annotate()` **可同时使用**，互相叠加

---

## 七、验证混淆是否生效

编译时控制台会输出 ArmorComp 的处理日志：

```
[ArmorComp] function: secure_decrypt (8 basic blocks)
[ArmorComp][CFF] flattened: secure_decrypt
[ArmorComp][BCF] obfuscated: secure_decrypt
[ArmorComp][STRENC] encrypted: .str.2
[ArmorComp][STRENC] injected constructor: __armorcomp_str_init
```

如果没有上述输出，请确认：
1. 工具链文件路径正确（`cmake --build` 输出中可见 `armorcomp-launcher` 被调用）
2. 函数已正确标注 `__attribute__((annotate(...)))` 或 YAML 配置路径正确

---

## 八、常见问题

**Q: 编译报错 `fatal error: 'stddef.h' file not found`**
A: 这通常发生在手动调用 `armorcomp-clang` 而未传入 `--sysroot` 或 `--target` 时。
通过 `android.cmake` / `ios.cmake` 集成时会自动处理，无需手动传入。

**Q: 提示 `[ArmorComp] Plugin not found`**
A: 检查 `toolchain/lib/darwin-arm64/libArmorComp.dylib` 文件是否存在。
Apple Silicon 机器使用 `darwin-arm64`，Intel 机器使用 `darwin-x86_64`。

**Q: 编译后没有任何 `[ArmorComp]` 日志**
A: 可能是 NDK 版本问题。本工具链通过 `CMAKE_C_COMPILER_LAUNCHER` 注入，需要 NDK r21+。
确认 CMake 配置阶段输出了 `[ArmorComp] Launcher: .../armorcomp-launcher`。

**Q: `vmp` pass 导致运行时崩溃**
A: VMP 对函数有限制：不支持 C++ 异常、`longjmp`、可变参数函数。建议先单独测试后再上线。

**Q: 能否同时接入 Android 和 iOS 项目？**
A: 可以。同一份 `toolchain/` 目录分别被 `android.cmake` 和 `ios.cmake` 使用，互不干扰。

---

## 九、支持的 NDK 版本

| NDK 版本 | 状态 |
|----------|------|
| r26.x    | ✅ 已验证 |
| r25.x    | ✅ 支持 |
| r23–r24  | ⚠️ 未测试，理论支持 |
| r22 及以下 | ❌ 不支持（缺少 CMake launcher 机制）|

---

*ArmorComp v0.26.0 — 如有问题请联系技术支持*
