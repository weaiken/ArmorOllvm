# ArmorComp

面向 Android NDK（aarch64）的 OLLVM 风格混淆工具，作为 LLVM 17 的独立插件运行，无需修改 LLVM 源码——只需构建并通过 `-fpass-plugin` 加载即可。

## 混淆 Pass

| Pass | 注解 | -passes= 名称 | 描述 |
|------|-----------|---------------|-------------|
| CFFPass | `annotate("cff")` | `armorcomp-cff` | 控制流扁平化 — 分发-switch 循环 |
| BCFPass | `annotate("bcf")` | `armorcomp-bcf` | 虚假控制流 — 不透明谓词的死分支 |
| OpaquePredicatePass | `annotate("op")` | `armorcomp-op` | 不透明谓词 — 6 种公式（P0–P2 永真，P3–P5 永假）死分支 |
| SubPass | `annotate("sub")` | `armorcomp-sub` | 指令替换（13 种 ADD/SUB/AND/OR/XOR 模式） |
| MBAPass | `annotate("mba")` | `armorcomp-mba` | 混合布尔算术重写（10 种公式） |
| SplitPass | `annotate("split")` | `armorcomp-split` | 基本块分裂 — 在 BCF/CFF 前膨胀 CFG |
| StrEncPass | `annotate("strenc")` | `armorcomp-strenc` | 字符串加密 — XOR 密文 + ctor 解密器 |
| GlobalEncPass | `annotate("genc")`（在使用的函数上） | `armorcomp-genc` | 整数全局加密 — XOR 加密 `i8/i16/i32/i64` 初始化器，注入 ctor 解密器 |
| IndirectCallPass | `annotate("icall")` | `armorcomp-icall` | 间接调用 — 不透明指针隐藏调用目标 |
| IndirectBranchPass | `annotate("ibr")` | `armorcomp-ibr` | 间接分支 — `indirectbr` 隐藏分支目标 |
| IndirectGlobalVariablePass | `annotate("igv")` | `armorcomp-igv` | 间接全局变量 — 代理指针隐藏全局变量引用 |
| SPOPass | `annotate("spo")` | `armorcomp-spo` | 栈指针混淆 — volatile sub/add SP 击败 IDA sp_delta 分析 |
| ConstObfPass | `annotate("co")` | `armorcomp-co` | 整数常量混淆 — XOR 密钥拆分隐藏所有数字字面量 |
| FuncWrapPass | `annotate("fw")` | `armorcomp-fw` | 函数包装混淆 — 内部转发函数隐藏真实调用者 |
| RetAddrObfPass | `annotate("rao")` | `armorcomp-rao` | 返回地址/调用帧混淆 — 在每个 call 前后使用 volatile sub/add SP |
| OutlinePass | `annotate("outline")` | `armorcomp-outline` | 基本块提取 — 每个非入口 BB 提取到 `__armorcomp_outline_N`（noinline + optnone） |
| FlattenDataFlowPass | `annotate("df")` | `armorcomp-df` | 数据流扁平化 — 将所有 alloca 合并到单个 `[N x i8]` 池中，使用混淆的 GEP 索引，击败 IDA/Ghidra 变量恢复 |
| DataEncodingPass | `annotate("denc")` | `armorcomp-denc` | 局部变量内存编码 — 在每个整数 alloca store/load 前后进行 XOR 编码/解码；栈中始终包含密文 |
| FuncSigObfPass | `annotate("fsig")` | `armorcomp-fsig` | 函数签名混淆 — 入口处假参数读取（x1/x2/x3）+ 出口处假返回值写入（x1/x2）；干扰 IDA Hex-Rays 原型分析 |
| DwarfPoisonPass | `annotate("dpoison")` | `armorcomp-dpoison` | DWARF CFI 表污染 — 入口、每个 BB 和每个 ret 处使用 `.cfi_remember_state` + 假 `def_cfa`（sp+524288, x15, x16）+ 未定义 LR/FP + `.cfi_restore_state`；击败 IDA 基于 `.eh_frame` 的 sp_delta 分析 |
| ConditionObfPass | `annotate("cob")` | `armorcomp-cob` | 比较混淆 — 向两个 `ICmpInst` 操作数添加不透明噪声 `mul(volatile_zero, K)`；IDA Hex-Rays 无法解析条件表达式 |
| NeonTypeConfusionPass | `annotate("ntc")` | `armorcomp-ntc` | AArch64 NEON/FP 类型混淆 — 入口/出口处的 `fmov` GPR↔SIMD 往返；IDA 类型推断将整数参数注解为 `float`/`double` |
| ReturnValueObfPass | `annotate("rvo")` | `armorcomp-rvo` | 返回值混淆 — 在 `ret` 前使用 `eor x0/w0, x0/w0, volatile_zero`；IDA 无法静态确定返回类型或值；目标无关的纯 IR |
| LRObfPass | `annotate("lro")` | `armorcomp-lro` | 链接寄存器混淆 — 在 `ret` 前使用 `eor x30, x30, volatile_zero`；IDA 无法解析返回地址 → 调用者引用变为 JUMPOUT()；仅 AArch64 |
| GEPObfPass | `annotate("gepo")` | `armorcomp-gepo` | GEP 索引混淆 — 通过 `getelementptr i8` 将 GEP 索引折叠为单个 XOR 混淆的字节偏移；击败 IDA 结构体字段识别、数组下标分析和虚表调度识别 |
| SwitchObfPass | `annotate("sob")` | `armorcomp-sob` | Switch 语句混淆 — 用密集跳转表 + `indirectbr` 替换 `SwitchInst`；表加载和 `br` 之间的 volatile XOR 击败 IDA switch 模式匹配器 |
| JunkCodePass | `annotate("jci")` | `armorcomp-jci` | 垃圾代码注入 — 每个 BB 包含死运算链（4–7 个 xor/or/and/shl/lshr/mul/add/sub 操作，volatile-zero 基，`asm sideeffect` 沉降）；击败 IDA Hex-Rays 反编译器清洁输出 |
| VMPPass | `annotate("vmp")` | `armorcomp-vmp` | 虚拟机保护 — 将 IR 提升到 64 寄存器的自定义字节码 VM；原函数被 fetch-decode-execute 分发器替换；算法对静态分析完全隐藏 |

自动运行顺序（注解模式，optimizer-last 入口点）：
`STRENC → GENC → VMP → SOB → SPLIT → SUB → MBA → COB → DENC → JCI → CO → GEPO → DF → OUTLINE → BCF → OP → CFF → RAO → ICALL → IBR → IGV → FW → FSIG → SPO → NTC → RVO → LRO → DPOISON`

每个 pass 也有 `-all` 变体（例如 `armorcomp-cff-all`），无需注解即可应用于每个函数。

---

## 构建

要求：LLVM 17（Homebrew `llvm@17`）、Android NDK、CMake ≥ 3.20、Ninja。

```bash
git clone <repo>
cd ArmorComp
cmake -B build -G Ninja
cmake --build build --target ArmorComp
# → build/libArmorComp.dylib
```

---

## 使用方法

### 方法一 — 源码注解

使用 `__attribute__((annotate("...")))` 标记单个函数。无需修改构建系统。

```c
// 对此函数应用 CFF + BCF + IGV
__attribute__((annotate("cff")))
__attribute__((annotate("bcf")))
__attribute__((annotate("igv")))
int verify_license(const char *key) {
    /* ... */
}

// 对使用字符串字面量的函数进行字符串加密
__attribute__((annotate("strenc")))
void init_keys(void) {
    const char *api = "SECRET_API_KEY";   // → 在二进制中加密
    /* ... */
}
```

编译：

```bash
clang -fpass-plugin=build/libArmorComp.dylib \
      -target aarch64-linux-android21 \
      --sysroot=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot \
      -O0 source.c -o output
```

---

### 方法二 — YAML 配置文件（无需修改源码）

通过 YAML 配置文件选择函数和 pass。无需 `__attribute__`。适用于保护第三方代码或无法修改源文件的情况。

#### 激活

在运行 clang 之前设置 `ARMORCOMP_CONFIG` 环境变量：

```bash
export ARMORCOMP_CONFIG=/path/to/armorcomp.yaml

clang -fpass-plugin=build/libArmorComp.dylib \
      -target aarch64-linux-android21 \
      --sysroot=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot \
      -O0 source.c -o output
```

> **为什么使用环境变量而不是 `-mllvm -armorcomp-config=...`？**
> clang 在 LLVM 后端初始化期间加载 `-fpass-plugin` DSO，这发生在
> `cl::ParseCommandLineOptions()` 已经运行**之后**。插件注册的 `cl::opt`
> 因此无法接收来自 `-mllvm` 标志的值。环境变量在第一次 pass 调用时读取，
> 那时 DSO 已加载完毕——没有顺序问题。

自动发现：如果未设置 `ARMORCOMP_CONFIG`，ArmorComp 会在当前工作目录中查找
`armorcomp.yaml`。

#### 配置文件格式

```yaml
# armorcomp.yaml

functions:
  # 规则 1 — 精确函数名
  - name: "verify_license"
    passes: [cff, bcf, sub, mba, icall, ibr, igv, rao, fw, spo]

  # 规则 2 — POSIX ERE 模式（建议锚定）
  - pattern: "^Java_"
    passes: [cff, bcf, icall, ibr]

  # 规则 3 — 保护名称包含 "secret" 的任何函数
  - pattern: "secret"
    passes: [strenc, split, sub, cff]
```

**字段：**

| 字段 | 类型 | 描述 |
|-------|------|-------------|
| `name` | 字符串 | 精确函数名。与 `pattern` 互斥。 |
| `pattern` | 字符串 | 与函数名匹配的 POSIX ERE。与 `name` 互斥。 |
| `passes` | 列表 | 要应用的 pass 名称。有效值：`cff bcf op sub mba cob split strenc genc denc jci icall ibr igv spo co gepo fw rao outline df fsig dpoison ntc rvo lro sob vmp` |

**评估规则：**

- 规则按**从上到下**评估；**第一个匹配的规则获胜**。
- 配置与 `__attribute__((annotate(...)))` 是**累加**的：如果注解或配置规则选择了 pass，函数就会被转换。
- 如果没有规则匹配且没有注解，函数保持不变。

#### 验证配置选择

加载配置时，插件会向 stderr 打印摘要：

```
[ArmorComp][Config] loaded 3 rule(s) from "/path/to/armorcomp.yaml"
[ArmorComp][BCF] obfuscated: verify_license
[ArmorComp][CFF] flattened:  verify_license
[ArmorComp][IGV] indirected: verify_license (4 accesses, 2 globals)
[ArmorComp][RAO] obfuscated: verify_license (N calls)
[ArmorComp][FW]  wrapped:    verify_license (N calls, M wrappers)
[ArmorComp][SPO] obfuscated: verify_license (1 ret(s))
```

未被任何规则匹配的函数不会产生混淆日志行。

---

## 测试目标

```bash
cmake --build build --target test-cff      # 控制流扁平化
cmake --build build --target test-bcf      # 虚假控制流
cmake --build build --target test-op       # 不透明谓词插入
cmake --build build --target test-sub      # 指令替换
cmake --build build --target test-mba      # 混合布尔算术
cmake --build build --target test-strenc   # 字符串加密
cmake --build build --target test-icall    # 间接调用
cmake --build build --target test-ibr      # 间接分支
cmake --build build --target test-igv      # 间接全局变量
cmake --build build --target test-spo      # 栈指针混淆（IDA sp 分析失败）
cmake --build build --target test-co       # 整数常量混淆（无裸立即数）
cmake --build build --target test-fw       # 函数包装混淆（调用图间接化）
cmake --build build --target test-rao      # 返回地址/调用帧混淆（每个 call 处 sp_delta UNKNOWN）
cmake --build build --target test-outline  # 基本块提取（__armorcomp_outline_N 辅助函数）
cmake --build build --target test-df       # 数据流扁平化（栈池合并）
cmake --build build --target test-genc     # 整数全局变量加密（ctor 解密器）
cmake --build build --target test-denc     # 整数局部变量内存编码（store/load XOR 包装）
cmake --build build --target test-fsig     # 函数签名混淆（IDA 原型分析失败）
cmake --build build --target test-dpoison  # DWARF CFI 表污染（通过 .eh_frame 的 sp_delta UNKNOWN）
cmake --build build --target test-cob      # 比较混淆（ICmpInst 噪声，IDA 条件无法解析）
cmake --build build --target test-ntc      # NEON/FP 类型混淆（fmov GPR↔SIMD，IDA float 类型注解）
cmake --build build --target test-rvo      # 返回值混淆（eor x0/w0，IDA 返回类型未知）
cmake --build build --target test-lro      # 链接寄存器混淆（eor x30，IDA 调用者引用破坏，仅 AArch64）
cmake --build build --target test-gepo     # GEP 索引混淆（字节偏移 XOR，IDA 结构/数组布局无法恢复）
cmake --build build --target test-sob      # Switch 混淆（密集跳转表 + indirectbr，IDA JUMPOUT）
cmake --build build --target test-jci      # 垃圾代码注入（每个 BB 的死运算链，额外 Hex-Rays 变量）
cmake --build build --target test-vmp      # 虚拟机保护（64 寄存器字节码 VM，分发器隐藏算法）
cmake --build build --target test-config   # YAML 配置文件（无注解）
```

每个目标编译对应的 `test/*.c` 文件到 ARM64 Android ELF。在设备/模拟器上运行；每个测试的预期输出以 `ALL TESTS PASSED` 结尾。

`test-config` 目标使用 `ARMORCOMP_CONFIG=test/config_test.yaml` 和
`test/config_test.c`，该文件**零** `__attribute__((annotate(...)))`——所有
混淆完全由 YAML 配置驱动。

---

## 组合两种方法

注解和配置规则可以协同工作。例如：配置保护项目中所有
`Java_*` 导出；单个函数通过注解添加额外层。

```yaml
# armorcomp.yaml — 项目级基线
functions:
  - pattern: "^Java_"
    passes: [cff, bcf, icall]
```

```c
// 在配置基线之上添加额外层
__attribute__((annotate("igv")))   // IGV 不在配置中 → 由注解添加
__attribute__((annotate("sub")))
JNIEXPORT jint JNICALL Java_com_example_App_verify(JNIEnv *env, jobject obj) {
    /* 来自配置的 cff+bcf+icall，来自注解的 igv+sub */
}
```
