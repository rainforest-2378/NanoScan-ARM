# NanoScan-ARM

`NanoScan-ARM` 是一个基于 ARM NEON SIMD 指令集实现的极简高性能字符串匹配引擎。它通过向量化比对技术，能够在 ARM 架构（如 Apple Silicon M1/M2/M3）上实现远超传统逐字节扫描的匹配速度。

本项目旨在作为 **Hyperscan** 的极简 ARM 原生实现参考，适合学习 SIMD 编程、正则引擎原理及底层性能优化。

## 🌟 核心特性

- **SIMD 加速**：利用 128 位 NEON 寄存器，单次指令处理 16 个字符。
- **全向量化比对**：通过 `vceqq_u8` 与 `vandq_u8` 实现多字符连续匹配，彻底干掉 `strncmp`。
- **支持通配符**：原生支持正则表达式中的 `.` (点号) 通配符。
- **边界安全**：采用 Scalar Tail Handling 逻辑，确保任意长度字符串的完整覆盖，无越界风险。
- **工程化设计**：分离编译（Compile）与扫描（Scan）阶段，适配工业级使用场景。

## 📂 项目结构

- `include/`: API 定义与数据结构。
- `src/`: 核心逻辑实现（Compiler & Scanner）。
- `examples/`: 使用示例。
- `Makefile`: 针对 ARM 优化的自动化编译配置。

## 🚀 快速开始

### 1. 编译
在 Mac (M 芯片) 或其他 ARM 环境下，直接在根目录执行：
```bash
make
```

### 2. 运行示例
```bash
./nanoscan_demo
```

### 3. API 调用示例
```c
#include "nanoscan.h"

int main() {
    const char* text = "aim high, arm neon is powerful!";
    // 1. 编译模式 (支持通配符)
    ns_pattern_t* pat = ns_compile("a.m");
    
    // 2. 执行高速扫描
    ns_scan(pat, text, strlen(text));
    
    // 3. 释放资源
    ns_free(pat);
    return 0;
}
```

## 🛠 开发计划 (Roadmap)

- [x] 基于 NEON 的单模式固定字符串扫描
- [x] 支持 `.` 通配符
- [x] 跨 16 字节边界的完整覆盖逻辑
- [ ] 支持 `|` (OR) 逻辑的分支匹配
- [ ] 引入 Bit-parallel (Shift-And) 算法以支持更复杂的正则
- [ ] 实现针对大规模模式集的自动向量化调度

## 📜 许可证
MIT License
