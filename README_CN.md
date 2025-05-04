# Innora-Defender: 高级勒索软件解密框架

<div align="center">
<p>
    <img width="140" src="screenshots/logo.png" alt="Innora-Defender logo">
</p>
<p>
    <b>Advanced Ransomware Analysis and Recovery System</b>
</p>
<p>
    <b>高级勒索软件分析与恢复系统</b>
</p>
</div>

---

[English](./README.md) | **中文**

## 项目概述

**Innora-Defender** 是一个全面的勒索软件解密框架，专注于帮助受害者在不支付赎金的情况下恢复文件。我们的系统结合了先进的密码分析、内存取证和二进制分析，以恢复加密密钥并解密受各种勒索软件家族影响的文件。

### 核心功能

- **专业解密工具**：业界领先的LockBit、BlackCat等主要勒索软件家族恢复工具
- **多阶段密钥恢复**：从内存、网络流量和二进制分析中提取加密密钥的高级技术
- **增强的文件格式分析**：智能恢复被损坏的文件和复杂的加密结构
- **内存取证**：利用高级模式识别从内存转储中提取加密密钥和工件
- **优化的恢复算法**：支持AES-CBC、ChaCha20和多种自定义加密方案
- **自动化家族检测**：高精度识别特定勒索软件家族，应用正确的解密技术
- **多勒索软件恢复框架**：处理不同勒索软件家族的统一方法
- **二进制分析工具**：识别勒索软件实现中的弱点，实现解密
- **部分恢复能力**：即使在无法完全解密的情况下也能恢复数据

## 项目结构

```
innora-defender/
├── decryption_tools/          # 勒索软件特定解密工具
├── tools/                     # 分析和恢复工具
│   ├── crypto/                # 密码分析工具
│   ├── memory/                # 用于密钥提取的内存取证
│   ├── static/                # 二进制分析工具
├── threat_intel/              # 勒索软件家族信息
├── utils/                     # 通用工具和辅助函数
└── docs/                      # 文档和技术指南
```

## 安装说明

### 前提条件

- Python 3.9 或更高版本
- 所需的Python包（参见 `requirements.txt`）
- 可选：内存分析工具（Volatility）

### 设置步骤

1. 克隆仓库：
   ```bash
   git clone https://github.com/sgInnora/innora-defender.git
   cd innora-defender
   ```

2. 安装依赖项：
   ```bash
   pip install -r requirements.txt
   ```

## 使用方法

### LockBit解密

```python
from decryption_tools.network_forensics.lockbit_optimized_recovery import OptimizedLockBitRecovery

# 初始化优化的LockBit恢复模块
recovery = OptimizedLockBitRecovery()

# 解密单个加密文件
success = recovery.decrypt_file(
    encrypted_file="path/to/encrypted_file.docx.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}",
    output_file="path/to/recovered_file.docx"
)

if success:
    print("文件成功解密")

# 批量解密多个文件
results = recovery.batch_decrypt(
    encrypted_files=["file1.xlsx.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}", "file2.pdf.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}"],
    output_dir="recovered_files"
)

# 导出成功的密钥供将来使用
recovery.export_successful_keys("lockbit_successful_keys.json")
```

### 多勒索软件恢复

```python
from decryption_tools.multi_ransomware_recovery import MultiRecoveryOrchestrator

# 初始化恢复协调器
recovery = MultiRecoveryOrchestrator()

# 尝试解密文件（自动勒索软件家族检测）
result = recovery.decrypt_file(
    encrypted_file="path/to/encrypted_file",
    output_file="path/to/recovered_file"
)

print(f"解密成功: {result['success']}")
print(f"勒索软件家族: {result['family']}")
print(f"使用方法: {result['method']}")
```

### 基于内存的密钥提取

```python
from tools.memory.key_extractors.advanced_memory_key_extractor import AdvancedMemoryKeyExtractor

# 初始化高级内存密钥提取器
extractor = AdvancedMemoryKeyExtractor()

# 从内存转储中提取加密密钥，可选择提供勒索软件家族提示
keys = extractor.scan_memory_dump(
    memory_path="path/to/memory.dmp",
    ransomware_family="lockbit"  # 可选的家族提示
)

for key in keys:
    print(f"找到密钥: {key['data'].hex()[:16]}... (置信度: {key['confidence']:.2f})")
    print(f"算法: {key['algorithm']}, 偏移量: {key['offset']}")
```

### 二进制分析

```python
from tools.static.binary_analyzer import RansomwareBinaryAnalyzer

# 初始化二进制分析器
analyzer = RansomwareBinaryAnalyzer()

# 分析勒索软件二进制文件
results = analyzer.analyze_binary("path/to/ransomware_sample")

# 打印分析结果
print(f"检测到的算法: {results['static_analysis']['crypto']['detected_algorithms']}")
print(f"发现的弱点: {len(results['weaknesses'])}")
print(f"潜在密钥: {len(results['potential_keys'])}")
```

## 文档

详细文档请参见 `docs/` 目录：

### 解密文档
- [LockBit解密优化](docs/LOCKBIT_DECRYPTION_OPTIMIZATION.md) - 关于我们业界领先的LockBit恢复技术详情
- [增强解密能力计划](docs/DECRYPTION_CAPABILITIES_PLAN.md) - 多家族解密支持路线图
- [未来发展计划](docs/FUTURE_DEVELOPMENT_PLAN_CN_UPDATED.md) - 聚焦解密能力的更新计划

### 技术文档
- [勒索软件关系图](docs/RANSOMWARE_RELATIONSHIP_GRAPH.md) - 勒索软件家族间连接可视化
- [实现概要](docs/IMPLEMENTATION_SUMMARY_CN.md) - 项目技术概述
- [项目概览](docs/PROJECT_OVERVIEW_CN.md) - 架构和设计原则

### 机器学习文档
- [机器学习增强](docs/MACHINE_LEARNING_ENHANCEMENT_CN.md) - 基于AI的检测能力
- [机器学习增强更新日志](docs/MACHINE_LEARNING_ENHANCEMENT_UPDATE_LOG_CN.md) - 机器学习改进历史

## 测试与质量保证

我们对代码维持严格的质量标准，特别是针对安全关键组件：

### 覆盖率要求与状态

- **安全关键模块**：最低95%测试覆盖率
  - ✅ YARA增强生成器：95%覆盖率
  - ✅ LockBit优化恢复：96%覆盖率
  - ⚠️ YARA集成：87%覆盖率（进行中）
  - ⚠️ YARA命令行：78%覆盖率（进行中）
- **核心组件**：最低90%测试覆盖率
- **工具模块**：最低80%测试覆盖率

### 运行测试

```bash
# 运行所有测试
python tests/run_all_tests.py

# 运行YARA测试并测量覆盖率
python tests/run_yara_tests.py

# 为特定模块运行增强测试
python tests/run_enhanced_tests.py --module lockbit
python tests/run_enhanced_tests.py --module yara

# 验证安全关键模块的覆盖率
tests/check_security_coverage.sh
```

### 测试覆盖率可视化

我们的综合测试套件包括对关键操作的性能测量：

```
大文件分析：0.50秒
熵计算：处理1,049,397字节需要0.20秒
字符串特征提取：处理大文件需要0.03秒
规则优化：处理1,000个特征<0.01秒
```

### 设置Git钩子

我们提供Git钩子以确保提交前的代码质量：

```bash
# 安装Git钩子
./install_git_hooks.sh
```

这将安装一个前置提交钩子，在允许提交前检查安全关键模块的覆盖率。

有关我们测试方法的更多信息，请参阅：
- [维护测试覆盖率](docs/MAINTAINING_TEST_COVERAGE.md)
- [测试覆盖率报告](test_coverage_report.md)
- [YARA覆盖率改进](tests/FINAL_COVERAGE_REPORT.md)
- [测试覆盖率改进计划](tests/TEST_COVERAGE_IMPROVEMENT_PLAN.md)

## 贡献

欢迎贡献！请参阅 [CONTRIBUTING.md](CONTRIBUTING.md) 了解如何为此项目做出贡献的详细信息。

## 许可证

该项目根据MIT许可证授权 - 详情请参见 [LICENSE](LICENSE) 文件。

## 安全

如果您发现任何与安全相关的问题，请发送电子邮件至 info@innora.ai，而不是使用问题跟踪器。

---

© 2025 Innora-Sentinel安全团队 | 保留所有权利 | [https://innora.ai](https://innora.ai)