# Innora-Defender: 勒索软件检测与恢复模块

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

**Innora-Defender** 是一个全面的勒索软件检测、分析和恢复模块，作为 Innora-Sentinel 网络安全平台的核心组件。该系统通过静态分析、动态执行、内存取证和网络流量监控的组合，提供识别、分析和应对勒索软件威胁的高级功能。

### 核心功能

- **自动化勒索软件分析**：端到端工作流程，用于分析可疑的勒索软件样本
- **家族检测引擎**：高精度识别特定勒索软件家族
- **高级文件恢复**：专用工具，用于恢复已知勒索软件家族加密的文件
- **内存取证**：从内存转储中提取加密密钥和工件
- **网络密钥恢复**：分析网络流量以捕获加密密钥和命令与控制通信
- **AI增强检测**：使用机器学习模型识别新的勒索软件变种
- **威胁情报集成**：将发现与外部威胁情报源关联
- **YARA规则生成**：根据分析结果自动生成检测规则
- **勒索软件关系可视化**：显示不同勒索软件家族和变种之间的连接

## 项目结构

```
innora-defender/
├── ai_detection/              # 勒索软件检测的机器学习模型
├── behavior_analysis/         # 勒索软件行为的动态分析
├── decryption_tools/          # 加密文件恢复工具
├── memory_analysis/           # 用于密钥提取的内存取证
├── sandboxes/                 # 样本执行的隔离环境
├── threat_intel/              # 威胁情报集成组件
├── tools/                     # 各种分析功能的实用工具
├── utils/                     # 通用工具和辅助函数
└── docs/                      # 文档和技术指南
```

## 安装说明

### 前提条件

- Python 3.9 或更高版本
- 所需的Python包（参见 `requirements.txt`）
- 可选：Docker用于容器化执行

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

3. 配置系统：
   ```bash
   python -m setup.configure
   ```

## 使用方法

### 基本分析

```python
from innora_defender import RansomwareAnalyzer

# 初始化分析器
analyzer = RansomwareAnalyzer()

# 分析可疑文件
results = analyzer.analyze_file("path/to/suspicious_file")

# 打印分析结果
print(f"勒索软件家族: {results.family}")
print(f"检测置信度: {results.confidence}%")
print(f"加密算法: {results.encryption_algorithm}")
```

### 尝试解密

```python
from innora_defender import RecoveryEngine

# 初始化恢复引擎
recovery = RecoveryEngine()

# 尝试解密文件
success = recovery.attempt_decryption(
    encrypted_file="path/to/encrypted_file",
    output_file="path/to/recovered_file"
)

if success:
    print("文件成功恢复")
else:
    print("恢复失败")
```

### 内存分析

```python
from innora_defender import MemoryAnalyzer

# 初始化内存分析器
memory = MemoryAnalyzer()

# 从内存转储中提取加密密钥
keys = memory.extract_keys("path/to/memory.dmp")

print(f"找到 {len(keys)} 个潜在加密密钥")
```

## 与 Innora-Sentinel 的集成

Innora-Defender 旨在与 Innora-Sentinel 网络安全平台无缝集成：

- **API集成**：通过Sentinel API连接实现自动化分析
- **共享威胁情报**：向中央威胁情报数据库贡献并从中受益
- **协调响应**：通过Sentinel编排引擎触发自动响应操作
- **统一报告**：在Sentinel控制面板中集成报告

## 文档

详细文档请参见 `docs/` 目录：
- [技术架构](docs/PROJECT_OVERVIEW.md)
- [API参考](docs/IMPLEMENTATION_SUMMARY.md)
- [开发指南](docs/FUTURE_DEVELOPMENT_PLAN.md)
- [LockBit分析案例研究](docs/LOCKBIT_DECRYPTION_OPTIMIZATION.md)

## 贡献

欢迎贡献！请参阅 [CONTRIBUTING.md](CONTRIBUTING.md) 了解如何为此项目做出贡献的详细信息。

## 许可证

该项目根据MIT许可证授权 - 详情请参见 [LICENSE](LICENSE) 文件。

## 致谢

- 该项目整合了各种开源勒索软件分析工具的组件
- 特别感谢发布勒索软件技术研究成果的研究团队

## 安全

如果您发现任何与安全相关的问题，请发送电子邮件至 info@innora.ai，而不是使用问题跟踪器。

---

© 2025 Innora-Sentinel安全团队 | 保留所有权利 | [https://innora.ai](https://innora.ai)