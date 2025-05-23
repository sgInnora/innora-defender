# Innora-Defender: 技术架构

[English](./PROJECT_OVERVIEW.md) | **中文**

## 概述

Innora-Defender是一个全面的勒索软件检测、分析和恢复模块，旨在与Innora-Sentinel网络安全平台集成。本文档概述了系统的技术架构、关键组件和工作流程。

## 系统架构

Innora-Defender采用模块化架构，具有以下核心组件：

```
┌─────────────────────────────────────────────────────────────┐
│                      Innora-Defender                        │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐    │
│  │ 收集与分类   │   │   分析       │   │  响应与      │    │
│  │              │   │   管道       │   │  恢复        │    │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘    │
│         │                  │                  │            │
│  ┌──────V───────┐   ┌──────V───────┐   ┌──────V───────┐    │
│  │   沙箱       │   │  AI 检测     │   │   恢复       │    │
│  │   执行       │   │   引擎       │   │   引擎       │    │
│  └──────────────┘   └──────────────┘   └──────────────┘    │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐    │
│  │    内存      │   │   行为       │   │    YARA      │    │
│  │    分析      │   │   分析       │   │   生成器     │    │
│  └──────────────┘   └──────────────┘   └──────────────┘    │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                    集成层                            │  │
│  │                                                       │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────┐  │  │
│  │  │ Sentinel   │  │  威胁      │  │ 外部工具      │  │  │
│  │  │    API     │  │  情报      │  │ 集成          │  │  │
│  │  └────────────┘  └────────────┘  └────────────────┘  │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 关键组件

#### 1. 收集与分类

- **样本收集**：安全获取和存储勒索软件样本
- **初步评估**：快速静态分析以确定文件类型和潜在风险
- **优先级分配**：根据潜在影响和检测置信度对样本进行分类

#### 2. 分析管道

- **静态分析**：无需执行的代码和结构分析
- **动态分析**：在隔离环境中监控执行
- **家族检测**：识别特定勒索软件家族
- **加密分析**：确定加密算法和技术
- **行为分析**：记录系统更改和网络活动

#### 3. 响应与恢复

- **解密工具**：针对已知勒索软件家族的专用解密工具
- **密钥恢复**：从内存或网络流量中提取加密密钥的技术
- **文件恢复**：恢复加密文件的方法
- **YARA规则生成**：为安全工具创建检测签名
- **报告**：详细的分析报告和恢复建议

#### 4. 集成层

- **Sentinel API**：与Innora-Sentinel平台集成
- **威胁情报**：连接外部威胁数据源
- **外部工具集成**：与第三方安全工具的接口

## 技术工作流程

### 分析工作流程

1. **样本接收**
   - 样本注册和哈希计算
   - 初步静态分析和元数据提取
   - 基于风险评估的优先级划分

2. **详细分析**
   - 代码、字符串和文件结构的静态分析
   - 在沙箱环境中控制执行
   - 执行期间的内存分析
   - 网络流量捕获和分析
   - 勒索软件家族识别

3. **结果处理**
   - 加密算法确定
   - 漏洞评估
   - 恢复方法识别
   - 检测规则生成
   - 报告编制

### 恢复工作流程

1. **评估阶段**
   - 识别勒索软件家族和变种
   - 确定加密算法和技术
   - 定位潜在恢复向量（内存中的密钥、实现缺陷）

2. **恢复策略**
   - 选择适当的解密方法
   - 从内存、文件或网络流量中提取密钥（如果可能）
   - 通过样本解密验证密钥有效性

3. **文件恢复**
   - 对加密文件应用解密程序
   - 恢复后验证文件完整性
   - 记录成功的恢复方法

## 与Innora-Sentinel集成

Innora-Defender通过多个接口与Innora-Sentinel平台集成：

1. **API集成**
   - 用于样本提交和结果检索的RESTful API
   - 分析完成的Webhook通知
   - 用于实时分析更新的流式API

2. **共享数据模型**
   - 通用威胁情报格式
   - 共享样本数据库
   - 统一报告结构

3. **协调响应**
   - 编排事件响应工作流程
   - 自动遏制行动
   - 恢复程序自动化

## 部署选项

Innora-Defender支持多种部署场景：

1. **集成部署**
   - 与Innora-Sentinel平台完全集成
   - 共享资源和数据库
   - 单一管理界面

2. **独立部署**
   - 独立运行，可选择与Sentinel集成
   - 自包含数据库和处理
   - 基于API与其他系统通信

3. **混合部署**
   - 核心组件与Sentinel集成
   - 专门的分析节点单独部署
   - 分布式处理，集中管理

## 性能考量

- **资源要求**：高内存（16GB+）和CPU（8+核心）以进行有效分析
- **存储要求**：500GB+用于样本存储和分析产物
- **网络要求**：隔离网络段用于恶意软件执行
- **可扩展性**：通过分布式分析节点进行水平扩展
- **吞吐量**：在推荐硬件上每天能处理100+个样本

## 安全措施

- **样本隔离**：所有样本都在隔离环境中处理
- **数据保护**：敏感产物和结果加密
- **访问控制**：基于角色的功能和数据访问
- **审计日志**：全面记录所有系统活动
- **安全通信**：组件之间的加密通信

## 未来发展

Innora-Defender的路线图包括：

1. **增强AI检测**
   - 改进机器学习模型以检测新变种
   - 零日勒索软件识别的异常检测

2. **高级恢复技术**
   - 扩展对其他勒索软件家族的支持
   - 用于密钥恢复的新密码分析方法

3. **扩展集成**
   - 更多威胁情报源
   - 与更多安全工具和平台集成

4. **性能优化**
   - 通过硬件优化加速分析
   - 高容量环境的分布式处理

---

© 2025 Innora-Sentinel安全团队 | 保留所有权利 | [https://innora.ai](https://innora.ai)