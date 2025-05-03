# 增强型勒索软件检测系统

本文档提供了增强型勒索软件检测系统的全面概述，该系统包括家族检测、变种分析、实时监控和可视化功能。

## 系统组件

增强型勒索软件检测系统由四个主要组件组成：

1. **增强型家族检测**
   - 多特征分析，实现精确的家族识别
   - 带置信度评分的分层分类
   - 包含技术细节的全面家族定义
   - 集成YARA规则用于检测签名

2. **自动变种检测**
   - 特征提取和相似度匹配，用于新变种的识别
   - 基于聚类的变种识别分析
   - 自动家族定义生成
   - 变种特征分析

3. **实时监控与集成**
   - 持续样本处理和分析
   - 新变种的自动警报
   - 与跟踪系统集成（JIRA、Slack、MISP）
   - 提供与其他系统集成的API

4. **关系可视化**
   - 家族关系的交互式图形可视化
   - 变种之间的相似度分析
   - 基于特征的关系检测
   - 基于D3.js的网页可视化

## 目录结构

```
threat_intel/
├── family_detection/                # 家族检测组件
│   ├── enhanced_family_detector.py  # 增强型家族检测器
│   ├── auto_variant_detector.py     # 自动变种检测器
│   ├── integration.py               # 基础集成
│   ├── integration_with_variant.py  # 完整集成
│   ├── cli.py                       # 家族检测命令行界面
│   └── variant_cli.py               # 变种检测命令行界面
├── monitoring/                      # 监控组件
│   ├── realtime_monitor.py          # 实时监控系统
│   ├── tracking_integration.py      # 跟踪系统集成
│   ├── api.py                       # REST API
│   ├── monitoring_cli.py            # 监控命令行界面
│   └── tracking_handlers/           # 跟踪系统处理器
│       ├── __init__.py
│       └── jira_handler.py          # JIRA集成处理器
├── visualization/                   # 可视化组件
│   ├── relationship_graph.py        # 关系图生成器
│   └── graph_cli.py                 # 图形可视化命令行界面
├── correlation/                     # 关联组件
│   ├── correlation_engine.py        # 基础关联引擎
│   └── correlation_engine_patch.py  # 增强型关联引擎
└── data/                            # 数据存储
    ├── families/                    # 家族定义
    ├── variant_clusters/            # 变种聚类
    ├── visualization/               # 可视化输出
    ├── reports/                     # 报告文件
    ├── alerts/                      # 警报文件
    └── stats/                       # 统计文件
```

## 文档

- [增强型家族检测](ENHANCED_FAMILY_DETECTION.md)
- [自动变种检测](AUTO_VARIANT_DETECTION.md)
- [实时勒索软件监控](REALTIME_RANSOMWARE_MONITORING.md)
- [勒索软件关系图](RANSOMWARE_RELATIONSHIP_GRAPH.md)

## 使用方法

### 家族检测

```bash
# 识别勒索软件家族
python -m threat_intel.family_detection.cli identify --sample /path/to/sample.json

# 列出可用家族
python -m threat_intel.family_detection.cli list

# 显示家族详情
python -m threat_intel.family_detection.cli show --family lockbit
```

### 变种检测

```bash
# 处理样本进行变种检测
python -m threat_intel.family_detection.variant_cli process --sample /path/to/sample.json

# 批量处理样本
python -m threat_intel.family_detection.variant_cli batch --samples-dir /path/to/samples

# 列出变种聚类
python -m threat_intel.family_detection.variant_cli list

# 显示聚类详情
python -m threat_intel.family_detection.variant_cli show --cluster lockbit_variant_123

# 生成变种定义
python -m threat_intel.family_detection.variant_cli generate
```

### 实时监控

```bash
# 启动监控系统
python -m threat_intel.monitoring.monitoring_cli start

# 显示当前状态
python -m threat_intel.monitoring.monitoring_cli status

# 处理样本
python -m threat_intel.monitoring.monitoring_cli process /path/to/sample.json

# 监控目录中的新样本
python -m threat_intel.monitoring.monitoring_cli monitor /path/to/samples

# 运行REST API服务器
python -m threat_intel.monitoring.monitoring_cli server

# 停止监控系统
python -m threat_intel.monitoring.monitoring_cli stop
```

### 关系可视化

```bash
# 生成关系图
python -m threat_intel.visualization.graph_cli generate --format html --open-browser

# 列出可用的家族和变种
python -m threat_intel.visualization.graph_cli list --show-variants

# 分析变种之间的相似性
python -m threat_intel.visualization.graph_cli similarities

# 分析特定变种
python -m threat_intel.visualization.graph_cli variant --variant-name lockbit_variant_20230101
```

## 与现有系统集成

增强型勒索软件检测系统与现有的关联引擎集成：

```python
from threat_intel.correlation.correlation_engine_patch import EnhancedCorrelationEngine

# 创建增强型引擎
engine = EnhancedCorrelationEngine(
    families_dir="/path/to/families",
    yara_rules_dir="/path/to/yara_rules"
)

# 关联样本
result = engine.correlate_sample(sample_data)
```

## API访问

系统提供REST API以便与其他系统集成：

```python
import requests

# 获取检测状态
response = requests.get("http://localhost:5000/api/status")
status = response.json()

# 提交样本
response = requests.post("http://localhost:5000/api/sample", json=sample_data)
result = response.json()

# 获取家族详情
response = requests.get("http://localhost:5000/api/family/lockbit")
family = response.json()

# 获取变种聚类
response = requests.get("http://localhost:5000/api/variants?min_confidence=0.7")
variants = response.json()
```

## 特性与功能

### 增强型家族检测

- 多维度特征分析
- 家族识别的置信度评分
- 支持家族变种和版本
- 技术细节和恢复建议
- 与YARA规则集成用于检测签名
- 针对勒索软件特定属性的自定义特征

### 自动变种检测

- 特征向量提取和相似度匹配
- 基于聚类的变种识别方法
- 聚类验证的内聚度和相似度阈值
- 自动显著特征提取
- 为新变种生成家族定义
- 检测签名生成（YARA规则）

### 实时监控

- 持续样本处理和分析
- 批处理以实现高效资源使用
- 新变种的自动警报
- 与跟踪系统集成
- 用于程序化访问的REST API
- 用于手动操作的命令行界面
- 维护和统计收集

### 关系可视化

- 交互式图形可视化
- 家族-变种关系映射
- 跨家族相似度检测
- 基于特征的关系分析
- 可自定义的可视化参数
- 导出为HTML或JSON格式
- 用于生成和分析的命令行界面

## 未来增强

- **机器学习增强**：整合基于ML的分类
- **时间线分析**：添加时间维度以跟踪演变
- **地理分析**：添加目标地理信息
- **威胁行为者归因**：将变种与已知威胁行为者关联
- **攻击向量分析**：包括感染向量信息
- **受害者行业目标**：按行业分析目标模式
- **分布式处理**：支持分布式样本处理
- **预测分析**：预测新变种的出现
- **高级可视化**：复杂关系的3D可视化

## 结论

增强型勒索软件检测系统为识别、分析、监控和可视化勒索软件家族和变种提供了全面的解决方案。它与现有关联引擎集成，并为不同用例提供多种接口，包括命令行工具、REST API和可视化功能。

系统的模块化设计允许轻松扩展和与其他系统集成，使其能够适应不断变化的勒索软件威胁。增强型家族检测、自动变种检测、实时监控和关系可视化的组合为勒索软件分析和响应提供了强大的工具。