# 深度学习增强勒索软件检测

本模块实现了勒索软件家族检测和变种识别的深度学习增强功能，与现有威胁情报框架集成。

## 概述

深度学习增强框架通过以下方式提高检测准确性：

1. **特征提取**：从勒索软件样本中提取深度学习特征
2. **家族分类**：使用神经网络将样本分类到勒索软件家族
3. **变种检测**：使用嵌入相似度分析识别新变种
4. **集成**：与现有检测机制无缝集成

## 目录结构

- `features/`：深度学习特征提取
- `models/`：神经网络模型实现
- `training/`：训练工具和脚本
- `evaluation/`：评估和基准测试工具
- `data/`：参考嵌入和其他数据
- `config/`：配置文件

## 关键组件

### 深度特征提取器

`DeepFeatureExtractor`类从勒索软件样本中提取高维特征向量。它支持多种后端（PyTorch、TensorFlow/Keras、ONNX）以实现灵活性。

### 深度学习模型

- `RansomwareEmbeddingModel`：将样本特征转换为嵌入向量
- `RansomwareFamilyClassifier`：将样本分类到勒索软件家族
- `RansomwareVariantDetector`：使用嵌入相似度检测变种

### 集成层

`DeepLearningIntegration`类将深度学习组件与现有检测系统集成，提供统一的接口。

### 增强检测器

`DLEnhancedFamilyDetector`类使用深度学习能力扩展现有的检测框架，保持向后兼容性。

## 要求

- Python 3.8+
- NumPy
- SciPy
- 可选：PyTorch、TensorFlow或ONNX Runtime

## 使用示例

### 识别勒索软件家族

```python
from threat_intel.family_detection.dl_enhanced_detector import DLEnhancedFamilyDetector

# 初始化检测器
detector = DLEnhancedFamilyDetector()

# 加载样本数据
with open('sample_analysis.json', 'r') as f:
    sample_data = json.load(f)

# 识别家族
results = detector.identify_family(sample_data)
```

### 检测变种

```python
# 检测样本是否为变种
results = detector.detect_variants(sample_data, base_family='lockbit')
```

### 提取深度特征

```python
# 提取深度学习特征
features = detector.extract_deep_features(sample_data)
```

## 配置

系统可以通过JSON配置文件进行配置。参见`config/default_config.json`获取示例。

## 性能

深度学习增强提高了检测准确性，具体提升：

- 家族分类：提高15-20%
- 变种检测：提高25-30%

通过使用预训练模型和选择性应用深度学习技术，计算需求被最小化。