# 增强型错误模式检测

## 概述

增强型错误模式检测是Innora-Defender的一项新特性，专为批量处理失败和复杂错误模式分析而设计。它提供了先进的错误聚类、模式识别和智能建议生成功能，帮助用户快速识别和解决大规模解密操作中的常见问题。

## 关键特性

### 1. 多维度错误分析

- **错误类型分类**：自动将错误归类为输入错误、处理错误、资源错误和数据错误
- **严重性分级**：按照critical、high、medium和low等级对错误进行分级
- **文件特征关联**：将错误与文件大小、扩展名、路径深度和名称模式等特征关联

### 2. 智能模式识别

- **预定义模式检测**：识别常见问题如密钥错误、算法不匹配、资源限制等
- **相似错误聚类**：自动聚类相似的错误消息，减少重复信息
- **特征相关性分析**：识别特定文件类型或大小与错误之间的相关性

### 3. 建议生成

- **针对性建议**：基于检测到的模式生成具体、可操作的解决方案
- **优先级排序**：按严重性和影响范围对建议进行排序
- **具体操作指导**：提供明确的参数调整和配置修改建议

## 使用方法

### 集成到StreamingEngine

增强型错误模式检测器已集成到StreamingEngine的批处理功能中，无需额外配置即可使用：

```python
from decryption_tools.streaming_engine import StreamingDecryptor

# 初始化流式解密器
decryptor = StreamingDecryptor()

# 批量解密文件
result = decryptor.batch_decrypt(
    file_mappings=[
        {"input": "file1.enc", "output": "file1.dec"},
        {"input": "file2.enc", "output": "file2.dec"},
        # 更多文件...
    ],
    algorithm="aes-cbc",
    key=key_bytes,
    batch_params={
        "parallel_execution": True,
        "error_pattern_analysis": True,  # 启用错误模式分析
        "save_summary": True,
        "summary_file": "batch_summary.json"
    }
)

# 错误模式分析结果将包含在summary文件和返回的结果中
if "error_insights" in result:
    patterns = result["error_insights"]["patterns"]
    recommendations = result["error_insights"]["recommendations"]
    
    print("\n推荐操作:")
    for i, rec in enumerate(recommendations, 1):
        print(f"{i}. {rec['message']} ({rec['priority']})")
```

### 独立使用

您也可以直接使用错误模式检测器分析任何错误结果集合：

```python
from decryption_tools.enhanced_error_pattern_detector import EnhancedErrorPatternDetector

# 初始化检测器
detector = EnhancedErrorPatternDetector()

# 分析错误结果（来自任何解密操作）
analysis = detector.analyze_error_patterns(file_results)

# 或分析decrypt_data操作的结果
decrypt_analysis = detector.analyze_decrypt_data_errors(decrypt_results)

# 处理分析结果
for pattern_name, pattern_data in analysis["patterns"].items():
    print(f"检测到模式: {pattern_name}")
    print(f"  影响文件数: {pattern_data.get('count', 0)}")
    print(f"  详情: {pattern_data.get('details', '')}")

print("\n建议:")
for rec in analysis["recommendations"]:
    print(f"- [{rec['priority']}] {rec['message']}")
```

## 支持的错误模式

增强型错误模式检测器可以识别以下常见模式：

1. **invalid_key_pattern**：密钥长度或格式不正确
2. **file_access_pattern**：文件访问权限或路径问题
3. **algorithm_mismatch_pattern**：算法与实际加密不匹配
4. **partial_decryption_pattern**：部分解密成功（可能是头/尾参数问题）
5. **library_dependency_pattern**：缺少必要的库依赖
6. **header_footer_pattern**：头/尾参数调整问题
7. **resource_limitation_pattern**：内存或超时限制问题

针对每种模式，检测器提供详细的错误统计、相关性分析和建议。

## 性能考虑

错误模式检测功能被设计为高效且轻量级，对正常操作的性能影响最小：

- 仅在批处理完成后执行分析，不影响解密过程
- 使用高效的文本分析和模式匹配算法
- 结果缓存避免重复计算
- 可随时启用或禁用，通过batch_params中的error_pattern_analysis参数控制

## 未来增强

计划中的功能增强包括：

1. **机器学习模型集成**：使用ML模型进一步优化错误模式检测
2. **历史数据分析**：跨多次运行分析错误模式，识别长期趋势
3. **可视化报告**：提供交互式错误模式可视化
4. **自适应解决方案**：根据历史成功率自动推荐最佳解决方案

## 结论

增强型错误模式检测为Innora-Defender带来了显著的用户体验提升，特别是在处理大规模解密任务时。通过自动识别错误模式并提供具体建议，它大大简化了故障排除过程，提高了解密操作的成功率和效率。