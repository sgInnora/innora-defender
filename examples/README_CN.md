# Innora-Defender 示例

本目录包含展示Innora-Defender项目各种功能的示例脚本。

## 可用示例

### 增强型错误模式分析

- [**integrated_error_pattern_analysis.py**](integrated_error_pattern_analysis.py): 演示增强型错误模式检测系统的端到端使用。此示例展示了如何以集成和独立模式使用系统，并提供各种命令行选项。

  ```bash
  # 使用集成分析
  python examples/integrated_error_pattern_analysis.py \
      --input_dir /path/to/encrypted/files \
      --output_dir /path/to/output \
      --key your_decryption_key \
      --recursive \
      --summary_file error_analysis.md
  ```

- [**enhanced_error_detection.py**](enhanced_error_detection.py): 一个专注于核心错误模式检测功能的实现，展示如何将EnhancedErrorPatternDetector与StreamingEngine一起使用。

### 自适应解密

- [**adaptive_decryption.py**](adaptive_decryption.py): 演示Innora-Defender项目的自适应解密功能，展示如何基于文件特征自动选择和应用最合适的解密算法。

## 使用指南

### 先决条件

在运行这些示例之前，请确保您：

1. 已安装所有必需的依赖项（参见main README.md）
2. 有用于测试的加密文件（或使用提供的测试文件）
3. 在适用的情况下有效的解密密钥

### 命令行选项

大多数示例脚本通过`--help`选项提供详细帮助：

```bash
python examples/integrated_error_pattern_analysis.py --help
```

### 输出格式

示例通常支持各种输出格式：

- 控制台输出用于即时反馈
- 详细的摘要文件（通常为Markdown格式）
- JSON输出用于程序化处理

## 集成到自定义工作流程

示例脚本旨在既有教育意义又实用。您可以通过以下方式将它们用作构建自定义解决方案的起点：

1. 复制并修改脚本以满足您的特定需求
2. 将核心功能导入到您自己的Python代码中
3. 将它们用作API使用模式的参考

## 文档

有关这些示例中演示的功能的更详细信息，请参阅以下文档：

- [增强型错误模式检测](../docs/ENHANCED_ERROR_PATTERN_DETECTION.md)
- [集成指南](../docs/集成指南.md)
- [端到端测试总结](../docs/端到端测试总结.md)
- [实现总结](../docs/实现总结_2025_05_06.md)

## 开发中的示例

未来的示例将包括：

- 多算法批处理
- 自定义错误模式检测
- 与外部报告工具集成
- 高级加密类型分析