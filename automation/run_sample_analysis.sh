#!/bin/bash
#
# 简化的样本分析脚本 - 直接调用Python分析工具
#

# 确保在正确的目录中运行
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT" || { echo "无法切换到项目根目录"; exit 1; }

# 检查参数
if [ "$#" -lt 1 ]; then
    echo "用法: $0 <样本路径> [输出目录]"
    echo "例如: $0 samples/any/test.exe output/test_results"
    exit 1
fi

SAMPLE_PATH="$1"
OUTPUT_DIR=""

# 如果提供了输出目录
if [ "$#" -ge 2 ]; then
    OUTPUT_DIR="$2"
fi

# 检查样本文件是否存在
if [ ! -f "$SAMPLE_PATH" ]; then
    echo "错误: 样本文件不存在: $SAMPLE_PATH"
    exit 1
fi

# 创建日志目录
mkdir -p logs

# 设置日志文件
LOG_FILE="logs/analysis_$(date +%Y%m%d_%H%M%S).log"

echo "开始分析样本: $SAMPLE_PATH"
echo "日志文件: $LOG_FILE"

# 执行分析
if [ -z "$OUTPUT_DIR" ]; then
    echo "运行不带输出目录的分析..."
    python3 advanced_malware_analysis.py -v "$SAMPLE_PATH" 2>&1 | tee "$LOG_FILE"
else
    echo "运行带输出目录的分析: $OUTPUT_DIR"
    python3 advanced_malware_analysis.py -v -o "$OUTPUT_DIR" "$SAMPLE_PATH" 2>&1 | tee "$LOG_FILE"
fi

# 检查执行结果
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo "分析成功完成. 查看日志文件获取详情: $LOG_FILE"
    exit 0
else
    echo "分析失败. 查看日志文件获取错误详情: $LOG_FILE"
    exit 1
fi