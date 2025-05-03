#!/bin/bash
#
# 高级恶意软件分析自动化脚本
# 将样本分析集成到自动工作流中，并尝试自动解密
#

# 确保在正确的目录中运行
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT" || { echo "无法切换到项目根目录"; exit 1; }

# 显示帮助信息
show_help() {
    echo "高级恶意软件分析与自动解密工具"
    echo
    echo "用法: $0 [选项] <样本路径>"
    echo
    echo "选项:"
    echo "  -o, --output-dir <目录>  指定输出目录"
    echo "  -w, --work-dir <目录>    指定工作目录"
    echo "  -v, --verbose           启用详细日志"
    echo "  -h, --help              显示本帮助信息"
    echo
    echo "示例:"
    echo "  $0 /path/to/sample.exe"
    echo "  $0 -v -o /path/to/output /path/to/sample.exe"
}

# 解析命令行参数
OPTS=$(getopt -o o:w:vh --long output-dir:,work-dir:,verbose,help -n 'run_advanced_analysis.sh' -- "$@")
if [ $? != 0 ]; then echo "参数解析失败"; exit 1; fi

eval set -- "$OPTS"

VERBOSE=""
OUTPUT_DIR=""
WORK_DIR=""

while true; do
    case "$1" in
        -o | --output-dir ) OUTPUT_DIR="$2"; shift 2 ;;
        -w | --work-dir ) WORK_DIR="$2"; shift 2 ;;
        -v | --verbose ) VERBOSE="-v"; shift ;;
        -h | --help ) show_help; exit 0 ;;
        -- ) shift; break ;;
        * ) break ;;
    esac
done

# 检查是否提供了样本路径
if [ $# -ne 1 ]; then
    echo "错误: 请提供样本路径"
    show_help
    exit 1
fi

SAMPLE_PATH="$1"

# 检查样本文件是否存在
if [ ! -f "$SAMPLE_PATH" ]; then
    echo "错误: 样本文件不存在: $SAMPLE_PATH"
    exit 1
fi

# 构建命令参数
CMD_ARGS=""
if [ ! -z "$OUTPUT_DIR" ]; then
    CMD_ARGS="$CMD_ARGS -o \"$OUTPUT_DIR\""
fi
if [ ! -z "$WORK_DIR" ]; then
    CMD_ARGS="$CMD_ARGS -w \"$WORK_DIR\""
fi
if [ ! -z "$VERBOSE" ]; then
    CMD_ARGS="$CMD_ARGS $VERBOSE"
fi

# 创建目录
mkdir -p logs

# 运行高级分析
echo "开始高级恶意软件分析: $SAMPLE_PATH"
cmd_str="python3 advanced_malware_analysis.py"
[ ! -z "$VERBOSE" ] && cmd_str+=" $VERBOSE"
[ ! -z "$OUTPUT_DIR" ] && cmd_str+=" -o \"$OUTPUT_DIR\""
[ ! -z "$WORK_DIR" ] && cmd_str+=" -w \"$WORK_DIR\""
cmd_str+=" \"$SAMPLE_PATH\""
echo "命令: $cmd_str"

LOG_FILE="logs/analysis_$(date +%Y%m%d_%H%M%S).log"
echo "日志文件: $LOG_FILE"

# 执行分析
python3 advanced_malware_analysis.py $VERBOSE $([ ! -z "$OUTPUT_DIR" ] && echo "-o \"$OUTPUT_DIR\"") $([ ! -z "$WORK_DIR" ] && echo "-w \"$WORK_DIR\"") "$SAMPLE_PATH" 2>&1 | tee "$LOG_FILE"

# 检查执行结果
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo "分析成功完成. 查看日志文件了解详情: $LOG_FILE"
    exit 0
else
    echo "分析失败. 查看日志文件了解错误详情: $LOG_FILE"
    exit 1
fi