#\!/bin/bash
# 勒索软件分析启动脚本

set -e

# 显示帮助
show_help() {
    echo "勒索软件分析启动脚本"
    echo "用法: $0 [选项] <样本文件>"
    echo ""
    echo "选项:"
    echo "  -h, --help              显示帮助信息"
    echo "  -o, --output-dir DIR    指定输出目录"
    echo "  -w, --work-dir DIR      指定工作目录"
    echo "  -v, --verbose           显示详细输出"
    echo "  -s, --static-only       仅执行静态分析"
    echo "  -c, --check-environment 检查环境是否正确配置"
    echo ""
    echo "示例:"
    echo "  $0 samples/suspicious.exe"
    echo "  $0 --output-dir results/analysis1 samples/suspicious.exe"
    echo "  $0 --static-only samples/suspicious.exe"
}

# 检查环境配置
check_environment() {
    echo "检查分析环境配置..."
    
    # 检查Python
    if command -v python3 >/dev/null 2>&1; then
        echo "[✓] Python 已安装"
        python3 --version
    else
        echo "[✗] 错误: 未找到 Python 3"
        exit 1
    fi
    
    # 检查必要的Python包
    echo "检查Python包..."
    required_packages=("cryptography" "numpy" "matplotlib")
    for package in "${required_packages[@]}"; do
        if python3 -c "import $package" >/dev/null 2>&1; then
            echo "[✓] 包已安装: $package"
        else
            echo "[✗] 警告: 未找到包 $package"
            echo "    可以使用以下命令安装: pip3 install $package"
        fi
    done
    
    # 检查必要工具
    echo "检查系统工具..."
    tools=("file" "strings" "xxd" "hexdump")
    for tool in "${tools[@]}"; do
        if command -v $tool >/dev/null 2>&1; then
            echo "[✓] 工具已安装: $tool"
        else
            echo "[✗] 警告: 未找到工具 $tool"
        fi
    done
    
    # 检查Docker（用于动态分析）
    if command -v docker >/dev/null 2>&1; then
        echo "[✓] Docker 已安装"
        docker --version
    else
        echo "[✗] 警告: 未找到 Docker，动态分析将受限"
    fi
    
    # 检查工具目录
    tool_dirs=("../tools/crypto" "../tools/static" "../tools/dynamic" "../tools/network")
    for dir in "${tool_dirs[@]}"; do
        if [ -d "$dir" ]; then
            echo "[✓] 工具目录存在: $dir"
        else
            echo "[✗] 警告: 工具目录不存在: $dir"
        fi
    done
    
    echo "环境检查完成"
}

# 初始化变量
SAMPLE_FILE=""
OUTPUT_DIR=""
WORK_DIR=""
VERBOSE=""
STATIC_ONLY=""

# 解析参数
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -o|--output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -w|--work-dir)
            WORK_DIR="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE="-v"
            shift
            ;;
        -s|--static-only)
            STATIC_ONLY="yes"
            shift
            ;;
        -c|--check-environment)
            check_environment
            exit 0
            ;;
        *)
            SAMPLE_FILE="$1"
            shift
            ;;
    esac
done

# 验证样本文件
if [ -z "$SAMPLE_FILE" ]; then
    echo "错误: 未提供样本文件"
    show_help
    exit 1
fi

if [ \! -f "$SAMPLE_FILE" ]; then
    echo "错误: 样本文件不存在: $SAMPLE_FILE"
    exit 1
fi

# 准备命令参数
CMD_ARGS=""

if [ \! -z "$OUTPUT_DIR" ]; then
    CMD_ARGS="$CMD_ARGS --output-dir $OUTPUT_DIR"
fi

if [ \! -z "$WORK_DIR" ]; then
    CMD_ARGS="$CMD_ARGS --work-dir $WORK_DIR"
fi

if [ \! -z "$VERBOSE" ]; then
    CMD_ARGS="$CMD_ARGS $VERBOSE"
fi

# 打印横幅
echo "============================================="
echo "    勒索软件自动化分析系统                  "
echo "============================================="
echo "样本文件: $SAMPLE_FILE"
echo "启动分析..."

# 检查静态分析模式
if [ \! -z "$STATIC_ONLY" ]; then
    echo "模式: 仅静态分析"
    
    # 这里可以添加静态分析特定的命令
    # 例如，只运行静态和加密分析工具
    
    python3 analyze_ransomware.py $CMD_ARGS "$SAMPLE_FILE"
else
    echo "模式: 完整分析"
    
    # 运行分析
    python3 analyze_ransomware.py $CMD_ARGS "$SAMPLE_FILE"
    
    # 提示用户关于动态分析的信息
    if [ -d "${OUTPUT_DIR:-analysis_$(basename "$SAMPLE_FILE")_*}/dynamic" ]; then
        echo ""
        echo "动态分析准备已完成。"
        echo "请查看动态分析目录以获取在隔离环境中运行样本的指南。"
        echo "警告: 只在安全隔离的环境中运行此样本\!"
    fi
fi

echo "分析完成。"
EOF < /dev/null