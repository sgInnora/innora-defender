#\!/bin/bash
# 综合勒索软件监控脚本
# 用法: ./monitor_ransomware.sh <样本路径> [监控目录]

set -e

# 默认参数
SAMPLE_PATH=""
MONITOR_DIR="/tmp/ransomware_testdir"
LOG_DIR="/logs"
TARGET_PID=""

# 解析参数
if [ $# -lt 1 ]; then
    echo "用法: $0 <样本路径> [监控目录]"
    exit 1
fi

SAMPLE_PATH="$1"

if [ \! -f "$SAMPLE_PATH" ]; then
    echo "错误: 样本文件不存在: $SAMPLE_PATH"
    exit 1
fi

if [ $# -ge 2 ]; then
    MONITOR_DIR="$2"
fi

# 创建监控目录
mkdir -p "$MONITOR_DIR"

# 准备测试文件
echo "准备测试目录: $MONITOR_DIR"
for i in {1..10}; do
    # 创建文本文件
    echo "这是测试文件 $i 的内容。此文件用于监控勒索软件加密行为。" > "$MONITOR_DIR/testfile_$i.txt"
    
    # 创建Office文档模拟文件
    echo "DOCX文件内容模拟" > "$MONITOR_DIR/document_$i.docx"
    echo "XLSX文件内容模拟" > "$MONITOR_DIR/spreadsheet_$i.xlsx"
    echo "PPTX文件内容模拟" > "$MONITOR_DIR/presentation_$i.pptx"
    
    # 创建PDF模拟文件
    echo "%PDF-1.5" > "$MONITOR_DIR/document_$i.pdf"
    echo "模拟PDF文件内容" >> "$MONITOR_DIR/document_$i.pdf"
    echo "%%EOF" >> "$MONITOR_DIR/document_$i.pdf"
    
    # 创建图片模拟文件
    dd if=/dev/urandom bs=1024 count=10 > "$MONITOR_DIR/image_$i.jpg" 2>/dev/null
done

# 创建子目录
mkdir -p "$MONITOR_DIR/important_files"
mkdir -p "$MONITOR_DIR/backup"

# 在子目录中创建文件
echo "重要文档1内容" > "$MONITOR_DIR/important_files/important1.txt"
echo "重要文档2内容" > "$MONITOR_DIR/important_files/important2.txt"
echo "备份文件内容" > "$MONITOR_DIR/backup/backup1.txt"

echo "测试文件已准备完成"

# 启动监控
echo "启动监控进程..."

# 启动文件监控
python3 file_monitor.py "$MONITOR_DIR" -d "$LOG_DIR" -i 2 &
FILE_MONITOR_PID=$\!
echo "文件监控已启动，PID: $FILE_MONITOR_PID"

# 准备执行样本
echo "准备执行样本: $SAMPLE_PATH"
echo "将在3秒后启动样本..."
sleep 3

# 在子进程中执行样本文件，方便跟踪PID
(
    # 确定样本文件类型并执行
    file_type=$(file -b "$SAMPLE_PATH")
    
    if [[ $file_type == *"executable"* ]]; then
        # 可执行文件
        chmod +x "$SAMPLE_PATH"
        "$SAMPLE_PATH" &
    elif [[ $file_type == *"Python"* ]]; then
        # Python脚本
        python3 "$SAMPLE_PATH" &
    elif [[ $file_type == *"shell script"* ]]; then
        # Shell脚本
        bash "$SAMPLE_PATH" &
    elif [[ $file_type == *"DOS batch"* ]]; then
        # Windows批处理（在Linux下可能无法执行）
        echo "警告: 检测到Windows批处理文件，尝试使用Wine执行"
        wine cmd.exe /c "$SAMPLE_PATH" &
    else
        # 其他类型，假设为可执行文件尝试执行
        echo "警告: 未知文件类型: $file_type"
        echo "尝试直接执行文件..."
        chmod +x "$SAMPLE_PATH"
        "$SAMPLE_PATH" &
    fi
    
    # 获取样本PID
    SAMPLE_PID=$\!
    echo "$SAMPLE_PID" > /tmp/sample_pid.txt
    echo "样本已启动，PID: $SAMPLE_PID"
    
    # 等待样本执行
    wait $SAMPLE_PID
    echo "样本执行完成或中断"
) &

# 等待样本启动
sleep 2

# 获取样本PID
if [ -f /tmp/sample_pid.txt ]; then
    TARGET_PID=$(cat /tmp/sample_pid.txt)
    echo "获取到样本PID: $TARGET_PID"
    
    # 启动进程监控
    python3 process_monitor.py -p "$TARGET_PID" -d "$LOG_DIR" -i 1 &
    PROCESS_MONITOR_PID=$\!
    echo "进程监控已启动，PID: $PROCESS_MONITOR_PID"
else
    echo "警告: 无法获取样本PID，启动全系统进程监控"
    
    # 启动全系统进程监控
    python3 process_monitor.py -d "$LOG_DIR" -i 1 &
    PROCESS_MONITOR_PID=$\!
    echo "全系统进程监控已启动，PID: $PROCESS_MONITOR_PID"
fi

# 等待用户中断
echo "监控正在运行，按 CTRL+C 停止..."
trap "kill $FILE_MONITOR_PID $PROCESS_MONITOR_PID 2>/dev/null; echo '监控已停止'; exit 0" INT TERM

# 保持脚本运行
wait
EOF < /dev/null