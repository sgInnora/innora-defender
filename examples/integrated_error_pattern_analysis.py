#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
集成错误模式分析示例

演示如何在实际场景中使用StreamingEngine的集成错误模式分析功能。
本示例展示如何分析加密文件批处理中的错误模式，并生成有价值的洞察和建议。
"""

import os
import sys
import argparse
import json
import logging
from datetime import datetime

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from decryption_tools.streaming_engine import StreamingEngine
from decryption_tools.enhanced_error_pattern_detector import EnhancedErrorPatternDetector

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('integrated_error_analysis')

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='运行集成错误模式分析示例')
    parser.add_argument('--input_dir', type=str, required=True, 
                        help='包含加密文件的输入目录')
    parser.add_argument('--output_dir', type=str, required=True, 
                        help='解密文件的输出目录')
    parser.add_argument('--key_file', type=str,
                        help='包含解密密钥的文件（可选）')
    parser.add_argument('--key', type=str,
                        help='解密密钥（可选，与key_file二选一）')
    parser.add_argument('--pattern', type=str, default='*.encrypted',
                        help='文件匹配模式 (默认: *.encrypted)')
    parser.add_argument('--algorithm', type=str,
                        help='加密算法 (可选，如未指定则自动检测)')
    parser.add_argument('--max_workers', type=int, default=4,
                        help='并行工作线程数量 (默认: 4)')
    parser.add_argument('--summary_file', type=str,
                        help='错误分析摘要文件路径 (可选)')
    parser.add_argument('--standalone', action='store_true',
                        help='使用独立的错误模式分析而非集成分析')
    parser.add_argument('--recursive', action='store_true',
                        help='递归处理子目录')
    
    return parser.parse_args()

def get_encrypted_files(input_dir, pattern, recursive=False):
    """获取加密文件列表"""
    import glob
    
    if recursive:
        # 使用**递归匹配
        search_pattern = os.path.join(input_dir, '**', pattern)
        files = glob.glob(search_pattern, recursive=True)
    else:
        # 仅在指定目录中匹配
        search_pattern = os.path.join(input_dir, pattern)
        files = glob.glob(search_pattern)
    
    logger.info(f"找到{len(files)}个匹配文件")
    return files

def get_decryption_key(args):
    """从命令行参数获取解密密钥"""
    if args.key:
        return args.key
    elif args.key_file and os.path.exists(args.key_file):
        with open(args.key_file, 'r') as f:
            return f.read().strip()
    else:
        raise ValueError("必须提供解密密钥（使用--key或--key_file参数）")

def process_files_with_error_analysis(files, output_dir, key, args):
    """使用错误模式分析处理文件"""
    engine = StreamingEngine()
    
    # 准备批处理参数
    batch_params = {
        "parallel_execution": True,
        "auto_detect_algorithm": args.algorithm is None,
        "max_workers": args.max_workers,
        "continue_on_error": True,
        "error_pattern_analysis": not args.standalone,  # 使用集成分析或独立分析
    }
    
    # 如果指定了算法，添加到参数中
    if args.algorithm:
        batch_params["algorithm"] = args.algorithm
    
    # 执行批处理
    logger.info(f"开始批处理解密 {len(files)} 个文件...")
    result = engine.batch_decrypt(
        files,
        output_dir=output_dir,
        key=key,
        batch_params=batch_params
    )
    
    logger.info(f"批处理完成. 成功: {result.successful_files}, "
                f"失败: {result.failed_files}, "
                f"总时间: {result.total_time:.2f}秒")
    
    # 如果使用独立分析（非集成）
    if args.standalone and result.failed_files > 0:
        logger.info("执行独立错误模式分析...")
        detector = EnhancedErrorPatternDetector()
        error_analysis = detector.analyze_error_patterns(result.file_results)
        
        # 将独立分析添加到结果中，使后续处理一致
        result.enhanced_error_analysis = error_analysis
    
    return result

def display_error_analysis(result, summary_file=None):
    """显示错误分析结果并可选保存摘要"""
    if not hasattr(result, 'enhanced_error_analysis') or not result.enhanced_error_analysis:
        logger.warning("没有可用的错误分析结果")
        return
    
    analysis = result.enhanced_error_analysis
    
    # 显示错误统计
    print("\n===== 错误统计 =====")
    stats = analysis["error_statistics"]
    print(f"总错误数: {stats['total_errors']}")
    print(f"唯一错误类型数: {stats['unique_error_types']}")
    
    # 显示错误类型分布
    print("\n错误类型分布:")
    for error_type, count in stats.get("error_types", {}).items():
        if isinstance(error_type, str) and error_type != "total_errors" and error_type != "unique_error_types":
            print(f"  - {error_type}: {count}")
    
    # 显示检测到的错误模式
    print("\n===== 检测到的错误模式 =====")
    for i, pattern in enumerate(analysis["error_patterns"], 1):
        print(f"{i}. {pattern['description']}")
        print(f"   严重性: {pattern['severity']}")
        print(f"   影响文件数: {pattern['affected_files']}")
        print()
    
    # 显示建议
    print("\n===== 建议 =====")
    for i, rec in enumerate(analysis["recommendations"], 1):
        print(f"{i}. {rec}")
        print()
    
    # 如果指定了摘要文件，生成详细报告
    if summary_file:
        logger.info(f"生成错误分析摘要到 {summary_file}")
        detector = EnhancedErrorPatternDetector()
        detector.generate_error_analysis_summary(analysis, summary_file)
        print(f"\n详细分析报告已保存到: {summary_file}")

def main():
    """主函数"""
    args = parse_arguments()
    
    # 确保输出目录存在
    os.makedirs(args.output_dir, exist_ok=True)
    
    try:
        # 获取加密文件
        files = get_encrypted_files(args.input_dir, args.pattern, args.recursive)
        if not files:
            logger.error(f"在 {args.input_dir} 中没有找到匹配 {args.pattern} 的文件")
            return 1
        
        # 获取解密密钥
        key = get_decryption_key(args)
        
        # 确定摘要文件名
        summary_file = args.summary_file
        if not summary_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            summary_file = os.path.join(args.output_dir, f"error_analysis_{timestamp}.md")
        
        # 处理文件
        result = process_files_with_error_analysis(files, args.output_dir, key, args)
        
        # 显示错误分析
        display_error_analysis(result, summary_file)
        
        return 0
    
    except Exception as e:
        logger.exception(f"程序执行期间发生错误: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())