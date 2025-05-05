#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
集成测试：错误模式检测器与流式引擎的集成测试
测试EnhancedErrorPatternDetector与StreamingEngine的集成功能
"""

import os
import sys
import unittest
import tempfile
import json
from unittest.mock import patch, MagicMock, mock_open

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from decryption_tools.streaming_engine import StreamingEngine, BatchProcessingResult
from decryption_tools.enhanced_error_pattern_detector import EnhancedErrorPatternDetector

class TestIntegratedErrorDetection(unittest.TestCase):
    """测试错误模式检测器与流式引擎的集成功能"""
    
    def setUp(self):
        """设置测试环境"""
        self.streaming_engine = StreamingEngine()
        self.sample_files = [
            "/tmp/test1.encrypted",
            "/tmp/test2.encrypted",
            "/tmp/test3.encrypted",
            "/tmp/subfolder/test4.encrypted",
            "/tmp/subfolder/test5.encrypted"
        ]
        
        # 创建模拟的文件结果
        self.file_results = {
            "/tmp/test1.encrypted": {
                "status": "success",
                "output_file": "/tmp/test1.decrypted",
                "algorithm": "aes-256-cbc",
                "execution_time": 0.5
            },
            "/tmp/test2.encrypted": {
                "status": "error",
                "error": "Invalid key format: Key must be 32 bytes for AES-256",
                "execution_time": 0.2
            },
            "/tmp/test3.encrypted": {
                "status": "error",
                "error": "Operation timed out after 60 seconds",
                "execution_time": 60.1
            },
            "/tmp/subfolder/test4.encrypted": {
                "status": "error",
                "error": "Failed to open file: Permission denied",
                "execution_time": 0.1
            },
            "/tmp/subfolder/test5.encrypted": {
                "status": "error",
                "error": "Algorithm detection failed: Unknown encryption format",
                "execution_time": 1.2
            }
        }
        
        # 创建模拟的批处理结果
        self.batch_result = BatchProcessingResult()
        self.batch_result.total_files = len(self.sample_files)
        self.batch_result.processed_files = len(self.sample_files)
        self.batch_result.successful_files = 1
        self.batch_result.failed_files = 4
        self.batch_result.total_time = 62.1
        self.batch_result.file_results = self.file_results
        
    def test_error_pattern_analysis_integration(self):
        """测试错误模式分析与流式引擎的集成"""
        
        # 模拟batch_decrypt方法
        with patch.object(StreamingEngine, 'batch_decrypt') as mock_batch_decrypt:
            mock_batch_decrypt.return_value = self.batch_result
            
            # 调用带有错误模式分析的批处理
            batch_params = {
                "parallel_execution": True,
                "error_pattern_analysis": True,
                "max_workers": 4
            }
            
            result = self.streaming_engine.batch_decrypt(
                self.sample_files, 
                output_dir="/tmp/output",
                key="dummy_key",
                batch_params=batch_params
            )
            
            # 验证结果包含增强错误分析
            self.assertIn("enhanced_error_analysis", result.__dict__)
            self.assertIsNotNone(result.enhanced_error_analysis)
            
            # 验证错误分析包含预期的字段
            error_analysis = result.enhanced_error_analysis
            self.assertIn("error_patterns", error_analysis)
            self.assertIn("recommendations", error_analysis)
            self.assertIn("error_statistics", error_analysis)
            
            # 验证错误统计数据正确
            self.assertEqual(error_analysis["error_statistics"]["total_errors"], 4)
            
    def test_standalone_error_detection_with_batch_results(self):
        """测试独立使用错误检测器分析批处理结果"""
        
        # 创建错误模式检测器实例
        detector = EnhancedErrorPatternDetector()
        
        # 分析批处理结果
        error_analysis = detector.analyze_error_patterns(self.file_results)
        
        # 验证基本结构
        self.assertIsInstance(error_analysis, dict)
        self.assertIn("error_patterns", error_analysis)
        self.assertIn("recommendations", error_analysis)
        self.assertIn("error_statistics", error_analysis)
        
        # 验证检测到的错误模式
        patterns = error_analysis["error_patterns"]
        self.assertTrue(any("key format" in p["description"].lower() for p in patterns))
        self.assertTrue(any("timeout" in p["description"].lower() for p in patterns))
        self.assertTrue(any("permission" in p["description"].lower() for p in patterns))
        
        # 验证生成的建议
        recommendations = error_analysis["recommendations"]
        self.assertGreater(len(recommendations), 0)
        
    def test_error_pattern_detector_summary_generation(self):
        """测试错误模式检测器生成摘要报告"""
        
        # 创建错误模式检测器实例
        detector = EnhancedErrorPatternDetector()
        
        # 分析批处理结果
        error_analysis = detector.analyze_error_patterns(self.file_results)
        
        # 生成摘要
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            summary_path = temp_file.name
        
        # 模拟写入文件
        m = mock_open()
        with patch('builtins.open', m):
            detector.generate_error_analysis_summary(error_analysis, summary_path)
            
        # 验证文件写入被调用
        m.assert_called_once_with(summary_path, 'w', encoding='utf-8')
        handle = m()
        
        # 验证写入内容包含预期章节
        written_content = ''.join([call.args[0] for call in handle.write.call_args_list])
        self.assertIn("Error Pattern Analysis Summary", written_content)
        self.assertIn("Error Statistics", written_content)
        self.assertIn("Detected Error Patterns", written_content)
        self.assertIn("Recommendations", written_content)
        
        # 清理临时文件
        if os.path.exists(summary_path):
            os.unlink(summary_path)
            
    def test_error_analysis_disabled(self):
        """测试禁用错误分析时的行为"""
        
        # 模拟batch_decrypt方法
        with patch.object(StreamingEngine, 'batch_decrypt') as mock_batch_decrypt:
            mock_batch_decrypt.return_value = self.batch_result
            
            # 调用不带错误模式分析的批处理
            batch_params = {
                "parallel_execution": True,
                "error_pattern_analysis": False,
                "max_workers": 4
            }
            
            result = self.streaming_engine.batch_decrypt(
                self.sample_files, 
                output_dir="/tmp/output",
                key="dummy_key",
                batch_params=batch_params
            )
            
            # 验证结果不包含增强错误分析
            self.assertNotIn("enhanced_error_analysis", result.__dict__)

if __name__ == '__main__':
    unittest.main()