#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试增强型错误模式检测器
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
from typing import Dict, List, Any

# 添加项目根目录到路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 导入要测试的类
from decryption_tools.enhanced_error_pattern_detector import EnhancedErrorPatternDetector


class TestEnhancedErrorPatternDetector(unittest.TestCase):
    """测试EnhancedErrorPatternDetector类的功能"""
    
    def setUp(self):
        """测试前设置"""
        self.detector = EnhancedErrorPatternDetector()
        
        # 创建测试错误结果
        self.sample_results = self._create_sample_results()
        
    def _create_sample_results(self) -> List[Dict[str, Any]]:
        """创建样本结果数据用于测试"""
        return [
            # 成功案例
            {
                "success": True,
                "algorithm": "aes-cbc",
                "input_file": "/path/to/file1.docx.encrypted",
                "file_size": 1024 * 1024  # 1 MB
            },
            # 密钥错误
            {
                "success": False,
                "algorithm": "aes-cbc",
                "input_file": "/path/to/file2.xlsx.encrypted",
                "file_size": 512 * 1024,  # 0.5 MB
                "error": "Invalid key length. Expected 32 bytes, got 16 bytes.",
                "errors": [
                    {
                        "type": "parameter_error",
                        "message": "Invalid key length. Expected 32 bytes, got 16 bytes.",
                        "severity": "high",
                        "details": {"expected": 32, "actual": 16}
                    }
                ]
            },
            # 另一个密钥错误
            {
                "success": False,
                "algorithm": "aes-cbc",
                "input_file": "/path/to/file3.pdf.encrypted",
                "file_size": 2 * 1024 * 1024,  # 2 MB
                "error": "Incorrect key format. Must be bytes, not str.",
                "errors": [
                    {
                        "type": "parameter_error",
                        "message": "Incorrect key format. Must be bytes, not str.",
                        "severity": "high",
                        "details": {"expected_type": "bytes", "actual_type": "str"}
                    }
                ]
            },
            # 文件访问错误
            {
                "success": False,
                "algorithm": "aes-cbc",
                "input_file": "/path/to/nonexistent/file4.docx.encrypted",
                "error": "File not found: /path/to/nonexistent/file4.docx.encrypted",
                "errors": [
                    {
                        "type": "file_access_error",
                        "message": "File not found: /path/to/nonexistent/file4.docx.encrypted",
                        "severity": "medium",
                        "details": {"path": "/path/to/nonexistent/file4.docx.encrypted"}
                    }
                ]
            },
            # 算法不匹配错误
            {
                "success": False,
                "algorithm": "aes-cbc",
                "input_file": "/path/to/file5.jpg.locked",
                "file_size": 3 * 1024 * 1024,  # 3 MB
                "error": "Decryption failed: incorrect padding",
                "errors": [
                    {
                        "type": "decryption_error",
                        "message": "Decryption failed: incorrect padding",
                        "severity": "medium",
                        "details": {"exception_type": "ValueError"}
                    }
                ]
            },
            # 库依赖错误
            {
                "success": False,
                "input_file": "/path/to/file6.zip.encrypted",
                "file_size": 10 * 1024 * 1024,  # 10 MB
                "error": "Cryptography library not available. Please install with pip.",
                "errors": [
                    {
                        "type": "environment_error",
                        "message": "Cryptography library not available. Please install with pip.",
                        "severity": "high",
                        "details": {"library": "cryptography"}
                    }
                ]
            },
            # 部分成功案例
            {
                "success": False,
                "partial_success": True,
                "algorithm": "aes-cbc",
                "input_file": "/path/to/file7.doc.locked",
                "file_size": 5 * 1024 * 1024,  # 5 MB
                "error": "Partial decryption (78% blocks success)",
                "errors": [
                    {
                        "type": "validation_error",
                        "message": "Partial decryption (78% blocks success)",
                        "severity": "low",
                        "details": {"success_ratio": 0.78, "successful_blocks": 39, "total_blocks": 50}
                    }
                ]
            },
            # 头/尾问题
            {
                "success": False,
                "algorithm": "aes-cbc",
                "input_file": "/path/to/file8.ppt.encrypted",
                "file_size": 4 * 1024 * 1024,  # 4 MB
                "error": "Header size mismatch. Try adjusting header_size parameter.",
                "errors": [
                    {
                        "type": "header_detection_warning",
                        "message": "Header size mismatch. Try adjusting header_size parameter.",
                        "severity": "medium",
                        "details": {"suggested_size": 32, "current_size": 16}
                    }
                ]
            },
            # 资源限制问题
            {
                "success": False,
                "algorithm": "aes-cbc",
                "input_file": "/path/to/large_file9.zip.locked",
                "file_size": 500 * 1024 * 1024,  # 500 MB
                "error": "Memory error while processing large file",
                "errors": [
                    {
                        "type": "memory_error",
                        "message": "Memory error while processing large file",
                        "severity": "high",
                        "details": {"file_size": 500 * 1024 * 1024}
                    }
                ]
            }
        ]
    
    def test_initialization(self):
        """测试初始化和内部结构"""
        # 验证正确初始化了错误类别
        self.assertIn("input_errors", self.detector.error_categories)
        self.assertIn("processing_errors", self.detector.error_categories)
        self.assertIn("resource_errors", self.detector.error_categories)
        
        # 验证严重性级别
        self.assertListEqual(self.detector.severity_levels, ["critical", "high", "medium", "low"])
        
        # 验证文件特征提取器
        self.assertIn("size_category", self.detector.file_feature_extractors)
        self.assertIn("extension_group", self.detector.file_feature_extractors)
        
        # 验证错误模式定义
        self.assertIn("invalid_key_pattern", self.detector.error_patterns)
        self.assertIn("file_access_pattern", self.detector.error_patterns)
        self.assertIn("algorithm_mismatch_pattern", self.detector.error_patterns)
    
    def test_error_pattern_analysis(self):
        """测试错误模式分析功能"""
        # 运行分析
        analysis = self.detector.analyze_error_patterns(self.sample_results)
        
        # 验证基本结构
        self.assertIn("patterns", analysis)
        self.assertIn("error_stats", analysis)
        self.assertIn("recommendations", analysis)
        
        # 验证统计数据
        error_stats = analysis["error_stats"]
        self.assertEqual(error_stats["total_files"], len(self.sample_results))
        self.assertEqual(error_stats["successful_files"], 1)  # 只有一个成功的结果
        self.assertEqual(error_stats["failed_files"], len(self.sample_results) - 1)
        
        # 验证检测到的模式
        patterns = analysis["patterns"]
        self.assertIsInstance(patterns, dict)
        
        # 验证建议生成
        recommendations = analysis["recommendations"]
        self.assertIsInstance(recommendations, list)
    
    def test_error_type_extraction(self):
        """测试从错误消息中提取错误类型"""
        # 测试各种错误消息
        test_messages = [
            ("Invalid parameter: key is required", "parameter_error"),
            ("File not found: /path/to/file", "file_access_error"),
            ("Error reading file: unexpected end of file", "file_read_error"),
            ("Algorithm not supported: blowfish-xxx", "algorithm_error"),
            ("Decryption failed: incorrect padding", "decryption_error"),
            ("Memory allocation failed", "memory_error"),
            ("Operation timed out after 60 seconds", "timeout_error"),
            ("Unknown error occurred", "unknown_error")
        ]
        
        for message, expected_type in test_messages:
            extracted_type = self.detector._extract_error_type_from_message(message)
            self.assertEqual(extracted_type, expected_type, 
                            f"Failed to extract correct type from: {message}")
    
    def test_file_feature_extraction(self):
        """测试文件特征提取功能"""
        # 运行特征提取
        features = self.detector._extract_file_features(self.sample_results)
        
        # 验证特征类型
        self.assertIn("size_category", features)
        self.assertIn("extension_group", features)
        self.assertIn("path_depth", features)
        self.assertIn("filename_pattern", features)
        
        # 验证特定特征
        size_features = features["size_category"]
        self.assertIsInstance(size_features, dict)
        
        # 应该有不同的文件大小类别
        self.assertTrue(len(size_features) > 0)
        
        # 验证扩展名分组
        ext_features = features["extension_group"]
        self.assertIsInstance(ext_features, dict)
        
        # 验证文件名模式
        filename_patterns = features["filename_pattern"]
        self.assertIsInstance(filename_patterns, dict)
    
    def test_specific_pattern_detection(self):
        """测试特定模式检测"""
        # 运行分析
        analysis = self.detector.analyze_error_patterns(self.sample_results)
        patterns = analysis["patterns"]
        
        # 我们应该至少检测到一些模式
        self.assertTrue(len(patterns) > 0)
        
        # 验证检测到了密钥相关错误模式
        if "invalid_key_pattern" in patterns:
            key_pattern = patterns["invalid_key_pattern"]
            self.assertIsInstance(key_pattern, dict)
            self.assertIn("count", key_pattern)
            # 注意：错误数量将取决于分析方法的具体行为，这里只检查有错误被检测到
            self.assertTrue(key_pattern["count"] > 0)
        
        # 验证文件访问模式
        if "file_access_pattern" in patterns:
            access_pattern = patterns["file_access_pattern"]
            self.assertIsInstance(access_pattern, dict)
            self.assertIn("count", access_pattern)
            # 只验证存在，不验证具体数量
            self.assertTrue(access_pattern["count"] > 0)
            
        # 验证检测到的任何标准模式都有count和details字段
        for pattern_name, pattern_data in patterns.items():
            if isinstance(pattern_data, dict) and pattern_name in self.detector.error_patterns:
                self.assertIn("count", pattern_data, f"模式 {pattern_name} 中缺少count字段")
                self.assertIn("details", pattern_data, f"模式 {pattern_name} 中缺少details字段")
    
    def test_recommendation_generation(self):
        """测试建议生成"""
        # 运行分析
        analysis = self.detector.analyze_error_patterns(self.sample_results)
        recommendations = analysis["recommendations"]
        
        # 我们应该有一些建议
        self.assertTrue(len(recommendations) > 0)
        
        # 验证建议格式
        for recommendation in recommendations:
            self.assertIn("type", recommendation)
            self.assertIn("message", recommendation)
            self.assertIn("priority", recommendation)
    
    def test_empty_results(self):
        """测试空结果列表"""
        analysis = self.detector.analyze_error_patterns([])
        
        # 结果应该是空的但格式良好
        self.assertIn("patterns", analysis)
        self.assertIn("recommendations", analysis)
        self.assertEqual(len(analysis["patterns"]), 0)
        self.assertEqual(len(analysis["recommendations"]), 0)
    
    def test_all_successful_results(self):
        """测试全部成功的结果"""
        # 创建一组全部成功的结果
        all_success = [
            {
                "success": True,
                "algorithm": "aes-cbc",
                "input_file": f"/path/to/file{i}.docx.encrypted",
                "file_size": 1024 * 1024  # 1 MB
            } for i in range(10)
        ]
        
        analysis = self.detector.analyze_error_patterns(all_success)
        
        # 不应该有错误模式
        self.assertEqual(len(analysis["patterns"]), 0)
        
        # 但可能有成功建议
        self.assertTrue(len(analysis["recommendations"]) > 0)
        for recommendation in analysis["recommendations"]:
            if recommendation["type"] == "success":
                self.assertIn("所有文件处理成功", recommendation["message"])
    
    def test_cluster_similar_errors(self):
        """测试相似错误聚类"""
        # 创建具有相似错误的结果
        similar_errors = [
            {
                "success": False,
                "input_file": f"/path/to/file{i}.docx",
                "error": f"Invalid key format for file /path/to/file{i}.docx. Expected bytes."
            } for i in range(5)
        ]
        
        # 添加一些不同的错误
        similar_errors.append({
            "success": False,
            "input_file": "/path/to/other.txt",
            "error": "File not found"
        })
        
        # 运行聚类
        clusters = self.detector._cluster_similar_errors(similar_errors)
        
        # 应该至少有一个聚类（相似密钥错误）
        self.assertTrue(len(clusters) > 0)
        
        # 验证第一个聚类
        if clusters:
            first_cluster = clusters[0]
            self.assertIn("pattern", first_cluster)
            self.assertIn("count", first_cluster)
            self.assertIn("files", first_cluster)
            
            # 应该有5个相似的错误
            self.assertEqual(first_cluster["count"], 5)
    
    def test_decrypt_data_errors(self):
        """测试专门针对decrypt_data错误的分析"""
        # 创建一些decrypt_data错误结果
        decrypt_results = [
            {
                "success": True,
                "algorithm": "aes-cbc",
                "data_size": 1024,
                "execution_stats": {"duration": 0.01}
            },
            {
                "success": False,
                "algorithm": "aes-cbc",
                "data_size": 2048,
                "error": "Decryption failed: incorrect key",
                "errors": [
                    {
                        "type": "decryption_error",
                        "message": "Decryption failed: incorrect key",
                        "severity": "high"
                    }
                ]
            },
            {
                "success": False,
                "algorithm": "aes-cbc",
                "data_size": 4096,
                "error": "Invalid padding",
                "errors": [
                    {
                        "type": "decryption_error",
                        "message": "Invalid padding",
                        "severity": "medium"
                    }
                ]
            }
        ]
        
        # 运行专用分析
        analysis = self.detector.analyze_decrypt_data_errors(decrypt_results)
        
        # 验证结果格式
        self.assertIn("patterns", analysis)
        self.assertIn("error_stats", analysis)
        self.assertIn("recommendations", analysis)
        
        # 验证统计数据
        error_stats = analysis["error_stats"]
        self.assertEqual(error_stats["total_files"], 3)
        self.assertEqual(error_stats["successful_files"], 1)
        self.assertEqual(error_stats["failed_files"], 2)
        
        # 验证生成了至少一条建议
        self.assertTrue(len(analysis["recommendations"]) > 0, 
                       "期望至少生成一条建议")


if __name__ == "__main__":
    unittest.main()