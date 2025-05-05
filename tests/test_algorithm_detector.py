#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试AlgorithmDetector类的强化错误处理能力

本测试关注以下方面：
1. 验证参数验证过程是否正确处理无效输入
2. 验证文件访问错误是否得到正确处理
3. 验证文件分析过程中的错误处理
4. 验证算法检测的健壮性
5. 验证结果结构的完整性
"""

import os
import sys
import unittest
import tempfile
from typing import Dict, Any

# 添加项目根目录到路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 导入被测模块
from decryption_tools.streaming_engine import AlgorithmDetector

class TestAlgorithmDetector(unittest.TestCase):
    """测试AlgorithmDetector类的错误处理能力"""
    
    def setUp(self):
        """测试前准备"""
        self.detector = AlgorithmDetector()
        
        # 创建临时测试文件
        self._create_test_files()
        
    def tearDown(self):
        """测试后清理"""
        # 删除临时文件
        for path in self.temp_files.values():
            if os.path.exists(path):
                try:
                    os.remove(path)
                except:
                    pass
    
    def _create_test_files(self):
        """创建不同类型的测试文件"""
        self.temp_files = {}
        
        # 1. 空文件
        empty_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_files['empty'] = empty_file.name
        empty_file.close()
        
        # 2. 带有RYUK标记的"加密"文件
        ryuk_file = tempfile.NamedTemporaryFile(delete=False)
        ryuk_file.write(b'RYUK' + os.urandom(100))  # 随机数据加RYUK标头
        self.temp_files['ryuk'] = ryuk_file.name
        ryuk_file.close()
        
        # 3. 带有LOCKBIT标记的"加密"文件
        lockbit_file = tempfile.NamedTemporaryFile(delete=False)
        lockbit_file.write(b'LOCKBIT' + os.urandom(100))
        self.temp_files['lockbit'] = lockbit_file.name
        lockbit_file.close()
        
        # 4. 普通随机数据文件（高熵值）
        random_file = tempfile.NamedTemporaryFile(delete=False)
        random_file.write(os.urandom(1024))
        self.temp_files['random'] = random_file.name
        random_file.close()
        
        # 5. "损坏"的文件（非常小文件）
        tiny_file = tempfile.NamedTemporaryFile(delete=False)
        tiny_file.write(b'ab')
        self.temp_files['tiny'] = tiny_file.name
        tiny_file.close()
        
    def test_invalid_file_input(self):
        """测试无效文件输入的错误处理"""
        # 1. 不存在的文件
        result = self.detector.detect_algorithm("/path/to/nonexistent/file.xyz", None)
        self.assertIn("errors", result)
        # 检查是否在错误中包含文件不存在信息
        self.assertTrue(any(
            err.get("type") == "file_access_error" and "不存在" in err.get("message", "")
            for err in result["errors"]
        ))
        
        # 2. 空文件
        result = self.detector.detect_algorithm(self.temp_files['empty'], None)
        # 检查是否将文件标记为过小
        self.assertTrue(result["params"].get("too_small", False))
        # 检查是否包含警告
        self.assertTrue(any(
            warn.get("type") == "file_too_small"
            for warn in result.get("warnings", [])
        ))
        
        # 3. 微小文件
        result = self.detector.detect_algorithm(self.temp_files['tiny'], None)
        # 检查是否将文件标记为过小
        self.assertTrue(result["params"].get("too_small", False))
        # 检查是否包含警告
        self.assertTrue(any(
            warn.get("type") == "file_too_small"
            for warn in result.get("warnings", [])
        ))
    
    def test_known_family_detection(self):
        """测试已知勒索家族的检测"""
        # 1. 使用已知家族名称
        result = self.detector.detect_algorithm(self.temp_files['random'], "ryuk")
        self.assertGreater(result["confidence"], 0.7)
        self.assertEqual(result["algorithm"], "aes-ecb")
        self.assertEqual(result.get("family"), "ryuk")
        
        # 2. 使用无效的家族名称
        result = self.detector.detect_algorithm(self.temp_files['random'], "invalid_family")
        self.assertLess(result["confidence"], 0.7)  # 置信度应该较低
        
        # 3. 使用None作为家族名称（不应报错）
        result = self.detector.detect_algorithm(self.temp_files['random'], None)
        self.assertIsNotNone(result)
        
        # 4. 使用非字符串家族名称（应优雅处理）
        result = self.detector.detect_algorithm(self.temp_files['random'], 123)
        self.assertIsNotNone(result)
        self.assertIn("errors", result)
    
    def test_file_signature_detection(self):
        """测试文件签名检测"""
        # 1. 测试RYUK标记检测
        result = self.detector.detect_algorithm(self.temp_files['ryuk'], None)
        self.assertGreater(result["confidence"], 0.9)
        self.assertEqual(result.get("family"), "ryuk")
        
        # 2. 测试LOCKBIT标记检测
        result = self.detector.detect_algorithm(self.temp_files['lockbit'], None)
        self.assertGreater(result["confidence"], 0.9)
        self.assertEqual(result.get("family"), "lockbit")
    
    def test_result_structure(self):
        """测试结果结构的完整性"""
        result = self.detector.detect_algorithm(self.temp_files['random'], None)
        
        # 确保结果包含所有必要字段
        self.assertIn("algorithm", result)
        self.assertIn("confidence", result)
        self.assertIn("params", result)
        self.assertIn("errors", result)
        
        # 确保params是字典
        self.assertIsInstance(result["params"], dict)
        
        # 确保errors是列表
        self.assertIsInstance(result["errors"], list)
        
    def test_error_recovery(self):
        """测试错误恢复能力"""
        # 尝试创建一个无法读取的文件
        unreadable_file = tempfile.NamedTemporaryFile(delete=False)
        unreadable_path = unreadable_file.name
        unreadable_file.close()
        
        # 在Windows上不太好模拟权限问题，所以我们删除文件来模拟
        os.remove(unreadable_path)
        open(unreadable_path, 'w').close()  # 创建空文件
        
        try:
            # 在某些系统上，我们无法可靠地创建"无法读取"的文件，所以这段代码可能会失败
            # 这里使用专门的无法读取的文件或目录可能会更可靠
            if os.path.exists(unreadable_path):
                result = self.detector.detect_algorithm(unreadable_path, None)
                # 应该能够处理错误并返回结果对象
                self.assertIsNotNone(result)
                self.assertIn("algorithm", result)
        finally:
            # 清理
            if os.path.exists(unreadable_path):
                try:
                    os.remove(unreadable_path)
                except:
                    pass

if __name__ == "__main__":
    unittest.main()