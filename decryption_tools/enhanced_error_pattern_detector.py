#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强型错误模式检测器

为StreamingDecryptor提供高级错误分析和模式检测功能，帮助识别批量处理中的共同问题和模式。
"""

import os
import re
import time
import logging
from typing import Dict, List, Any, Set, Tuple, Optional, Union
from collections import Counter, defaultdict

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("EnhancedErrorPatternDetector")

class EnhancedErrorPatternDetector:
    """
    增强型错误模式检测器
    
    检测批量处理中的错误模式，生成洞察和解决建议。支持深层次分析，
    包括文件特征关联、错误类型分析、路径模式识别等。
    """
    
    def __init__(self):
        """初始化错误模式检测器"""
        # 错误类型分类
        self.error_categories = {
            "input_errors": [
                "parameter_error", "file_access_error", "file_read_error", 
                "output_error", "environment_error"
            ],
            "processing_errors": [
                "algorithm_error", "decryption_error", "entropy_calculation_warning",
                "validation_error", "pattern_check_warning", "algorithm_pattern_warning",
                "header_detection_warning", "signature_check_warning"
            ],
            "resource_errors": [
                "resource_error", "memory_error", "timeout_error"
            ],
            "data_errors": [
                "malformed_data", "corrupt_file", "invalid_structure"
            ]
        }
        
        # 错误严重性级别
        self.severity_levels = ["critical", "high", "medium", "low"]
        
        # 常见文件特征分类
        self.file_feature_extractors = {
            "size_category": self._categorize_file_size,
            "extension_group": self._categorize_extension,
            "path_depth": self._extract_path_depth,
            "filename_pattern": self._extract_filename_pattern
        }
        
        # 常见错误模式和建议
        self.error_patterns = self._initialize_error_patterns()
    
    def analyze_error_patterns(self, file_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        分析批处理结果中的错误模式
        
        Args:
            file_results: 文件处理结果列表
            
        Returns:
            包含错误模式分析和建议的字典
        """
        if not file_results:
            return {"patterns": {}, "recommendations": []}
        
        # 收集基本错误统计
        error_stats = self._collect_error_statistics(file_results)
        
        # 提取文件特征
        file_features = self._extract_file_features(file_results)
        
        # 关联错误与文件特征
        correlations = self._correlate_errors_with_features(error_stats, file_features)
        
        # 识别高级错误模式
        patterns = self._identify_advanced_patterns(file_results, error_stats, correlations)
        
        # 生成建议
        recommendations = self._generate_recommendations(patterns, error_stats)
        
        return {
            "patterns": patterns,
            "error_stats": error_stats,
            "correlations": correlations,
            "recommendations": recommendations
        }
    
    def _collect_error_statistics(self, file_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        收集错误统计信息
        
        Args:
            file_results: 文件处理结果列表
            
        Returns:
            错误统计信息字典
        """
        # 统计基本计数
        total_files = len(file_results)
        successful_files = sum(1 for r in file_results if r.get("success", False))
        failed_files = sum(1 for r in file_results if not r.get("success", False))
        
        # 收集错误类型和计数
        error_types = defaultdict(int)
        error_messages = defaultdict(int)
        error_files = defaultdict(list)
        severity_counts = defaultdict(int)
        
        for result in file_results:
            if result.get("success", False):
                continue
                
            # 处理旧格式错误（简单字符串）
            if "error" in result and isinstance(result["error"], str):
                error_msg = result["error"]
                error_messages[error_msg] += 1
                error_files[error_msg].append(result.get("input_file", "unknown"))
                
                # 尝试从错误消息中提取类型
                error_type = self._extract_error_type_from_message(error_msg)
                error_types[error_type] += 1
                severity_counts["medium"] += 1  # 默认为中等严重性
            
            # 处理新格式错误（结构化列表）
            if "errors" in result and isinstance(result["errors"], list):
                for error in result["errors"]:
                    error_type = error.get("type", "unknown_error")
                    error_msg = error.get("message", "Unknown error")
                    severity = error.get("severity", "medium").lower()
                    
                    error_types[error_type] += 1
                    error_messages[error_msg] += 1
                    error_files[error_msg].append(result.get("input_file", "unknown"))
                    severity_counts[severity] += 1
        
        return {
            "total_files": total_files,
            "successful_files": successful_files,
            "failed_files": failed_files,
            "error_types": error_types,
            "error_messages": error_messages,
            "error_files": error_files,
            "severity_counts": severity_counts,
            "error_rate": failed_files / max(1, total_files) * 100
        }
    
    def _extract_file_features(self, file_results: List[Dict[str, Any]]) -> Dict[str, Dict[str, List[str]]]:
        """
        从文件结果中提取文件特征
        
        Args:
            file_results: 文件处理结果列表
            
        Returns:
            按特征类型组织的文件特征字典
        """
        features = {feature_name: {} for feature_name in self.file_feature_extractors}
        
        for result in file_results:
            input_file = result.get("input_file", "")
            if not input_file:
                continue
                
            for feature_name, extractor in self.file_feature_extractors.items():
                feature_value = extractor(input_file, result)
                
                if feature_value:
                    if feature_value not in features[feature_name]:
                        features[feature_name][feature_value] = []
                    features[feature_name][feature_value].append(input_file)
        
        return features
    
    def _correlate_errors_with_features(
        self, error_stats: Dict[str, Any], 
        file_features: Dict[str, Dict[str, List[str]]]
    ) -> Dict[str, Any]:
        """
        关联错误与文件特征
        
        Args:
            error_stats: 错误统计信息
            file_features: 文件特征信息
            
        Returns:
            错误与特征的相关性分析
        """
        correlations = {}
        
        # 遍历每种错误类型
        for error_type, count in error_stats["error_types"].items():
            if count <= 1:  # 忽略单一实例
                continue
                
            # 查找相关文件
            error_files = set()
            for error_msg, files in error_stats["error_files"].items():
                if self._error_message_matches_type(error_msg, error_type):
                    error_files.update(files)
            
            # 检查每种特征类型的相关性
            feature_correlations = {}
            for feature_name, feature_values in file_features.items():
                value_counts = {}
                for value, files in feature_values.items():
                    # 计算有多少错误文件具有此特征值
                    matching_files = error_files.intersection(files)
                    if matching_files:
                        value_counts[value] = len(matching_files)
                
                if value_counts:
                    # 按计数排序
                    sorted_values = sorted(value_counts.items(), key=lambda x: x[1], reverse=True)
                    feature_correlations[feature_name] = sorted_values
            
            correlations[error_type] = feature_correlations
        
        return correlations
    
    def _identify_advanced_patterns(
        self, file_results: List[Dict[str, Any]], 
        error_stats: Dict[str, Any],
        correlations: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        识别高级错误模式
        
        Args:
            file_results: 文件处理结果列表
            error_stats: 错误统计信息
            correlations: 错误与特征相关性
            
        Returns:
            高级错误模式分析
        """
        patterns = {}
        
        # 检查每种预定义的错误模式
        for pattern_name, pattern_info in self.error_patterns.items():
            detection_func = pattern_info.get("detection_function")
            if detection_func:
                match_result = detection_func(file_results, error_stats, correlations)
                if match_result:
                    patterns[pattern_name] = match_result
        
        # 聚类分析 - 查找相似的错误模式
        clustered_errors = self._cluster_similar_errors(file_results)
        if clustered_errors:
            patterns["error_clusters"] = clustered_errors
        
        # 文件特征分析 - 查找与特定文件特征相关的错误模式
        feature_related_errors = self._analyze_feature_related_errors(correlations)
        if feature_related_errors:
            patterns["feature_related_errors"] = feature_related_errors
        
        return patterns
    
    def _generate_recommendations(
        self, patterns: Dict[str, Any], 
        error_stats: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        基于错误模式生成建议
        
        Args:
            patterns: 检测到的错误模式
            error_stats: 错误统计信息
            
        Returns:
            建议列表
        """
        recommendations = []
        
        # 检查是否有任何模式匹配
        if not patterns and error_stats["failed_files"] == 0:
            recommendations.append({
                "type": "success",
                "message": "所有文件处理成功，无需调整。",
                "priority": "low"
            })
            return recommendations
        
        # 如果没有错误模式但有失败，提供通用建议
        if not patterns and error_stats["failed_files"] > 0:
            recommendations.append({
                "type": "general",
                "message": "处理中有失败但未检测到明确模式。检查单个文件错误详情获取更多信息。",
                "priority": "medium"
            })
        
        # 为每种识别到的模式生成特定建议
        for pattern_name, pattern_data in patterns.items():
            if pattern_name in self.error_patterns:
                pattern_info = self.error_patterns[pattern_name]
                
                # 使用模式信息生成建议
                recommendation = {
                    "type": pattern_name,
                    "message": pattern_info["recommendation_template"].format(**pattern_data),
                    "priority": pattern_info["priority"],
                    "details": pattern_data
                }
                
                recommendations.append(recommendation)
        
        # 按优先级排序建议
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        recommendations.sort(key=lambda x: priority_order.get(x["priority"], 4))
        
        return recommendations
    
    # 辅助方法
    
    def _initialize_error_patterns(self) -> Dict[str, Dict[str, Any]]:
        """初始化预定义的错误模式及其检测函数"""
        return {
            "invalid_key_pattern": {
                "description": "检测与密钥相关的错误模式",
                "detection_function": self._detect_invalid_key_pattern,
                "recommendation_template": "检测到多个密钥相关错误 ({count} 个文件)。检查密钥格式和长度是否正确。{details}",
                "priority": "high"
            },
            "file_access_pattern": {
                "description": "检测文件访问和权限问题",
                "detection_function": self._detect_file_access_pattern,
                "recommendation_template": "检测到文件访问问题 ({count} 个文件)。检查文件权限和路径是否正确。{details}",
                "priority": "medium"
            },
            "algorithm_mismatch_pattern": {
                "description": "检测算法不匹配问题",
                "detection_function": self._detect_algorithm_mismatch,
                "recommendation_template": "检测到算法不匹配问题 ({count} 个文件)。尝试使用自动检测功能或指定正确的算法。{details}",
                "priority": "high"
            },
            "partial_decryption_pattern": {
                "description": "检测部分解密成功情况",
                "detection_function": self._detect_partial_decryption,
                "recommendation_template": "检测到部分解密情况 ({count} 个文件)。可能是由于文件头/尾损坏或参数不完全匹配。{details}",
                "priority": "medium"
            },
            "library_dependency_pattern": {
                "description": "检测库依赖问题",
                "detection_function": self._detect_library_dependency_issues,
                "recommendation_template": "检测到缺少必要的库依赖 ({count} 个实例)。{details}",
                "priority": "high"
            },
            "header_footer_pattern": {
                "description": "检测文件头/尾参数问题",
                "detection_function": self._detect_header_footer_issues,
                "recommendation_template": "检测到文件头/尾参数问题 ({count} 个文件)。尝试调整header_size或footer_size参数。{details}",
                "priority": "medium"
            },
            "resource_limitation_pattern": {
                "description": "检测资源限制问题",
                "detection_function": self._detect_resource_limitations,
                "recommendation_template": "检测到资源限制问题 ({count} 个实例)。考虑减小批处理大小或增加可用资源。{details}",
                "priority": "medium"
            }
        }
    
    def _extract_error_type_from_message(self, error_msg: str) -> str:
        """从错误消息中提取错误类型"""
        lower_msg = error_msg.lower()
        
        # 检查输入错误
        if any(term in lower_msg for term in ["invalid", "missing", "parameter", "argument"]):
            return "parameter_error"
        elif any(term in lower_msg for term in ["file not found", "no such file", "access denied"]):
            return "file_access_error"
        elif any(term in lower_msg for term in ["read error", "cannot read", "reading file"]):
            return "file_read_error"
        elif any(term in lower_msg for term in ["write error", "cannot write", "output"]):
            return "output_error"
        elif any(term in lower_msg for term in ["environment", "library", "import", "not available"]):
            return "environment_error"
        
        # 检查处理错误
        elif any(term in lower_msg for term in ["algorithm", "cipher", "mode"]):
            return "algorithm_error"
        elif any(term in lower_msg for term in ["decrypt", "decryption", "padding", "incorrect key"]):
            return "decryption_error"
        elif any(term in lower_msg for term in ["validation", "verify", "invalid result"]):
            return "validation_error"
        elif any(term in lower_msg for term in ["header", "footer", "offset"]):
            return "header_detection_warning"
        
        # 检查资源错误
        elif any(term in lower_msg for term in ["memory", "allocation", "out of memory"]):
            return "memory_error"
        elif any(term in lower_msg for term in ["timeout", "timed out", "time limit", "too long"]):
            return "timeout_error"
        
        # 默认未知错误类型
        return "unknown_error"
    
    def _error_message_matches_type(self, error_msg: str, error_type: str) -> bool:
        """检查错误消息是否匹配指定错误类型"""
        # 直接在消息中查找类型名称
        if error_type.lower() in error_msg.lower():
            return True
            
        # 尝试提取消息中的错误类型并比较
        extracted_type = self._extract_error_type_from_message(error_msg)
        return extracted_type == error_type
    
    def _categorize_file_size(self, file_path: str, file_result: Dict[str, Any]) -> Optional[str]:
        """对文件大小进行分类"""
        # 尝试从结果中获取文件大小
        file_size = file_result.get("file_size", None)
        
        # 如果结果中没有，尝试从文件系统获取
        if file_size is None and os.path.exists(file_path):
            try:
                file_size = os.path.getsize(file_path)
            except (OSError, IOError):
                return None
        
        if file_size is None:
            return None
            
        # 分类文件大小
        if file_size < 10 * 1024:  # < 10 KB
            return "tiny"
        elif file_size < 1024 * 1024:  # < 1 MB
            return "small"
        elif file_size < 10 * 1024 * 1024:  # < 10 MB
            return "medium"
        elif file_size < 100 * 1024 * 1024:  # < 100 MB
            return "large"
        else:  # >= 100 MB
            return "huge"
    
    def _categorize_extension(self, file_path: str, file_result: Dict[str, Any]) -> Optional[str]:
        """对文件扩展名进行分类"""
        try:
            # 获取文件扩展名
            _, ext = os.path.splitext(file_path)
            ext = ext.lower()
            
            if not ext:
                return "no_extension"
                
            # 移除前导点
            if ext.startswith('.'):
                ext = ext[1:]
                
            # 对某些扩展名进行分组
            document_exts = {'doc', 'docx', 'pdf', 'txt', 'rtf', 'odt', 'md', 'tex'}
            spreadsheet_exts = {'xls', 'xlsx', 'csv', 'ods'}
            image_exts = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'svg', 'webp'}
            archive_exts = {'zip', 'rar', '7z', 'tar', 'gz', 'bz2'}
            database_exts = {'db', 'sqlite', 'mdb', 'accdb', 'sql'}
            
            if ext in document_exts:
                return "document"
            elif ext in spreadsheet_exts:
                return "spreadsheet"
            elif ext in image_exts:
                return "image"
            elif ext in archive_exts:
                return "archive"
            elif ext in database_exts:
                return "database"
            else:
                # 返回原始扩展名，如果它太少见，可能不会产生有用的模式
                return ext
                
        except Exception:
            return None
    
    def _extract_path_depth(self, file_path: str, file_result: Dict[str, Any]) -> Optional[str]:
        """提取文件路径深度"""
        try:
            # 使用规范路径
            norm_path = os.path.normpath(file_path)
            # 计算路径部分数
            parts = norm_path.split(os.sep)
            # 过滤空部分
            parts = [p for p in parts if p]
            depth = len(parts)
            
            # 返回深度范围
            if depth <= 2:
                return "shallow"
            elif depth <= 5:
                return "medium_depth"
            else:
                return "deep"
        except Exception:
            return None
    
    def _extract_filename_pattern(self, file_path: str, file_result: Dict[str, Any]) -> Optional[str]:
        """提取文件名模式"""
        try:
            # 获取文件名（不含路径）
            filename = os.path.basename(file_path)
            
            # 检查常见勒索软件加密文件命名模式
            if re.search(r'\.\w+\.[a-fA-F0-9-]{36}$', filename):
                return "ransomware_uuid_pattern"
            elif re.search(r'\.(encrypted|enc|locked|crypt)$', filename):
                return "generic_encrypted_extension"
            elif re.search(r'\.[a-zA-Z0-9]{4,10}$', filename) and '.' in filename[:-10]:
                return "double_extension"
            elif re.search(r'_locked$|_encrypted$|_crypted$', filename):
                return "encrypted_suffix"
            elif re.search(r'^\d{12,}_', filename):
                return "timestamp_prefix"
            else:
                return "normal_filename"
        except Exception:
            return None
    
    def _detect_invalid_key_pattern(
        self, file_results: List[Dict[str, Any]], 
        error_stats: Dict[str, Any],
        correlations: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """检测无效密钥模式"""
        # 搜索与密钥相关的错误
        key_related_errors = [
            count for error_type, count in error_stats["error_types"].items()
            if any(term in error_type.lower() for term in ["key", "decrypt", "parameter"])
        ]
        
        if not key_related_errors:
            return None
            
        key_error_count = sum(key_related_errors)
        
        # 如果超过10%的失败与密钥有关，认为是一个模式
        if key_error_count > 0.1 * error_stats["failed_files"]:
            return {
                "count": key_error_count,
                "percentage": key_error_count / max(1, error_stats["failed_files"]) * 100,
                "details": "可能是密钥长度不正确或格式不匹配（如十六进制字符串vs字节、Base64等）。"
            }
        
        return None
    
    def _detect_file_access_pattern(
        self, file_results: List[Dict[str, Any]], 
        error_stats: Dict[str, Any],
        correlations: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """检测文件访问模式问题"""
        # 搜索与文件访问相关的错误
        access_related_errors = [
            count for error_type, count in error_stats["error_types"].items()
            if any(term in error_type.lower() for term in ["access", "permission", "not found", "no such file"])
        ]
        
        if not access_related_errors:
            return None
            
        access_error_count = sum(access_related_errors)
        
        # 如果有显著数量的文件访问错误
        if access_error_count > 0.05 * error_stats["total_files"]:
            # 检查是否与特定路径深度相关
            path_depth_correlation = None
            if "file_access_error" in correlations:
                path_depths = correlations["file_access_error"].get("path_depth", [])
                if path_depths:
                    path_depth_correlation = path_depths[0]  # 最常见的路径深度
            
            return {
                "count": access_error_count,
                "percentage": access_error_count / max(1, error_stats["total_files"]) * 100,
                "path_correlation": path_depth_correlation,
                "details": "检查文件路径是否存在，以及程序是否有足够的权限访问这些文件。"
            }
        
        return None
    
    def _detect_algorithm_mismatch(
        self, file_results: List[Dict[str, Any]], 
        error_stats: Dict[str, Any],
        correlations: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """检测算法不匹配问题"""
        # 搜索与算法相关的错误
        algorithm_related_errors = [
            count for error_type, count in error_stats["error_types"].items()
            if any(term in error_type.lower() for term in ["algorithm", "decrypt", "padding", "mode"])
        ]
        
        if not algorithm_related_errors:
            return None
            
        algorithm_error_count = sum(algorithm_related_errors)
        
        # 检查算法错误是否集中在特定文件类型上
        extension_correlation = None
        if "algorithm_error" in correlations or "decryption_error" in correlations:
            for error_type in ["algorithm_error", "decryption_error"]:
                if error_type in correlations:
                    extensions = correlations[error_type].get("extension_group", [])
                    if extensions:
                        extension_correlation = extensions[0]  # 最常见的扩展名组
        
        if algorithm_error_count > 0.1 * error_stats["failed_files"]:
            details = "指定的算法可能与文件的实际加密方式不匹配。"
            
            if extension_correlation:
                ext_name, ext_count = extension_correlation
                details += f" {ext_count}个'{ext_name}'类型的文件有此问题。"
                
            return {
                "count": algorithm_error_count,
                "percentage": algorithm_error_count / max(1, error_stats["failed_files"]) * 100,
                "extension_correlation": extension_correlation,
                "details": details
            }
        
        return None
    
    def _detect_partial_decryption(
        self, file_results: List[Dict[str, Any]], 
        error_stats: Dict[str, Any],
        correlations: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """检测部分解密成功的情况"""
        # 计算部分成功的文件数
        partial_success_count = sum(1 for r in file_results 
                                  if r.get("partial_success", False) or r.get("partial", False))
        
        if partial_success_count == 0:
            return None
            
        # 检查是否与特定文件大小相关
        size_correlation = None
        for error_type, corr in correlations.items():
            sizes = corr.get("size_category", [])
            if sizes:
                size_correlation = sizes[0]  # 最常见的文件大小类别
                break
                
        return {
            "count": partial_success_count,
            "percentage": partial_success_count / max(1, error_stats["total_files"]) * 100,
            "size_correlation": size_correlation,
            "details": "这可能表明需要调整解密参数如header_size或使用recovery_threshold。"
        }
    
    def _detect_library_dependency_issues(
        self, file_results: List[Dict[str, Any]], 
        error_stats: Dict[str, Any],
        correlations: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """检测库依赖性问题"""
        # 搜索与环境或库相关的错误
        env_related_errors = [
            count for error_type, count in error_stats["error_types"].items()
            if any(term in error_type.lower() for term in ["environment", "library", "import", "module"])
        ]
        
        # 从错误消息中搜索库名称
        lib_names = set()
        for error_msg in error_stats["error_messages"]:
            lower_msg = error_msg.lower()
            if "library" in lower_msg or "import" in lower_msg or "module" in lower_msg:
                # 尝试提取库名称
                for lib in ["cryptography", "pycryptodome", "crypto", "numpy", "openssl"]:
                    if lib.lower() in lower_msg:
                        lib_names.add(lib)
        
        if not env_related_errors and not lib_names:
            return None
            
        env_error_count = sum(env_related_errors)
        
        if env_error_count > 0 or lib_names:
            details = f"缺少必要的库依赖。"
            if lib_names:
                details += f" 可能需要安装: {', '.join(lib_names)}"
                
            return {
                "count": env_error_count,
                "percentage": env_error_count / max(1, error_stats["total_files"]) * 100,
                "libraries": list(lib_names),
                "details": details
            }
        
        return None
    
    def _detect_header_footer_issues(
        self, file_results: List[Dict[str, Any]], 
        error_stats: Dict[str, Any],
        correlations: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """检测文件头/尾参数问题"""
        # 搜索与头部/尾部相关的错误
        header_related_errors = [
            count for error_type, count in error_stats["error_types"].items()
            if any(term in error_type.lower() for term in ["header", "footer", "offset", "padding"])
        ]
        
        header_mentions = sum(1 for msg in error_stats["error_messages"] 
                           if "header" in msg.lower() or "offset" in msg.lower())
        
        if not header_related_errors and header_mentions == 0:
            return None
            
        header_error_count = sum(header_related_errors) + header_mentions
        
        if header_error_count > 0:
            # 检查是否有算法相关性
            affected_extensions = []
            for error_type, corr in correlations.items():
                if "extension_group" in corr:
                    for ext, count in corr["extension_group"]:
                        affected_extensions.append((ext, count))
            
            details = "文件头/尾参数可能需要调整。"
            if affected_extensions:
                affected_extensions.sort(key=lambda x: x[1], reverse=True)
                ext_info = ", ".join(f"{ext} ({count}个)" for ext, count in affected_extensions[:3])
                details += f" 主要影响文件类型: {ext_info}"
                
            return {
                "count": header_error_count,
                "affected_extensions": affected_extensions[:3] if affected_extensions else [],
                "details": details
            }
        
        return None
    
    def _detect_resource_limitations(
        self, file_results: List[Dict[str, Any]], 
        error_stats: Dict[str, Any],
        correlations: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """检测资源限制问题"""
        # 搜索与资源相关的错误
        resource_related_errors = [
            count for error_type, count in error_stats["error_types"].items()
            if any(term in error_type.lower() for term in ["resource", "memory", "timeout", "overflow"])
        ]
        
        resource_mentions = sum(1 for msg in error_stats["error_messages"] 
                             if any(term in msg.lower() for term in 
                                   ["memory", "timeout", "too many", "resource", "limit"]))
        
        if not resource_related_errors and resource_mentions == 0:
            return None
            
        resource_error_count = sum(resource_related_errors) + resource_mentions
        
        # 检查是否与大文件相关
        size_correlation = None
        large_file_errors = 0
        for error_type, corr in correlations.items():
            if "size_category" in corr:
                for size, count in corr["size_category"]:
                    if size in ["large", "huge"]:
                        large_file_errors += count
                        size_correlation = (size, count)
        
        if resource_error_count > 0:
            details = "检测到资源限制问题。"
            
            if size_correlation:
                size_name, size_count = size_correlation
                details += f" {size_count}个{size_name}文件可能超出资源限制。"
                
            return {
                "count": resource_error_count,
                "large_file_errors": large_file_errors,
                "size_correlation": size_correlation,
                "details": details
            }
        
        return None
    
    def _cluster_similar_errors(self, file_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        聚类相似的错误消息
        
        Args:
            file_results: 文件处理结果列表
            
        Returns:
            相似错误聚类列表
        """
        # 收集所有错误消息
        all_errors = []
        for result in file_results:
            if not result.get("success", False):
                # 处理旧格式错误
                if "error" in result and isinstance(result["error"], str):
                    all_errors.append({
                        "message": result["error"],
                        "file": result.get("input_file", "unknown"),
                        "type": self._extract_error_type_from_message(result["error"])
                    })
                
                # 处理新格式错误
                if "errors" in result and isinstance(result["errors"], list):
                    for error in result["errors"]:
                        all_errors.append({
                            "message": error.get("message", "Unknown error"),
                            "file": result.get("input_file", "unknown"),
                            "type": error.get("type", "unknown_error"),
                            "severity": error.get("severity", "medium")
                        })
        
        if not all_errors:
            return []
            
        # 简化错误消息以便聚类
        def simplify_message(msg):
            # 移除具体文件路径、数字、十六进制值等
            simplified = re.sub(r'\/[\w\/\.-]+', '[PATH]', msg)
            simplified = re.sub(r'\b0x[0-9a-f]+\b', '[HEX]', simplified)
            simplified = re.sub(r'\b\d+\b', '[NUM]', simplified)
            return simplified
            
        # 通过简化消息聚类错误
        clusters = defaultdict(list)
        for error in all_errors:
            simplified = simplify_message(error["message"])
            clusters[simplified].append(error)
        
        # 只保留有多个实例的聚类
        significant_clusters = []
        for simplified, errors in clusters.items():
            if len(errors) > 1:
                significant_clusters.append({
                    "pattern": simplified,
                    "count": len(errors),
                    "error_type": errors[0].get("type", "unknown"),
                    "sample_message": errors[0]["message"],
                    "files": [e["file"] for e in errors][:5]  # 最多显示5个示例文件
                })
        
        # 按计数排序
        significant_clusters.sort(key=lambda x: x["count"], reverse=True)
        return significant_clusters
    
    def _analyze_feature_related_errors(self, correlations: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        分析与特定文件特征相关的错误
        
        Args:
            correlations: 错误与特征相关性
            
        Returns:
            按特征分组的错误模式
        """
        feature_patterns = defaultdict(list)
        
        # 遍历错误类型和相关特征
        for error_type, features in correlations.items():
            for feature_name, feature_values in features.items():
                if not feature_values:
                    continue
                    
                # 只处理前三个最显著的特征值
                for feature_value, count in feature_values[:3]:
                    if count > 1:  # 忽略单个实例
                        feature_patterns[feature_name].append({
                            "error_type": error_type,
                            "feature_value": feature_value,
                            "count": count,
                            "description": f"{error_type}错误与{feature_name}={feature_value}相关"
                        })
        
        # 将字典转换为正常字典（而非defaultdict）
        return dict(feature_patterns)
    
    def analyze_decrypt_data_errors(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        专门分析decrypt_data方法的错误模式
        
        Args:
            results: decrypt_data调用的结果列表
            
        Returns:
            错误模式分析和建议
        """
        # 转换结果格式以匹配文件结果
        file_style_results = []
        
        for i, result in enumerate(results):
            file_result = {
                "success": result.get("success", False),
                "input_file": f"data_block_{i}",  # 虚拟文件名
                "data_size": result.get("data_size", 0) 
            }
            
            # 处理错误信息
            if "error" in result:
                file_result["error"] = result["error"]
                
            if "errors" in result:
                file_result["errors"] = result["errors"]
                
            # 复制其他相关字段
            for field in ["algorithm", "confidence", "partial_success", "warnings"]:
                if field in result:
                    file_result[field] = result[field]
                    
            file_style_results.append(file_result)
        
        # 使用常规文件分析方法
        return self.analyze_error_patterns(file_style_results)