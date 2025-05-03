#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LSTM序列分析器与整体检测框架的集成模块。
"""

import os
import sys
import logging
from typing import Dict, List, Any, Optional

import numpy as np
import torch

# 调整路径以查找模块
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from ai_detection.models.deep.lstm.sequence_lstm_analyzer import (
    SequenceLSTMAnalyzer,
    SequenceTokenizer,
    SequenceExtractor
)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


class LSTMSequenceDetector:
    """
    基于LSTM的序列检测器，用于与勒索软件检测框架集成。
    这为LSTM序列分析器提供了一个标准化接口，以便与检测系统的其他组件交互。
    """
    
    def __init__(
        self,
        model_path: Optional[str] = None,
        tokenizer_path: Optional[str] = None,
        device: str = None,
        batch_size: int = 32,
        max_seq_length: int = 500,
        embedding_dim: int = 64,
        hidden_dim: int = 128,
        confidence_threshold: float = 0.5
    ):
        """
        初始化LSTM序列检测器
        
        Args:
            model_path: 预训练模型的可选路径
            tokenizer_path: 预训练分词器的可选路径
            device: 计算设备（'cuda'或'cpu'）
            batch_size: 处理的批次大小
            max_seq_length: 最大序列长度
            embedding_dim: 标记嵌入的维度
            hidden_dim: LSTM隐藏状态的维度
            confidence_threshold: 正面检测的阈值
        """
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.batch_size = batch_size
        self.max_seq_length = max_seq_length
        self.embedding_dim = embedding_dim
        self.hidden_dim = hidden_dim
        self.confidence_threshold = confidence_threshold
        
        # 加载或初始化分析器
        if model_path and tokenizer_path and os.path.exists(model_path) and os.path.exists(tokenizer_path):
            logger.info(f"从{model_path}加载LSTM序列分析器")
            self.analyzer = SequenceLSTMAnalyzer.load(
                model_path=model_path,
                tokenizer_path=tokenizer_path,
                device=self.device
            )
        else:
            logger.info("初始化新的LSTM序列分析器")
            self.analyzer = SequenceLSTMAnalyzer(
                device=self.device,
                batch_size=batch_size,
                max_seq_length=max_seq_length,
                embedding_dim=embedding_dim,
                hidden_dim=hidden_dim
            )
    
    def train(
        self,
        execution_logs: Dict[str, List[str]],
        model_save_dir: str = './models',
        epochs: int = 10,
        learning_rate: float = 0.001
    ) -> Dict[str, Any]:
        """
        训练LSTM序列检测器
        
        Args:
            execution_logs: 将样本ID映射到执行日志路径的字典
            model_save_dir: 保存训练模型的目录
            epochs: 训练轮数
            learning_rate: 训练的学习率
            
        Returns:
            包含训练结果的字典
        """
        # 准备路径和标签
        train_paths = []
        train_labels = []
        
        for sample_id, log_paths in execution_logs.items():
            # 从样本ID中提取标签（假设格式如'ransomware_123'或'benign_456'）
            is_ransomware = 1 if 'ransomware' in sample_id.lower() else 0
            
            # 添加每个日志路径及其标签
            for log_path in log_paths:
                train_paths.append(log_path)
                train_labels.append(is_ransomware)
        
        # 确保模型保存目录存在
        os.makedirs(model_save_dir, exist_ok=True)
        model_save_path = os.path.join(model_save_dir, 'sequence_lstm_model.pt')
        tokenizer_save_path = os.path.join(model_save_dir, 'sequence_tokenizer.pkl')
        
        # 训练模型
        logger.info(f"在{len(train_paths)}个样本上训练LSTM模型...")
        history = self.analyzer.train(
            train_log_paths=train_paths,
            train_labels=train_labels,
            epochs=epochs,
            learning_rate=learning_rate,
            model_save_path=model_save_path
        )
        
        # 保存分词器
        self.analyzer.save(
            model_path=model_save_path,
            tokenizer_path=tokenizer_save_path
        )
        
        return {
            'history': history,
            'model_path': model_save_path,
            'tokenizer_path': tokenizer_save_path,
            'samples_trained': len(train_paths)
        }
    
    def detect(self, execution_logs: List[str]) -> Dict[str, Any]:
        """
        基于执行日志检测勒索软件
        
        Args:
            execution_logs: 执行日志路径列表
            
        Returns:
            检测结果
        """
        if not execution_logs:
            return {
                'is_ransomware': False,
                'confidence': 0.0,
                'features': None,
                'details': {
                    'error': '未提供执行日志'
                }
            }
        
        try:
            # 获取每个日志的概率
            probabilities = self.analyzer.predict(
                execution_logs, 
                return_probabilities=True
            )
            
            # 提取特征
            features = self.analyzer.extract_features(execution_logs)
            
            # 总体概率（各个概率的最大值）
            overall_probability = max(probabilities) if probabilities else 0.0
            
            # 确定是否为勒索软件
            is_ransomware = overall_probability >= self.confidence_threshold
            
            # 获取概率最高的日志的注意力分析
            attention_details = {}
            if probabilities:
                max_prob_idx = np.argmax(probabilities)
                max_prob_log = execution_logs[max_prob_idx]
                
                try:
                    api_calls, weights = self.analyzer.analyze_attention(max_prob_log)
                    
                    # 按注意力权重获取前10个API调用
                    top_indices = np.argsort(weights)[-10:][::-1]
                    top_api_calls = [api_calls[i] for i in top_indices]
                    top_weights = [weights[i] for i in top_indices]
                    
                    attention_details = {
                        'top_api_calls': top_api_calls,
                        'top_weights': top_weights,
                        'log_path': max_prob_log
                    }
                except Exception as e:
                    logger.error(f"分析注意力时出错: {str(e)}")
                    attention_details = {
                        'error': str(e)
                    }
            
            return {
                'is_ransomware': is_ransomware,
                'confidence': float(overall_probability),
                'features': features.tolist() if isinstance(features, np.ndarray) else None,
                'details': {
                    'probabilities': [float(p) for p in probabilities],
                    'log_paths': execution_logs,
                    'attention_analysis': attention_details
                }
            }
        
        except Exception as e:
            logger.error(f"勒索软件检测出错: {str(e)}")
            return {
                'is_ransomware': False,
                'confidence': 0.0,
                'features': None,
                'error': str(e)
            }
    
    def extract_behavioral_features(self, execution_logs: List[str]) -> Dict[str, Any]:
        """
        从执行日志中提取行为特征
        
        Args:
            execution_logs: 执行日志路径列表
            
        Returns:
            提取特征的字典
        """
        try:
            # 提取特征
            features = self.analyzer.extract_features(execution_logs)
            
            # 分析随机日志以获取注意力见解
            if execution_logs:
                log_path = execution_logs[0]
                api_calls, weights = self.analyzer.analyze_attention(log_path)
                
                # 按注意力权重获取前几个API调用
                top_indices = np.argsort(weights)[-10:][::-1]
                top_api_calls = [api_calls[i] for i in top_indices]
                top_weights = [weights[i] for i in top_indices]
                
                return {
                    'features': features.tolist() if isinstance(features, np.ndarray) else None,
                    'feature_dim': features.shape[1] if isinstance(features, np.ndarray) else None,
                    'behavioral_indicators': {
                        'top_api_calls': top_api_calls,
                        'importance_scores': top_weights
                    },
                    'sequence_length': len(api_calls)
                }
            else:
                return {
                    'features': None,
                    'error': '未提供执行日志'
                }
        
        except Exception as e:
            logger.error(f"提取行为特征时出错: {str(e)}")
            return {
                'features': None,
                'error': str(e)
            }


# 创建检测器的工厂函数
def create_lstm_sequence_detector(
    model_path: Optional[str] = None,
    tokenizer_path: Optional[str] = None,
    **kwargs
) -> LSTMSequenceDetector:
    """
    创建LSTM序列检测器的工厂函数
    
    Args:
        model_path: 预训练模型的可选路径
        tokenizer_path: 预训练分词器的可选路径
        **kwargs: 检测器初始化的其他参数
        
    Returns:
        初始化的LSTM序列检测器
    """
    return LSTMSequenceDetector(
        model_path=model_path,
        tokenizer_path=tokenizer_path,
        **kwargs
    )