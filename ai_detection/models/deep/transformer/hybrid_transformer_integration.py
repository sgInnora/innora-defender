#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
混合变压器模型的集成模块，用于将变压器模型与其他深度学习组件集成。
该模块允许多源特征融合和交互，提供强大的勒索软件检测能力。
"""

import os
import sys
import json
import logging
import pickle
from typing import Dict, List, Any, Tuple, Optional, Union

import numpy as np
import torch

# 调整路径以查找模块
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from ai_detection.models.deep.transformer.hybrid_transformer import (
    HybridTransformerAnalyzer,
    HybridDataset,
    SequenceEmbedding
)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


class TransformerIntegration:
    """用于混合Transformer模型的集成类"""
    
    def __init__(
        self,
        model_dir: Optional[str] = None,
        device: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        初始化Transformer集成
        
        Args:
            model_dir: 存储模型的目录
            device: 计算设备 ('cuda' 或 'cpu')
            config: 配置参数字典
        """
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.config = config or {}
        self.model_dir = model_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
        
        # 初始化分析器
        self.analyzer = None
        self.initialized = False
        
        # 从配置中加载参数
        self.cnn_feature_dim = self.config.get('cnn_feature_dim', 64)
        self.lstm_feature_dim = self.config.get('lstm_feature_dim', 64)
        self.static_feature_dim = self.config.get('static_feature_dim', 32)
        self.embed_dim = self.config.get('embed_dim', 128)
        self.num_heads = self.config.get('num_heads', 8)
        self.ff_dim = self.config.get('ff_dim', 256)
        self.num_layers = self.config.get('num_layers', 4)
        self.dropout = self.config.get('dropout', 0.1)
        self.batch_size = self.config.get('batch_size', 32)
        self.vocab_size = self.config.get('vocab_size', 1000)
        self.max_seq_len = self.config.get('max_seq_len', 200)
        
        # 加载默认模型（如果目录存在）
        if os.path.exists(self.model_dir):
            self._load_default_model()
    
    def _load_default_model(self):
        """
        加载默认Transformer模型
        """
        try:
            model_path = os.path.join(self.model_dir, "hybrid_transformer_model.pt")
            
            if os.path.exists(model_path):
                logger.info(f"加载混合Transformer模型: {model_path}")
                # 创建序列嵌入
                sequence_embedding = None
                if self.config.get('with_sequences', True):
                    sequence_embedding = HybridTransformerAnalyzer.create_sequence_embedding(
                        vocab_size=self.vocab_size,
                        embed_dim=self.embed_dim,
                        max_seq_len=self.max_seq_len,
                        dropout=self.dropout,
                        padding_idx=0
                    )
                
                # 创建分析器
                self.analyzer = HybridTransformerAnalyzer(
                    cnn_feature_dim=self.cnn_feature_dim,
                    lstm_feature_dim=self.lstm_feature_dim,
                    static_feature_dim=self.static_feature_dim,
                    embed_dim=self.embed_dim,
                    num_heads=self.num_heads,
                    ff_dim=self.ff_dim,
                    num_layers=self.num_layers,
                    dropout=self.dropout,
                    device=self.device,
                    batch_size=self.batch_size,
                    sequence_embedding=sequence_embedding
                )
                
                # 加载模型
                self.analyzer.load(model_path)
                self.initialized = True
            else:
                logger.warning("未找到默认混合Transformer模型，将在首次使用时初始化")
        except Exception as e:
            logger.error(f"加载默认混合Transformer模型时出错: {str(e)}")
    
    def initialize(self, with_sequences: bool = True):
        """
        初始化Transformer分析器（如果尚未初始化）
        
        Args:
            with_sequences: 是否包含序列数据
        """
        if self.initialized:
            logger.info("混合Transformer分析器已初始化")
            return
        
        # 创建序列嵌入
        sequence_embedding = None
        if with_sequences:
            sequence_embedding = HybridTransformerAnalyzer.create_sequence_embedding(
                vocab_size=self.vocab_size,
                embed_dim=self.embed_dim,
                max_seq_len=self.max_seq_len,
                dropout=self.dropout,
                padding_idx=0
            )
        
        # 创建分析器
        self.analyzer = HybridTransformerAnalyzer(
            cnn_feature_dim=self.cnn_feature_dim,
            lstm_feature_dim=self.lstm_feature_dim,
            static_feature_dim=self.static_feature_dim,
            embed_dim=self.embed_dim,
            num_heads=self.num_heads,
            ff_dim=self.ff_dim,
            num_layers=self.num_layers,
            dropout=self.dropout,
            device=self.device,
            batch_size=self.batch_size,
            sequence_embedding=sequence_embedding
        )
        
        self.initialized = True
        logger.info("混合Transformer分析器已初始化")
    
    def analyze_sample(
        self, 
        cnn_features: np.ndarray, 
        lstm_features: np.ndarray, 
        static_features: np.ndarray,
        sequence: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """
        分析样本以提取特征和预测
        
        Args:
            cnn_features: CNN特征向量
            lstm_features: LSTM特征向量
            static_features: 静态特征向量
            sequence: 可选的标记化序列
            
        Returns:
            带有特征和预测的结果字典
        """
        # 确保分析器已初始化
        if not self.initialized:
            self.initialize(with_sequences=sequence is not None)
        
        # 创建数据集
        dataset = HybridDataset(
            cnn_features=[cnn_features],
            lstm_features=[lstm_features],
            static_features=[static_features],
            sequences=[sequence] if sequence is not None else None,
            max_seq_len=self.max_seq_len
        )
        
        # 预测
        probability = self.analyzer.predict(dataset, return_probabilities=True)[0]
        
        # 提取特征
        features = self.analyzer.extract_features(dataset)[0]
        
        # 分析注意力
        attention_results = {}
        if sequence is not None:
            attention_analysis = self.analyzer.analyze_attention(dataset)
            if 'attention_analysis' in attention_analysis and attention_analysis['attention_analysis']:
                attention_results = attention_analysis['attention_analysis'][0]
        
        return {
            'transformer_analysis': {
                'status': 'success',
                'prediction': float(probability),
                'features': features.tolist(),
                'is_ransomware': bool(probability >= 0.5),
                'attention_analysis': attention_results
            }
        }
    
    def train(
        self,
        cnn_features: List[np.ndarray],
        lstm_features: List[np.ndarray],
        static_features: List[np.ndarray],
        labels: List[int],
        sequences: Optional[List[List[int]]] = None,
        epochs: int = 10,
        val_split: float = 0.2,
        save_model: bool = True
    ) -> Dict[str, Any]:
        """
        训练混合Transformer模型
        
        Args:
            cnn_features: CNN特征向量列表
            lstm_features: LSTM特征向量列表
            static_features: 静态特征向量列表
            labels: 标签列表（1表示勒索软件，0表示良性）
            sequences: 可选的标记化序列列表
            epochs: 训练轮数
            val_split: 验证集比例
            save_model: 是否保存模型
            
        Returns:
            训练结果字典
        """
        # 确保分析器已初始化
        if not self.initialized:
            self.initialize(with_sequences=sequences is not None)
        
        # 创建输出目录
        os.makedirs(self.model_dir, exist_ok=True)
        
        # 分割训练集和验证集
        n_samples = len(labels)
        n_val = int(n_samples * val_split)
        indices = np.random.permutation(n_samples)
        
        train_indices = indices[n_val:]
        val_indices = indices[:n_val]
        
        # 创建训练集
        train_cnn = [cnn_features[i] for i in train_indices]
        train_lstm = [lstm_features[i] for i in train_indices]
        train_static = [static_features[i] for i in train_indices]
        train_labels = [labels[i] for i in train_indices]
        train_sequences = [sequences[i] for i in train_indices] if sequences else None
        
        # 创建验证集
        val_cnn = [cnn_features[i] for i in val_indices]
        val_lstm = [lstm_features[i] for i in val_indices]
        val_static = [static_features[i] for i in val_indices]
        val_labels = [labels[i] for i in val_indices]
        val_sequences = [sequences[i] for i in val_indices] if sequences else None
        
        # 创建数据集
        train_dataset = HybridDataset(
            cnn_features=train_cnn,
            lstm_features=train_lstm,
            static_features=train_static,
            labels=train_labels,
            sequences=train_sequences,
            max_seq_len=self.max_seq_len
        )
        
        val_dataset = HybridDataset(
            cnn_features=val_cnn,
            lstm_features=val_lstm,
            static_features=val_static,
            labels=val_labels,
            sequences=val_sequences,
            max_seq_len=self.max_seq_len
        )
        
        # 训练模型
        logger.info(f"训练混合Transformer模型：{len(train_indices)}个训练样本，{len(val_indices)}个验证样本")
        history = self.analyzer.train(
            train_dataset=train_dataset,
            val_dataset=val_dataset,
            epochs=epochs,
            patience=3,
            model_save_path=os.path.join(self.model_dir, 'hybrid_transformer_model.pt') if save_model else None
        )
        
        return {
            'status': 'success',
            'message': '混合Transformer模型训练完成',
            'history': history,
            'train_samples': len(train_indices),
            'val_samples': len(val_indices)
        }
    
    def save(self, model_path: Optional[str] = None):
        """
        保存模型
        
        Args:
            model_path: 模型保存路径（可选）
        """
        if not self.initialized or self.analyzer is None:
            logger.error("无法保存：分析器未初始化")
            return False
        
        # 使用默认路径（如果未指定）
        if model_path is None:
            model_path = os.path.join(self.model_dir, "hybrid_transformer_model.pt")
        
        # 创建目录（如果不存在）
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        # 保存模型
        self.analyzer.save(model_path)
        logger.info(f"混合Transformer模型已保存到 {model_path}")
        
        return True
    
    def load(self, model_path: Optional[str] = None):
        """
        加载模型
        
        Args:
            model_path: 模型加载路径（可选）
        """
        # 使用默认路径（如果未指定）
        if model_path is None:
            model_path = os.path.join(self.model_dir, "hybrid_transformer_model.pt")
        
        # 检查文件是否存在
        if not os.path.exists(model_path):
            logger.error(f"模型文件不存在: {model_path}")
            return False
        
        # 确保分析器已初始化
        if not self.initialized:
            self.initialize()
        
        try:
            # 加载模型
            self.analyzer.load(model_path)
            logger.info(f"混合Transformer模型已加载: {model_path}")
            return True
        except Exception as e:
            logger.error(f"加载混合Transformer模型时出错: {str(e)}")
            return False


# 工厂函数
def create_transformer_integration(
    model_dir: Optional[str] = None,
    device: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None
) -> TransformerIntegration:
    """
    创建Transformer集成实例
    
    Args:
        model_dir: 存储模型的目录
        device: 计算设备 ('cuda' 或 'cpu')
        config: 配置参数字典
        
    Returns:
        TransformerIntegration实例
    """
    return TransformerIntegration(model_dir=model_dir, device=device, config=config)