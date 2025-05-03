#\!/usr/bin/env python3
"""
加密密钥查找工具 - 搜索可能的加密密钥和初始化向量
"""
import os
import sys
import re
import json
import binascii
import argparse
import math
from datetime import datetime
from collections import Counter

class KeyFinder:
    def __init__(self, file_path=None, data=None, memory_dump=False, verbose=False):
        self.file_path = file_path
        self.data = data
        self.memory_dump = memory_dump  # 是否为内存转储文件
        self.verbose = verbose
        self.results = {}
        
        # 密钥大小配置
        self.key_sizes = {
            'aes': [16, 24, 32],  # AES-128/192/256
            'des': [8],           # DES
            '3des': [24],         # 3DES
            'blowfish': [4, 8, 16, 32], # Blowfish变长密钥
            'rc4': [5, 8, 16],    # RC4变长密钥
            'chacha20': [32],     # ChaCha20
            'salsa20': [32]       # Salsa20
        }
        
        # IV大小配置
        self.iv_sizes = {
            'aes-cbc': 16,    # AES-CBC
            'aes-ctr': 16,    # AES-CTR
            'des-cbc': 8,     # DES-CBC
            'blowfish': 8     # Blowfish
        }
        
        # 密钥特征定义
        self.key_patterns = {
            # RSA公钥开始/结束标记
            'rsa_public': [
                rb'-----BEGIN PUBLIC KEY-----',
                rb'-----BEGIN RSA PUBLIC KEY-----',
                rb'-----END PUBLIC KEY-----',
                rb'-----END RSA PUBLIC KEY-----'
            ],
            # RSA私钥开始/结束标记
            'rsa_private': [
                rb'-----BEGIN RSA PRIVATE KEY-----',
                rb'-----END RSA PRIVATE KEY-----',
                rb'-----BEGIN PRIVATE KEY-----',
                rb'-----END PRIVATE KEY-----'
            ],
            # PGP密钥块
            'pgp_key': [
                rb'-----BEGIN PGP PUBLIC KEY BLOCK-----',
                rb'-----END PGP PUBLIC KEY BLOCK-----',
                rb'-----BEGIN PGP PRIVATE KEY BLOCK-----',
                rb'-----END PGP PRIVATE KEY BLOCK-----'
            ],
            # 某些常见密钥格式标识符
            'key_identifiers': [
                rb'AES KEY',
                rb'aes key',
                rb'encryption key',
                rb'key=',
                rb'KEY=',
                rb'iv=',
                rb'IV=',
                rb'secret',
                rb'SECRET'
            ],
            # Base64编码特征（对于存储的密钥）
            'base64_keys': [
                rb'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
            ],
            # 十六进制密钥特征
            'hex_keys': [
                rb'(?:0x)?[0-9a-fA-F]{32,}',  # 至少16字节(32个十六进制字符)
                rb'[0-9a-fA-F]{32}',  # 16字节密钥
                rb'[0-9a-fA-F]{48}',  # 24字节密钥
                rb'[0-9a-fA-F]{64}'   # 32字节密钥
            ]
        }
    
    def load_file(self):
        """加载文件数据"""
        if self.data is not None:
            return True
            
        if not self.file_path:
            print("错误: 未提供文件路径")
            return False
        
        try:
            with open(self.file_path, 'rb') as f:
                self.data = f.read()
            return True
        except Exception as e:
            print(f"读取文件时出错: {e}")
            return False
    
    def calculate_entropy(self, data):
        """计算给定数据的熵值"""
        if not data:
            return 0.0
            
        # 计算字节频率
        counter = Counter(data)
        length = len(data)
        
        # 计算频率
        frequencies = [count / length for count in counter.values()]
        
        # 计算熵值
        entropy = -sum(freq * math.log2(freq) for freq in frequencies)
        return entropy
    
    def is_likely_key(self, data):
        """判断给定数据是否可能是加密密钥"""
        # 检查熵值 - 高熵值数据更可能是密钥
        entropy = self.calculate_entropy(data)
        if entropy < 3.0:  # 熵值过低，可能不是密钥
            return False, entropy
        
        # 检查重复字节 - 密钥通常不会有大量重复字节
        byte_counts = Counter(data)
        unique_bytes = len(byte_counts)
        if unique_bytes < len(data) * 0.3:  # 如果独特字节数小于30%，可能不是密钥
            return False, entropy
        
        # 检查字节分布 - 密钥通常有较均匀的分布
        values = list(byte_counts.values())
        std_dev = (sum((x - (len(data) / 256)) ** 2 for x in values) / len(values)) ** 0.5
        if std_dev > len(data) * 0.1:  # 如果标准差太大，可能不是密钥
            return False, entropy
        
        return True, entropy
    
    def find_potential_keys(self):
        """在数据中搜索潜在的密钥"""
        potential_keys = []
        all_keys = []
        
        # 检查是否有明文存储的密钥
        for key_type, patterns in self.key_patterns.items():
            for pattern in patterns:
                # 如果是正则表达式模式
                if pattern.startswith(b'(?'):
                    try:
                        regex = re.compile(pattern)
                        for match in regex.finditer(self.data):
                            start, end = match.span()
                            all_keys.append({
                                'type': key_type,
                                'position': start,
                                'length': end - start,
                                'data': self.data[start:end],
                                'hex': binascii.hexlify(self.data[start:end]).decode('ascii'),
                                'ascii': self.data[start:end].decode('ascii', errors='replace'),
                                'entropy': self.calculate_entropy(self.data[start:end]),
                                'confidence': 0.7
                            })
                    except Exception as e:
                        if self.verbose:
                            print(f"正则表达式匹配错误: {e}")
                # 普通字节模式
                else:
                    start = 0
                    while True:
                        pos = self.data.find(pattern, start)
                        if pos == -1:
                            break
                            
                        # 对于明确的密钥标识符，尝试提取后续数据
                        if key_type == 'key_identifiers':
                            # 提取标识符后的潜在密钥数据
                            identifier_end = pos + len(pattern)
                            
                            # 尝试不同大小的密钥
                            for key_size in [16, 24, 32]:
                                if identifier_end + key_size <= len(self.data):
                                    key_data = self.data[identifier_end:identifier_end+key_size]
                                    is_key, entropy = self.is_likely_key(key_data)
                                    
                                    if is_key:
                                        confidence = min(0.6 + entropy * 0.05, 0.9)  # 基于熵值计算置信度
                                        all_keys.append({
                                            'type': 'extracted_key',
                                            'position': identifier_end,
                                            'length': key_size,
                                            'data': key_data,
                                            'hex': binascii.hexlify(key_data).decode('ascii'),
                                            'ascii': key_data.decode('ascii', errors='replace'),
                                            'entropy': entropy,
                                            'confidence': confidence,
                                            'identifier': pattern.decode('ascii', errors='replace')
                                        })
                        
                        # RSA、PGP等密钥块
                        elif key_type in ['rsa_public', 'rsa_private', 'pgp_key']:
                            # 寻找对应的结束标记
                            end_pattern = None
                            for end_pat in self.key_patterns[key_type]:
                                if end_pat.startswith(b'-----END'):
                                    end_pattern = end_pat
                                    break
                            
                            if end_pattern:
                                end_pos = self.data.find(end_pattern, pos)
                                if end_pos \!= -1:
                                    key_block = self.data[pos:end_pos + len(end_pattern)]
                                    all_keys.append({
                                        'type': key_type,
                                        'position': pos,
                                        'length': len(key_block),
                                        'data': key_block,
                                        'ascii': key_block.decode('ascii', errors='replace'),
                                        'entropy': self.calculate_entropy(key_block),
                                        'confidence': 0.9
                                    })
                        
                        start = pos + 1
        
        # 搜索特定大小、高熵值的数据块作为潜在对称加密密钥
        for algo, sizes in self.key_sizes.items():
            for size in sizes:
                for i in range(0, len(self.data) - size, 4):  # 4字节步长以加快速度
                    block = self.data[i:i+size]
                    is_key, entropy = self.is_likely_key(block)
                    
                    if is_key and entropy > 3.5:  # 熵值阈值
                        # 计算置信度
                        confidence = min(0.3 + entropy * 0.08, 0.8)  # 基于熵值计算置信度
                        
                        # 记录潜在密钥
                        potential_keys.append({
                            'type': f'{algo}_key',
                            'position': i,
                            'length': size,
                            'data': block,
                            'hex': binascii.hexlify(block).decode('ascii'),
                            'entropy': entropy,
                            'confidence': confidence
                        })
        
        # 过滤和排序潜在密钥
        filtered_keys = []
        
        # 首先加入高置信度的明确密钥
        for key in all_keys:
            if key.get('confidence', 0) > 0.7:
                if 'data' in key and len(key['data']) > 1000:
                    # 对于大型密钥块（如RSA密钥），不包含原始数据以减小结果大小
                    key_copy = key.copy()
                    key_copy['data_preview'] = key['data'][:100] + b'...'
                    del key_copy['data']
                    filtered_keys.append(key_copy)
                else:
                    filtered_keys.append(key)
        
        # 按熵值排序潜在的对称密钥
        potential_keys.sort(key=lambda x: x['entropy'], reverse=True)
        
        # 过滤重叠的密钥（保留熵值最高的）
        non_overlapping_keys = []
        for key in potential_keys:
            pos = key['position']
            length = key['length']
            
            # 检查是否与已选密钥重叠
            overlapping = False
            for existing_key in non_overlapping_keys:
                existing_pos = existing_key['position']
                existing_length = existing_key['length']
                
                # 检查重叠
                if not (pos + length <= existing_pos or pos >= existing_pos + existing_length):
                    overlapping = True
                    break
            
            if not overlapping and key['entropy'] > 5.0:  # 只保留高熵值的密钥
                non_overlapping_keys.append(key)
        
        # 只保留置信度最高的前N个密钥
        top_keys = sorted(non_overlapping_keys, key=lambda x: x['confidence'], reverse=True)[:50]
        filtered_keys.extend(top_keys)
        
        return filtered_keys
    
    def find_potential_ivs(self):
        """在数据中搜索潜在的初始化向量"""
        potential_ivs = []
        
        # 搜索特定大小数据块作为潜在IV
        for algo, size in self.iv_sizes.items():
            for i in range(0, len(self.data) - size, 4):  # 4字节步长以加快速度
                block = self.data[i:i+size]
                is_iv, entropy = self.is_likely_key(block)  # 使用相同的判断逻辑
                
                if is_iv and entropy > 3.0:  # IV的熵值通常也较高
                    # 检查是否可能是IV（通常在密钥附近）
                    is_near_key = False
                    for key in self.results.get('potential_keys', []):
                        key_pos = key['position']
                        distance = abs(i - key_pos)
                        if distance < 100:  # 100字节内的距离
                            is_near_key = True
                            break
                    
                    # 计算置信度
                    confidence = min(0.3 + entropy * 0.07, 0.7)
                    if is_near_key:
                        confidence += 0.1  # 如果靠近密钥则提高置信度
                    
                    # 记录潜在IV
                    potential_ivs.append({
                        'type': f'{algo}_iv',
                        'position': i,
                        'length': size,
                        'data': block,
                        'hex': binascii.hexlify(block).decode('ascii'),
                        'entropy': entropy,
                        'confidence': confidence,
                        'near_key': is_near_key
                    })
        
        # 排序并过滤
        potential_ivs.sort(key=lambda x: x['confidence'], reverse=True)
        
        # 只保留前N个潜在IV
        return potential_ivs[:20]
    
    def analyze(self):
        """执行分析"""
        # 加载文件(如果提供了文件路径)
        if not self.data and not self.load_file():
            return None
        
        # 基本信息
        self.results['analysis_time'] = datetime.now().isoformat()
        if self.file_path:
            self.results['file_path'] = self.file_path
            self.results['file_size'] = len(self.data)
        else:
            self.results['data_size'] = len(self.data)
        
        self.results['is_memory_dump'] = self.memory_dump
        
        # 总体熵值
        self.results['entropy'] = self.calculate_entropy(self.data)
        
        # 查找潜在密钥
        if self.verbose:
            print("查找潜在密钥...")
        
        potential_keys = self.find_potential_keys()
        self.results['potential_keys'] = potential_keys
        
        # 查找潜在IV
        if self.verbose:
            print("查找潜在初始化向量...")
        
        potential_ivs = self.find_potential_ivs()
        self.results['potential_ivs'] = potential_ivs
        
        # 生成摘要
        self.generate_summary()
        
        if self.verbose:
            self.print_summary()
        
        return self.results
    
    def generate_summary(self):
        """生成分析摘要"""
        summary = {
            'total_potential_keys': len(self.results.get('potential_keys', [])),
            'total_potential_ivs': len(self.results.get('potential_ivs', [])),
            'high_confidence_keys': []
        }
        
        # 统计高置信度的密钥
        high_confidence_count = 0
        for key in self.results.get('potential_keys', []):
            if key.get('confidence', 0) > 0.7:
                high_confidence_count += 1
                
                # 添加高置信度密钥到摘要
                key_summary = {
                    'type': key.get('type', 'unknown'),
                    'position': key.get('position', 0),
                    'length': key.get('length', 0),
                    'entropy': key.get('entropy', 0),
                    'confidence': key.get('confidence', 0)
                }
                
                # 如果是明确标识的密钥，添加更多信息
                if 'identifier' in key:
                    key_summary['identifier'] = key['identifier']
                
                # 添加十六进制预览
                if 'hex' in key:
                    hex_preview = key['hex']
                    if len(hex_preview) > 50:
                        hex_preview = hex_preview[:50] + '...'
                    key_summary['hex_preview'] = hex_preview
                
                summary['high_confidence_keys'].append(key_summary)
        
        summary['high_confidence_key_count'] = high_confidence_count
        
        # 对结果进行评估
        if high_confidence_count > 0 or len(self.results.get('potential_keys', [])) > 10:
            summary['assessment'] = (
                "文件中存在多个可能的加密密钥。建议进一步分析高置信度密钥以确定其用途。"
            )
        elif self.results.get('entropy', 0) > 7.0:
            summary['assessment'] = (
                "文件熵值很高，表明可能是加密或压缩数据，但未找到明确的密钥标识。"
            )
        else:
            summary['assessment'] = (
                "未找到明确的加密密钥特征。文件可能未使用常见的加密方法或密钥存储在其他位置。"
            )
        
        self.results['summary'] = summary
    
    def print_summary(self):
        """打印分析摘要"""
        print("\n============== 密钥分析摘要 ==============")
        if self.file_path:
            print(f"文件: {self.results['file_path']}")
            print(f"大小: {self.results['file_size']} 字节")
        else:
            print(f"数据大小: {self.results['data_size']} 字节")
        
        print(f"总体熵值: {self.results['entropy']:.6f}")
        
        summary = self.results['summary']
        print(f"\n发现的潜在密钥: {summary['total_potential_keys']}")
        print(f"高置信度密钥: {summary['high_confidence_key_count']}")
        print(f"潜在初始化向量: {summary['total_potential_ivs']}")
        
        if summary['high_confidence_keys']:
            print("\n高置信度密钥:")
            for i, key in enumerate(summary['high_confidence_keys'][:5]):  # 只显示前5个
                print(f"  [{i+1}] 类型: {key['type']}, 位置: {key['position']}, 长度: {key['length']}")
                print(f"      熵值: {key['entropy']:.4f}, 置信度: {key['confidence']:.4f}")
                if 'hex_preview' in key:
                    print(f"      十六进制预览: {key['hex_preview']}")
                if 'identifier' in key:
                    print(f"      标识符: {key['identifier']}")
                print()
        
        print(f"评估: {summary['assessment']}")
        print("==========================================")
    
    def save_results(self, output_path=None):
        """保存分析结果到JSON文件"""
        try:
            if not output_path:
                if self.file_path:
                    output_path = f"{os.path.basename(self.file_path)}_key_analysis.json"
                else:
                    output_path = f"memory_dump_key_analysis.json"
            
            # 清理包含二进制数据的大字段
            clean_results = self.results.copy()
            
            # 清理密钥数据
            if 'potential_keys' in clean_results:
                for key in clean_results['potential_keys']:
                    if 'data' in key:
                        # 保留十六进制表示形式，移除二进制数据
                        del key['data']
            
            # 清理IV数据
            if 'potential_ivs' in clean_results:
                for iv in clean_results['potential_ivs']:
                    if 'data' in iv:
                        # 保留十六进制表示形式，移除二进制数据
                        del iv['data']
            
            with open(output_path, 'w') as f:
                json.dump(clean_results, f, indent=2)
            
            if self.verbose:
                print(f"分析结果已保存至: {output_path}")
            
            return True
            
        except Exception as e:
            print(f"保存结果时出错: {e}")
            return False

def analyze_file(file_path, memory_dump=False, output_path=None, verbose=False):
    """分析单个文件"""
    finder = KeyFinder(file_path=file_path, memory_dump=memory_dump, verbose=verbose)
    results = finder.analyze()
    
    if results and output_path:
        finder.save_results(output_path)
    elif results:
        finder.save_results()
    
    return results

def analyze_data(data, memory_dump=False, output_path=None, verbose=False):
    """分析内存中的数据"""
    finder = KeyFinder(data=data, memory_dump=memory_dump, verbose=verbose)
    results = finder.analyze()
    
    if results and output_path:
        finder.save_results(output_path)
    elif results:
        finder.save_results()
    
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="加密密钥查找工具")
    parser.add_argument("file", help="要分析的文件路径")
    parser.add_argument("-m", "--memory-dump", action="store_true", help="将文件视为内存转储")
    parser.add_argument("-o", "--output", help="输出结果文件路径")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出")
    
    args = parser.parse_args()
    
    analyze_file(args.file, args.memory_dump, args.output, args.verbose)
EOF < /dev/null