#\!/usr/bin/env python3
"""
内存密钥提取工具 - 从内存转储中扫描和提取加密密钥
"""
import os
import sys
import re
import json
import binascii
import struct
import argparse
import logging
from datetime import datetime
from pathlib import Path

# 设置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('MemoryKeyExtractor')

class MemoryKeyExtractor:
    def __init__(self, memory_dump, output_dir=None, verbose=False):
        self.memory_dump = memory_dump
        self.output_dir = output_dir or os.path.join(os.path.dirname(memory_dump), 'extracted_keys')
        self.verbose = verbose
        self.results = []
        
        # 确保输出目录存在
        os.makedirs(self.output_dir, exist_ok=True)
        
        # 设置日志级别
        if verbose:
            logger.setLevel(logging.DEBUG)
        
        # 加载密钥签名数据库
        self.load_signatures()
    
    def load_signatures(self):
        """加载加密密钥签名和模式"""
        self.signatures = {
            "aes": {
                "name": "AES",
                "key_sizes": [16, 24, 32],  # AES-128, AES-192, AES-256
                "iv_sizes": [16],
                # AES S-box常量
                "constants": [
                    binascii.unhexlify("637c777bf26b6fc53001672bfed7ab76"),
                    binascii.unhexlify("52096ad53036a538bf40a39e81f3d7fb"),
                    binascii.unhexlify("7be0e1de09123456789abcdef0fedcba")
                ],
                # AES Rijndael S-box
                "sbox": binascii.unhexlify(
                    "637c777bf26b6fc53001672bfed7ab76"
                    "ca82c97dfa5947f0add4a2af9ca472c0"
                    "b7fd9326363ff7cc34a5e5f171d83115"
                    "04c723c31896059a071280e2eb27b275"
                    "09832c1a1b6e5aa0523bd6b329e32f84"
                    "53d100ed20fcb15b6acbbe394a4c58cf"
                    "d0efaafb434d338545f9027f503c9fa8"
                    "51a3408f929d38f5bcb6da2110fff3d2"
                    "cd0c13ec5f974417c4a77e3d645d1973"
                    "60814fdc222a908846eeb814de5e0bdb"
                    "e0323a0a4906245cc2d3ac629195e479"
                    "e7c8376d8dd54ea96c56f4ea657aae08"
                    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
                    "703eb5664803f60e613557b986c11d9e"
                    "e1f8981169d98e949b1e87e9ce5528df"
                    "8ca1890dbfe6426841992d0fb054bb16"
                )
            },
            "rsa": {
                "name": "RSA",
                "patterns": [
                    # PKCS#1 标记
                    rb"-----BEGIN RSA PRIVATE KEY-----",
                    rb"-----BEGIN RSA PUBLIC KEY-----",
                    # RSA公共模数和指数特征
                    rb"publicExponent",
                    rb"privateExponent",
                    rb"prime1",
                    rb"prime2"
                ]
            },
            "aes_key_schedule": {
                "name": "AES Key Schedule",
                "description": "AES密钥扩展表特征",
                "pattern_128": [
                    # AES-128用于轮密钥生成的常量
                    rb"\x01\x00\x00\x00",
                    rb"\x02\x00\x00\x00",
                    rb"\x04\x00\x00\x00",
                    rb"\x08\x00\x00\x00",
                    rb"\x10\x00\x00\x00",
                    rb"\x20\x00\x00\x00",
                    rb"\x40\x00\x00\x00",
                    rb"\x80\x00\x00\x00",
                    rb"\x1b\x00\x00\x00",
                    rb"\x36\x00\x00\x00"
                ]
            },
            "salsa20": {
                "name": "Salsa20/ChaCha20",
                "description": "Salsa20和ChaCha20的常量签名",
                "constants": [
                    # Salsa20和ChaCha20的魔术常量
                    binascii.unhexlify("657870616e642033322d62797465206b"),  # "expand 32-byte k"
                    binascii.unhexlify("61707865"),  # "apxe" in ChaCha20
                    binascii.unhexlify("3320646e"),  # "3 dn" in ChaCha20
                ]
            },
            "generic_keys": {
                "name": "Generic Encryption Keys",
                "description": "常见加密密钥格式",
                "patterns": [
                    # 常见密钥前缀/标识符
                    rb"key=",
                    rb"Key=",
                    rb"KEY=",
                    rb"iv=",
                    rb"IV=",
                    rb"password=",
                    rb"SECRET_KEY",
                    rb"PRIVATE_KEY",
                    rb"Crypto",
                    rb"Encrypt"
                ]
            }
        }
        
        # 添加勒索软件特定签名
        self.ransomware_signatures = {
            "wannacry": {
                "name": "WannaCry",
                "key_patterns": [
                    # WannaCry特有的密钥结构
                    rb"WanaDecryptor",
                    rb"WNcry@2ol7",
                    rb"WANACRY\!"
                ]
            },
            "ryuk": {
                "name": "Ryuk",
                "key_patterns": [
                    rb"RyukReadMe",
                    rb"UNIQUE_ID_DO_NOT_REMOVE"
                ]
            },
            "sodinokibi": {
                "name": "REvil/Sodinokibi",
                "key_patterns": [
                    rb"Sodinokibi",
                    rb"REvil"
                ]
            },
            "lockbit": {
                "name": "LockBit",
                "key_patterns": [
                    rb"LockBit",
                    rb"github.com/lockbit"
                ]
            }
        }
    
    def scan_for_aes_keys(self, data, chunk_size=4096):
        """扫描数据中的AES密钥特征"""
        found_keys = []
        
        # 首先查找AES S-box特征
        sbox_positions = []
        for i in range(0, len(data) - len(self.signatures["aes"]["sbox"]), chunk_size):
            chunk = data[i:i+chunk_size]
            pos = chunk.find(self.signatures["aes"]["sbox"])
            if pos \!= -1:
                sbox_positions.append(i + pos)
        
        if sbox_positions:
            logger.debug(f"找到 {len(sbox_positions)} 个AES S-box特征")
        
        # 在S-box附近搜索可能的密钥
        for pos in sbox_positions:
            # 检查S-box前后4KB范围内的数据
            search_start = max(0, pos - 4096)
            search_end = min(len(data), pos + 4096 + len(self.signatures["aes"]["sbox"]))
            search_area = data[search_start:search_end]
            
            # 对该区域中的每个字节进行检查
            for key_size in self.signatures["aes"]["key_sizes"]:
                for i in range(len(search_area) - key_size):
                    potential_key = search_area[i:i+key_size]
                    
                    # 使用启发式方法评估是否是AES密钥
                    # AES密钥通常具有高熵值且不会有太多重复字节
                    unique_bytes = len(set(potential_key))
                    
                    # 假设好的密钥至少有50%的字节是唯一的
                    if unique_bytes < key_size * 0.5:
                        continue
                    
                    key_entropy = self._calculate_entropy(potential_key)
                    
                    # AES密钥通常具有高熵值
                    if key_entropy > 4.0:
                        # 计算实际位置
                        actual_pos = search_start + i
                        
                        # 记录发现的可能密钥
                        found_keys.append({
                            'type': 'aes_key',
                            'size': key_size,
                            'position': actual_pos,
                            'value': binascii.hexlify(potential_key).decode('ascii'),
                            'entropy': key_entropy,
                            'confidence': min(key_entropy / 8.0 * 100, 90)  # 最高置信度为90%
                        })
                        
                        if self.verbose:
                            logger.debug(f"在位置 {actual_pos} 找到可能的AES-{key_size * 8}密钥，"
                                      f"熵值: {key_entropy:.2f}")
        
        return found_keys
    
    def scan_for_aes_ivs(self, data, chunk_size=4096):
        """扫描数据中的AES IV特征"""
        found_ivs = []
        
        # AES IV通常是16字节，在密钥附近
        iv_size = 16
        
        # 与密钥相同的启发式方法，但对熵值要求略低
        for i in range(0, len(data) - iv_size, chunk_size):
            chunk = data[i:i+chunk_size]
            
            for j in range(0, len(chunk) - iv_size):
                potential_iv = chunk[j:j+iv_size]
                
                unique_bytes = len(set(potential_iv))
                
                # IV通常至少有40%的字节是唯一的
                if unique_bytes < iv_size * 0.4:
                    continue
                
                iv_entropy = self._calculate_entropy(potential_iv)
                
                # IV通常也具有较高熵值，但可能低于密钥
                if iv_entropy > 3.5:
                    # 计算实际位置
                    actual_pos = i + j
                    
                    # 记录发现的可能IV
                    found_ivs.append({
                        'type': 'aes_iv',
                        'size': iv_size,
                        'position': actual_pos,
                        'value': binascii.hexlify(potential_iv).decode('ascii'),
                        'entropy': iv_entropy,
                        'confidence': min(iv_entropy / 8.0 * 90, 80)  # 最高置信度为80%
                    })
                    
                    if self.verbose:
                        logger.debug(f"在位置 {actual_pos} 找到可能的AES IV，"
                                  f"熵值: {iv_entropy:.2f}")
        
        return found_ivs
    
    def scan_for_rsa_keys(self, data):
        """扫描数据中的RSA密钥特征"""
        found_keys = []
        
        # 查找PKCS格式的RSA密钥
        for pattern in self.signatures["rsa"]["patterns"]:
            start = 0
            while True:
                pos = data.find(pattern, start)
                if pos == -1:
                    break
                
                # 对于PKCS头部，尝试提取完整的密钥块
                if pattern in [rb"-----BEGIN RSA PRIVATE KEY-----", rb"-----BEGIN RSA PUBLIC KEY-----"]:
                    # 寻找对应的结束标记
                    end_pattern = rb"-----END RSA PRIVATE KEY-----" if pattern == rb"-----BEGIN RSA PRIVATE KEY-----" else rb"-----END RSA PUBLIC KEY-----"
                    end_pos = data.find(end_pattern, pos)
                    
                    if end_pos \!= -1:
                        key_blob = data[pos:end_pos + len(end_pattern)]
                        key_type = "rsa_private_key" if pattern == rb"-----BEGIN RSA PRIVATE KEY-----" else "rsa_public_key"
                        
                        found_keys.append({
                            'type': key_type,
                            'position': pos,
                            'size': len(key_blob),
                            'value': key_blob.decode('ascii', errors='ignore'),
                            'confidence': 95  # PKCS格式密钥几乎肯定是真实的
                        })
                        
                        if self.verbose:
                            logger.debug(f"在位置 {pos} 找到{key_type}")
                
                # 移动到下一个潜在匹配
                start = pos + 1
        
        # 检测RSA密钥组件（非PKCS格式）
        # 这需要更复杂的分析，这里只做简单实现
        start = 0
        while True:
            # 寻找可能的RSA模数（通常是大整数）
            modulus_pattern = rb"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # 用于识别潜在的大整数边界
            pos = data.find(modulus_pattern, start)
            if pos == -1:
                break
            
            # 检查后续数据是否像RSA模数（高熵值、合适大小）
            for size in [128, 256, 384, 512]:  # 常见RSA密钥大小
                if pos + size <= len(data):
                    potential_modulus = data[pos:pos+size]
                    modulus_entropy = self._calculate_entropy(potential_modulus)
                    
                    # RSA模数通常具有高熵值
                    if modulus_entropy > 4.5:
                        found_keys.append({
                            'type': 'possible_rsa_modulus',
                            'position': pos,
                            'size': size,
                            'value': binascii.hexlify(potential_modulus[:32]).decode('ascii') + "...",  # 只保存前32字节
                            'entropy': modulus_entropy,
                            'confidence': min(modulus_entropy / 8.0 * 80, 70)  # 最高置信度为70%
                        })
                        
                        if self.verbose:
                            logger.debug(f"在位置 {pos} 找到可能的RSA模数，"
                                      f"大小: {size}，熵值: {modulus_entropy:.2f}")
            
            # 移动到下一个潜在匹配
            start = pos + 1
        
        return found_keys
    
    def scan_for_generic_keys(self, data):
        """扫描通用密钥标识符和格式"""
        found_keys = []
        
        for pattern in self.signatures["generic_keys"]["patterns"]:
            start = 0
            while True:
                pos = data.find(pattern, start)
                if pos == -1:
                    break
                
                # 提取标识符后的数据作为可能的密钥
                # 假设密钥紧随标识符，并且可能长度为16-64字节
                end_pos = pos + len(pattern)
                for key_size in [16, 24, 32, 48, 64]:
                    if end_pos + key_size <= len(data):
                        potential_key = data[end_pos:end_pos+key_size]
                        key_entropy = self._calculate_entropy(potential_key)
                        
                        # 只关注高熵值的数据
                        if key_entropy > 3.5:
                            pattern_text = pattern.decode('ascii', errors='ignore')
                            found_keys.append({
                                'type': 'generic_key',
                                'identifier': pattern_text,
                                'position': end_pos,
                                'size': key_size,
                                'value': binascii.hexlify(potential_key).decode('ascii'),
                                'entropy': key_entropy,
                                'confidence': min(key_entropy / 8.0 * 70, 60)  # 最高置信度为60%
                            })
                            
                            if self.verbose:
                                logger.debug(f"在位置 {end_pos} 找到可能的通用密钥，"
                                          f"标识符: {pattern_text}，熵值: {key_entropy:.2f}")
                
                # 移动到下一个潜在匹配
                start = pos + 1
        
        return found_keys
    
    def scan_for_ransomware_keys(self, data):
        """扫描勒索软件特有的密钥特征"""
        found_keys = []
        
        for ransomware_id, signature in self.ransomware_signatures.items():
            for pattern in signature["key_patterns"]:
                start = 0
                while True:
                    pos = data.find(pattern, start)
                    if pos == -1:
                        break
                    
                    # 记录发现的勒索软件特征
                    found_keys.append({
                        'type': 'ransomware_marker',
                        'ransomware': signature["name"],
                        'position': pos,
                        'pattern': pattern.decode('ascii', errors='ignore'),
                        'confidence': 80  # 特定勒索软件特征通常比较可靠
                    })
                    
                    if self.verbose:
                        logger.debug(f"在位置 {pos} 找到{signature['name']}特征")
                    
                    # 扫描附近区域的潜在密钥
                    # 勒索软件的密钥通常在其标识符附近
                    search_start = max(0, pos - 1024)
                    search_end = min(len(data), pos + 1024)
                    search_area = data[search_start:search_end]
                    
                    # 对搜索区域进行分析
                    for key_size in [16, 24, 32, 48, 64]:  # 常见加密密钥大小
                        for i in range(len(search_area) - key_size):
                            potential_key = search_area[i:i+key_size]
                            key_entropy = self._calculate_entropy(potential_key)
                            
                            # 只关注高熵值的数据
                            if key_entropy > 4.0:
                                actual_pos = search_start + i
                                found_keys.append({
                                    'type': f'{ransomware_id}_possible_key',
                                    'ransomware': signature["name"],
                                    'position': actual_pos,
                                    'size': key_size,
                                    'value': binascii.hexlify(potential_key).decode('ascii'),
                                    'entropy': key_entropy,
                                    'near_marker': True,
                                    'confidence': min(key_entropy / 8.0 * 85, 75)  # 最高置信度为75%
                                })
                                
                                if self.verbose:
                                    logger.debug(f"在位置 {actual_pos} 找到可能的{signature['name']}密钥，"
                                              f"熵值: {key_entropy:.2f}")
                    
                    # 移动到下一个潜在匹配
                    start = pos + 1
        
        return found_keys
    
    def _calculate_entropy(self, data):
        """计算数据的熵值"""
        if not data:
            return 0.0
        
        # 计算字节频率
        byte_counts = {}
        for b in data:
            byte_counts[b] = byte_counts.get(b, 0) + 1
        
        # 计算熵值
        entropy = 0.0
        for count in byte_counts.values():
            p = count / len(data)
            entropy -= p * (math.log(p) / math.log(2))
        
        return entropy
    
    def analyze_dump(self, chunk_size=4096):
        """分析内存转储文件以提取密钥"""
        logger.info(f"开始分析内存转储文件: {self.memory_dump}")
        results = {'keys': []}
        
        try:
            # 获取文件大小
            file_size = os.path.getsize(self.memory_dump)
            logger.info(f"转储文件大小: {file_size} 字节")
            
            # 分块读取并分析文件
            with open(self.memory_dump, 'rb') as f:
                # 对于小文件，一次性读取
                if file_size < 100 * 1024 * 1024:  # 小于100MB
                    logger.debug("一次性读取整个文件")
                    data = f.read()
                    
                    # 扫描各种密钥
                    logger.info("扫描AES密钥...")
                    aes_keys = self.scan_for_aes_keys(data)
                    results['keys'].extend(aes_keys)
                    
                    logger.info("扫描AES初始化向量...")
                    aes_ivs = self.scan_for_aes_ivs(data)
                    results['keys'].extend(aes_ivs)
                    
                    logger.info("扫描RSA密钥...")
                    rsa_keys = self.scan_for_rsa_keys(data)
                    results['keys'].extend(rsa_keys)
                    
                    logger.info("扫描通用加密标识符...")
                    generic_keys = self.scan_for_generic_keys(data)
                    results['keys'].extend(generic_keys)
                    
                    logger.info("扫描勒索软件特征...")
                    ransomware_keys = self.scan_for_ransomware_keys(data)
                    results['keys'].extend(ransomware_keys)
                    
                else:
                    # 对于大文件，分块处理
                    logger.debug(f"分块处理文件，每块 {chunk_size} 字节")
                    
                    # 迭代处理文件块
                    total_chunks = file_size // chunk_size + (1 if file_size % chunk_size else 0)
                    chunk_overlap = 64  # 块间重叠字节数，确保不会漏掉分割在块边界的内容
                    
                    data_buffer = b''  # 保留上一块的末尾部分
                    processed_chunks = 0
                    
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        
                        processed_chunks += 1
                        if processed_chunks % 100 == 0:
                            logger.debug(f"处理进度: {processed_chunks}/{total_chunks} 块")
                        
                        # 将上一块的末尾与当前块合并
                        data = data_buffer + chunk
                        
                        # 保留当前块的末尾部分
                        if len(chunk) >= chunk_overlap:
                            data_buffer = chunk[-chunk_overlap:]
                        else:
                            data_buffer = chunk
                        
                        # 扫描各种密钥
                        aes_keys = self.scan_for_aes_keys(data)
                        results['keys'].extend(aes_keys)
                        
                        aes_ivs = self.scan_for_aes_ivs(data)
                        results['keys'].extend(aes_ivs)
                        
                        rsa_keys = self.scan_for_rsa_keys(data)
                        results['keys'].extend(rsa_keys)
                        
                        generic_keys = self.scan_for_generic_keys(data)
                        results['keys'].extend(generic_keys)
                        
                        ransomware_keys = self.scan_for_ransomware_keys(data)
                        results['keys'].extend(ransomware_keys)
            
            # 对结果进行去重和排序
            unique_keys = {}
            for key in results['keys']:
                # 使用位置和类型作为去重标识
                key_id = f"{key['position']}_{key['type']}"
                
                # 如果是新发现的键或者置信度更高，则更新
                if key_id not in unique_keys or key['confidence'] > unique_keys[key_id]['confidence']:
                    unique_keys[key_id] = key
            
            # 将去重后的键按置信度排序
            sorted_keys = sorted(unique_keys.values(), key=lambda x: x['confidence'], reverse=True)
            results['keys'] = sorted_keys
            
            # 按类型对结果进行分组
            key_by_types = {}
            for key in sorted_keys:
                key_type = key['type']
                if key_type not in key_by_types:
                    key_by_types[key_type] = []
                key_by_types[key_type].append(key)
            
            results['keys_by_type'] = key_by_types
            
            # 添加分析汇总信息
            results['summary'] = {
                'file': self.memory_dump,
                'size': file_size,
                'analysis_time': datetime.now().isoformat(),
                'total_keys_found': len(sorted_keys),
                'key_type_counts': {k: len(v) for k, v in key_by_types.items()}
            }
            
            # 评估勒索软件特征
            ransomware_markers = key_by_types.get('ransomware_marker', [])
            if ransomware_markers:
                ransomware_names = set(marker['ransomware'] for marker in ransomware_markers)
                results['summary']['ransomware_detected'] = list(ransomware_names)
                logger.info(f"检测到勒索软件特征: {', '.join(ransomware_names)}")
            
            # 保存分析结果
            self.results = results
            self._save_results()
            
            logger.info(f"分析完成，共找到 {len(sorted_keys)} 个潜在密钥")
            return results
            
        except Exception as e:
            logger.error(f"分析内存转储文件时出错: {e}")
            return {'keys': [], 'error': str(e)}
    
    def _save_results(self):
        """保存分析结果到文件"""
        # 确定输出文件名
        dump_basename = os.path.basename(self.memory_dump)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        result_file = os.path.join(self.output_dir, f"{dump_basename}_keys_{timestamp}.json")
        
        # 保存JSON格式的结果
        with open(result_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        logger.info(f"分析结果已保存至: {result_file}")
        
        # 保存高置信度密钥提取
        high_conf_file = os.path.join(self.output_dir, f"{dump_basename}_high_conf_keys_{timestamp}.txt")
        with open(high_conf_file, 'w') as f:
            f.write(f"高置信度密钥提取 - {self.memory_dump}\n")
            f.write(f"分析时间: {datetime.now().isoformat()}\n\n")
            
            for key in self.results['keys']:
                if key['confidence'] >= 70:  # 只保存高置信度密钥
                    f.write(f"类型: {key['type']}\n")
                    f.write(f"位置: {key['position']}\n")
                    f.write(f"置信度: {key['confidence']:.2f}%\n")
                    
                    if 'size' in key:
                        f.write(f"大小: {key['size']} 字节\n")
                    
                    if 'value' in key:
                        if len(key['value']) > 200:
                            f.write(f"值: {key['value'][:200]}...\n")
                        else:
                            f.write(f"值: {key['value']}\n")
                    
                    if 'entropy' in key:
                        f.write(f"熵值: {key['entropy']:.4f}\n")
                    
                    if 'ransomware' in key:
                        f.write(f"勒索软件: {key['ransomware']}\n")
                    
                    f.write("\n" + "-" * 40 + "\n\n")
        
        logger.info(f"高置信度密钥已保存至: {high_conf_file}")
        
        return result_file, high_conf_file

import math  # 用于熵值计算

def main():
    parser = argparse.ArgumentParser(description="内存密钥提取工具")
    parser.add_argument("memory_dump", help="要分析的内存转储文件路径")
    parser.add_argument("-o", "--output-dir", help="输出目录")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出")
    
    args = parser.parse_args()
    
    extractor = MemoryKeyExtractor(
        memory_dump=args.memory_dump,
        output_dir=args.output_dir,
        verbose=args.verbose
    )
    
    results = extractor.analyze_dump()
    
    # 打印分析摘要
    print("\n=== 分析摘要 ===")
    print(f"内存转储文件: {args.memory_dump}")
    print(f"文件大小: {results['summary']['size']} 字节")
    print(f"找到潜在密钥: {results['summary']['total_keys_found']} 个")
    
    if 'ransomware_detected' in results['summary']:
        print(f"检测到勒索软件特征: {', '.join(results['summary']['ransomware_detected'])}")
    
    print("\n密钥类型统计:")
    for key_type, count in results['summary']['key_type_counts'].items():
        print(f"  {key_type}: {count} 个")
    
    print("\n前5个高置信度密钥:")
    for i, key in enumerate(results['keys'][:5]):
        print(f"#{i+1} {key['type']} (置信度: {key['confidence']:.2f}%)")
        if 'value' in key and isinstance(key['value'], str):
            if len(key['value']) > 60:
                print(f"  值: {key['value'][:60]}...")
            else:
                print(f"  值: {key['value']}")
    
    print(f"\n详细结果已保存至: {args.output_dir or os.path.dirname(args.memory_dump)}")

if __name__ == "__main__":
    main()
EOF < /dev/null