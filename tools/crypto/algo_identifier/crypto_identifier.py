#\!/usr/bin/env python3
"""
加密算法识别工具 - 识别文件中使用的加密算法特征
"""
import os
import sys
import re
import json
import binascii
import argparse
from datetime import datetime
from collections import Counter

class CryptoIdentifier:
    def __init__(self, file_path, verbose=False):
        self.file_path = file_path
        self.verbose = verbose
        self.results = {}
        
        # 加密算法特征
        self.signatures = {
            'aes': {
                'name': 'Advanced Encryption Standard (AES)',
                'description': 'Rijndael对称加密算法，在众多勒索软件中常用',
                'patterns': [
                    rb'\x52\x69\x6A\x6E\x64\x61\x65\x6C',  # "Rijndael" 字符串
                    rb'AES',  # AES字符串
                    rb'aes',  # aes字符串(小写)
                    # AES S-box部分特征
                    rb'\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76',
                    # AES-128密钥扩展常量
                    rb'\x01\x00\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x08\x00\x00\x00'
                ],
                'confidence': 0.7,
                'block_sizes': [16, 32, 64]  # 128位、256位、512位块
            },
            'rsa': {
                'name': 'RSA',
                'description': '公钥加密算法，通常用于加密对称密钥',
                'patterns': [
                    rb'RSA',
                    rb'rsa',
                    rb'-----BEGIN PUBLIC KEY-----',
                    rb'-----BEGIN RSA PUBLIC KEY-----',
                    rb'-----BEGIN RSA PRIVATE KEY-----'
                ],
                'confidence': 0.8,
                'min_key_size': 128  # 最小RSA密钥字节大小
            },
            'rc4': {
                'name': 'RC4',
                'description': '流加密算法，因其简单性在某些勒索软件中使用',
                'patterns': [
                    rb'RC4',
                    rb'rc4',
                    rb'ARCFOUR',
                    rb'arcfour'
                ],
                'confidence': 0.5
            },
            'blowfish': {
                'name': 'Blowfish',
                'description': '对称块加密算法，在早期勒索软件中有使用',
                'patterns': [
                    rb'Blowfish',
                    rb'blowfish',
                    rb'BLOWFISH',
                    # Blowfish P-数组初始化部分特征
                    rb'\x24\x3f\x6a\x88\x85\xa3\x08\xd3\x13\x19\x8a\x2e\x03\x70\x73\x44'
                ],
                'confidence': 0.6,
                'block_sizes': [8]  # 64位块
            },
            'des': {
                'name': 'Data Encryption Standard (DES)',
                'description': '较旧的对称加密算法，但在一些勒索软件变种中仍有使用',
                'patterns': [
                    rb'DES',
                    rb'des',
                    rb'3DES',
                    rb'3des',
                    # DES初始置换表部分特征
                    rb'\x3A\x32\x2A\x22\x1A\x12\x0A\x02'
                ],
                'confidence': 0.4,
                'block_sizes': [8]  # 64位块
            },
            'sha1': {
                'name': 'SHA-1',
                'description': '哈希算法，常用于数据完整性验证',
                'patterns': [
                    rb'SHA1',
                    rb'sha1',
                    rb'SHA-1',
                    rb'sha-1',
                    # SHA-1常量
                    rb'\x67\x45\x23\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x10\x32\x54\x76'
                ],
                'confidence': 0.5
            },
            'sha256': {
                'name': 'SHA-256',
                'description': '安全哈希算法，常用于数据完整性和文件签名',
                'patterns': [
                    rb'SHA256',
                    rb'sha256',
                    rb'SHA-256',
                    rb'sha-256',
                    # SHA-256常量
                    rb'\x6a\x09\xe6\x67\xbb\x67\xae\x85\x3c\x6e\xf3\x72\xa5\x4f\xf5\x3a'
                ],
                'confidence': 0.6
            },
            'salsa20': {
                'name': 'Salsa20',
                'description': '流加密算法，某些新型勒索软件使用',
                'patterns': [
                    rb'Salsa20',
                    rb'salsa20',
                    rb'SALSA20',
                    # Salsa20魔术常量"expand 32-byte k"
                    rb'expand 32-byte k'
                ],
                'confidence': 0.7
            },
            'chacha20': {
                'name': 'ChaCha20',
                'description': 'Salsa20的改进版流加密算法',
                'patterns': [
                    rb'ChaCha20',
                    rb'chacha20',
                    rb'CHACHA20',
                    # ChaCha20魔术常量"expand 32-byte k"
                    rb'expand 32-byte k'
                ],
                'confidence': 0.7
            },
            'twofish': {
                'name': 'Twofish',
                'description': '对称块加密算法，性能良好',
                'patterns': [
                    rb'Twofish',
                    rb'twofish',
                    rb'TWOFISH'
                ],
                'confidence': 0.5,
                'block_sizes': [16]  # 128位块
            },
            'serpent': {
                'name': 'Serpent',
                'description': '对称块加密算法，以其安全性著称',
                'patterns': [
                    rb'Serpent',
                    rb'serpent',
                    rb'SERPENT'
                ],
                'confidence': 0.4,
                'block_sizes': [16]  # 128位块
            }
        }
        
        # 勒索软件特定加密特征
        self.ransomware_profiles = {
            'wannacry': {
                'name': 'WannaCry',
                'description': '2017年大规模传播的勒索软件，利用永恒之蓝漏洞',
                'patterns': [
                    rb'WannaCry',
                    rb'wannacry',
                    rb'WannaCrypt',
                    rb'WANACRY',
                    rb'wncry',
                    rb'.wncry',
                    rb'WNCRYT',
                    rb'msg/m_bulgarian.wnry', 
                    rb'msg/m_chinese (simplified).wnry',
                    rb'\!Please Read Me\!.txt'
                ],
                'extensions': ['.wncry', '.wcry', '.wncrypt', '.wnry'],
                'algorithms': ['rsa', 'aes'],
                'confidence': 0.9
            },
            'ryuk': {
                'name': 'Ryuk',
                'description': '针对企业的勒索软件，常与TrickBot一起使用',
                'patterns': [
                    rb'Ryuk',
                    rb'ryuk',
                    rb'RyukReadMe.txt',
                    rb'RyukReadMe.html',
                    rb'No system is safe'
                ],
                'extensions': ['.ryuk', '.RYK'],
                'algorithms': ['rsa', 'aes'],
                'confidence': 0.8
            },
            'gandcrab': {
                'name': 'GandCrab',
                'description': '通过RaaS模式分发的勒索软件',
                'patterns': [
                    rb'GandCrab',
                    rb'gandcrab',
                    rb'GANDCRAB',
                    rb'KRAB',
                    rb'.CRAB'
                ],
                'extensions': ['.gdcb', '.crab', '.krab', '.GandCrab'],
                'algorithms': ['rsa', 'salsa20'],
                'confidence': 0.7
            },
            'locky': {
                'name': 'Locky',
                'description': '通过恶意邮件传播的勒索软件',
                'patterns': [
                    rb'Locky',
                    rb'locky',
                    rb'LOCKY',
                    rb'_Locky_recover_instructions.txt',
                    rb'_Locky_recover_instructions.bmp',
                    rb'_HELP_instructions.bmp'
                ],
                'extensions': ['.locky', '.zepto', '.odin', '.aesir', '.thor', '.zzzzz', '.osiris'],
                'algorithms': ['rsa', 'aes'],
                'confidence': 0.7
            },
            'revil': {
                'name': 'REvil/Sodinokibi',
                'description': 'RaaS勒索软件，曾针对多家大型企业',
                'patterns': [
                    rb'REvil',
                    rb'revil',
                    rb'Sodinokibi',
                    rb'sodinokibi',
                    rb'SODINOKIBI',
                    rb'[Decryptor]',
                    rb'.onion'
                ],
                'extensions': ['.sodinokibi', '.rvl', '.revil', '.sodin'],
                'algorithms': ['rsa', 'salsa20', 'elliptic'],
                'confidence': 0.8
            },
            'maze': {
                'name': 'Maze',
                'description': '数据窃取+加密类型的勒索软件',
                'patterns': [
                    rb'Maze',
                    rb'maze',
                    rb'MAZE',
                    rb'DECRYPT-FILES.txt',
                    rb'DECRYPT-FILES.html',
                    rb'Maze Ransomware'
                ],
                'extensions': ['.maze'],
                'algorithms': ['chacha20', 'rsa'],
                'confidence': 0.7
            },
            'djvu': {
                'name': 'DJVU/STOP',
                'description': '针对个人用户的常见勒索软件',
                'patterns': [
                    rb'DJVU',
                    rb'djvu',
                    rb'STOP',
                    rb'.djvus.ext',
                    rb'_readme.txt',
                    rb'RestoreFiles.txt'
                ],
                'extensions': ['.djvu', '.djvuu', '.udjvu', '.djvuq', '.djvur', '.djvut', '.pdff'],
                'algorithms': ['rsa', 'aes'],
                'confidence': 0.7
            }
        }
    
    def check_file_header(self, data):
        """检查文件头部以识别文件类型"""
        file_type = "未知"
        confidence = 0.0
        
        # 检查常见文件头
        if data.startswith(b'MZ'):
            file_type = "Windows可执行文件 (PE)"
            confidence = 0.9
        elif data.startswith(b'PK\x03\x04'):
            file_type = "ZIP归档 (可能是Office文档、JAR等)"
            confidence = 0.9
        elif data.startswith(b'\x7FELF'):
            file_type = "Linux可执行文件 (ELF)"
            confidence = 0.9
        elif data.startswith(b'%PDF'):
            file_type = "PDF文档"
            confidence = 0.9
        elif data[0:8] == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
            file_type = "Microsoft复合文档格式 (DOC、XLS等)"
            confidence = 0.9
        # 添加更多文件头检测...
        
        return {
            'type': file_type,
            'confidence': confidence
        }
    
    def check_entropy(self, data):
        """简单的熵检查"""
        if not data:
            return 0.0
            
        # 计算字节频率
        counter = Counter(data)
        length = len(data)
        
        # 计算频率
        frequencies = [count / length for count in counter.values()]
        
        # 计算熵值
        import math
        entropy = -sum(freq * math.log2(freq) for freq in frequencies)
        
        return entropy
    
    def check_crypto_signatures(self, data):
        """检查数据中是否存在加密算法特征"""
        findings = {}
        
        for algo_id, algo_info in self.signatures.items():
            matches = []
            confidence = 0.0
            
            for pattern in algo_info['patterns']:
                # 在数据中搜索特征
                found = []
                start = 0
                while True:
                    pos = data.find(pattern, start)
                    if pos == -1:
                        break
                    found.append(pos)
                    start = pos + 1
                
                if found:
                    matches.extend(found)
                    confidence += algo_info['confidence'] * (len(found) / len(algo_info['patterns']))
            
            # 如果找到匹配，添加到结果
            if matches:
                # 归一化置信度，最高为1.0
                norm_confidence = min(confidence, 1.0)
                
                findings[algo_id] = {
                    'name': algo_info['name'],
                    'description': algo_info['description'],
                    'match_positions': matches,
                    'match_count': len(matches),
                    'confidence': norm_confidence
                }
        
        return findings
    
    def check_ransomware_profiles(self, data):
        """检查是否匹配已知勒索软件特征"""
        findings = {}
        
        for ransomware_id, profile in self.ransomware_profiles.items():
            matches = []
            confidence = 0.0
            
            for pattern in profile['patterns']:
                # 在数据中搜索特征
                found = []
                start = 0
                while True:
                    pos = data.find(pattern, start)
                    if pos == -1:
                        break
                    found.append(pos)
                    start = pos + 1
                
                if found:
                    matches.extend(found)
                    confidence += profile['confidence'] * (len(found) / len(profile['patterns']))
            
            # 检查文件扩展名是否匹配
            file_ext = os.path.splitext(self.file_path)[1].lower()
            if file_ext in profile['extensions']:
                confidence += 0.3
                matches.append(f"文件扩展名匹配: {file_ext}")
            
            # 如果找到匹配，添加到结果
            if matches or confidence > 0:
                # 归一化置信度，最高为1.0
                norm_confidence = min(confidence, 1.0)
                
                findings[ransomware_id] = {
                    'name': profile['name'],
                    'description': profile['description'],
                    'match_details': matches,
                    'match_count': len(matches),
                    'confidence': norm_confidence,
                    'likely_algorithms': profile['algorithms']
                }
        
        return findings
    
    def check_encryption_patterns(self, data):
        """检查加密特征模式"""
        features = {}
        
        # 检查块大小特征
        blocks = []
        for size in [8, 16, 32, 64, 128]:
            # 分析数据块重复性
            chunk_size = size
            chunks = [data[i:i+chunk_size] for i in range(0, len(data)-chunk_size, chunk_size)]
            if not chunks:
                continue
                
            unique_ratio = len(set(chunks)) / len(chunks)
            blocks.append({
                'size': size,
                'unique_ratio': unique_ratio
            })
        
        features['block_analysis'] = blocks
        
        # 检查基于位的特征
        import numpy as np
        if len(data) > 1000:
            # 转换为位序列并分析
            bits = np.unpackbits(np.frombuffer(data[:1000], dtype=np.uint8))
            bits_mean = np.mean(bits)
            bits_std = np.std(bits)
            
            features['bit_analysis'] = {
                'mean': float(bits_mean),
                'std': float(bits_std),
                'randomness': float(bits_std / 0.5)  # 值接近1表示良好的随机性
            }
        
        # 检查是否存在密钥或IV（初始向量）
        key_iv_patterns = []
        
        # 16字节 (128位) 的重复或明显模式 - 常见的AES密钥/IV大小
        for i in range(0, len(data)-16):
            block = data[i:i+16]
            # 检查是否为可能的密钥/IV
            # 重复的字节很少是有效的密钥
            if len(set(block)) > 8:  # 至少8个不同的字节
                hex_block = binascii.hexlify(block).decode('ascii')
                key_iv_patterns.append({
                    'position': i,
                    'size': 16,
                    'hex': hex_block,
                    'entropy': self.check_entropy(block)
                })
        
        # 只保留熵值高的前10个可能的密钥/IV
        key_iv_patterns = sorted(key_iv_patterns, key=lambda x: x['entropy'], reverse=True)[:10]
        features['possible_keys_ivs'] = key_iv_patterns
        
        return features
    
    def analyze(self):
        """对文件进行分析"""
        try:
            if self.verbose:
                print(f"分析文件: {self.file_path}")
            
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            file_size = len(data)
            
            # 基本信息
            self.results['file_path'] = self.file_path
            self.results['file_size'] = file_size
            self.results['analysis_time'] = datetime.now().isoformat()
            
            # 检查文件类型
            file_type_info = self.check_file_header(data)
            self.results['file_type'] = file_type_info
            
            # 计算总体熵
            entropy = self.check_entropy(data)
            self.results['entropy'] = entropy
            
            # 评估熵值
            if entropy > 7.8:
                entropy_assessment = "非常高 (几乎肯定是加密的)"
            elif entropy > 7.0:
                entropy_assessment = "高 (很可能是加密的)"
            elif entropy > 6.0:
                entropy_assessment = "中等 (可能部分加密或压缩)"
            else:
                entropy_assessment = "低 (可能未加密)"
            self.results['entropy_assessment'] = entropy_assessment
            
            # 寻找加密算法特征
            crypto_findings = self.check_crypto_signatures(data)
            self.results['crypto_algorithms'] = crypto_findings
            
            # 检查是否匹配已知勒索软件
            ransomware_findings = self.check_ransomware_profiles(data)
            self.results['ransomware_matches'] = ransomware_findings
            
            # 分析加密模式
            encryption_features = self.check_encryption_patterns(data)
            self.results['encryption_features'] = encryption_features
            
            # 生成摘要结论
            self.generate_conclusion()
            
            if self.verbose:
                self.print_summary()
            
            return self.results
            
        except Exception as e:
            print(f"分析文件时出错: {e}")
            return None
    
    def generate_conclusion(self):
        """基于分析生成结论"""
        conclusion = {
            'is_encrypted': False,
            'encryption_probability': 0.0,
            'likely_algorithms': [],
            'ransomware_match': None,
            'recommendations': []
        }
        
        # 根据熵值评估加密可能性
        entropy = self.results.get('entropy', 0)
        if entropy > 7.8:
            conclusion['encryption_probability'] = 0.95
            conclusion['is_encrypted'] = True
        elif entropy > 7.0:
            conclusion['encryption_probability'] = 0.8
            conclusion['is_encrypted'] = True
        elif entropy > 6.5:
            conclusion['encryption_probability'] = 0.5
        elif entropy > 6.0:
            conclusion['encryption_probability'] = 0.3
        else:
            conclusion['encryption_probability'] = 0.1
        
        # 确定可能的加密算法
        crypto_algos = self.results.get('crypto_algorithms', {})
        if crypto_algos:
            # 按置信度排序
            sorted_algos = sorted(crypto_algos.items(), key=lambda x: x[1]['confidence'], reverse=True)
            conclusion['likely_algorithms'] = [
                {
                    'id': algo_id,
                    'name': algo_info['name'],
                    'confidence': algo_info['confidence']
                }
                for algo_id, algo_info in sorted_algos if algo_info['confidence'] > 0.3
            ]
        
        # 确定匹配的勒索软件
        ransomware_matches = self.results.get('ransomware_matches', {})
        if ransomware_matches:
            # 按置信度排序
            sorted_ransomware = sorted(ransomware_matches.items(), 
                                     key=lambda x: x[1]['confidence'], reverse=True)
            
            top_match = sorted_ransomware[0]
            if top_match[1]['confidence'] > 0.5:
                conclusion['ransomware_match'] = {
                    'id': top_match[0],
                    'name': top_match[1]['name'],
                    'confidence': top_match[1]['confidence'],
                    'description': top_match[1]['description']
                }
        
        # 基于发现生成建议
        if conclusion['is_encrypted']:
            conclusion['recommendations'].append(
                "文件很可能已被加密，根据熵值和加密特征分析。"
            )
            
            if conclusion['ransomware_match']:
                match = conclusion['ransomware_match']
                conclusion['recommendations'].append(
                    f"文件可能被{match['name']}勒索软件加密。考虑查看"
                    f"https://www.nomoreransom.org/以寻找潜在的解密工具。"
                )
            
            if conclusion['likely_algorithms']:
                algo_names = [algo['name'] for algo in conclusion['likely_algorithms'][:2]]
                conclusion['recommendations'].append(
                    f"检测到可能使用的加密算法: {', '.join(algo_names)}。"
                )
        else:
            conclusion['recommendations'].append(
                "文件可能未加密或仅部分加密。考虑进一步分析。"
            )
        
        self.results['conclusion'] = conclusion
    
    def print_summary(self):
        """打印分析摘要"""
        print("\n============== 加密分析摘要 ==============")
        print(f"文件: {self.results['file_path']}")
        print(f"大小: {self.results['file_size']} 字节")
        print(f"熵值: {self.results['entropy']:.6f} ({self.results['entropy_assessment']})")
        print(f"文件类型: {self.results['file_type']['type']} (置信度: {self.results['file_type']['confidence']:.2f})")
        
        print("\n检测到的加密算法:")
        for algo_id, algo_info in self.results['crypto_algorithms'].items():
            print(f"- {algo_info['name']} (置信度: {algo_info['confidence']:.2f})")
        
        print("\n勒索软件匹配:")
        for ransomware_id, ransomware_info in self.results['ransomware_matches'].items():
            print(f"- {ransomware_info['name']} (置信度: {ransomware_info['confidence']:.2f})")
            print(f"  描述: {ransomware_info['description']}")
            print(f"  可能使用的算法: {', '.join(ransomware_info['likely_algorithms'])}")
        
        print("\n结论:")
        conclusion = self.results['conclusion']
        print(f"加密可能性: {conclusion['encryption_probability']:.2f}")
        if conclusion['likely_algorithms']:
            print("可能的加密算法:")
            for algo in conclusion['likely_algorithms']:
                print(f"- {algo['name']} (置信度: {algo['confidence']:.2f})")
        
        if conclusion['ransomware_match']:
            match = conclusion['ransomware_match']
            print(f"可能的勒索软件: {match['name']} (置信度: {match['confidence']:.2f})")
            print(f"描述: {match['description']}")
        
        print("\n建议:")
        for rec in conclusion['recommendations']:
            print(f"- {rec}")
        
        print("==========================================")
    
    def save_results(self, output_path=None):
        """保存分析结果到JSON文件"""
        try:
            if not output_path:
                output_path = f"{os.path.basename(self.file_path)}_crypto_analysis.json"
            
            with open(output_path, 'w') as f:
                json.dump(self.results, f, indent=2)
            
            if self.verbose:
                print(f"分析结果已保存至: {output_path}")
            
            return True
            
        except Exception as e:
            print(f"保存结果时出错: {e}")
            return False

def analyze_files(file_paths, output_dir=None, verbose=False):
    """分析多个文件并保存结果"""
    results = []
    
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    for file_path in file_paths:
        try:
            analyzer = CryptoIdentifier(file_path, verbose)
            result = analyzer.analyze()
            
            if output_dir:
                output_path = os.path.join(output_dir, f"{os.path.basename(file_path)}_crypto_analysis.json")
                analyzer.save_results(output_path)
            else:
                analyzer.save_results()
            
            results.append(result)
            
        except Exception as e:
            print(f"分析文件 {file_path} 时出错: {e}")
    
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="加密算法识别工具")
    parser.add_argument("files", nargs='+', help="要分析的文件路径")
    parser.add_argument("-o", "--output-dir", help="输出目录")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出")
    
    args = parser.parse_args()
    
    analyze_files(args.files, args.output_dir, args.verbose)
EOF < /dev/null