#\!/usr/bin/env python3
"""
熵分析工具 - 分析文件熵以检测加密、压缩或混淆
"""
import os
import sys
import math
import argparse
import json
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
from collections import Counter

class EntropyAnalyzer:
    def __init__(self, file_path, block_size=256, verbose=False):
        self.file_path = file_path
        self.block_size = block_size
        self.verbose = verbose
        self.results = {}
    
    def calculate_entropy(self, data):
        """计算给定数据的香农熵"""
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
    
    def analyze_file(self):
        """分析整个文件的熵值"""
        try:
            file_size = os.path.getsize(self.file_path)
            
            if self.verbose:
                print(f"分析文件: {self.file_path}")
                print(f"文件大小: {file_size} 字节")
            
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            # 计算整个文件的熵
            total_entropy = self.calculate_entropy(data)
            
            # 结果保存
            self.results['file_path'] = self.file_path
            self.results['file_size'] = file_size
            self.results['total_entropy'] = total_entropy
            self.results['analysis_time'] = datetime.now().isoformat()
            
            # 加密文件通常熵值大于7.0
            if total_entropy > 7.5:
                encryption_likelihood = "非常高 (几乎可以确定)"
            elif total_entropy > 7.0:
                encryption_likelihood = "高"
            elif total_entropy > 6.5:
                encryption_likelihood = "中等"
            elif total_entropy > 6.0:
                encryption_likelihood = "低"
            else:
                encryption_likelihood = "非常低"
            
            self.results['encryption_likelihood'] = encryption_likelihood
            
            if self.verbose:
                print(f"总熵值: {total_entropy:.6f}")
                print(f"加密可能性: {encryption_likelihood}")
            
            return total_entropy
                
        except Exception as e:
            print(f"分析文件时出错: {e}")
            return None
    
    def analyze_blocks(self):
        """分析文件块的熵值"""
        try:
            with open(self.file_path, 'rb') as f:
                blocks = []
                entropies = []
                
                # 读取块并计算熵
                while True:
                    block = f.read(self.block_size)
                    if not block:
                        break
                    
                    blocks.append(block)
                    entropy = self.calculate_entropy(block)
                    entropies.append(entropy)
            
            # 保存结果
            self.results['block_size'] = self.block_size
            self.results['num_blocks'] = len(blocks)
            self.results['block_entropies'] = entropies
            self.results['min_block_entropy'] = min(entropies) if entropies else 0
            self.results['max_block_entropy'] = max(entropies) if entropies else 0
            self.results['avg_block_entropy'] = sum(entropies) / len(entropies) if entropies else 0
            
            # 检测熵值变化点
            if len(entropies) > 1:
                entropy_diffs = [abs(entropies[i] - entropies[i-1]) for i in range(1, len(entropies))]
                max_diff_idx = entropy_diffs.index(max(entropy_diffs))
                self.results['max_entropy_change'] = {
                    'position': (max_diff_idx + 1) * self.block_size,
                    'from_entropy': entropies[max_diff_idx],
                    'to_entropy': entropies[max_diff_idx + 1],
                    'difference': entropy_diffs[max_diff_idx]
                }
                
                # 检测熵值突变点（对于加密文件起始点的判断）
                significant_changes = [(i, diff) for i, diff in enumerate(entropy_diffs) if diff > 1.0]
                if significant_changes:
                    self.results['significant_entropy_changes'] = [
                        {
                            'position': (idx + 1) * self.block_size,
                            'difference': diff
                        }
                        for idx, diff in significant_changes
                    ]
            
            if self.verbose:
                print(f"块大小: {self.block_size} 字节")
                print(f"块数量: {len(blocks)}")
                print(f"平均块熵值: {self.results['avg_block_entropy']:.6f}")
                print(f"最小块熵值: {self.results['min_block_entropy']:.6f}")
                print(f"最大块熵值: {self.results['max_block_entropy']:.6f}")
                
                if 'max_entropy_change' in self.results:
                    change = self.results['max_entropy_change']
                    print(f"最大熵值变化点: 位置 {change['position']} 字节, 变化 {change['difference']:.6f}")
                
                if 'significant_entropy_changes' in self.results:
                    print("显著熵值变化点:")
                    for change in self.results['significant_entropy_changes'][:5]:  # 显示前5个
                        print(f"  位置 {change['position']} 字节, 变化 {change['difference']:.6f}")
            
            return entropies
                
        except Exception as e:
            print(f"分析文件块时出错: {e}")
            return None
    
    def generate_plot(self, output_path=None):
        """生成熵值分布图"""
        if 'block_entropies' not in self.results or not self.results['block_entropies']:
            print("没有块熵值数据，无法生成图表")
            return False
        
        try:
            entropies = self.results['block_entropies']
            blocks = range(len(entropies))
            
            plt.figure(figsize=(12, 6))
            plt.plot(blocks, entropies, 'b-')
            plt.axhline(y=7.0, color='r', linestyle='--', label='加密/压缩阈值 (7.0)')
            
            # 总熵线
            if 'total_entropy' in self.results:
                plt.axhline(y=self.results['total_entropy'], color='g', linestyle='-', 
                           label=f"总熵值 ({self.results['total_entropy']:.4f})")
            
            # 标记显著变化点
            if 'significant_entropy_changes' in self.results:
                for change in self.results['significant_entropy_changes']:
                    position = change['position'] // self.block_size - 1
                    if 0 <= position < len(entropies):
                        plt.axvline(x=position, color='m', linestyle=':', 
                                   label=f"显著变化 (位置: {change['position']})")
            
            plt.title(f"文件熵值分析: {os.path.basename(self.file_path)}")
            plt.xlabel('块索引 (块大小: {} 字节)'.format(self.block_size))
            plt.ylabel('熵值 (bits)')
            plt.ylim(0, 8)
            plt.grid(True)
            plt.legend()
            
            # 保存或显示
            if output_path:
                plt.savefig(output_path)
                if self.verbose:
                    print(f"熵值分布图已保存至: {output_path}")
            else:
                plt.savefig(f"{os.path.basename(self.file_path)}_entropy.png")
                if self.verbose:
                    print(f"熵值分布图已保存至: {os.path.basename(self.file_path)}_entropy.png")
            
            plt.close()
            return True
            
        except Exception as e:
            print(f"生成图表时出错: {e}")
            return False
    
    def save_results(self, output_path=None):
        """保存分析结果到JSON文件"""
        try:
            if not output_path:
                output_path = f"{os.path.basename(self.file_path)}_entropy_analysis.json"
            
            # 转换numpy数组为普通列表以便JSON序列化
            if 'block_entropies' in self.results and isinstance(self.results['block_entropies'], np.ndarray):
                self.results['block_entropies'] = self.results['block_entropies'].tolist()
            
            with open(output_path, 'w') as f:
                json.dump(self.results, f, indent=2)
            
            if self.verbose:
                print(f"分析结果已保存至: {output_path}")
            
            return True
            
        except Exception as e:
            print(f"保存结果时出错: {e}")
            return False
    
    def run_analysis(self, output_dir=None):
        """运行完整分析"""
        # 创建输出目录
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            
        # 分析总熵
        self.analyze_file()
        
        # 分析块熵
        self.analyze_blocks()
        
        # 生成图表
        if output_dir:
            plot_path = os.path.join(output_dir, f"{os.path.basename(self.file_path)}_entropy.png")
            self.generate_plot(plot_path)
            
            # 保存结果
            result_path = os.path.join(output_dir, f"{os.path.basename(self.file_path)}_entropy_analysis.json")
            self.save_results(result_path)
        else:
            self.generate_plot()
            self.save_results()
        
        return self.results

def multi_file_analysis(file_paths, block_size=256, output_dir=None, verbose=False):
    """分析多个文件并比较结果"""
    results = []
    
    for file_path in file_paths:
        if verbose:
            print(f"\n分析文件: {file_path}")
        
        analyzer = EntropyAnalyzer(file_path, block_size, verbose)
        result = analyzer.run_analysis(output_dir)
        results.append(result)
    
    # 比较结果
    if len(results) > 1 and verbose:
        print("\n文件熵值比较:")
        for result in results:
            print(f"{result['file_path']}: 总熵值 = {result['total_entropy']:.6f}, 加密可能性 = {result['encryption_likelihood']}")
    
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="文件熵分析工具 - 检测加密或混淆")
    parser.add_argument("files", nargs='+', help="要分析的文件路径")
    parser.add_argument("-b", "--block-size", type=int, default=256, help="分析块大小(字节)")
    parser.add_argument("-o", "--output-dir", help="输出目录")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出")
    
    args = parser.parse_args()
    
    multi_file_analysis(args.files, args.block_size, args.output_dir, args.verbose)
EOF < /dev/null