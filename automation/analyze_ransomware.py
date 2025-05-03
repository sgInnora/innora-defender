#\!/usr/bin/env python3
"""
勒索软件自动化分析流程 - 集成多种分析方法的全面流水线
"""
import os
import sys
import json
import argparse
import shutil
import hashlib
import logging
import tempfile
import datetime
import time
import threading
import subprocess
from pathlib import Path

class RansomwareAnalyzer:
    def __init__(self, sample_path, work_dir=None, output_dir=None, verbose=False):
        self.sample_path = os.path.abspath(sample_path)
        self.sample_name = os.path.basename(sample_path)
        self.verbose = verbose
        
        # 设置工作目录
        if work_dir:
            self.work_dir = os.path.abspath(work_dir)
        else:
            self.work_dir = tempfile.mkdtemp(prefix='ransom_analysis_')
        
        # 设置输出目录
        if output_dir:
            self.output_dir = os.path.abspath(output_dir)
        else:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = os.path.join(os.path.dirname(self.sample_path), 
                                         f"analysis_{os.path.splitext(self.sample_name)[0]}_{timestamp}")
        
        # 创建必要的目录
        os.makedirs(self.work_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, 'static'), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, 'dynamic'), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, 'crypto'), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, 'network'), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, 'reports'), exist_ok=True)
        
        # 设置日志
        log_file = os.path.join(self.output_dir, 'analysis.log')
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('RansomwareAnalyzer')
        
        # 样本副本路径
        self.sample_copy = os.path.join(self.work_dir, self.sample_name)
        
        # 分析结果
        self.results = {
            'sample': {
                'path': self.sample_path,
                'name': self.sample_name,
                'size': 0,
                'hashes': {}
            },
            'analysis_time': datetime.datetime.now().isoformat(),
            'static': {},
            'dynamic': {},
            'crypto': {},
            'network': {}
        }
    
    def compute_hashes(self):
        """计算样本文件哈希值"""
        self.logger.info("计算样本哈希值...")
        
        try:
            with open(self.sample_path, 'rb') as f:
                data = f.read()
            
            self.results['sample']['size'] = len(data)
            
            # MD5
            md5 = hashlib.md5(data).hexdigest()
            self.results['sample']['hashes']['md5'] = md5
            
            # SHA-1
            sha1 = hashlib.sha1(data).hexdigest()
            self.results['sample']['hashes']['sha1'] = sha1
            
            # SHA-256
            sha256 = hashlib.sha256(data).hexdigest()
            self.results['sample']['hashes']['sha256'] = sha256
            
            self.logger.info(f"MD5: {md5}")
            self.logger.info(f"SHA-1: {sha1}")
            self.logger.info(f"SHA-256: {sha256}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"计算哈希值失败: {e}")
            return False
    
    def prepare_sample(self):
        """准备样本文件副本"""
        self.logger.info("准备样本文件...")
        
        try:
            # 复制样本到工作目录
            shutil.copy2(self.sample_path, self.sample_copy)
            self.logger.info(f"样本已复制到: {self.sample_copy}")
            
            # 设置权限
            os.chmod(self.sample_copy, 0o600)
            
            return True
            
        except Exception as e:
            self.logger.error(f"准备样本失败: {e}")
            return False
    
    def run_static_analysis(self):
        """运行静态分析"""
        self.logger.info("开始静态分析...")
        static_results = {}
        
        # 1. 文件类型识别
        try:
            self.logger.info("识别文件类型...")
            file_output = subprocess.check_output(['file', self.sample_copy]).decode('utf-8')
            static_results['file_type'] = file_output.strip()
            self.logger.info(f"文件类型: {file_output.strip()}")
        except Exception as e:
            self.logger.error(f"文件类型识别失败: {e}")
        
        # 2. 提取字符串
        try:
            self.logger.info("提取字符串...")
            strings_output = os.path.join(self.output_dir, 'static', 'strings.txt')
            with open(strings_output, 'w') as out_file:
                subprocess.run(['strings', '-a', '-n', '8', self.sample_copy], 
                             stdout=out_file, check=True)
            
            static_results['strings_file'] = strings_output
            self.logger.info(f"字符串已保存到: {strings_output}")
            
            # 分析字符串中的关键词
            self.logger.info("分析字符串中的关键词...")
            keyword_patterns = [
                "ransom", "encrypt", "decrypt", "bitcoin", "btc", "wallet", 
                "payment", "victim", "restore", "recovery", ".onion", "tor", 
                "readme", "locker", "locked", "unlock", "key", "aes", "rsa"
            ]
            
            matched_keywords = {}
            with open(strings_output, 'r', errors='ignore') as f:
                strings_data = f.read()
                for keyword in keyword_patterns:
                    if keyword in strings_data.lower():
                        count = strings_data.lower().count(keyword)
                        matched_keywords[keyword] = count
            
            static_results['keyword_matches'] = matched_keywords
            if matched_keywords:
                self.logger.info(f"匹配的关键词: {matched_keywords}")
        except Exception as e:
            self.logger.error(f"字符串提取失败: {e}")
        
        # 3. 导入工具检查PE文件（如果是Windows可执行文件）
        if "PE32" in static_results.get('file_type', ''):
            try:
                self.logger.info("分析PE文件...")
                
                # 尝试使用工具目录中的Python脚本
                crypto_identifier_path = "../tools/crypto/algo_identifier/crypto_identifier.py"
                if os.path.exists(crypto_identifier_path):
                    output_file = os.path.join(self.output_dir, 'static', 'pe_crypto_analysis.json')
                    self.logger.info(f"运行加密算法识别分析...")
                    
                    try:
                        cmd = [sys.executable, crypto_identifier_path, self.sample_copy, 
                             '-o', os.path.dirname(output_file), '-v']
                        subprocess.run(cmd, check=True)
                        
                        # 读取结果
                        if os.path.exists(output_file):
                            with open(output_file, 'r') as f:
                                static_results['crypto_analysis'] = json.load(f)
                            self.logger.info(f"加密算法分析结果已保存到: {output_file}")
                    except Exception as e:
                        self.logger.error(f"加密算法分析失败: {e}")
                
                # 检查是否有哈希特征数据
                hash_sample = {
                    'md5': self.results['sample']['hashes'].get('md5', ''),
                    'sha1': self.results['sample']['hashes'].get('sha1', ''),
                    'sha256': self.results['sample']['hashes'].get('sha256', '')
                }
                static_results['hash_info'] = hash_sample
                
            except Exception as e:
                self.logger.error(f"PE文件分析失败: {e}")
        
        # 保存静态分析结果
        self.results['static'] = static_results
        
        # 写入JSON报告
        static_report = os.path.join(self.output_dir, 'static', 'static_analysis.json')
        with open(static_report, 'w') as f:
            json.dump(static_results, f, indent=2)
        
        self.logger.info(f"静态分析报告已保存到: {static_report}")
        return True
    
    def run_crypto_analysis(self):
        """运行加密相关分析"""
        self.logger.info("开始加密分析...")
        crypto_results = {}
        
        # 1. 熵分析
        try:
            self.logger.info("执行熵分析...")
            
            entropy_script = "../tools/crypto/entropy/entropy_analyzer.py"
            if os.path.exists(entropy_script):
                output_dir = os.path.join(self.output_dir, 'crypto')
                
                cmd = [sys.executable, entropy_script, self.sample_copy, 
                     '-o', output_dir, '-v']
                subprocess.run(cmd, check=True)
                
                # 检查结果
                entropy_result = os.path.join(output_dir, f"{self.sample_name}_entropy_analysis.json")
                if os.path.exists(entropy_result):
                    with open(entropy_result, 'r') as f:
                        crypto_results['entropy_analysis'] = json.load(f)
                    self.logger.info(f"熵分析结果已保存到: {entropy_result}")
            else:
                self.logger.warning(f"熵分析脚本未找到: {entropy_script}")
        except Exception as e:
            self.logger.error(f"熵分析失败: {e}")
        
        # 2. 查找潜在密钥
        try:
            self.logger.info("查找潜在加密密钥...")
            
            key_finder = "../tools/crypto/key_finder/key_finder.py"
            if os.path.exists(key_finder):
                output_file = os.path.join(self.output_dir, 'crypto', f"{self.sample_name}_key_analysis.json")
                
                cmd = [sys.executable, key_finder, self.sample_copy, 
                     '-o', output_file, '-v']
                subprocess.run(cmd, check=True)
                
                # 检查结果
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        crypto_results['key_analysis'] = json.load(f)
                    self.logger.info(f"密钥分析结果已保存到: {output_file}")
            else:
                self.logger.warning(f"密钥查找脚本未找到: {key_finder}")
        except Exception as e:
            self.logger.error(f"密钥查找失败: {e}")
        
        # 保存加密分析结果
        self.results['crypto'] = crypto_results
        
        # 写入JSON报告
        crypto_report = os.path.join(self.output_dir, 'crypto', 'crypto_analysis.json')
        with open(crypto_report, 'w') as f:
            json.dump(crypto_results, f, indent=2)
        
        self.logger.info(f"加密分析报告已保存到: {crypto_report}")
        return True
    
    def setup_test_directory(self):
        """创建测试目录用于监控加密行为"""
        self.logger.info("设置测试目录...")
        
        test_dir = os.path.join(self.work_dir, 'test_files')
        os.makedirs(test_dir, exist_ok=True)
        
        # 创建测试文件
        file_types = [
            {'ext': '.txt', 'content': '这是测试文本文件，用于测试勒索软件加密行为。'},
            {'ext': '.doc', 'content': 'TEST DOCUMENT FILE'},
            {'ext': '.xls', 'content': 'TEST SPREADSHEET FILE'},
            {'ext': '.pdf', 'content': '%PDF-1.5\nTEST PDF FILE\n%%EOF'},
            {'ext': '.jpg', 'content': 'TESTJPGFILE'}
        ]
        
        created_files = []
        
        for i in range(1, 11):  # 创建10个文件
            for file_type in file_types:
                file_name = f"test_{i}{file_type['ext']}"
                file_path = os.path.join(test_dir, file_name)
                
                with open(file_path, 'w') as f:
                    f.write(file_type['content'])
                
                created_files.append(file_path)
        
        # 创建子目录
        subdir = os.path.join(test_dir, 'important')
        os.makedirs(subdir, exist_ok=True)
        
        # 在子目录中创建文件
        for i in range(1, 6):  # 创建5个文件
            file_path = os.path.join(subdir, f"important_{i}.txt")
            with open(file_path, 'w') as f:
                f.write(f"这是重要文件 {i}")
            created_files.append(file_path)
        
        self.logger.info(f"测试目录已创建: {test_dir}")
        self.logger.info(f"已创建 {len(created_files)} 个测试文件")
        
        return test_dir
    
    def run_dynamic_analysis(self):
        """准备动态分析（使用Docker沙箱）"""
        self.logger.info("开始准备动态分析环境...")
        dynamic_results = {}
        
        # 1. 设置测试目录
        test_dir = self.setup_test_directory()
        dynamic_results['test_directory'] = test_dir
        
        # 2. 检查Docker可用性
        try:
            subprocess.check_output(['docker', '--version'])
            dynamic_results['docker_available'] = True
            self.logger.info("Docker可用，准备设置分析容器...")
            
            # 3. 使用Docker沙箱
            # 注意：此处仅打印Docker运行命令，实际执行可能需要更多安全措施
            docker_cmd = (
                f"docker run --rm -it --network none "
                f"-v {self.work_dir}:/analysis/workspace "
                f"-v {self.output_dir}/dynamic:/analysis/output "
                f"ransomware-analysis-sandbox "
                f"/analysis/workspace/{self.sample_name}"
            )
            
            dynamic_results['docker_command'] = docker_cmd
            self.logger.info(f"Docker运行命令: {docker_cmd}")
            self.logger.warning("注意：为安全起见，需手动在隔离环境中运行上述命令")
        except Exception as e:
            dynamic_results['docker_available'] = False
            self.logger.warning(f"Docker不可用: {e}")
            self.logger.warning("请确保在安全的虚拟机或沙箱环境中运行样本")
        
        # 4. 准备监控脚本
        monitor_script_src = "../sandboxes/isolation/monitor_scripts/monitor_ransomware.sh"
        if os.path.exists(monitor_script_src):
            monitor_script_dst = os.path.join(self.work_dir, "monitor_ransomware.sh")
            shutil.copy2(monitor_script_src, monitor_script_dst)
            os.chmod(monitor_script_dst, 0o755)
            
            dynamic_results['monitor_script'] = monitor_script_dst
            self.logger.info(f"监控脚本已复制到: {monitor_script_dst}")
            
            # 监控命令示例
            monitor_cmd = f"{monitor_script_dst} {self.sample_copy} {test_dir}"
            dynamic_results['monitor_command'] = monitor_cmd
            self.logger.info(f"监控命令: {monitor_cmd}")
        else:
            self.logger.warning(f"监控脚本未找到: {monitor_script_src}")
        
        # 保存动态分析准备结果
        self.results['dynamic'] = dynamic_results
        
        # 写入JSON报告
        dynamic_report = os.path.join(self.output_dir, 'dynamic', 'dynamic_analysis_setup.json')
        with open(dynamic_report, 'w') as f:
            json.dump(dynamic_results, f, indent=2)
        
        self.logger.info(f"动态分析设置报告已保存到: {dynamic_report}")
        return True
    
    def generate_report(self):
        """生成综合分析报告"""
        self.logger.info("生成综合分析报告...")
        
        report = {
            'analysis_time': datetime.datetime.now().isoformat(),
            'sample': self.results['sample'],
            'summary': {
                'static_analysis': True if self.results.get('static') else False,
                'crypto_analysis': True if self.results.get('crypto') else False,
                'dynamic_analysis_setup': True if self.results.get('dynamic') else False
            },
            'findings': {
                'encryption_indicators': [],
                'ransomware_indicators': [],
                'recommendations': []
            }
        }
        
        # 处理静态分析结果
        static = self.results.get('static', {})
        if static:
            # 检查关键词匹配
            keywords = static.get('keyword_matches', {})
            if keywords:
                ransom_keywords = ['ransom', 'encrypt', 'decrypt', 'bitcoin', 'wallet', 'payment']
                found_ransom_keywords = [k for k in ransom_keywords if k in keywords]
                
                if found_ransom_keywords:
                    indicator = f"在字符串中发现勒索软件相关关键词: {', '.join(found_ransom_keywords)}"
                    report['findings']['ransomware_indicators'].append(indicator)
            
            # 检查加密分析
            crypto_analysis = static.get('crypto_analysis', {})
            if crypto_analysis and 'crypto_algorithms' in crypto_analysis:
                crypto_algos = crypto_analysis['crypto_algorithms']
                if crypto_algos:
                    algo_names = [algo['name'] for algo_id, algo in crypto_algos.items()]
                    indicator = f"在静态分析中检测到加密算法特征: {', '.join(algo_names)}"
                    report['findings']['encryption_indicators'].append(indicator)
        
        # 处理加密分析结果
        crypto = self.results.get('crypto', {})
        if crypto:
            # 检查熵分析
            entropy_analysis = crypto.get('entropy_analysis', {})
            if entropy_analysis and 'entropy' in entropy_analysis:
                entropy = entropy_analysis['entropy']
                if entropy > 7.0:
                    indicator = f"文件熵值很高 ({entropy:.4f})，表明可能是加密或压缩数据"
                    report['findings']['encryption_indicators'].append(indicator)
            
            # 检查密钥分析
            key_analysis = crypto.get('key_analysis', {})
            if key_analysis and 'potential_keys' in key_analysis:
                keys = key_analysis['potential_keys']
                if keys:
                    indicator = f"发现 {len(keys)} 个潜在的加密密钥"
                    report['findings']['encryption_indicators'].append(indicator)
        
        # 形成结论和建议
        if report['findings']['ransomware_indicators']:
            report['findings']['recommendations'].append(
                "文件显示出勒索软件的特征。建议在完全隔离的环境中进行进一步动态分析。"
            )
            
            report['findings']['recommendations'].append(
                "不要在生产环境中执行此文件。考虑使用提供的沙箱或监控脚本在受控环境中观察其行为。"
            )
        
        if report['findings']['encryption_indicators']:
            report['findings']['recommendations'].append(
                "文件包含加密相关特征，可能具有加密功能。更多详情请查看加密分析报告。"
            )
        
        # 写入最终报告
        report_file = os.path.join(self.output_dir, 'reports', 'analysis_report.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # 生成HTML报告
        html_file = os.path.join(self.output_dir, 'reports', 'analysis_report.html')
        self.generate_html_report(report, html_file)
        
        self.logger.info(f"综合分析报告已保存到: {report_file}")
        self.logger.info(f"HTML报告已保存到: {html_file}")
        
        return report
    
    def generate_html_report(self, report, output_file):
        """生成HTML格式的报告"""
        html = f"""<\!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>勒索软件分析报告 - {report['sample']['name']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin-bottom: 30px; border: 1px solid #ddd; border-radius: 5px; padding: 20px; }}
        .info-table {{ width: 100%; border-collapse: collapse; }}
        .info-table th, .info-table td {{ padding: 10px; border-bottom: 1px solid #ddd; text-align: left; }}
        .info-table th {{ background-color: #f5f5f5; }}
        .indicator {{ padding: 8px; margin: 5px 0; border-radius: 3px; }}
        .ransomware-indicator {{ background-color: #ffecb3; border-left: 4px solid #ffc107; }}
        .encryption-indicator {{ background-color: #e1f5fe; border-left: 4px solid #03a9f4; }}
        .recommendation {{ background-color: #e8f5e9; border-left: 4px solid #4caf50; padding: 8px; margin: 5px 0; border-radius: 3px; }}
        .highlight {{ background-color: #fff9c4; }}
        pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>勒索软件分析报告</h1>
            <p>分析时间: {report['analysis_time']}</p>
        </div>
        
        <div class="section">
            <h2>样本信息</h2>
            <table class="info-table">
                <tr>
                    <th>文件名</th>
                    <td>{report['sample']['name']}</td>
                </tr>
                <tr>
                    <th>文件大小</th>
                    <td>{report['sample']['size']} 字节</td>
                </tr>
                <tr>
                    <th>MD5</th>
                    <td><code>{report['sample']['hashes'].get('md5', 'N/A')}</code></td>
                </tr>
                <tr>
                    <th>SHA-1</th>
                    <td><code>{report['sample']['hashes'].get('sha1', 'N/A')}</code></td>
                </tr>
                <tr>
                    <th>SHA-256</th>
                    <td><code>{report['sample']['hashes'].get('sha256', 'N/A')}</code></td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>执行的分析</h2>
            <table class="info-table">
                <tr>
                    <th>静态分析</th>
                    <td>{'已完成' if report['summary']['static_analysis'] else '未执行'}</td>
                </tr>
                <tr>
                    <th>加密分析</th>
                    <td>{'已完成' if report['summary']['crypto_analysis'] else '未执行'}</td>
                </tr>
                <tr>
                    <th>动态分析准备</th>
                    <td>{'已完成' if report['summary']['dynamic_analysis_setup'] else '未执行'}</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>主要发现</h2>
            
            <h3>勒索软件指标</h3>
            {self._render_indicators(report['findings']['ransomware_indicators'], 'ransomware-indicator')}
            
            <h3>加密指标</h3>
            {self._render_indicators(report['findings']['encryption_indicators'], 'encryption-indicator')}
        </div>
        
        <div class="section">
            <h2>建议</h2>
            {self._render_recommendations(report['findings']['recommendations'])}
        </div>
        
        <div class="section">
            <h2>后续步骤</h2>
            <ol>
                <li>查看详细的分析报告以获取更多信息。</li>
                <li>如果需要，在安全的隔离环境中进行动态分析。</li>
                <li>参考输出目录中的JSON报告获取技术细节。</li>
                <li>对于检测到的潜在加密密钥，考虑使用解密工具进行尝试。</li>
            </ol>
        </div>
    </div>
</body>
</html>
"""
        with open(output_file, 'w') as f:
            f.write(html)
    
    def _render_indicators(self, indicators, class_name):
        """渲染指标列表为HTML"""
        if not indicators:
            return "<p>未发现指标</p>"
        
        html = ""
        for indicator in indicators:
            html += f'<div class="indicator {class_name}">{indicator}</div>\n'
        
        return html
    
    def _render_recommendations(self, recommendations):
        """渲染建议列表为HTML"""
        if not recommendations:
            return "<p>无建议</p>"
        
        html = ""
        for recommendation in recommendations:
            html += f'<div class="recommendation">{recommendation}</div>\n'
        
        return html
    
    def cleanup(self):
        """清理临时文件和目录"""
        self.logger.info("清理临时文件...")
        
        # 清理工作目录（如果使用了临时目录）
        if "temp" in self.work_dir or "_tmp" in self.work_dir:
            try:
                shutil.rmtree(self.work_dir)
                self.logger.info(f"工作目录已清理: {self.work_dir}")
            except Exception as e:
                self.logger.error(f"清理工作目录失败: {e}")
    
    def run(self):
        """运行完整分析流程"""
        try:
            self.logger.info(f"开始分析样本: {self.sample_path}")
            
            # 1. 计算哈希值
            if not self.compute_hashes():
                return False
            
            # 2. 准备样本
            if not self.prepare_sample():
                return False
            
            # 3. 运行静态分析
            if not self.run_static_analysis():
                self.logger.warning("静态分析失败或部分失败")
            
            # 4. 运行加密分析
            if not self.run_crypto_analysis():
                self.logger.warning("加密分析失败或部分失败")
            
            # 5. 准备动态分析
            if not self.run_dynamic_analysis():
                self.logger.warning("动态分析准备失败或部分失败")
            
            # 6. 生成综合报告
            report = self.generate_report()
            
            # 7. 清理
            self.cleanup()
            
            self.logger.info(f"分析完成。结果保存在: {self.output_dir}")
            return True
            
        except Exception as e:
            self.logger.error(f"分析过程中发生错误: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description="勒索软件自动化分析流程")
    parser.add_argument("sample", help="要分析的样本文件路径")
    parser.add_argument("-w", "--work-dir", help="工作目录（默认使用临时目录）")
    parser.add_argument("-o", "--output-dir", help="结果输出目录（默认在样本旁创建）")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出")
    
    args = parser.parse_args()
    
    analyzer = RansomwareAnalyzer(
        sample_path=args.sample,
        work_dir=args.work_dir,
        output_dir=args.output_dir,
        verbose=args.verbose
    )
    
    analyzer.run()

if __name__ == "__main__":
    main()
EOF < /dev/null