#\!/usr/bin/env python3
"""
YARA内存扫描工具 - 使用YARA规则扫描内存转储或进程
"""
import os
import sys
import glob
import time
import argparse
import logging
import yara
import json
import psutil
import binascii
import tempfile
from datetime import datetime
from pathlib import Path

# 设置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('YARAMemScanner')

class YARAMemScanner:
    def __init__(self, rules_path=None, output_dir=None, verbose=False):
        self.rules_path = rules_path
        self.output_dir = output_dir or os.path.join(os.getcwd(), 'yara_results')
        self.verbose = verbose
        self.rules = None
        
        # 设置日志级别
        if verbose:
            logger.setLevel(logging.DEBUG)
        
        # 确保输出目录存在
        os.makedirs(self.output_dir, exist_ok=True)
    
    def load_rules(self, rules_path=None):
        """加载YARA规则"""
        rules_path = rules_path or self.rules_path
        
        if not rules_path:
            # 使用内置规则
            logger.info("使用内置的加密和勒索软件YARA规则")
            rules_dir = self._create_builtin_rules()
            self.rules_path = rules_dir
        elif os.path.isdir(rules_path):
            # 加载目录中的所有规则
            logger.info(f"从目录加载YARA规则: {rules_path}")
            rules_files = glob.glob(os.path.join(rules_path, "*.yar")) + \
                        glob.glob(os.path.join(rules_path, "*.yara"))
            if not rules_files:
                logger.error(f"在目录 {rules_path} 中未找到YARA规则文件")
                return False
        elif os.path.isfile(rules_path):
            # 加载单个规则文件
            logger.info(f"加载YARA规则文件: {rules_path}")
            rules_files = [rules_path]
        else:
            logger.error(f"规则路径无效: {rules_path}")
            return False
        
        # 加载规则
        try:
            if os.path.isdir(self.rules_path):
                # 从目录加载多个规则文件
                filepaths = {}
                for rule_file in glob.glob(os.path.join(self.rules_path, "*.yar")) + \
                              glob.glob(os.path.join(self.rules_path, "*.yara")):
                    rule_name = os.path.splitext(os.path.basename(rule_file))[0]
                    filepaths[rule_name] = rule_file
                
                self.rules = yara.compile(filepaths=filepaths)
                logger.info(f"已加载 {len(filepaths)} 个YARA规则文件")
            else:
                # 加载单个规则文件
                self.rules = yara.compile(filepath=self.rules_path)
                logger.info("YARA规则文件已加载")
            
            return True
        except Exception as e:
            logger.error(f"加载YARA规则时出错: {e}")
            return False
    
    def _create_builtin_rules(self):
        """创建并保存内置的YARA规则"""
        rules_dir = os.path.join(self.output_dir, 'builtin_rules')
        os.makedirs(rules_dir, exist_ok=True)
        
        # 加密算法规则
        crypto_rules = """
        rule AES_Constants {
            meta:
                description = "检测AES加密常量"
                author = "YARAMemScanner"
                severity = "medium"
            strings:
                $aes_sbox = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
                $aes_constants1 = { 01 00 00 00 02 00 00 00 04 00 00 00 08 00 00 00 }
                $aes_constants2 = { 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f }
                $aes_string = "Rijndael" ascii wide nocase
                $aes_string2 = "AES_set_encrypt_key" ascii wide
            condition:
                any of them
        }
        
        rule RSA_Constants {
            meta:
                description = "检测RSA加密相关特征"
                author = "YARAMemScanner"
                severity = "medium"
            strings:
                $rsa_begin_pub = "-----BEGIN PUBLIC KEY-----" ascii wide
                $rsa_begin_priv = "-----BEGIN RSA PRIVATE KEY-----" ascii wide
                $rsa_end_pub = "-----END PUBLIC KEY-----" ascii wide
                $rsa_end_priv = "-----END RSA PRIVATE KEY-----" ascii wide
                $rsa_string1 = "RSA_public_encrypt" ascii wide
                $rsa_string2 = "RSA_private_decrypt" ascii wide
            condition:
                any of them
        }
        
        rule ChaCha20_Salsa20_Constants {
            meta:
                description = "检测ChaCha20/Salsa20加密常量"
                author = "YARAMemScanner"
                severity = "medium"
            strings:
                $s20_constant = "expand 32-byte k" ascii wide
                $cc20_constant1 = { 61 70 78 65 } // "apxe"
                $cc20_constant2 = { 33 20 64 6e } // "3 dn"
            condition:
                any of them
        }
        """
        
        # 勒索软件特征规则
        ransomware_rules = """
        rule WannaCry_Indicators {
            meta:
                description = "检测WannaCry勒索软件特征"
                author = "YARAMemScanner"
                severity = "high"
            strings:
                $marker1 = "WanaCrypt0r" ascii wide nocase
                $marker2 = "WANACRY\!" ascii wide
                $marker3 = "WNcry@2ol7" ascii
                $marker4 = ".WNCRY" ascii
                $marker5 = "tasksche.exe" ascii wide nocase
                $marker6 = "msg/m_" ascii
                $marker7 = "Please Read Me\!.txt" ascii wide
                $marker8 = "Wana Decrypt0r" ascii wide
            condition:
                any of them
        }
        
        rule Ryuk_Indicators {
            meta:
                description = "检测Ryuk勒索软件特征"
                author = "YARAMemScanner"
                severity = "high"
            strings:
                $marker1 = "RyukReadMe" ascii wide
                $marker2 = "UNIQUE_ID_DO_NOT_REMOVE" ascii
                $marker3 = ".RYK" ascii
                $marker4 = "RyukReadMe.html" ascii wide
                $marker5 = "RyukReadMe.txt" ascii wide
                $marker6 = "No system is safe" ascii wide
            condition:
                any of them
        }
        
        rule REvil_Sodinokibi_Indicators {
            meta:
                description = "检测REvil/Sodinokibi勒索软件特征"
                author = "YARAMemScanner"
                severity = "high"
            strings:
                $marker1 = "Sodinokibi" ascii wide
                $marker2 = "REvil" ascii wide
                $marker3 = ".sodinokibi" ascii
                $marker4 = ".revil" ascii
                $marker5 = ".rvl" ascii
                $marker6 = "r3v1l" ascii wide nocase
                $marker7 = "nrv_key" ascii
            condition:
                any of them
        }
        
        rule LockBit_Indicators {
            meta:
                description = "检测LockBit勒索软件特征"
                author = "YARAMemScanner"
                severity = "high"
            strings:
                $marker1 = "LockBit" ascii wide
                $marker2 = ".lockbit" ascii
                $marker3 = "Restore-My-Files.txt" ascii wide
                $marker4 = "LockBit_Ransomware" ascii wide
                $marker5 = "github.com/lockbit" ascii wide
            condition:
                any of them
        }
        
        rule BlackCat_ALPHV_Indicators {
            meta:
                description = "检测BlackCat/ALPHV勒索软件特征"
                author = "YARAMemScanner"
                severity = "high"
            strings:
                $marker1 = "BlackCat" ascii wide
                $marker2 = "ALPHV" ascii wide
                $marker3 = ".alphv" ascii
                $marker4 = ".bc" ascii
                $marker5 = "RECOVER-FILES.txt" ascii wide
                $marker6 = "BlackCat-README.txt" ascii wide
            condition:
                any of them
        }
        """
        
        # 通用加密/勒索特征规则
        generic_rules = """
        rule Generic_Encryption_Keys {
            meta:
                description = "检测可能的加密密钥或密码"
                author = "YARAMemScanner"
                severity = "medium"
            strings:
                $key1 = /[Kk]ey[-:=_\s]{1,5}[A-Za-z0-9+\/]{16,}={0,2}/ ascii wide
                $key2 = /[Pp]assword[-:=_\s]{1,5}[A-Za-z0-9+\/]{8,}/ ascii wide
                $key3 = /[Ss]ecret[-:=_\s]{1,5}[A-Za-z0-9+\/]{16,}={0,2}/ ascii wide
                $key4 = /[Ee]ncrypt.{1,10}[Kk]ey[-:=_\s]{1,5}[A-Za-z0-9+\/]{16,}/ ascii wide
            condition:
                any of them
        }
        
        rule Generic_Ransomware_Indicators {
            meta:
                description = "检测通用的勒索软件特征"
                author = "YARAMemScanner"
                severity = "high"
            strings:
                $ransom1 = /[Rr]ansom/ ascii wide
                $ransom2 = /[Bb]itcoin.{1,30}[Ww]allet/ ascii wide
                $ransom3 = /[Dd]ecrypt.{1,10}[Ff]iles/ ascii wide
                $ransom4 = /[Pp]ay.{1,15}[Mm]oney/ ascii wide
                $ransom5 = /[Tt]ime.{1,10}[Ll]eft/ ascii wide
                $ransom6 = /YOUR_FILES_ARE_ENCRYPTED/ ascii wide nocase
                $ransom7 = "README" ascii wide nocase
                $ransom8 = /[Rr]ecovery.{1,20}[Kk]ey/ ascii wide
                $ransom9 = /\.(crypto|crypted|crypt|locked|encrypted)$/
                $ransom10 = "Tor " ascii wide nocase
            condition:
                3 of them
        }
        
        rule Base64_PEM_Keys {
            meta:
                description = "检测Base64编码的密钥块"
                author = "YARAMemScanner"
                severity = "medium"
            strings:
                $b64_1 = /([A-Za-z0-9+\/]{4}){16,}={0,3}/ ascii
            condition:
                $b64_1
        }
        """
        
        # 保存规则文件
        with open(os.path.join(rules_dir, "crypto.yar"), "w") as f:
            f.write(crypto_rules)
        
        with open(os.path.join(rules_dir, "ransomware.yar"), "w") as f:
            f.write(ransomware_rules)
        
        with open(os.path.join(rules_dir, "generic.yar"), "w") as f:
            f.write(generic_rules)
        
        logger.info(f"内置YARA规则已创建: {rules_dir}")
        return rules_dir
    
    def scan_memory_dump(self, dump_file):
        """使用YARA规则扫描内存转储文件"""
        logger.info(f"扫描内存转储文件: {dump_file}")
        
        if not self.rules:
            if not self.load_rules():
                return None
        
        results = []
        
        try:
            # 获取文件大小
            file_size = os.path.getsize(dump_file)
            logger.info(f"转储文件大小: {file_size} 字节")
            
            # 对于大文件，分块扫描
            if file_size > 100 * 1024 * 1024:  # 大于100MB
                chunk_size = 50 * 1024 * 1024  # 50MB块
                overlap = 1024  # 1KB重叠
                
                logger.info(f"使用分块扫描，块大小: {chunk_size // (1024 * 1024)}MB")
                
                with open(dump_file, 'rb') as f:
                    offset = 0
                    while offset < file_size:
                        # 设置文件位置
                        f.seek(offset)
                        
                        # 读取块
                        current_size = min(chunk_size, file_size - offset)
                        data = f.read(current_size)
                        
                        logger.debug(f"扫描块: 偏移 {offset}, 大小 {current_size}")
                        
                        # 扫描当前块
                        try:
                            matches = self.rules.match(data=data)
                            
                            if matches:
                                for match in matches:
                                    # 对每个匹配项，调整字符串偏移
                                    for string_match in match.strings:
                                        # 记录匹配项
                                        results.append({
                                            'rule': match.rule,
                                            'namespace': match.namespace,
                                            'tags': match.tags,
                                            'meta': match.meta,
                                            'offset': offset + string_match[0],
                                            'identifier': string_match[1],
                                            'data': binascii.hexlify(string_match[2][:100]).decode('ascii'),
                                            'data_length': len(string_match[2])
                                        })
                                        
                                        if self.verbose:
                                            logger.debug(f"匹配规则 '{match.rule}' 在偏移 {offset + string_match[0]}")
                        
                        except Exception as e:
                            logger.error(f"扫描块时出错: {e}")
                        
                        # 移动到下一个块，考虑重叠
                        offset += chunk_size - overlap
            else:
                # 对于小文件，一次性扫描
                logger.info("一次性扫描整个文件")
                
                try:
                    matches = self.rules.match(filepath=dump_file)
                    
                    if matches:
                        for match in matches:
                            for string_match in match.strings:
                                # 记录匹配项
                                results.append({
                                    'rule': match.rule,
                                    'namespace': match.namespace,
                                    'tags': match.tags,
                                    'meta': match.meta,
                                    'offset': string_match[0],
                                    'identifier': string_match[1],
                                    'data': binascii.hexlify(string_match[2][:100]).decode('ascii'),
                                    'data_length': len(string_match[2])
                                })
                                
                                if self.verbose:
                                    logger.debug(f"匹配规则 '{match.rule}' 在偏移 {string_match[0]}")
                
                except Exception as e:
                    logger.error(f"扫描文件时出错: {e}")
            
            # 保存结果
            if results:
                logger.info(f"找到 {len(results)} 个匹配项")
                
                # 按规则对结果分组
                results_by_rule = {}
                for r in results:
                    rule_name = r['rule']
                    if rule_name not in results_by_rule:
                        results_by_rule[rule_name] = []
                    results_by_rule[rule_name].append(r)
                
                # 添加摘要
                summary = {
                    'file': dump_file,
                    'file_size': file_size,
                    'scan_time': datetime.now().isoformat(),
                    'total_matches': len(results),
                    'rules_matched': list(results_by_rule.keys()),
                    'matches_by_rule': {rule: len(matches) for rule, matches in results_by_rule.items()}
                }
                
                # 评估是否检测到加密或勒索软件特征
                crypto_detected = any(rule.startswith(('AES', 'RSA', 'ChaCha', 'Salsa', 'Blowfish', 'DES', 'Generic_Encryption')) for rule in results_by_rule.keys())
                ransomware_detected = any(rule.endswith(('_Indicators', 'Ransomware_Indicators')) for rule in results_by_rule.keys())
                
                summary['encryption_detected'] = crypto_detected
                summary['ransomware_detected'] = ransomware_detected
                
                # 保存完整结果
                result_file = os.path.join(self.output_dir, f"{os.path.basename(dump_file)}_yara_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                
                with open(result_file, 'w') as f:
                    json.dump({
                        'summary': summary,
                        'results': results
                    }, f, indent=2)
                
                logger.info(f"扫描结果已保存至: {result_file}")
                
                return {
                    'summary': summary,
                    'results': results,
                    'result_file': result_file
                }
            else:
                logger.info("未找到匹配项")
                return {
                    'summary': {
                        'file': dump_file,
                        'file_size': file_size,
                        'scan_time': datetime.now().isoformat(),
                        'total_matches': 0,
                        'rules_matched': [],
                        'encryption_detected': False,
                        'ransomware_detected': False
                    },
                    'results': []
                }
                
        except Exception as e:
            logger.error(f"扫描内存转储文件时出错: {e}")
            return None
    
    def scan_process(self, pid):
        """扫描指定进程的内存"""
        logger.info(f"扫描进程 (PID {pid}) 的内存")
        
        if not self.rules:
            if not self.load_rules():
                return None
        
        try:
            # 检查进程是否存在
            if not psutil.pid_exists(pid):
                logger.error(f"进程 {pid} 不存在")
                return None
            
            process = psutil.Process(pid)
            process_name = process.name()
            
            logger.info(f"进程信息: {process_name} (PID {pid})")
            
            # 创建临时内存转储
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_path = temp_file.name
            
            logger.info(f"创建进程内存转储: {temp_path}")
            
            # 使用平台特定方法创建内存转储
            import platform
            if platform.system() == 'Windows':
                # 使用Windows特定方法
                self._dump_windows_process(pid, temp_path)
            elif platform.system() == 'Linux':
                # 使用Linux特定方法
                self._dump_linux_process(pid, temp_path)
            elif platform.system() == 'Darwin':
                # 使用macOS特定方法
                self._dump_macos_process(pid, temp_path)
            else:
                logger.error(f"不支持的平台: {platform.system()}")
                os.unlink(temp_path)
                return None
            
            # 检查转储文件是否创建成功
            if not os.path.exists(temp_path) or os.path.getsize(temp_path) == 0:
                logger.error("内存转储创建失败")
                os.unlink(temp_path)
                return None
            
            # 扫描转储文件
            results = self.scan_memory_dump(temp_path)
            
            # 清理临时文件
            os.unlink(temp_path)
            
            if results:
                # 添加进程信息
                results['summary']['process_name'] = process_name
                results['summary']['process_id'] = pid
                results['summary']['command_line'] = " ".join(process.cmdline())
                
                return results
            else:
                return None
            
        except Exception as e:
            logger.error(f"扫描进程内存时出错: {e}")
            return None
    
    def _dump_windows_process(self, pid, output_file):
        """使用Windows特定方法转储进程内存"""
        try:
            # 这里可以使用ProcDump或其他工具
            import subprocess
            subprocess.run(["procdump", "-ma", str(pid), output_file], check=True)
            return True
        except Exception as e:
            logger.error(f"创建Windows进程转储时出错: {e}")
            return False
    
    def _dump_linux_process(self, pid, output_file):
        """使用Linux特定方法转储进程内存"""
        try:
            import subprocess
            
            # 尝试使用GDB
            try:
                gdb_commands = f"gcore -o {output_file} {pid}"
                subprocess.run(["gdb", "-batch", "-ex", gdb_commands], check=True)
                return True
            except:
                logger.warning("使用GDB转储失败，尝试备用方法")
            
            # 备用方法：使用/proc文件系统
            mem_path = f"/proc/{pid}/mem"
            maps_path = f"/proc/{pid}/maps"
            
            # 确保当前用户有权限访问进程内存
            if not os.access(mem_path, os.R_OK):
                logger.error(f"无权读取进程 {pid} 的内存，可能需要root权限")
                return False
            
            # 读取内存映射
            with open(maps_path, 'r') as maps_file:
                mappings = maps_file.readlines()
            
            # 打开进程内存和输出文件
            with open(mem_path, 'rb') as mem_file, open(output_file, 'wb') as out_file:
                for line in mappings:
                    # 解析映射范围
                    fields = line.split()
                    if len(fields) < 6:
                        continue
                    
                    addr_range = fields[0]
                    perms = fields[1]
                    
                    # 只转储可读内存区域
                    if 'r' not in perms:
                        continue
                    
                    start_addr, end_addr = [int(x, 16) for x in addr_range.split('-')]
                    size = end_addr - start_addr
                    
                    try:
                        # 定位到内存区域起始位置
                        mem_file.seek(start_addr)
                        
                        # 读取内存内容
                        content = mem_file.read(size)
                        out_file.write(content)
                    except Exception as e:
                        logger.debug(f"读取区域 {addr_range} 时出错: {e}")
            
            return True
            
        except Exception as e:
            logger.error(f"创建Linux进程转储时出错: {e}")
            return False
    
    def _dump_macos_process(self, pid, output_file):
        """使用macOS特定方法转储进程内存"""
        try:
            import subprocess
            
            # 尝试使用lldb
            try:
                script_file = os.path.join(tempfile.gettempdir(), "lldb_dump_script.txt")
                with open(script_file, 'w') as f:
                    f.write(f"process attach --pid {pid}\n")
                    f.write(f"process save-core {output_file}\n")
                    f.write("quit\n")
                
                subprocess.run(["lldb", "-s", script_file], check=True)
                
                # 清理脚本文件
                os.remove(script_file)
                return True
            except:
                logger.warning("使用lldb转储失败")
            
            # 如果lldb失败，提供手动指南
            logger.error("无法自动转储macOS进程内存")
            return False
            
        except Exception as e:
            logger.error(f"创建macOS进程转储时出错: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description="YARA内存扫描工具")
    subparsers = parser.add_subparsers(dest="command", help="子命令")
    
    # 扫描内存转储文件子命令
    dump_parser = subparsers.add_parser("dump", help="扫描内存转储文件")
    dump_parser.add_argument("dump_file", help="内存转储文件路径")
    dump_parser.add_argument("-r", "--rules", help="YARA规则文件或目录")
    dump_parser.add_argument("-o", "--output-dir", help="输出目录")
    dump_parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出")
    
    # 扫描进程内存子命令
    process_parser = subparsers.add_parser("process", help="扫描进程内存")
    process_parser.add_argument("pid", type=int, help="目标进程ID")
    process_parser.add_argument("-r", "--rules", help="YARA规则文件或目录")
    process_parser.add_argument("-o", "--output-dir", help="输出目录")
    process_parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出")
    
    args = parser.parse_args()
    
    if args.command == "dump":
        scanner = YARAMemScanner(
            rules_path=args.rules,
            output_dir=args.output_dir,
            verbose=args.verbose
        )
        
        results = scanner.scan_memory_dump(args.dump_file)
        
        if results:
            print("\n=== 扫描摘要 ===")
            print(f"文件: {results['summary']['file']}")
            print(f"大小: {results['summary']['file_size']} 字节")
            print(f"匹配项: {results['summary']['total_matches']} 个")
            
            if results['summary']['rules_matched']:
                print("\n触发的规则:")
                for rule, count in results['summary']['matches_by_rule'].items():
                    print(f"  {rule}: {count} 个匹配项")
            
            print("\n加密检测:")
            print(f"  检测到加密特征: {'是' if results['summary']['encryption_detected'] else '否'}")
            print(f"  检测到勒索软件特征: {'是' if results['summary']['ransomware_detected'] else '否'}")
            
            print(f"\n详细结果已保存至: {results['result_file']}")
    
    elif args.command == "process":
        scanner = YARAMemScanner(
            rules_path=args.rules,
            output_dir=args.output_dir,
            verbose=args.verbose
        )
        
        results = scanner.scan_process(args.pid)
        
        if results:
            print("\n=== 扫描摘要 ===")
            print(f"进程: {results['summary']['process_name']} (PID: {results['summary']['process_id']})")
            print(f"命令行: {results['summary']['command_line']}")
            print(f"匹配项: {results['summary']['total_matches']} 个")
            
            if results['summary']['rules_matched']:
                print("\n触发的规则:")
                for rule, count in results['summary']['matches_by_rule'].items():
                    print(f"  {rule}: {count} 个匹配项")
            
            print("\n加密检测:")
            print(f"  检测到加密特征: {'是' if results['summary']['encryption_detected'] else '否'}")
            print(f"  检测到勒索软件特征: {'是' if results['summary']['ransomware_detected'] else '否'}")
            
            print(f"\n详细结果已保存至: {results['result_file']}")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
EOF < /dev/null