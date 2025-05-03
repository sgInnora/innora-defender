"""
Volatility3 插件 - 用于从内存中提取勒索软件加密密钥
"""
import re
import io
import logging
import binascii
import hashlib
import json
from typing import List, Tuple, Dict, Optional, Iterable, Type

from volatility3.framework import interfaces, renderers, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, vadinfo, handles, dlllist

vollog = logging.getLogger(__name__)

class RansomKey(interfaces.plugins.PluginInterface):
    """搜索进程内存中的加密密钥，特别关注勒索软件使用的密钥"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel', description='Windows kernel',
                                          architectures=["Intel32", "Intel64"]),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
            requirements.ListRequirement(name='pid',
                                        description='进程ID过滤器列表',
                                        element_type=int,
                                        optional=True),
            requirements.BooleanRequirement(name='dump-keys',
                                          description='将提取的密钥转储到文件',
                                          default=False,
                                          optional=True),
            requirements.StringRequirement(name='output-dir',
                                        description='提取密钥的输出目录',
                                        default=None,
                                        optional=True),
            requirements.StringRequirement(name='ransomware-type',
                                        description='特定勒索软件类型',
                                        default=None,
                                        optional=True)
        ]

    def _initialize_ransomware_signatures(self):
        """初始化勒索软件特征库"""
        self.signatures = {
            "generic": {
                "name": "通用加密模式",
                "key_patterns": [
                    rb"([A-Za-z0-9+/]{4}){16,}={0,3}", # Base64编码密钥
                    rb"0x[A-Fa-f0-9]{32,}", # 十六进制格式的密钥
                    rb"(?:key|KEY|Key|password|PASSWORD|Password|secret|SECRET|Secret)[_:= ]\s*([^\s;]{16,})"
                ],
                "magic_constants": [
                    # AES S-box
                    binascii.unhexlify("637c777bf26b6fc53001672bfed7ab76"),
                    # AES轮常量
                    binascii.unhexlify("01000000010000000100000001000000")
                ]
            },
            "wannacry": {
                "name": "WannaCry",
                "process_names": ["@WanaDecryptor@.exe", "tasksche.exe", "wcry.exe", "taskhsvc.exe"],
                "key_patterns": [
                    rb"WNcry@2ol7", 
                    rb"([A-Za-z0-9+/]{4}){43}={1}", # WannaCry公钥格式
                    rb"00000000[\da-f]{16}0{20}01000000" # WannaCry密钥结构
                ],
                "file_markers": [".WNCRY", ".WNCRYT", "WANNACRY\!"]
            },
            "ryuk": {
                "name": "Ryuk",
                "process_names": ["ryuk.exe", "svchost2.exe"],
                "key_patterns": [
                    rb"RyukReadMe", 
                    rb"UNIQUE_ID_DO_NOT_REMOVE",
                    rb"([A-Za-z0-9+/]{4}){43}={0,2}" # Ryuk的RSA密钥格式
                ],
                "file_markers": [".RYK", ".RYUK", "UseRyukReadMe\!\!.txt"]
            },
            "revil": {
                "name": "REvil/Sodinokibi",
                "process_names": ["revil.exe", "sodinokobi.exe", "vssadmin.exe"],
                "key_patterns": [
                    rb"Sodinokibi", 
                    rb"REvil", 
                    rb"\[SYSTEM INFO\].+\[KEYS\].+\[FILES\]",
                    rb"nrv_key\W+\w{32}"
                ],
                "file_markers": [".rxxx", ".sodinokibi", ".revil", "r3v1l-readme.txt"]
            },
            "lockbit": {
                "name": "LockBit",
                "process_names": ["lockbit.exe", "lock.exe", "svchost_.exe"],
                "key_patterns": [
                    rb"LockBit", 
                    rb"github.com/lockbit", 
                    rb"LockBit_Ransomware",
                    rb"([A-Za-z0-9+/]{4}){10,}={0,3}" # LockBit 2.0使用的编码密钥
                ],
                "file_markers": [".lockbit", "Restore-My-Files.txt", "LockBit_Ransomware.hta"]
            },
            "blackcat": {
                "name": "BlackCat/ALPHV",
                "process_names": ["blackcat.exe", "bc.exe", "alphv.exe"],
                "key_patterns": [
                    rb"BlackCat", 
                    rb"ALPHV", 
                    rb"---BEGIN PUBLIC KEY---([A-Za-z0-9+/]{4})*---END PUBLIC KEY---"
                ],
                "file_markers": [".bc", ".alphv", "RECOVER-FILES.txt", "BlackCat-README.txt"]
            },
            "locky": {
                "name": "Locky",
                "process_names": ["locky.exe", "svchost_.exe"],
                "key_patterns": [
                    rb"Locky", 
                    rb"_Locky_recover_instructions", 
                    rb"([A-Za-z0-9+/]{4}){10,}={0,3}" # Locky加密密钥格式
                ],
                "file_markers": [".locky", ".zepto", ".osiris", "_HELP_instructions.html"]
            }
        }

    def _extract_key_from_match(self, proc_layer, proc_offset, match_offset, match_data, match_type):
        """从匹配位置提取完整的密钥"""
        result = {
            'type': match_type,
            'offset': match_offset,
            'data': binascii.hexlify(match_data).decode('ascii')
        }
        
        # 对于特定类型的密钥，尝试提取更多信息
        if "AES" in match_type:
            # 检查是否为AES密钥表，继续读取更多数据
            try:
                more_data = proc_layer.read(match_offset, 0x100)  # 读取更多数据
                # 检查轮密钥特征
                if b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" in more_data:
                    result['key_type'] = "AES expanded key schedule"
            except:
                pass
        
        # 尝试推断密钥大小
        result['key_size'] = len(match_data)
        
        # 计算密钥的哈希值
        result['md5'] = hashlib.md5(match_data).hexdigest()
        
        return result

    def _scan_process_memory(self, context, proc: interfaces.objects.ObjectInterface) -> List[Dict]:
        """扫描单个进程的内存空间以寻找加密密钥"""
        proc_layer_name = proc.add_process_layer()
        proc_layer = context.layers[proc_layer_name]
        
        results = []
        
        # 1. 扫描进程VAD
        for vad in vadinfo.VadInfo.list_vads(proc):
            try:
                # 只扫描可读的区域
                if vad.get_protection(vadinfo.VadInfo.protect_values(context, proc.vol.layer_name), False)[0] \!= 'PAGE_NOACCESS':
                    vad_start = vad.get_start()
                    vad_end = vad.get_end()
                    vad_size = vad_end - vad_start
                    
                    # 跳过超大的VAD
                    if vad_size > 0x10000000:  # 256MB
                        continue
                    
                    # 读取VAD内容
                    try:
                        data = proc_layer.read(vad_start, vad_size)
                    except exceptions.InvalidAddressException:
                        continue
                    
                    # 扫描勒索软件特征
                    for ransomware_id, signature in self.signatures.items():
                        if 'key_patterns' in signature:
                            for pattern in signature['key_patterns']:
                                for match in re.finditer(pattern, data):
                                    match_data = match.group(0)
                                    match_offset = vad_start + match.start()
                                    key_info = self._extract_key_from_match(
                                        proc_layer, proc.vol.offset, match_offset, match_data, 
                                        f"{signature['name']} key pattern"
                                    )
                                    results.append(key_info)
                    
                    # 扫描魔术常量
                    for ransomware_id, signature in self.signatures.items():
                        if 'magic_constants' in signature:
                            for magic in signature['magic_constants']:
                                offset = 0
                                while True:
                                    index = data.find(magic, offset)
                                    if index == -1:
                                        break
                                    match_offset = vad_start + index
                                    key_info = self._extract_key_from_match(
                                        proc_layer, proc.vol.offset, match_offset, magic, 
                                        f"{signature['name']} magic constant"
                                    )
                                    results.append(key_info)
                                    offset = index + 1
            except Exception as e:
                vollog.debug(f"扫描进程 {proc.UniqueProcessId} (VAD at {vad.vol.offset:#x}) 时出错: {e}")
                continue
        
        return results

    def _run(self, context, progress_callback=None):
        self._initialize_ransomware_signatures()
        
        filter_pids = self.config.get('pid', None)
        
        # 获取进程列表
        processes = pslist.PsList.list_processes(context, 
                                                self.config['kernel'],
                                                filter_func=lambda p: filter_pids is None or p.UniqueProcessId in filter_pids)
        
        # 处理指定的勒索软件类型
        ransomware_type = self.config.get('ransomware-type', None)
        if ransomware_type:
            if ransomware_type in self.signatures:
                process_filter = self.signatures[ransomware_type].get('process_names', [])
                if process_filter:
                    processes = [p for p in processes if p.ImageFileName.cast("string", max_length=100) in process_filter]
            else:
                vollog.warning(f"未知的勒索软件类型: {ransomware_type}")
        
        # 收集结果
        all_results = []
        
        for proc in processes:
            proc_name = proc.ImageFileName.cast("string", max_length=100)
            pid = proc.UniqueProcessId
            
            vollog.info(f"扫描进程 {pid}: {proc_name}")
            
            try:
                results = self._scan_process_memory(context, proc)
                if results:
                    for r in results:
                        r['pid'] = pid
                        r['process_name'] = proc_name
                        all_results.append(r)
            except Exception as e:
                vollog.debug(f"扫描进程 {pid} 时出错: {e}")
                continue
        
        # 如果请求，写入提取的密钥
        if self.config.get('dump-keys', False) and all_results:
            output_dir = self.config.get('output-dir', None)
            if output_dir:
                import os
                from datetime import datetime
                
                # 确保输出目录存在
                os.makedirs(output_dir, exist_ok=True)
                
                # 创建输出文件
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(output_dir, f"ransomkeys_{timestamp}.json")
                
                with open(output_file, 'w') as f:
                    json.dump(all_results, f, indent=2)
                
                vollog.info(f"已写入 {len(all_results)} 个提取的密钥到 {output_file}")
        
        # 按进程组织结果
        results_by_pid = {}
        for r in all_results:
            pid = r['pid']
            if pid not in results_by_pid:
                results_by_pid[pid] = []
            results_by_pid[pid].append(r)
        
        # 返回表格结果
        for pid, results in results_by_pid.items():
            for r in results:
                yield (0, (pid, 
                         r['process_name'], 
                         format_hints.Hex(r['offset']), 
                         r['type'], 
                         r.get('key_size', 0),
                         r['data'][:64] + ('...' if len(r['data']) > 64 else '')))

    def run(self):
        return renderers.TreeGrid([
            ("PID", int),
            ("Process", str),
            ("Offset", format_hints.Hex),
            ("Key Type", str),
            ("Size", int),
            ("Data", str)
        ], self._run)
EOF < /dev/null