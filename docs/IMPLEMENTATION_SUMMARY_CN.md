# Innora-Defender: API参考

[English](./IMPLEMENTATION_SUMMARY.md) | **中文**

## 简介

本文档为Innora-Defender（Innora-Sentinel网络安全平台的勒索软件检测和恢复模块）提供了全面的API参考。它涵盖了核心模块、它们的接口以及使用示例。

## 核心模块

### 1. 勒索软件分析器

`RansomwareAnalyzer`类是分析可疑文件和识别勒索软件特征的主要入口点。

#### 主要类和方法

```python
class RansomwareAnalyzer:
    def __init__(self, config=None):
        """
        使用可选配置初始化分析器。
        
        参数:
        - config (dict, 可选): 配置选项，包括:
          - use_ai (bool): 是否使用AI增强检测
          - sandbox_type (str): 要使用的沙箱类型 ('docker', 'vm', 'emulation')
          - memory_analysis (bool): 是否执行内存分析
          - network_analysis (bool): 是否分析网络流量
        """
        pass
        
    def analyze_file(self, file_path, detailed=False):
        """
        分析可疑文件的勒索软件特征。
        
        参数:
        - file_path (str): 要分析的文件路径
        - detailed (bool): 是否执行详细分析
        
        返回:
        - AnalysisResult: 包含分析结果的对象
        """
        pass
        
    def analyze_directory(self, directory_path, recursive=True, file_types=None):
        """
        分析目录中的所有文件的勒索软件特征。
        
        参数:
        - directory_path (str): 目录路径
        - recursive (bool): 是否分析子目录
        - file_types (list): 要分析的文件扩展名列表
        
        返回:
        - list: AnalysisResult对象列表
        """
        pass
        
    def detect_family(self, file_path):
        """
        识别文件的勒索软件家族。
        
        参数:
        - file_path (str): 文件路径
        
        返回:
        - tuple: (family_name, confidence_score)
        """
        pass
```

#### 使用示例

```python
from innora_defender import RansomwareAnalyzer

# 使用默认配置初始化
analyzer = RansomwareAnalyzer()

# 分析可疑文件
result = analyzer.analyze_file("/path/to/suspicious_file.exe")

print(f"勒索软件检测: {result.is_ransomware}")
print(f"家族: {result.family} (置信度: {result.confidence}%)")
print(f"加密算法: {result.encryption_algorithm}")
print(f"行为摘要: {result.behavior_summary}")

# 获取有关勒索软件家族的详细信息
if result.is_ransomware and result.family:
    family_info = analyzer.get_family_info(result.family)
    print(f"家族描述: {family_info.description}")
    print(f"已知加密方法: {family_info.encryption_methods}")
    print(f"恢复潜力: {family_info.recovery_potential}/10")
```

### 2. 恢复引擎

`RecoveryEngine`提供了恢复被勒索软件加密文件的功能。

#### 主要类和方法

```python
class RecoveryEngine:
    def __init__(self, config=None):
        """
        使用可选配置初始化恢复引擎。
        
        参数:
        - config (dict, 可选): 配置选项，包括:
          - use_memory_analysis (bool): 是否使用内存分析进行密钥恢复
          - use_network_forensics (bool): 是否使用网络流量分析
          - brute_force_level (int): 暴力尝试的强度级别 (0-3)
        """
        pass
        
    def attempt_decryption(self, encrypted_file, output_file=None, family=None, key=None):
        """
        尝试解密被勒索软件加密的文件。
        
        参数:
        - encrypted_file (str): 加密文件的路径
        - output_file (str, 可选): 保存解密文件的路径
        - family (str, 可选): 已知的勒索软件家族
        - key (str/bytes, 可选): 已知的加密密钥
        
        返回:
        - bool: 成功或失败
        - str: 如果成功，解密文件的路径
        """
        pass
        
    def batch_decrypt(self, file_list, output_dir, family=None, key=None):
        """
        尝试解密多个文件。
        
        参数:
        - file_list (list): 加密文件路径列表
        - output_dir (str): 保存解密文件的目录
        - family (str, 可选): 已知的勒索软件家族
        - key (str/bytes, 可选): 已知的加密密钥
        
        返回:
        - dict: 将文件路径映射到成功/失败和输出路径的字典
        """
        pass
        
    def extract_keys_from_memory(self, memory_dump):
        """
        从内存转储中提取加密密钥。
        
        参数:
        - memory_dump (str): 内存转储文件的路径
        
        返回:
        - list: 潜在加密密钥列表
        """
        pass
        
    def extract_keys_from_network(self, pcap_file):
        """
        从网络流量捕获中提取加密密钥。
        
        参数:
        - pcap_file (str): PCAP文件的路径
        
        返回:
        - list: 潜在加密密钥列表
        """
        pass
```

#### 使用示例

```python
from innora_defender import RecoveryEngine

# 初始化恢复引擎
recovery = RecoveryEngine()

# 尝试解密单个文件
success, output_path = recovery.attempt_decryption(
    encrypted_file="/path/to/encrypted.file",
    output_file="/path/to/recovered.file",
    family="lockbit"  # 可选：指定已知的勒索软件家族
)

if success:
    print(f"成功恢复文件到: {output_path}")
else:
    print("恢复失败")
    
    # 尝试从内存转储中提取密钥
    keys = recovery.extract_keys_from_memory("/path/to/memory.dmp")
    
    if keys:
        print(f"在内存转储中找到 {len(keys)} 个潜在密钥")
        
        # 尝试每个密钥
        for idx, key in enumerate(keys):
            print(f"尝试密钥 {idx+1}...")
            success, output_path = recovery.attempt_decryption(
                encrypted_file="/path/to/encrypted.file",
                output_file=f"/path/to/recovered_with_key_{idx+1}.file",
                key=key
            )
            
            if success:
                print(f"密钥 {idx+1} 起作用！恢复文件到: {output_path}")
                break
```

### 3. 内存分析器

`MemoryAnalyzer`专注于从内存转储中提取加密密钥和勒索软件工件。

#### 主要类和方法

```python
class MemoryAnalyzer:
    def __init__(self, config=None):
        """
        使用可选配置初始化内存分析器。
        
        参数:
        - config (dict, 可选): 配置选项，包括:
          - volatility_path (str): Volatility框架的路径
          - use_custom_plugins (bool): 是否使用自定义插件
          - temp_dir (str): 临时文件目录
        """
        pass
        
    def analyze_dump(self, dump_path, ransomware_family=None):
        """
        分析内存转储中的勒索软件工件。
        
        参数:
        - dump_path (str): 内存转储文件的路径
        - ransomware_family (str, 可选): 目标勒索软件家族
        
        返回:
        - MemoryAnalysisResult: 分析结果
        """
        pass
        
    def extract_keys(self, dump_path, ransomware_family=None, min_entropy=3.5):
        """
        从内存转储中提取潜在的加密密钥。
        
        参数:
        - dump_path (str): 内存转储文件的路径
        - ransomware_family (str, 可选): 目标勒索软件家族
        - min_entropy (float): 密钥候选项的最小熵
        
        返回:
        - list: 潜在加密密钥列表
        """
        pass
        
    def extract_configuration(self, dump_path, ransomware_family):
        """
        从内存转储中提取勒索软件配置。
        
        参数:
        - dump_path (str): 内存转储文件的路径
        - ransomware_family (str): 目标勒索软件家族
        
        返回:
        - dict: 提取的配置参数
        """
        pass
        
    def find_key_schedules(self, dump_path, algorithm="aes"):
        """
        在内存中查找加密密钥表。
        
        参数:
        - dump_path (str): 内存转储文件的路径
        - algorithm (str): 目标加密算法
        
        返回:
        - list: 潜在密钥表地址和派生密钥列表
        """
        pass
```

#### 使用示例

```python
from innora_defender import MemoryAnalyzer

# 初始化内存分析器
memory = MemoryAnalyzer()

# 分析内存转储
result = memory.analyze_dump("/path/to/memory.dmp", ransomware_family="lockbit")

print(f"找到 {len(result.processes)} 个可疑进程")
for proc in result.processes:
    print(f"进程: {proc.name} (PID: {proc.pid})")
    print(f"匹配的指标: {proc.indicators}")

# 提取加密密钥
keys = memory.extract_keys("/path/to/memory.dmp")
print(f"找到 {len(keys)} 个潜在加密密钥")

# 提取勒索软件配置
if result.identified_family:
    config = memory.extract_configuration("/path/to/memory.dmp", result.identified_family)
    print("勒索软件配置:")
    for key, value in config.items():
        print(f"  {key}: {value}")
```

### 4. YARA规则生成器

`YaraGenerator`根据分析结果创建检测规则。

#### 主要类和方法

```python
class YaraGenerator:
    def __init__(self, config=None):
        """
        使用可选配置初始化YARA规则生成器。
        
        参数:
        - config (dict, 可选): 配置选项，包括:
          - rule_template_dir (str): 包含规则模板的目录
          - output_dir (str): 生成规则的目录
          - metadata_fields (list): 包含在规则元数据中的字段
        """
        pass
        
    def generate_from_sample(self, sample_path, rule_name=None, author=None):
        """
        从样本文件生成YARA规则。
        
        参数:
        - sample_path (str): 样本文件的路径
        - rule_name (str, 可选): 生成规则的名称
        - author (str, 可选): 规则元数据的作者名称
        
        返回:
        - str: 生成的YARA规则内容
        - str: 保存的规则文件路径
        """
        pass
        
    def generate_from_analysis(self, analysis_result, rule_name=None, author=None):
        """
        从分析结果生成YARA规则。
        
        参数:
        - analysis_result (AnalysisResult): 分析结果对象
        - rule_name (str, 可选): 生成规则的名称
        - author (str, 可选): 规则元数据的作者名称
        
        返回:
        - str: 生成的YARA规则内容
        - str: 保存的规则文件路径
        """
        pass
        
    def generate_family_ruleset(self, family_name, samples_dir, author=None):
        """
        为勒索软件家族生成综合规则集。
        
        参数:
        - family_name (str): 勒索软件家族的名称
        - samples_dir (str): 包含家族样本的目录
        - author (str, 可选): 规则元数据的作者名称
        
        返回:
        - list: 生成的规则文件路径列表
        """
        pass
        
    def test_rule(self, rule_path, test_samples_dir):
        """
        针对样本目录测试YARA规则。
        
        参数:
        - rule_path (str): YARA规则文件的路径
        - test_samples_dir (str): 包含测试样本的目录
        
        返回:
        - dict: 包含匹配统计的测试结果字典
        """
        pass
```

#### 使用示例

```python
from innora_defender import YaraGenerator, RansomwareAnalyzer

# 初始化组件
analyzer = RansomwareAnalyzer()
generator = YaraGenerator()

# 分析勒索软件样本
analysis = analyzer.analyze_file("/path/to/ransomware_sample.exe")

# 从分析结果生成YARA规则
if analysis.is_ransomware:
    rule_content, rule_path = generator.generate_from_analysis(
        analysis,
        rule_name=f"{analysis.family}_detector",
        author="Innora安全团队"
    )
    
    print(f"生成的YARA规则保存到: {rule_path}")
    print("\n规则预览:")
    print(rule_content[:500] + "..." if len(rule_content) > 500 else rule_content)
    
    # 针对样本目录测试规则
    test_results = generator.test_rule(rule_path, "/path/to/test_samples")
    
    print("\n规则测试结果:")
    print(f"真阳性: {test_results['true_positives']}")
    print(f"假阳性: {test_results['false_positives']}")
    print(f"真阴性: {test_results['true_negatives']}")
    print(f"假阴性: {test_results['false_negatives']}")
    print(f"准确率: {test_results['accuracy']:.2f}%")
```

### 5. 威胁情报集成

`ThreatIntelligence`类提供与外部威胁情报源的集成。

#### 主要类和方法

```python
class ThreatIntelligence:
    def __init__(self, config=None):
        """
        使用可选配置初始化威胁情报模块。
        
        参数:
        - config (dict, 可选): 配置选项，包括:
          - api_keys (dict): 威胁情报源的API密钥
          - cache_dir (str): 缓存威胁数据的目录
          - cache_timeout (int): 缓存超时时间（秒）
        """
        pass
        
    def query_sample(self, file_hash, sources=None):
        """
        通过哈希查询样本信息。
        
        参数:
        - file_hash (str): 样本的哈希值（MD5、SHA1或SHA256）
        - sources (list, 可选): 要查询的情报源列表
        
        返回:
        - dict: 来自各种源的样本信息
        """
        pass
        
    def get_family_info(self, family_name, full=False):
        """
        获取有关勒索软件家族的信息。
        
        参数:
        - family_name (str): 勒索软件家族的名称
        - full (bool): 是否包含完整详细信息
        
        返回:
        - dict: 有关勒索软件家族的信息
        """
        pass
        
    def get_iocs(self, family_name=None, days=30):
        """
        获取妥协指标。
        
        参数:
        - family_name (str, 可选): 按勒索软件家族过滤
        - days (int): 时间范围（天）
        
        返回:
        - list: IOC字典列表
        """
        pass
        
    def submit_sample(self, file_path, platforms=None):
        """
        将样本提交给威胁情报平台。
        
        参数:
        - file_path (str): 样本文件的路径
        - platforms (list, 可选): 要提交的平台
        
        返回:
        - dict: 提交状态和引用
        """
        pass
        
    def correlate_iocs(self, ioc_list, threshold=0.6):
        """
        关联IOC列表以识别活动。
        
        参数:
        - ioc_list (list): 要关联的IOC列表
        - threshold (float): 相似度阈值
        
        返回:
        - list: 潜在活动列表
        """
        pass
```

#### 使用示例

```python
from innora_defender import ThreatIntelligence

# 初始化威胁情报模块
ti = ThreatIntelligence()

# 查询样本信息
sample_info = ti.query_sample("e5e7c213cf3333c9abcdf2871d896c7a5415b8da")

print("样本信息:")
for source, info in sample_info.items():
    print(f"\n来源: {source}")
    print(f"检测名称: {info.get('detection_name', 'N/A')}")
    print(f"首次发现: {info.get('first_seen', 'N/A')}")
    print(f"最后发现: {info.get('last_seen', 'N/A')}")
    print(f"检测率: {info.get('detection_rate', 'N/A')}")

# 获取有关勒索软件家族的信息
family_info = ti.get_family_info("lockbit", full=True)

print("\n勒索软件家族信息:")
print(f"家族: {family_info['name']}")
print(f"别名: {', '.join(family_info.get('aliases', []))}")
print(f"首次发现: {family_info.get('first_seen', 'N/A')}")
print(f"活跃: {family_info.get('active', False)}")
print(f"加密算法: {', '.join(family_info.get('encryption_algorithms', []))}")
print(f"勒索信模式: {', '.join(family_info.get('ransom_note_patterns', []))}")

# 获取妥协指标
iocs = ti.get_iocs(family_name="lockbit", days=30)

print(f"\n找到 {len(iocs)} 个最近的LockBit IOC:")
for idx, ioc in enumerate(iocs[:5]):  # 显示前5个IOC
    print(f"IOC {idx+1}: {ioc['value']} ({ioc['type']})")
```

## 与Innora-Sentinel集成

### API接口

要将Innora-Defender与Innora-Sentinel平台集成，请使用`SentinelConnector`类：

```python
from innora_defender import SentinelConnector

# 初始化连接器
connector = SentinelConnector(
    api_url="https://sentinel.innora.com/api/v1",
    api_key="your_api_key_here"
)

# 向Sentinel注册模块
connector.register()

# 将分析结果发送到Sentinel
analysis_result = analyzer.analyze_file("/path/to/sample.exe")
connector.send_analysis_result(analysis_result)

# 从Sentinel检索任务
tasks = connector.get_pending_tasks()
for task in tasks:
    print(f"处理任务 {task['id']}: {task['type']}")
    
    if task['type'] == 'analyze_file':
        # 下载文件
        file_path = connector.download_file(task['file_id'])
        
        # 分析文件
        result = analyzer.analyze_file(file_path)
        
        # 发送结果
        connector.update_task(task['id'], status='completed', result=result)
```

## 错误处理

Innora-Defender中的所有API方法都遵循使用自定义异常的一致错误处理模式：

```python
from innora_defender.exceptions import (
    AnalysisError,
    RecoveryError,
    MemoryAnalysisError,
    ThreatIntelError,
    ConfigurationError
)

try:
    result = analyzer.analyze_file("/path/to/file.exe")
except AnalysisError as e:
    print(f"分析失败: {e}")
    # 适当处理错误

try:
    success = recovery.attempt_decryption(
        encrypted_file="/path/to/encrypted.file",
        output_file="/path/to/output.file"
    )
except RecoveryError as e:
    print(f"恢复失败: {e}")
    # 适当处理错误
```

## 日志记录

Innora-Defender提供广泛的日志功能：

```python
import logging
from innora_defender import configure_logging

# 配置日志
configure_logging(
    log_file="/path/to/innora_defender.log",
    log_level=logging.INFO,
    rotation="daily",
    max_size_mb=100
)

# 日志现在将被捕获到指定的文件
analyzer = RansomwareAnalyzer()
analyzer.analyze_file("/path/to/sample.exe")
```

## 配置

全局配置可以通过`Config`类管理：

```python
from innora_defender import Config

# 加载配置
config = Config.load_from_file("/path/to/config.json")

# 访问配置值
print(f"使用AI检测: {config.get('use_ai', True)}")
print(f"沙箱类型: {config.get('sandbox_type', 'docker')}")

# 更新配置
config.set('use_network_analysis', True)
config.set('api_keys.virustotal', 'your_api_key_here')

# 保存配置
config.save_to_file("/path/to/config.json")

# 使用配置初始化组件
analyzer = RansomwareAnalyzer(config=config)
recovery = RecoveryEngine(config=config)
```

---

© 2025 Innora-Sentinel安全团队 | 保留所有权利 | [https://innora.ai](https://innora.ai)