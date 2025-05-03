#\!/usr/bin/env python3
"""
内存转储工具 - 用于提取进程内存以进行分析
"""
import os
import sys
import time
import argparse
import logging
import psutil
import datetime
import platform
from pathlib import Path

# 设置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('MemoryDumper')

class MemoryDumper:
    def __init__(self, output_dir=None, verbose=False):
        self.output_dir = output_dir or os.path.join(os.getcwd(), 'memory_dumps')
        self.verbose = verbose
        
        # 确保输出目录存在
        os.makedirs(self.output_dir, exist_ok=True)
        
        # 设置日志级别
        if verbose:
            logger.setLevel(logging.DEBUG)
    
    def list_processes(self):
        """列出所有运行进程"""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                try:
                    proc_info = proc.info
                    processes.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'username': proc_info['username'],
                        'cmdline': ' '.join(proc_info['cmdline'] or [])
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        except Exception as e:
            logger.error(f"列出进程时出错: {e}")
        
        return processes
    
    def dump_process_memory(self, pid, output_format='raw'):
        """转储特定进程的内存"""
        try:
            process = psutil.Process(pid)
            
            # 获取进程信息
            proc_info = {
                'pid': process.pid,
                'name': process.name(),
                'username': process.username(),
                'create_time': datetime.datetime.fromtimestamp(process.create_time()).isoformat(),
                'cmdline': process.cmdline(),
                'exe': process.exe(),
                'cwd': process.cwd(),
                'status': process.status()
            }
            
            # 创建输出文件名
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = ''.join(c if c.isalnum() else '_' for c in process.name())
            dump_file = os.path.join(self.output_dir, f"{safe_name}_{pid}_{timestamp}.dmp")
            
            # 写入内存内容
            logger.info(f"正在转储进程 {pid} ({process.name()}) 的内存...")
            
            # 这里的实现取决于平台
            if platform.system() == 'Windows':
                self._dump_windows_process(pid, dump_file)
            elif platform.system() == 'Linux':
                self._dump_linux_process(pid, dump_file)
            elif platform.system() == 'Darwin':  # macOS
                self._dump_macos_process(pid, dump_file)
            else:
                logger.error(f"不支持的平台: {platform.system()}")
                return None
            
            # 保存进程信息
            info_file = os.path.join(self.output_dir, f"{safe_name}_{pid}_{timestamp}_info.txt")
            with open(info_file, 'w') as f:
                for key, value in proc_info.items():
                    f.write(f"{key}: {value}\n")
            
            logger.info(f"内存转储完成: {dump_file}")
            logger.info(f"进程信息保存为: {info_file}")
            
            return {
                'dump_file': dump_file,
                'info_file': info_file,
                'process': proc_info
            }
            
        except psutil.NoSuchProcess:
            logger.error(f"进程 {pid} 不存在")
        except psutil.AccessDenied:
            logger.error(f"无权访问进程 {pid} 的内存")
        except Exception as e:
            logger.error(f"转储进程 {pid} 的内存时出错: {e}")
        
        return None
    
    def _dump_windows_process(self, pid, output_file):
        """使用Windows API转储进程内存"""
        try:
            # 在实际实现中，这将使用Windows API
            # 例如使用ProcDump或其他工具
            import subprocess
            subprocess.run(["procdump", "-ma", str(pid), output_file], check=True)
            return True
        except ImportError:
            logger.error("无法在Windows上进行内存转储: 缺少必要的组件")
        except subprocess.SubprocessError as e:
            logger.error(f"使用procdump转储内存失败: {e}")
        except Exception as e:
            logger.error(f"Windows内存转储出错: {e}")
        
        return False
    
    def _dump_linux_process(self, pid, output_file):
        """使用Linux内存转储方法"""
        try:
            # 使用/proc文件系统
            mem_path = f"/proc/{pid}/mem"
            maps_path = f"/proc/{pid}/maps"
            
            # 确保当前用户有权限访问进程内存
            if not os.access(mem_path, os.R_OK):
                logger.error(f"无权读取进程 {pid} 的内存，可能需要root权限")
                return False
            
            # 读取内存映射
            with open(maps_path, 'r') as maps_file:
                mappings = maps_file.readlines()
            
            logger.debug(f"发现 {len(mappings)} 个内存映射")
            
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
                    
                    # 写入区域头部
                    region_header = f"# 内存区域: {addr_range} {' '.join(fields[1:])}\n".encode()
                    out_file.write(region_header)
                    
                    try:
                        # 定位到内存区域起始位置
                        mem_file.seek(start_addr)
                        
                        # 读取内存内容
                        content = mem_file.read(size)
                        out_file.write(content)
                        
                        # 区域分隔符
                        out_file.write(b"\n\n")
                        
                        if self.verbose:
                            logger.debug(f"已转储区域 {addr_range} ({size} 字节)")
                    except Exception as e:
                        logger.debug(f"读取区域 {addr_range} 时出错: {e}")
            
            return True
            
        except Exception as e:
            logger.error(f"Linux内存转储出错: {e}")
            return False
    
    def _dump_macos_process(self, pid, output_file):
        """使用macOS内存转储方法"""
        try:
            # 在macOS上，我们可以使用lldb或gcore
            import subprocess
            
            # 检查gcore是否可用
            try:
                subprocess.run(["which", "gcore"], check=True, stdout=subprocess.PIPE)
                
                # 使用gcore转储内存
                logger.info("使用gcore转储内存...")
                subprocess.run(["gcore", "-o", output_file, str(pid)], check=True)
                return True
                
            except subprocess.SubprocessError:
                logger.warning("gcore不可用，尝试使用lldb...")
                
                # 使用lldb转储内存
                script_file = os.path.join(self.output_dir, "lldb_dump_script.txt")
                with open(script_file, 'w') as f:
                    f.write(f"process attach --pid {pid}\n")
                    f.write(f"process save-core {output_file}\n")
                    f.write("quit\n")
                
                subprocess.run(["lldb", "-s", script_file], check=True)
                
                # 清理脚本文件
                os.remove(script_file)
                return True
                
        except Exception as e:
            logger.error(f"macOS内存转储出错: {e}")
            
            # 提供备用方法
            logger.info("您可以尝试使用以下命令手动转储内存:")
            logger.info(f"sudo gcore -o {output_file} {pid}")
            logger.info("或者:")
            logger.info(f"lldb -p {pid} -o 'process save-core {output_file}' -o 'quit'")
            
            return False
    
    def dump_system_memory(self):
        """转储整个系统内存（仅限特定平台）"""
        try:
            # 创建输出文件名
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            dump_file = os.path.join(self.output_dir, f"system_memory_{timestamp}.raw")
            
            logger.info("正在转储系统内存...")
            
            # 平台特定实现
            if platform.system() == 'Windows':
                import subprocess
                # 使用WinPmem或类似工具
                subprocess.run(["winpmem", "-o", dump_file], check=True)
            elif platform.system() == 'Linux':
                # 使用/dev/mem或LiME
                logger.warning("Linux系统内存转储需要内核模块支持")
                logger.info("可以使用以下命令安装LiME并转储内存:")
                logger.info("sudo insmod lime.ko 'path={dump_file} format=raw'")
                return None
            elif platform.system() == 'Darwin':  # macOS
                logger.warning("macOS不支持完整的系统内存转储")
                return None
            else:
                logger.error(f"不支持的平台: {platform.system()}")
                return None
            
            logger.info(f"系统内存转储完成: {dump_file}")
            return dump_file
            
        except Exception as e:
            logger.error(f"系统内存转储出错: {e}")
            return None
    
    def monitor_process(self, pid, interval=60, duration=3600):
        """定期转储进程内存，用于跟踪密钥变化"""
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            logger.info(f"开始监控进程 {pid} ({process_name})...")
            
            # 创建监控子目录
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            monitor_dir = os.path.join(self.output_dir, f"{process_name}_{pid}_monitor_{timestamp}")
            os.makedirs(monitor_dir, exist_ok=True)
            
            # 保存原始输出目录
            original_output_dir = self.output_dir
            self.output_dir = monitor_dir
            
            # 记录监控信息
            info_file = os.path.join(monitor_dir, "monitor_info.txt")
            with open(info_file, 'w') as f:
                f.write(f"Process: {process_name} (PID: {pid})\n")
                f.write(f"Start time: {datetime.datetime.now().isoformat()}\n")
                f.write(f"Interval: {interval} seconds\n")
                f.write(f"Duration: {duration} seconds\n")
            
            # 计算转储次数
            dumps_count = duration // interval
            
            # 进行周期性转储
            dumps = []
            start_time = time.time()
            
            for i in range(dumps_count):
                # 检查是否超出持续时间
                if time.time() - start_time >= duration:
                    break
                
                # 检查进程是否仍在运行
                try:
                    if not psutil.pid_exists(pid):
                        logger.warning(f"进程 {pid} 已终止，停止监控")
                        break
                except:
                    logger.warning(f"检查进程 {pid} 状态时出错，停止监控")
                    break
                
                # 转储内存
                logger.info(f"执行第 {i+1}/{dumps_count} 次内存转储...")
                dump_result = self.dump_process_memory(pid)
                
                if dump_result:
                    dumps.append(dump_result)
                
                # 等待下一个间隔
                if i < dumps_count - 1:  # 不在最后一次转储后等待
                    logger.info(f"等待 {interval} 秒进行下一次转储...")
                    time.sleep(interval)
            
            # 恢复原始输出目录
            self.output_dir = original_output_dir
            
            # 更新监控信息
            with open(info_file, 'a') as f:
                f.write(f"End time: {datetime.datetime.now().isoformat()}\n")
                f.write(f"Total dumps: {len(dumps)}\n")
            
            logger.info(f"监控完成，共生成 {len(dumps)} 个内存转储")
            logger.info(f"转储保存在: {monitor_dir}")
            
            return {
                'monitor_dir': monitor_dir,
                'dumps': dumps,
                'info_file': info_file
            }
            
        except psutil.NoSuchProcess:
            logger.error(f"进程 {pid} 不存在")
        except Exception as e:
            logger.error(f"监控进程 {pid} 时出错: {e}")
        
        return None

def list_processes_cmd(args):
    """列出进程命令处理函数"""
    dumper = MemoryDumper(verbose=args.verbose)
    processes = dumper.list_processes()
    
    # 打印进程列表
    print(f"{'PID':<10} {'用户名':<15} {'进程名':<30} 命令行")
    print("-" * 80)
    for proc in sorted(processes, key=lambda x: x['name'].lower()):
        print(f"{proc['pid']:<10} {proc['username'][:15]:<15} {proc['name'][:30]:<30} {proc['cmdline'][:50]}")
    
    print(f"\n共找到 {len(processes)} 个进程")

def dump_process_cmd(args):
    """转储进程内存命令处理函数"""
    dumper = MemoryDumper(output_dir=args.output_dir, verbose=args.verbose)
    result = dumper.dump_process_memory(args.pid)
    
    if result:
        print(f"内存转储已保存至: {result['dump_file']}")
        print(f"进程信息已保存至: {result['info_file']}")

def dump_system_cmd(args):
    """转储系统内存命令处理函数"""
    dumper = MemoryDumper(output_dir=args.output_dir, verbose=args.verbose)
    result = dumper.dump_system_memory()
    
    if result:
        print(f"系统内存转储已保存至: {result}")

def monitor_process_cmd(args):
    """监控进程内存命令处理函数"""
    dumper = MemoryDumper(output_dir=args.output_dir, verbose=args.verbose)
    result = dumper.monitor_process(args.pid, args.interval, args.duration)
    
    if result:
        print(f"进程监控已完成")
        print(f"转储保存在: {result['monitor_dir']}")
        print(f"共生成 {len(result['dumps'])} 个内存转储")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="内存转储工具")
    subparsers = parser.add_subparsers(dest="command", help="子命令")
    
    # 列出进程子命令
    list_parser = subparsers.add_parser("list", help="列出运行中的进程")
    list_parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出")
    
    # 转储进程内存子命令
    dump_parser = subparsers.add_parser("dump", help="转储进程内存")
    dump_parser.add_argument("pid", type=int, help="目标进程ID")
    dump_parser.add_argument("-o", "--output-dir", help="输出目录")
    dump_parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出")
    
    # 转储系统内存子命令
    system_parser = subparsers.add_parser("system", help="转储系统内存")
    system_parser.add_argument("-o", "--output-dir", help="输出目录")
    system_parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出")
    
    # 监控进程内存子命令
    monitor_parser = subparsers.add_parser("monitor", help="定期监控进程内存")
    monitor_parser.add_argument("pid", type=int, help="目标进程ID")
    monitor_parser.add_argument("-i", "--interval", type=int, default=60, help="转储间隔(秒)")
    monitor_parser.add_argument("-d", "--duration", type=int, default=3600, help="监控持续时间(秒)")
    monitor_parser.add_argument("-o", "--output-dir", help="输出目录")
    monitor_parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出")
    
    args = parser.parse_args()
    
    # 处理命令
    if args.command == "list":
        list_processes_cmd(args)
    elif args.command == "dump":
        dump_process_cmd(args)
    elif args.command == "system":
        dump_system_cmd(args)
    elif args.command == "monitor":
        monitor_process_cmd(args)
    else:
        parser.print_help()
EOF < /dev/null