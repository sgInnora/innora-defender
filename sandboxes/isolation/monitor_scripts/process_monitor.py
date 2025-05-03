#\!/usr/bin/env python3
"""
进程监控脚本 - 跟踪和记录进程活动
"""
import os
import sys
import time
import json
import psutil
import argparse
from datetime import datetime

class ProcessMonitor:
    def __init__(self, pid=None, log_dir="/logs", interval=1.0):
        self.target_pid = pid
        self.log_dir = log_dir
        self.interval = interval
        self.log_file = None
        self.process_data = {}
        self.file_activity = {}
        self.network_connections = {}
        
    def setup_logging(self):
        """设置日志文件"""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        pid_str = f"pid{self.target_pid}" if self.target_pid else "allprocs"
        log_filename = f"procmon_{pid_str}_{timestamp}.json"
        self.log_file = os.path.join(self.log_dir, log_filename)
        
        # 确保日志目录存在
        os.makedirs(self.log_dir, exist_ok=True)
        
    def collect_process_info(self, process):
        """收集单个进程的信息"""
        try:
            proc_info = {
                'pid': process.pid,
                'name': process.name(),
                'status': process.status(),
                'created_time': datetime.fromtimestamp(process.create_time()).isoformat(),
                'cpu_percent': process.cpu_percent(interval=0.1),
                'memory_percent': process.memory_percent(),
                'command_line': process.cmdline(),
                'cwd': process.cwd(),
                'username': process.username(),
                'open_files': [],
                'connections': [],
                'children': []
            }
            
            # 收集打开的文件
            try:
                for file in process.open_files():
                    proc_info['open_files'].append(file.path)
                    # 记录文件活动
                    if file.path not in self.file_activity:
                        self.file_activity[file.path] = []
                    self.file_activity[file.path].append({
                        'pid': process.pid,
                        'timestamp': datetime.now().isoformat(),
                        'operation': 'open'
                    })
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
            # 收集网络连接
            try:
                for conn in process.connections():
                    connection_info = {
                        'fd': conn.fd,
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'status': conn.status
                    }
                    
                    if conn.laddr:
                        connection_info['local_addr'] = f"{conn.laddr.ip}:{conn.laddr.port}"
                    
                    if conn.raddr:
                        connection_info['remote_addr'] = f"{conn.raddr.ip}:{conn.raddr.port}"
                        # 记录网络连接
                        conn_key = f"{conn.raddr.ip}:{conn.raddr.port}"
                        if conn_key not in self.network_connections:
                            self.network_connections[conn_key] = []
                        self.network_connections[conn_key].append({
                            'pid': process.pid,
                            'timestamp': datetime.now().isoformat(),
                            'status': conn.status
                        })
                    
                    proc_info['connections'].append(connection_info)
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
            # 收集子进程
            try:
                for child in process.children(recursive=True):
                    try:
                        proc_info['children'].append({
                            'pid': child.pid,
                            'name': child.name()
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
            return proc_info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
    
    def monitor_specific_process(self):
        """监控特定PID的进程"""
        try:
            process = psutil.Process(self.target_pid)
            snapshot = self.collect_process_info(process)
            if snapshot:
                timestamp = datetime.now().isoformat()
                if str(self.target_pid) not in self.process_data:
                    self.process_data[str(self.target_pid)] = []
                self.process_data[str(self.target_pid)].append({
                    'timestamp': timestamp,
                    'data': snapshot
                })
        except psutil.NoSuchProcess:
            print(f"进程 {self.target_pid} 不存在或已终止。")
            return False
        return True
    
    def monitor_all_processes(self):
        """监控所有进程"""
        timestamp = datetime.now().isoformat()
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                # 跳过一些系统进程以减少噪音
                if proc.pid < 1000 and sys.platform == 'linux':
                    continue
                    
                pid = str(proc.pid)
                proc_info = self.collect_process_info(proc)
                if proc_info:
                    if pid not in self.process_data:
                        self.process_data[pid] = []
                    self.process_data[pid].append({
                        'timestamp': timestamp,
                        'data': proc_info
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return True
    
    def save_data(self):
        """保存收集的数据到文件"""
        output_data = {
            'processes': self.process_data,
            'file_activity': self.file_activity,
            'network_connections': self.network_connections,
            'monitoring_info': {
                'start_time': datetime.now().isoformat(),
                'target_pid': self.target_pid,
                'interval': self.interval
            }
        }
        
        with open(self.log_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"数据已保存至: {self.log_file}")
    
    def run(self):
        """运行监控循环"""
        self.setup_logging()
        print(f"开始进程监控，日志将保存到: {self.log_file}")
        print(f"监控{'PID: ' + str(self.target_pid) if self.target_pid else '所有进程'}")
        
        try:
            while True:
                if self.target_pid:
                    if not self.monitor_specific_process():
                        break
                else:
                    self.monitor_all_processes()
                
                # 定期保存数据
                self.save_data()
                
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print("\n监控已停止。")
        finally:
            self.save_data()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="进程监控工具")
    parser.add_argument("-p", "--pid", type=int, help="要监控的特定进程ID")
    parser.add_argument("-d", "--log-dir", default="/logs", help="日志保存目录")
    parser.add_argument("-i", "--interval", type=float, default=1.0, help="监控间隔(秒)")
    
    args = parser.parse_args()
    
    monitor = ProcessMonitor(
        pid=args.pid,
        log_dir=args.log_dir,
        interval=args.interval
    )
    monitor.run()
EOF < /dev/null