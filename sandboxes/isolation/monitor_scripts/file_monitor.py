#\!/usr/bin/env python3
"""
文件系统监控脚本 - 跟踪和记录文件系统变化
"""
import os
import sys
import time
import json
import argparse
import hashlib
from datetime import datetime
from pathlib import Path

class FileSystemMonitor:
    def __init__(self, target_dir, log_dir="/logs", interval=5.0, recursive=True):
        self.target_dir = target_dir
        self.log_dir = log_dir
        self.interval = interval
        self.recursive = recursive
        self.log_file = None
        self.file_snapshot = {}
        self.file_changes = []
        
    def setup_logging(self):
        """设置日志文件"""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        dir_name = os.path.basename(os.path.normpath(self.target_dir))
        log_filename = f"filemon_{dir_name}_{timestamp}.json"
        self.log_file = os.path.join(self.log_dir, log_filename)
        
        # 确保日志目录存在
        os.makedirs(self.log_dir, exist_ok=True)
    
    def hash_file(self, file_path):
        """计算文件的SHA256哈希值"""
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (IOError, OSError, PermissionError):
            return None
    
    def get_file_metadata(self, file_path):
        """获取文件的元数据"""
        try:
            stat_info = os.stat(file_path)
            return {
                'path': str(file_path),
                'size': stat_info.st_size,
                'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                'hash': self.hash_file(file_path),
                'type': 'file' if os.path.isfile(file_path) else 'directory'
            }
        except (IOError, OSError, PermissionError):
            return None
    
    def take_snapshot(self):
        """获取目标目录的文件系统快照"""
        snapshot = {}
        target_path = Path(self.target_dir)
        
        try:
            if self.recursive:
                for file_path in target_path.rglob('*'):
                    if file_path.is_file():
                        metadata = self.get_file_metadata(file_path)
                        if metadata:
                            snapshot[str(file_path)] = metadata
            else:
                for file_path in target_path.glob('*'):
                    if file_path.is_file():
                        metadata = self.get_file_metadata(file_path)
                        if metadata:
                            snapshot[str(file_path)] = metadata
        except (IOError, OSError, PermissionError) as e:
            print(f"获取快照时出错: {e}")
        
        return snapshot
    
    def compare_snapshots(self, old_snapshot, new_snapshot):
        """比较两个快照并记录变化"""
        timestamp = datetime.now().isoformat()
        
        # 检查新增文件
        for file_path in new_snapshot:
            if file_path not in old_snapshot:
                self.file_changes.append({
                    'timestamp': timestamp,
                    'action': 'created',
                    'file': new_snapshot[file_path]
                })
        
        # 检查删除的文件
        for file_path in old_snapshot:
            if file_path not in new_snapshot:
                self.file_changes.append({
                    'timestamp': timestamp,
                    'action': 'deleted',
                    'file': old_snapshot[file_path]
                })
        
        # 检查修改的文件
        for file_path in new_snapshot:
            if file_path in old_snapshot:
                old_file = old_snapshot[file_path]
                new_file = new_snapshot[file_path]
                
                # 检查是否有变化
                if (old_file['hash'] \!= new_file['hash'] or 
                    old_file['size'] \!= new_file['size'] or 
                    old_file['modified'] \!= new_file['modified']):
                    self.file_changes.append({
                        'timestamp': timestamp,
                        'action': 'modified',
                        'file': new_file,
                        'previous': {
                            'hash': old_file['hash'],
                            'size': old_file['size'],
                            'modified': old_file['modified']
                        }
                    })
    
    def save_data(self):
        """保存收集的数据到文件"""
        output_data = {
            'monitoring_info': {
                'target_directory': self.target_dir,
                'start_time': datetime.now().isoformat(),
                'interval': self.interval,
                'recursive': self.recursive
            },
            'file_changes': self.file_changes,
            'current_snapshot': self.file_snapshot
        }
        
        with open(self.log_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"数据已保存至: {self.log_file}")
    
    def run(self):
        """运行监控循环"""
        self.setup_logging()
        print(f"开始文件系统监控，日志将保存到: {self.log_file}")
        print(f"监控目录: {self.target_dir} {'(递归)' if self.recursive else ''}")
        
        # 获取初始快照
        self.file_snapshot = self.take_snapshot()
        print(f"已获取初始快照，共 {len(self.file_snapshot)} 个文件")
        
        try:
            while True:
                time.sleep(self.interval)
                
                # 获取新快照
                new_snapshot = self.take_snapshot()
                
                # 比较快照
                self.compare_snapshots(self.file_snapshot, new_snapshot)
                
                # 更新当前快照
                self.file_snapshot = new_snapshot
                
                # 保存数据
                self.save_data()
                
        except KeyboardInterrupt:
            print("\n监控已停止。")
        finally:
            self.save_data()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="文件系统监控工具")
    parser.add_argument("target_dir", help="要监控的目标目录")
    parser.add_argument("-d", "--log-dir", default="/logs", help="日志保存目录")
    parser.add_argument("-i", "--interval", type=float, default=5.0, help="监控间隔(秒)")
    parser.add_argument("-n", "--no-recursive", action="store_false", dest="recursive", help="禁用递归监控")
    
    args = parser.parse_args()
    
    monitor = FileSystemMonitor(
        target_dir=args.target_dir,
        log_dir=args.log_dir,
        interval=args.interval,
        recursive=args.recursive
    )
    monitor.run()
EOF < /dev/null