# 安全隔离配置指南

## 1. 网络隔离设置

### 1.1 VirtualBox网络配置
```bash
# 创建专用隔离网络
VBoxManage natnetwork add --netname MalwareNet --network "10.2.2.0/24" --enable --dhcp off

# 创建主机-客户机通信网络
VBoxManage natnetwork add --netname AnalysisNet --network "10.2.3.0/24" --enable --dhcp on

# 配置端口转发以便管理
VBoxManage natnetwork modify --netname AnalysisNet --port-forward-4 "SSH:tcp:[]:5555:[10.2.3.101]:22"
```

### 1.2 Docker网络隔离
```bash
# 创建隔离网络
docker network create --internal malware-analysis-net

# 使用隔离网络运行容器
docker run --rm -it --network malware-analysis-net --name malware-analysis malware-analysis-sandbox
```

### 1.3 系统级网络隔离
```bash
# macOS防火墙规则
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on

# 创建网络钩子监控恶意流量
sudo pfctl -e # 启用数据包过滤
```

## 2. 虚拟环境嵌套与快照

### 2.1 嵌套虚拟化
```bash
# 检查是否支持嵌套虚拟化
sysctl -a | grep -E "vmx|svm"

# VirtualBox启用嵌套虚拟化
VBoxManage modifyvm "MalwareAnalysisVM" --nested-hw-virt on
```

### 2.2 快照管理
```bash
# 创建基础快照
VBoxManage snapshot "MalwareAnalysisVM" take "Clean-Base-State" --description "干净的基础状态"

# 创建分析前快照
VBoxManage snapshot "MalwareAnalysisVM" take "Pre-Analysis-State" --description "分析前状态"

# 恢复到干净状态
VBoxManage snapshot "MalwareAnalysisVM" restore "Clean-Base-State"
```

### 2.3 自动快照脚本
```bash
#\!/bin/bash
# 自动创建和恢复快照
VM_NAME="MalwareAnalysisVM"
SNAPSHOT_NAME="Auto-$(date +%Y%m%d-%H%M%S)"

# 创建快照
create_snapshot() {
  VBoxManage snapshot "$VM_NAME" take "$SNAPSHOT_NAME" --description "自动快照: $1"
  echo "已创建快照: $SNAPSHOT_NAME"
}

# 恢复快照
restore_last_snapshot() {
  LAST_SNAPSHOT=$(VBoxManage snapshot "$VM_NAME" list | grep "Name:" | tail -1 | cut -d ':' -f 2 | tr -d ' ')
  VBoxManage snapshot "$VM_NAME" restore "$LAST_SNAPSHOT"
  echo "已恢复到快照: $LAST_SNAPSHOT"
}

# 使用示例
create_snapshot "分析前"
# 进行分析...
restore_last_snapshot
```

## 3. 物理设备隔离

### 3.1 专用设备设置
- 使用专用的物理机进行恶意软件分析
- 不保存个人数据或凭证
- 使用独立的网络连接

### 3.2 硬件隔离最佳实践
- 物理设备与企业网络隔离
- 使用不同的物理网络适配器
- 考虑使用USB启动的临时环境

## 4. 访问控制

### 4.1 设置文件权限
```bash
# 样本目录权限设置
chmod 700 /path/to/samples
chmod 600 /path/to/samples/*

# 使用ACL进一步限制
chmod +a "group:analysts deny delete" /path/to/samples
```

### 4.2 用户隔离
```bash
# 创建专用分析用户
sudo dscl . -create /Users/malware_analyst
sudo dscl . -create /Users/malware_analyst UserShell /bin/bash
sudo dscl . -create /Users/malware_analyst RealName "Malware Analyst"
sudo dscl . -create /Users/malware_analyst UniqueID 1001
sudo dscl . -create /Users/malware_analyst PrimaryGroupID 80
sudo dscl . -create /Users/malware_analyst NFSHomeDirectory /Users/malware_analyst
sudo mkdir -p /Users/malware_analyst
sudo chown -R malware_analyst:admin /Users/malware_analyst
```

---

© 2025 Innora-Sentinel安全团队 | All Rights Reserved | [https://innora.ai](https://innora.ai)