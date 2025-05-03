# 加密分析工具集

本目录包含专门用于分析恶意软件和勒索软件加密算法的工具。

## 目录结构

- `key_finder/` - 加密密钥提取工具
- `algo_identifier/` - 加密算法识别工具
- `entropy/` - 熵分析工具
- `bruteforce/` - 暴力破解工具
- `ransomware_db/` - 勒索软件家族特征数据库

## 安装依赖

```bash
pip3 install cryptography pycryptodome hashid
```

## 使用指南

每个工具目录都包含自己的README文件，详细说明了该工具的使用方法和示例。

---

© 2025 Innora-Sentinel安全团队 | All Rights Reserved | [https://innora.ai](https://innora.ai)