# OpenSSH Automated Installer for Windows

[English](README_EN.md) | 简体中文

## 📖 概述

一个功能强大、可靠且具有容错能力的Windows OpenSSH自动安装和配置脚本。本脚本提供了全自动的OpenSSH安装、配置和优化解决方案，支持多种安装方式和故障恢复机制。

## ✨ 特性

- 完全自动化的安装和配置流程
- 强大的错误处理和故障恢复机制
- 详细的日志记录和进度显示
- 多种安装方式的智能切换
- 防火墙规则自动配置
- Windows Defender排除项自动设置
- 服务自动配置和优化
- 支持本地和远程执行
- 完整的运行环境检查

## 🚀 快速开始

### 基础使用

1. 本地执行：

    ```powershell
    .\OpenSSH.ps1
    ```

2. 远程执行（确保使用可信来源）：

    ```powershell
    Set-ExecutionPolicy Bypass -Scope Process -Force
    $script = "你的可信存储位置/OpenSSH.ps1"
    Invoke-Expression (New-Object Net.WebClient).DownloadString($script)
    ```

### 高级参数

```powershell
.\OpenSSH.ps1 [-Remote] [-Force] [-LogDirectory <path>]
```

## 📋 前置要求

- Windows 10/Server 2019 或更高版本
- PowerShell 5.1 或更高版本
- 管理员权限
- 网络连接（用于下载组件）

## 🛠️ 安装过程

1. 环境检查
2. AMSI和安全性配置
3. OpenSSH组件安装
4. 服务配置
5. 防火墙规则设置
6. 安全优化
7. 验证和测试

## 🔧 配置选项

- Remote：启用远程执行模式
- Force：强制重新安装
- LogDirectory：自定义日志目录

## 📚 进阶使用

### 作为模块导入

```powershell
Import-Module .\OpenSSH.ps1
Install-OpenSSHWithFallback
```

### 自定义安装

```powershell
$Config = @{
    LogPath = "D:\logs"
    RetryCount = 5
    # 其他自定义配置...
}
```

## 🔍 故障排除

### 常见问题

1. 权限不足

    - 确保以管理员身份运行PowerShell
    - 检查执行策略设置

2. 安装失败

    - 查看详细日志
    - 检查网络连接
    - 验证系统要求

3. AMSI阻止

    - 检查防病毒软件设置
    - 使用备用安装方法

### 日志位置

- 默认：`.\logs\OpenSSH_[timestamp].log`
- 自定义：使用 `-LogDirectory` 参数

## 🔐 安全考虑

- 仅从可信来源执行脚本
- 验证脚本签名（如果提供）
- 检查执行环境
- 注意远程执行的安全风险

## 🤝 贡献指南

1. Fork 项目
2. 创建特性分支
3. 提交改动
4. 发起 Pull Request

### 开发指南

- 遵循PowerShell最佳实践
- 保持代码风格一致
- 添加适当的注释
- 更新文档

## 📜 版本历史

- v2.0.0: 完整重构，增加容错机制
- v1.0.0: 初始发布

## 🌟 高级特性

- 多级别日志记录
- 智能回退机制
- 自动化测试
- 性能优化
- 远程执行支持

## 📱 支持与反馈

- 提交 Issue
- 提供改进建议
- 报告问题

## 📄 许可证

MIT License

## 🙏 致谢

感谢所有贡献者和社区的支持。

---

详细的英文文档请查看 [README_EN.md](README_EN.md)
