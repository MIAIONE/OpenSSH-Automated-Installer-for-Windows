# 🚀 OpenSSH Automated Installer for Windows

简体中文 | [English](README_EN.md)

## 📖 简介

一个功能完备的 Windows OpenSSH 自动安装和配置脚本，支持自动权限提升、多级容错和智能安装。

## ✨ 特性

* 全自动的安装和配置过程
* 自动提升管理员权限
* 多种安装方式智能切换
* 自动配置防火墙和服务
* 详细的进度条和日志记录
* 完善的错误处理机制

## 💡 使用方法

```powershell
# 直接运行（会自动请求管理员权限）
.\OpenSSH.ps1

# 带参数运行
.\OpenSSH.ps1 [-Remote] [-Force] [-LogDirectory <path>]
```

## 🔧 系统要求

* Windows 10 / Windows Server 2019 或更高版本
* PowerShell 5.1 或更高版本
* 网络连接（用于组件下载）

## ⚙️ 参数说明

* `-Remote`: 启用远程执行模式
* `-Force`: 强制重新安装
* `-LogDirectory`: 指定日志目录位置

## ❓ 常见问题

1. 如何检查安装是否成功？

   ```powershell
   Get-Service sshd
   ```

2. 如何查看详细日志？

   ```powershell
   # 日志默认位置：
   .\logs\OpenSSH_[timestamp].log
   ```

## 📄 许可证

MIT License

## 💬 问题反馈

如果您在使用过程中遇到任何问题，欢迎在 [Issues](../../issues) 中反馈。
