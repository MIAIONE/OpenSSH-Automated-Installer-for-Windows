# 🚀 OpenSSH Automated Installer for Windows

[简体中文](README.md) | English

## 📖 Overview

A powerful Windows OpenSSH automated installation and configuration script with auto-elevation, multi-level fallback, and smart installation capabilities.

## ✨ Features

* Fully automated installation and configuration
* Automatic administrator privileges elevation
* Smart switching between installation methods
* Automatic firewall and service configuration
* Detailed progress bar and logging
* Comprehensive error handling

## 💡 Usage

```powershell
# Direct execution (will auto-request admin rights)
.\OpenSSH.ps1

# With parameters
.\OpenSSH.ps1 [-Remote] [-Force] [-LogDirectory <path>]
```

## 🔧 Requirements

* Windows 10 / Windows Server 2019 or higher
* PowerShell 5.1 or higher
* Network connectivity (for component download)

## ⚙️ Parameters

* `-Remote`: Enable remote execution mode
* `-Force`: Force reinstallation
* `-LogDirectory`: Specify log directory location

## ❓ Common Questions

1. How to verify successful installation?

   ```powershell
   Get-Service sshd
   ```

2. How to check detailed logs?

   ```powershell
   # Default log location:
   .\logs\OpenSSH_[timestamp].log
   ```

## 📄 License

MIT License

## 💬 Issues

If you encounter any problems during usage, please feel free to raise an [issue](../../issues).
