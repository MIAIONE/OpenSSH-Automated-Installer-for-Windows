# OpenSSH Automated Installer for Windows

[简体中文](README.md) | English

## 📖 Overview

A powerful, reliable, and fault-tolerant Windows OpenSSH automated installation and configuration script. This script provides a fully automated solution for OpenSSH installation, configuration, and optimization, supporting multiple installation methods and failure recovery mechanisms.

## ✨ Features

- Fully automated installation and configuration
- Robust error handling and recovery
- Detailed logging and progress display
- Smart switching between installation methods
- Automatic firewall rules configuration
- Windows Defender exclusions setup
- Service configuration and optimization
- Local and remote execution support
- Comprehensive environment checks

## 🚀 Quick Start

### Basic Usage

1. Local execution:

    ```powershell
    .\OpenSSH.ps1
    ```

2. Remote execution (ensure trusted source):

    ```powershell
    Set-ExecutionPolicy Bypass -Scope Process -Force
    $script = "your-trusted-location/OpenSSH.ps1"
    Invoke-Expression (New-Object Net.WebClient).DownloadString($script)
    ```

### Advanced Parameters

```powershell
.\OpenSSH.ps1 [-Remote] [-Force] [-LogDirectory <path>]
```

## 📋 Prerequisites

- Windows 10/Server 2019 or higher
- PowerShell 5.1 or higher
- Administrator privileges
- Network connectivity (for component downloads)

## 🛠️ Installation Process

1. Environment validation
2. AMSI and security setup
3. OpenSSH components installation
4. Service configuration
5. Firewall rules setup
6. Security optimization
7. Verification and testing

## 🔧 Configuration Options

- Remote: Enable remote execution mode
- Force: Force reinstallation
- LogDirectory: Custom log directory

## 📚 Advanced Usage

### Import as Module

```powershell
Import-Module .\OpenSSH.ps1
Install-OpenSSHWithFallback
```

### Custom Installation

```powershell
$Config = @{
    LogPath = "D:\logs"
    RetryCount = 5
    # Other custom configurations...
}
```

## 🔍 Troubleshooting

### Common Issues

1. Insufficient Permissions
   - Ensure PowerShell runs as Administrator
   - Check execution policy settings

2. Installation Failures
   - Review detailed logs
   - Check network connectivity
   - Verify system requirements

3. AMSI Blocking
   - Check antivirus settings
   - Use alternative installation methods

### Log Locations

- Default: `.\logs\OpenSSH_[timestamp].log`
- Custom: Use `-LogDirectory` parameter

## 🔐 Security Considerations

- Only execute from trusted sources
- Verify script signatures (if provided)
- Check execution environment
- Be aware of remote execution risks

## 🤝 Contributing

1. Fork the project
2. Create feature branch
3. Commit changes
4. Submit Pull Request

### Development Guidelines

- Follow PowerShell best practices
- Maintain consistent code style
- Add appropriate comments
- Update documentation

## 📜 Version History

- v2.0.0: Complete refactor, added fault tolerance
- v1.0.0: Initial release

## 🌟 Advanced Features

- Multi-level logging
- Smart fallback mechanisms
- Automated testing
- Performance optimization
- Remote execution support

## 📱 Support & Feedback

- Submit issues
- Provide improvement suggestions
- Report problems

## 📄 License

MIT License

## 🙏 Acknowledgments

Thanks to all contributors and community support.

---

For detailed Chinese documentation, please see [README.md](README.md)
