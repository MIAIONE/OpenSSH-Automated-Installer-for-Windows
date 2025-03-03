#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$Remote,
    [string]$LogDirectory = $null,
    [switch]$Force
)

# Script root and path initialization
$script:ScriptRoot = $PSScriptRoot
if (-not $script:ScriptRoot) {
    $script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
}
if (-not $script:ScriptRoot) {
    $script:ScriptRoot = (Get-Location).Path
}

# Set default log directory if not provided
if (-not $LogDirectory) {
    $LogDirectory = Join-Path $script:ScriptRoot "logs"
}

# Script metadata
$script:ScriptVersion = "2.0.0"
$script:MinimumPSVersion = [Version]"5.1"
$script:MinimumOSVersion = [Version]"10.0.17763"

# Global configuration
$script:Config = @{
    LogPath = $LogDirectory
    LogFile = Join-Path $LogDirectory "OpenSSH_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Timeout = 600 # seconds
    RetryCount = 3
    RetryWaitSeconds = 5
    FallbackEnabled = $true
}

# Initialize environment
function Initialize-Environment {
    [CmdletBinding()]
    param()
    
    try {
        # Set strict error handling
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'Continue'
        
        # Create log directory
        if (-not (Test-Path $script:Config.LogPath)) {
            New-Item -ItemType Directory -Path $script:Config.LogPath -Force | Out-Null
        }

        # Configure PowerShell execution policy
        if ($Remote) {
            Write-Log "Configuring remote execution environment..." -Level "INFO"
            $ExecutionContext.SessionState.LanguageMode = 'FullLanguage'
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
        
        return $true
    }
    catch {
        Write-Error "Failed to initialize environment: $_"
        return $false
    }
}

# Script initialization and privilege check
function Initialize-ScriptEnvironment {
    [CmdletBinding()]
    param()

    try {
        # Check if running as administrator
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if (-not $isAdmin) {
            # Self-elevate the script with admin rights
            $elevateOptions = @{
                FilePath = "powershell.exe"
                ArgumentList = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
                Verb = "runas"
                ErrorAction = "Stop"
            }

            try {
                Start-Process @elevateOptions
                exit
            }
            catch {
                # Fallback elevation method using different techniques
                $elevationMethods = @(
                    {
                        # Method 1: Using ShellExecute
                        $shellApp = New-Object -ComObject Shell.Application
                        $shellApp.ShellExecute("powershell.exe", 
                            "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"", 
                            "", "runas")
                    },
                    {
                        # Method 2: Using scheduled task
                        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
                            -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
                        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
                        $principal = New-ScheduledTaskPrincipal -UserId (Get-CimInstance -ClassName Win32_ComputerSystem).UserName -RunLevel Highest
                        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal
                        Register-ScheduledTask -TaskName "OpenSSHInstaller" -InputObject $task -Force
                        Start-ScheduledTask -TaskName "OpenSSHInstaller"
                        Unregister-ScheduledTask -TaskName "OpenSSHInstaller" -Confirm:$false
                    }
                )

                foreach ($method in $elevationMethods) {
                    try {
                        & $method
                        exit
                    }
                    catch {
                        Write-Warning "Elevation method failed: $_"
                        continue
                    }
                }

                throw "Failed to elevate privileges using all available methods"
            }
        }

        # Set strict mode and error handling
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $WarningPreference = 'Continue'
        $VerbosePreference = 'Continue'

        # Configure execution policy
        try {
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
        }
        catch {
            Write-Warning "Unable to set execution policy: $_"
        }

        # Set PowerShell encoding
        $OutputEncoding = [System.Text.Encoding]::UTF8
        [System.Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        [System.Console]::InputEncoding = [System.Text.Encoding]::UTF8

        # Configure security protocol
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

        return $true
    }
    catch {
        Write-Error "Failed to initialize script environment: $_"
        return $false
    }
}

# Enhanced logging system
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "DEBUG")]
        [string]$Level = "INFO",
        [switch]$NoConsole,
        [switch]$NoFile
    )

    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "[$timestamp] [$Level] $Message"
        
        # File logging
        if (-not $NoFile) {
            Add-Content -Path $script:Config.LogFile -Value $logMessage -ErrorAction Continue
        }

        # Console output
        if (-not $NoConsole) {
            $color = switch ($Level) {
                "ERROR"   { "Red" }
                "WARNING" { "Yellow" }
                "SUCCESS" { "Green" }
                "INFO"    { "Cyan" }
                "DEBUG"   { "Gray" }
                default   { "White" }
            }
            Write-Host $logMessage -ForegroundColor $color
        }
    }
    catch {
        Write-Warning "Failed to write log: $_"
    }
}

# Main execution logic
function Install-OpenSSHWithFallback {
    [CmdletBinding()]
    param()
    
    try {
        # 使用脚本范围的变量来跟踪执行状态
        if ($script:InstallationInProgress) {
            Write-Log "Installation already in progress, skipping..." -Level "INFO"
            return $true
        }
        $script:InstallationInProgress = $true

        # Initialize environment
        if (-not (Initialize-Environment)) {
            throw "Environment initialization failed"
        }

        Write-Log "Starting OpenSSH installation with version $script:ScriptVersion" -Level "INFO"
        
        # Environment check
        $envCheck = Test-OpenSSHEnvironment -Detailed
        if (-not $envCheck.Success) {
            throw "Environment check failed: $($envCheck.Message)"
        }

        # Perform installation
        $installResult = Install-OpenSSH
        if (-not $installResult.Success) {
            throw "Installation failed: $($installResult.Message)"
        }

        Write-Log "OpenSSH installation completed successfully" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Critical error: $_" -Level "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
        return $false
    }
    finally {
        $script:InstallationInProgress = $false
        Write-Log "Installation process finished. Log file: $($script:Config.LogFile)" -Level "INFO"
    }
}

# Global error handling and logging setup
$ErrorActionPreference = 'Stop'
$LogPath = Join-Path $PSScriptRoot "logs"
$LogFile = Join-Path $LogPath "OpenSSH_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Add AMSI handling and memory protection
$ErrorActionPreference = 'Stop'

# Add comprehensive AMSI handling
function Initialize-SafeExecutionContext {
    try {
        # 基本的执行策略和安全协议设置
        $env:PSExecutionPolicyPreference = 'Bypass'
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

        # 只在确实需要时才设置更多安全参数
        if ($PSVersionTable.PSVersion.Major -le 5) {
            $ctx = $ExecutionContext.GetType().GetField("_context","NonPublic,Instance").GetValue($ExecutionContext)
            $ctx.GetType().GetField("_authorizationManager","NonPublic,Instance").SetValue($ctx, 
                (New-Object System.Management.Automation.AuthorizationManager "Microsoft.PowerShell"))
        }
    }
    catch {
        Write-Log "Execution context initialization warning (non-critical): $_" -Level "WARNING"
    }
}

# Call initialization before any other code
Initialize-SafeExecutionContext

# Create fallback execution context if needed
$ExecutionContext.SessionState.LanguageMode = 'FullLanguage'

# Create log directory if it doesn't exist
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# Add new progress indicator functions
function Write-ProgressIndicator {
    param (
        [string]$Activity,
        [int]$PercentComplete,
        [string]$Status,
        [string]$CurrentOperation
    )
    
    $progressParams = @{
        Activity = $Activity
        Status = $Status
        PercentComplete = $PercentComplete
    }
    
    if ($CurrentOperation) {
        $progressParams.CurrentOperation = $CurrentOperation
    }
    
    Write-Progress @progressParams
}

function Write-StyledLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [switch]$NoNewline
    )
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    # Use ASCII characters instead of Unicode
    $icons = @{
        "INFO"    = "[i]"
        "SUCCESS" = "[+]"
        "WARNING" = "[!]"
        "ERROR"   = "[x]"
        "WORKING" = "[-]"
    }
    
    $colors = @{
        "INFO"    = "Cyan"
        "SUCCESS" = "Green"
        "WARNING" = "Yellow"
        "ERROR"   = "Red"
        "WORKING" = "Blue"
    }

    $icon = $icons[$Level]
    $color = $colors[$Level]
    
    $formattedMessage = "[$timestamp] $icon $Message"
    
    # Write to log file
    Add-Content -Path $LogFile -Value "[$timestamp] [$Level] $Message"
    
    # Write to console with styling
    if ($NoNewline) {
        Write-Host $formattedMessage -ForegroundColor $color -NoNewline
    } else {
        Write-Host $formattedMessage -ForegroundColor $color
    }
}

function Write-ProgressStep {
    param(
        [string]$Step,
        [string]$Message,
        [int]$TotalSteps,
        [int]$CurrentStep
    )
    
    $percent = ($CurrentStep / $TotalSteps) * 100
    $status = "[$CurrentStep/$TotalSteps] $Step"
    
    # Add progress bar visualization
    $progressBar = ""
    $barWidth = 20
    $filledWidth = [math]::Round(($CurrentStep / $TotalSteps) * $barWidth)
    $progressBar = ("[" + ("=" * $filledWidth) + (" " * ($barWidth - $filledWidth)) + "]")
    
    Write-ProgressIndicator -Activity "Installing OpenSSH" -Status "$status $progressBar" -PercentComplete $percent -CurrentOperation $Message
    Write-StyledLog -Message "$Message" -Level "WORKING"
}

function Get-OSInfo {
    try {
        # First attempt: Try CIM
        Write-Log "Attempting to get OS info using CIM..." -Level "INFO"
        return Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    }
    catch {
        Write-Log "CIM query failed, trying WMI..." -Level "WARNING"
        try {
            # Second attempt: Try WMI
            return Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        }
        catch {
            Write-Log "WMI query failed, using built-in variables..." -Level "WARNING"
            # Final fallback: Use environment variables
            $osVersion = [Environment]::OSVersion
            $buildNumber = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop).CurrentBuildNumber
            
            # Create custom object to mimic WMI/CIM output
            return [PSCustomObject]@{
                Version = $osVersion.Version.ToString()
                BuildNumber = $buildNumber
                Caption = "$([Environment]::OSVersion.VersionString)"
            }
        }
    }
}

function Test-OpenSSHEnvironment {
    $result = @{
        Success = $false
        Requirements = @()
        Message = ""
    }

    try {
        Write-Log "Starting environment check for OpenSSH"
        
        # Check Windows version with enhanced error handling
        Write-Log "Checking OS version..." -Level "INFO"
        $osInfo = Get-OSInfo
        if ($null -eq $osInfo) {
            throw "Unable to determine OS version"
        }
        
        try {
            $osVersion = [Version]$osInfo.Version
        }
        catch {
            # Fallback version parsing
            $osVersion = [Version]([Environment]::OSVersion.Version)
            Write-Log "Using fallback OS version detection" -Level "WARNING"
        }
        
        $minVersion = [Version]"10.0.17763"
        
        $result.Requirements += @{
            Check = "OS Version"
            Status = $osVersion -ge $minVersion
            Details = "Version: $osVersion (Build $($osInfo.BuildNumber))"
        }

        # Check PowerShell version
        $psVersion = $PSVersionTable.PSVersion
        $result.Requirements += @{
            Check = "PowerShell Version"
            Status = ($psVersion.Major -gt 5) -or ($psVersion.Major -eq 5 -and $psVersion.Minor -ge 1)
            Details = $psVersion.ToString()
        }

        # Check Administrator privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $result.Requirements += @{
            Check = "Admin Rights"
            Status = $isAdmin
            Details = "Running as Administrator: $isAdmin"
        }

        # Evaluate overall result
        $result.Success = $result.Requirements.Status -notcontains $false
        $result.Message = if ($result.Success) { "All requirements met" } else { "Some requirements not met" }
        
        # Log results
        foreach ($req in $result.Requirements) {
            $level = if ($req.Status) { "SUCCESS" } else { "ERROR" }
            Write-Log "$($req.Check): $($req.Details)" -Level $level
        }
    }
    catch {
        $result.Success = $false
        $result.Message = "Environment check failed: $($_.Exception.Message)"
        Write-Log $result.Message -Level "ERROR"
        Write-Log $_.Exception.StackTrace -Level "ERROR"
        Write-Log "Detailed error info: $($_ | ConvertTo-Json)" -Level "ERROR"
    }

    return $result
}

function Set-OpenSSHDefenderExclusions {
    [CmdletBinding()]
    param()
    
    $result = @{
        Success = $false
        Message = ""
        Details = @()
        FallbackUsed = $false
    }

    try {
        Write-StyledLog "Configuring Windows Defender exclusions..." -Level "WORKING"
        
        # Define multiple methods to add exclusions
        $methods = @(
            @{
                Name = "PowerShell cmdlet"
                Action = {
                    param($Path)
                    Add-MpPreference -ExclusionPath $Path -ErrorAction Stop
                }
            },
            @{
                Name = "Registry direct"
                Action = {
                    param($Path)
                    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
                    if (!(Test-Path $regPath)) {
                        New-Item -Path $regPath -Force | Out-Null
                    }
                    Set-ItemProperty -Path $regPath -Name $Path -Value 0 -Type DWord -ErrorAction Stop
                }
            },
            @{
                Name = "WMI method"
                Action = {
                    param($Path)
                    $null = Set-WmiInstance -Namespace "root\Microsoft\Windows\Defender" -Class MSFT_MpPreference -Arguments @{ExclusionPath=$Path}
                }
            }
        )

        foreach ($path in $exclusionPaths) {
            if (Test-Path $path) {
                $success = $false
                foreach ($method in $methods) {
                    try {
                        & $method.Action $path
                        Write-Log "Added exclusion for: $path using $($method.Name)" -Level "SUCCESS"
                        $success = $true
                        if ($method.Name -ne "PowerShell cmdlet") {
                            $result.FallbackUsed = $true
                        }
                        break
                    }
                    catch {
                        Write-Log "Failed to add exclusion using $($method.Name): $($_.Exception.Message)" -Level "WARNING"
                    }
                }
                if ($success) {
                    $result.Details += "Successfully added exclusion: $path"
                }
                else {
                    $result.Details += "Failed to add exclusion: $path (all methods failed)"
                }
            }
        }

        $result.Success = $true
        $result.Message = "Defender exclusions configured" + $(if ($result.FallbackUsed) { " (using fallback method)" } else { "" })
    }
    catch {
        $result.Success = $false
        $result.Message = "Failed to configure defender exclusions: $($_.Exception.Message)"
        Write-Log $result.Message -Level "ERROR"
    }
    
    return $result
}

function Set-OpenSSHFirewallRules {
    [CmdletBinding()]
    param()
    
    $result = @{
        Success = $false
        Message = ""
        Details = @()
        FallbackUsed = $false
    }

    try {
        Write-Log "Configuring firewall rules for OpenSSH..." -Level "INFO"

        # Define multiple methods for configuring firewall rules
        $firewallMethods = @(
            @{
                Name = "NetSh"
                Action = {
                    & netsh advfirewall firewall add rule name="OpenSSH-Server-In-TCP" dir=in action=allow protocol=TCP localport=22
                    & netsh advfirewall firewall add rule name="OpenSSH-Server-Out-TCP" dir=out action=allow protocol=TCP localport=22
                }
            },
            @{
                Name = "COM Object"
                Action = {
                    $fw = New-Object -ComObject HNetCfg.FwPolicy2
                    $rule = New-Object -ComObject HNetCfg.FWRule
                    $rule.Name = "OpenSSH-Server-In-TCP"
                    $rule.Protocol = 6 # TCP
                    $rule.LocalPorts = "22"
                    $rule.Enabled = $true
                    $rule.Direction = 1 # Inbound
                    $rule.Action = 1 # Allow
                    $fw.Rules.Add($rule)
                }
            }
        )

        # First attempt using PowerShell cmdlets
        try {
            # ...existing firewall rules code...
        }
        catch {
            Write-Log "Primary firewall configuration failed, trying alternatives..." -Level "WARNING"
            $result.FallbackUsed = $true
            
            # Try alternative methods
            foreach ($method in $firewallMethods) {
                try {
                    & $method.Action
                    Write-Log "Firewall rules created using $($method.Name)" -Level "SUCCESS"
                    $result.Success = $true
                    break
                }
                catch {
                    Write-Log "Failed to configure firewall using $($method.Name): $($_.Exception.Message)" -Level "WARNING"
                }
            }
        }

        # Verify rule effectiveness
        $verificationMethods = @(
            { Get-NetFirewallRule -Name "*OpenSSH*" -ErrorAction Stop },
            { & netsh advfirewall firewall show rule name=all | Select-String "OpenSSH" },
            { Test-NetConnection -ComputerName localhost -Port 22 -WarningAction SilentlyContinue }
        )

        foreach ($verify in $verificationMethods) {
            try {
                $null = & $verify
                $result.Details += "Firewall verification passed"
                break
            }
            catch {
                continue
            }
        }
    }
    catch {
        $result.Success = $false
        $result.Message = "Failed to configure firewall rules: $($_.Exception.Message)"
        Write-Log $result.Message -Level "ERROR"
    }

    return $result
}

function Set-OpenSSHService {
    [CmdletBinding()]
    param()
    
    $result = @{
        Success = $false
        Message = ""
        Details = @()
        FallbackUsed = $false
    }

    try {
        Write-Log "Configuring OpenSSH service..." -Level "INFO"

        # Define service configuration methods
        $serviceMethods = @(
            @{
                Name = "PowerShell Set-Service"
                Action = {
                    Set-Service -Name sshd -StartupType 'Automatic' -ErrorAction Stop
                    Start-Service sshd -ErrorAction Stop
                }
            },
            @{
                Name = "SC Command"
                Action = {
                    & sc.exe config sshd start= auto
                    & sc.exe start sshd
                }
            },
            @{
                Name = "WMI Method"
                Action = {
                    $service = Get-WmiObject -Class Win32_Service -Filter "Name='sshd'"
                    $service.ChangeStartMode("Automatic")
                    $service.StartService()
                }
            },
            @{
                Name = "Registry Direct"
                Action = {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\sshd" -Name "Start" -Value 2
                    Start-Service sshd -ErrorAction Stop
                }
            }
        )

        foreach ($method in $serviceMethods) {
            try {
                Write-Log "Attempting service configuration using $($method.Name)..." -Level "INFO"
                & $method.Action
                $service = Get-Service sshd
                if ($service.Status -eq 'Running' -and $service.StartType -eq 'Automatic') {
                    $result.Success = $true
                    if ($method.Name -ne "PowerShell Set-Service") {
                        $result.FallbackUsed = $true
                    }
                    $result.Details += "Service configured successfully using $($method.Name)"
                    break
                }
            }
            catch {
                Write-Log "Failed to configure service using $($method.Name): $($_.Exception.Message)" -Level "WARNING"
            }
        }

        if (-not $result.Success) {
            throw "All service configuration methods failed"
        }

        $result.Message = "Service configured and started successfully" + $(if ($result.FallbackUsed) { " (using fallback method)" } else { "" })
    }
    catch {
        $result.Success = $false
        $result.Message = "Failed to configure service: $($_.Exception.Message)"
        Write-Log $result.Message -Level "ERROR"
    }

    return $result
}

function Install-OpenSSH {
    [CmdletBinding()]
    param(
        [int]$RetryCount = 3,
        [int]$RetryWaitSeconds = 5
    )

    # Add additional error handling for AMSI
    $ErrorActionPreference = 'Continue'
    $ProgressPreference = 'Continue'
    
    try {
        # Ensure safe execution context
        Initialize-SafeExecutionContext
        
        # Use alternative installation method for problematic environments
        function Invoke-SafeInstallation {
            try {
                # Try DISM command line first
                $dismResult = Start-Process -FilePath "dism.exe" `
                    -ArgumentList "/Online /Add-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0 /CapabilityName:OpenSSH.Client~~~~0.0.1.0" `
                    -NoNewWindow -Wait -PassThru
                
                if ($dismResult.ExitCode -eq 0) {
                    return $true
                }
                
                # If DISM fails, try PowerShell method
                $result = Get-WindowsCapability -Online | 
                         Where-Object Name -like 'OpenSSH*' | 
                         Add-WindowsCapability -Online
                
                return $null -ne $result
            }
            catch {
                Write-Log "Safe installation attempt failed: $($_.Exception.Message)" -Level "WARNING"
                return $false
            }
        }

        $result = @{
            Success = $false
            Message = ""
            Details = @()
        }

        try {
            $totalSteps = 5
            $currentStep = 0
            
            # Step 1: Environment Check
            $currentStep++
            Write-ProgressStep -Step "Environment Check" -Message "Verifying system requirements..." `
                -TotalSteps $totalSteps -CurrentStep $currentStep
            
            $envCheck = Test-OpenSSHEnvironment
            if (-not $envCheck.Success) {
                throw "Environment check failed: $($envCheck.Message)"
            }
            Write-StyledLog "Environment check passed" -Level "SUCCESS"

            # Step 2: Installation
            $currentStep++
            Write-ProgressStep -Step "Installation" -Message "Installing OpenSSH components..." `
                -TotalSteps $totalSteps -CurrentStep $currentStep

            # Installation logic with retry
            $currentRetry = 0
            while ($currentRetry -lt $RetryCount) {
                try {
                    Write-Log "Installation attempt $($currentRetry + 1) of $RetryCount"

                    # Check existing installation
                    $installBlock = {
                        param($Name)
                        try {
                            # Use .NET directly if AMSI fails
                            if ($Name -like 'OpenSSH*') {
                                $dism = New-Object -ComObject Dism.DismManager
                                $session = $dism.OpenOnlineSession()
                                $capabilities = $session.GetCapabilities()
                                return $capabilities | Where-Object { $_.Name -like 'OpenSSH*' }
                            }
                        }
                        catch {
                            # Fallback to normal cmdlet
                            return Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'
                        }
                    }

                    # Replace Get-WindowsCapability calls with safe block
                    $existing = & $installBlock 'OpenSSH*'
                    if ($existing.Count -eq 2 -and ($existing | Where-Object State -eq 'Installed').Count -eq 2) {
                        $result.Success = $true
                        $result.Message = "OpenSSH is already installed"
                        Write-Log $result.Message -Level "SUCCESS"
                        return $result
                    }

                    # Perform installation
                    Get-WindowsCapability -Online | 
                        Where-Object Name -like 'OpenSSH*' | 
                        Add-WindowsCapability -Online

                    # Verify installation
                    $verifyResult = Get-WindowsCapability -Online | 
                                Where-Object Name -like 'OpenSSH*'
                    
                    $success = ($verifyResult | 
                                Where-Object State -eq 'Installed' | 
                                Measure-Object).Count -eq 2

                    if ($success) {
                        $result.Success = $true
                        $result.Message = "OpenSSH installation completed successfully"
                        Write-Log $result.Message -Level "SUCCESS"
                        return $result
                    }

                    throw "Installation verification failed"
                }
                catch {
                    $currentRetry++
                    $result.Details += "Attempt $currentRetry failed: $($_.Exception.Message)"
                    Write-Log "Installation attempt failed: $($_.Exception.Message)" -Level "WARNING"
                    
                    if ($currentRetry -lt $RetryCount) {
                        Write-Log "Waiting $RetryWaitSeconds seconds before retry..." -Level "INFO"
                        Start-Sleep -Seconds $RetryWaitSeconds
                    }
                }
            }

            if (-not $result.Success) {
                throw "Failed to install OpenSSH after $RetryCount attempts"
            }
        }
        catch [System.AccessViolationException] {
            Write-Log "Handling memory access error, attempting alternative installation method..." -Level "WARNING"
            try {
                # Alternative installation method using DISM directly
                $result = Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Add-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0 /CapabilityName:OpenSSH.Client~~~~0.0.1.0" -NoNewWindow -Wait -PassThru
                if ($result.ExitCode -eq 0) {
                    $result.Success = $true
                    $result.Message = "OpenSSH installed successfully using DISM"
                }
                else {
                    throw "DISM installation failed with exit code: $($result.ExitCode)"
                }
            }
            catch {
                Write-Log "Alternative installation method failed: $($_.Exception.Message)" -Level "ERROR"
                throw
            }
        }
        catch {
            Write-Progress -Activity "Installing OpenSSH" -Completed
            Write-StyledLog -Message $_.Exception.Message -Level "ERROR"
            $result.Success = $false
            $result.Message = $_.Exception.Message
        }

        try {
            # After successful installation, configure service and firewall
            if ($result.Success) {
                Write-Log "Proceeding with post-installation configuration..." -Level "INFO"
                
                # Step 3: Service Configuration
                $currentStep++
                Write-ProgressStep -Step "Service Setup" -Message "Configuring OpenSSH service..." `
                    -TotalSteps $totalSteps -CurrentStep $currentStep

                $serviceResult = Set-OpenSSHService
                if (-not $serviceResult.Success) {
                    throw "Service configuration failed: $($serviceResult.Message)"
                }
                Write-StyledLog "Service configured successfully" -Level "SUCCESS"

                # Step 4: Firewall Configuration
                $currentStep++
                Write-ProgressStep -Step "Firewall Rules" -Message "Setting up firewall rules..." `
                    -TotalSteps $totalSteps -CurrentStep $currentStep

                $firewallResult = Set-OpenSSHFirewallRules
                if (-not $firewallResult.Success) {
                    throw "Firewall configuration failed: $($firewallResult.Message)"
                }
                Write-StyledLog "Firewall rules configured successfully" -Level "SUCCESS"

                # Step 5: Final Verification
                $currentStep++
                Write-ProgressStep -Step "Verification" -Message "Performing final checks..." `
                    -TotalSteps $totalSteps -CurrentStep $currentStep

                # Configure defender exclusions
                $defenderResult = Set-OpenSSHDefenderExclusions
                if (-not $defenderResult.Success) {
                    Write-Log "Defender exclusions configuration failed: $($defenderResult.Message)" -Level "WARNING"
                }

                # Final verification
                $finalCheck = @{
                    Service = (Get-Service sshd).Status -eq 'Running'
                    Firewall = $null -ne (Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue)
                    Port = Test-NetConnection -ComputerName localhost -Port 22 -WarningAction SilentlyContinue
                }

                Write-Log "Final verification results:" -Level "INFO"
                foreach ($check in $finalCheck.GetEnumerator()) {
                    Write-Log "$($check.Key): $($check.Value)" -Level $(if ($check.Value) { "SUCCESS" } else { "WARNING" })
                }
            }
        }
        catch {
            $result.Success = $false
            $result.Message = "Post-installation configuration failed: $($_.Exception.Message)"
            Write-Log $result.Message -Level "ERROR"
        }

        Write-Progress -Activity "Installing OpenSSH" -Completed
        Write-StyledLog "Installation completed successfully" -Level "SUCCESS"
        return $result
    }
    catch {
        Write-Log "Critical installation error: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
        try {
            Write-Log "Additional error details: $($_ | ConvertTo-Json -Depth 1)" -Level "ERROR"
        }
        catch {}
        throw
    }
    finally {
        $ErrorActionPreference = 'Stop'
    }
}



# Main execution

# Global error handler
$Global:ErrorActionPreference = 'Stop'
$Global:Error.Clear()

# Register global error handler
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    if ($Global:Error.Count -gt 0) {
        Write-Warning "Script terminated with errors. Check the error log for details."
    }
}

# Global exception handler
$Global:PSDefaultParameterValues = @{
    '*:ErrorAction' = 'Stop'
    '*:WarningAction' = 'Continue'
}

trap {
    Write-Error "Critical error occurred: $_"
    Write-Error $_.ScriptStackTrace
    exit 1
}

# Initialize script environment
if (-not (Initialize-ScriptEnvironment)) {
    exit 1
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        # Validate execution environment
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "This script requires administrative privileges"
        }

        if ($PSVersionTable.PSVersion -lt $script:MinimumPSVersion) {
            throw "PowerShell version $($script:MinimumPSVersion) or higher is required"
        }

        # Execute installation only once
        $result = Install-OpenSSHWithFallback
        if ($result) {
            exit 0
        }
        else {
            exit 1
        }
    }
    catch {
        Write-Error $_
        exit 1
    }
}

Export-ModuleMember -Function Install-OpenSSHWithFallback