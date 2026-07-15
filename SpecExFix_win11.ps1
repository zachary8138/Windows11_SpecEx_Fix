<#
.SYNOPSIS
    Applies Microsoft-recommended speculative execution mitigations on Windows 11 workstations.

.DESCRIPTION
    Remediates Tenable Nessus findings:
      - Plugin 132101: Windows Speculative Execution Configuration Check
      - Plugin 302873: Windows Speculative Execution Configuration Check - Intel BHI (CVE-2022-0001)

    Registry guidance is based on Microsoft KB4073119 (Windows client guidance).

    Mitigations applied:
      - FeatureSettingsOverride / FeatureSettingsOverrideMask per KB4073119,
        selecting the correct value for the detected SMT/Hyper-Threading state
      - Intel BHI (CVE-2022-0001) via bitwise OR of 0x800000 when an Intel CPU is detected
      - MinVmVersionForCpuBasedMitigations when Hyper-V is present

    IMPORTANT PREREQUISITES:
      - Install current Windows security updates.
      - Install current OEM BIOS/UEFI firmware and CPU microcode.
      - Run in a 64-bit, elevated PowerShell 5.1+ process (SYSTEM for Intune).
      - Reboot after remediation. Registry values alone do not prove that the
        required OS and firmware protections are installed or active.
      - After reboot, validate with Microsoft's SpeculationControl module and
        rescan with Tenable.

    Supported processors:
      - Intel and AMD x86/x64 processors. The script fails closed if CPU vendor
        or processor topology cannot be determined.

    Intune deployment settings (Devices > Scripts and remediations > Platform scripts):
      - Run this script using the logged-on credentials: No  (SYSTEM required for HKLM)
      - Run script in 64-bit PowerShell host: Yes
      - Enforce script signature check: per organizational policy

    Exit codes (Intune reports success only on 0):
      0 = Registry configuration is compliant or was successfully remediated
      1 = Unsupported target, prerequisite detection failure, or remediation failure

    Log: C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\SpeculativeExecutionFix.log

.NOTES
    Requires: Windows 11, PowerShell 5.1+, elevated/SYSTEM context
    References:
      - https://www.tenable.com/plugins/nessus/132101
      - https://www.tenable.com/plugins/nessus/302873
      - https://support.microsoft.com/kb/4073119
#>

#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# --- Configuration (Microsoft KB4073119) ---
$LogPath = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\SpeculativeExecutionFix.log'

# Client mitigation values for TAA, MDS, Spectre, Meltdown, SSBD, and L1TF.
# Microsoft requires 72 when SMT/Hyper-Threading is enabled and 8264 when it is disabled.
$MitigationBaseSmtEnabled = 72      # 0x0048
$MitigationBaseSmtDisabled = 8264  # 0x2048

# Intel Branch History Injection (CVE-2022-0001) - Plugin 302873 / KB4073119
$MitigationBhiIntel = 0x00800000   # 8388608

$FeatureSettingsOverrideMask = 3

$MemoryManagementPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
$HyperVPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization'

# --- Logging ---
function Ensure-LogDirectory {
    $logDir = Split-Path -Parent $LogPath
    if (-not (Test-Path -Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
}

function Write-RemediationLog {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR')][string]$Type = 'INFO'
    )
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Type] $Message"
    Add-Content -Path $LogPath -Value $line -Encoding utf8
}

# --- Environment checks ---
function Test-IsWindows11 {
    try {
        $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $productName = ($cv.ProductName -as [string])

        if ($productName -and $productName -match 'Windows\s+11') { return $true }

        $build = [int]$cv.CurrentBuildNumber
        return ($build -ge 22000)
    }
    catch {
        Write-RemediationLog "Windows version detection failed: $($_.Exception.Message)" 'ERROR'
        return $false
    }
}

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ProcessorConfiguration {
    try {
        $processors = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
        if ($processors.Count -eq 0) {
            throw 'Win32_Processor returned no processors.'
        }

        $vendors = @(
            foreach ($processor in $processors) {
                $manufacturer = ($processor.Manufacturer -as [string])
                if ($manufacturer -match 'Intel') {
                    'Intel'
                }
                elseif ($manufacturer -match 'AMD|Advanced Micro Devices') {
                    'AMD'
                }
                else {
                    throw "Unsupported or unknown CPU manufacturer '$manufacturer'."
                }
            }
        )
        $vendors = @($vendors | Select-Object -Unique)

        if ($vendors.Count -ne 1) {
            throw "Mixed CPU vendors are not supported: $($vendors -join ', ')."
        }

        $coreCount = [int](($processors | Measure-Object -Property NumberOfCores -Sum).Sum)
        $logicalCount = [int](($processors | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum)
        if ($coreCount -le 0 -or $logicalCount -le 0) {
            throw "Invalid processor topology: cores=$coreCount, logical processors=$logicalCount."
        }

        # Intel calls this Hyper-Threading; AMD calls it SMT. Microsoft uses the
        # logical-processor versus core count to select the KB4073119 value.
        return [pscustomobject]@{
            Vendor                 = [string]$vendors[0]
            PhysicalCores          = $coreCount
            LogicalProcessors      = $logicalCount
            SmtEnabled             = ($logicalCount -gt $coreCount)
        }
    }
    catch {
        Write-RemediationLog "Processor detection failed: $($_.Exception.Message)" 'ERROR'
        throw
    }
}

function Get-TargetFeatureSettingsOverride {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Intel', 'AMD')][string]$CpuVendor,
        [Parameter(Mandatory = $true)][bool]$SmtEnabled
    )

    # Use a canonical Microsoft/Tenable baseline rather than OR-ing an arbitrary
    # existing value, which could retain bits that explicitly disable protections.
    $target = if ($SmtEnabled) {
        $MitigationBaseSmtEnabled
    }
    else {
        $MitigationBaseSmtDisabled
    }

    if ($CpuVendor -eq 'Intel') {
        # Microsoft requires BHI to be combined with other mitigations by bitwise OR.
        $target = $target -bor $MitigationBhiIntel
        Write-RemediationLog "Intel CPU detected. Target FeatureSettingsOverride = $target (0x$('{0:X}' -f $target)) includes BHI mitigation (CVE-2022-0001)." 'INFO'
    }
    else {
        Write-RemediationLog "CPU vendor '$CpuVendor'. Target FeatureSettingsOverride = $target (0x$('{0:X}' -f $target)) per KB4073119 client guidance." 'INFO'
    }
    return [int]$target
}

function Test-HyperVInstalledEnabled {
    try {
        # The management service exists when the full Hyper-V role is installed,
        # even if the service is currently stopped.
        if ($null -ne (Get-Service -Name 'vmms' -ErrorAction SilentlyContinue)) {
            return $true
        }

        $feature = Get-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Hyper-V-All' -ErrorAction SilentlyContinue
        if ($null -ne $feature -and $feature.State -eq 'Enabled') {
            return $true
        }

        return $false
    }
    catch {
        Write-RemediationLog "Hyper-V detection failed: $($_.Exception.Message)" 'WARNING'
        return $false
    }
}

function Get-RegistryDWord {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return [int]$item.$Name
}

function Get-RegistryValueKind {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not (Test-Path -Path $Path)) { return $null }
    try {
        return (Get-Item -Path $Path -ErrorAction Stop).GetValueKind($Name).ToString()
    }
    catch {
        return $null
    }
}

function Set-VerifiedRegistryDWord {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$Value
    )

    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    # New-ItemProperty -Force creates or replaces the value and guarantees REG_DWORD.
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    $read = Get-RegistryDWord -Path $Path -Name $Name
    $kind = Get-RegistryValueKind -Path $Path -Name $Name

    if ($read -ne $Value -or $kind -ne 'DWord') {
        Write-RemediationLog "Registry mismatch for $Name at $Path. Expected DWord $Value, read $kind $read." 'ERROR'
        return $false
    }

    Write-RemediationLog "Set $Name = $Value at $Path." 'SUCCESS'
    return $true
}

function Set-VerifiedRegistryString {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )

    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    # New-ItemProperty -Force creates or replaces the value and guarantees REG_SZ.
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force -ErrorAction Stop | Out-Null
    $read = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    $kind = Get-RegistryValueKind -Path $Path -Name $Name

    if ($read -ne $Value -or $kind -ne 'String') {
        Write-RemediationLog "Registry mismatch for $Name at $Path. Expected String '$Value', read $kind '$read'." 'ERROR'
        return $false
    }

    Write-RemediationLog "Set $Name = '$Value' at $Path." 'SUCCESS'
    return $true
}

function Test-MitigationCompliance {
    param(
        [Parameter(Mandatory = $true)][int]$ExpectedOverride,
        [Parameter(Mandatory = $true)][bool]$ExpectHyperVKey
    )

    $override = Get-RegistryDWord -Path $MemoryManagementPath -Name 'FeatureSettingsOverride'
    $mask = Get-RegistryDWord -Path $MemoryManagementPath -Name 'FeatureSettingsOverrideMask'
    $overrideKind = Get-RegistryValueKind -Path $MemoryManagementPath -Name 'FeatureSettingsOverride'
    $maskKind = Get-RegistryValueKind -Path $MemoryManagementPath -Name 'FeatureSettingsOverrideMask'

    $overrideOk = ($override -eq $ExpectedOverride -and $overrideKind -eq 'DWord')
    $maskOk = ($mask -eq $FeatureSettingsOverrideMask -and $maskKind -eq 'DWord')

    $hyperVOk = $true
    if ($ExpectHyperVKey) {
        $hvValue = (Get-ItemProperty -Path $HyperVPath -Name 'MinVmVersionForCpuBasedMitigations' -ErrorAction SilentlyContinue).MinVmVersionForCpuBasedMitigations
        $hvKind = Get-RegistryValueKind -Path $HyperVPath -Name 'MinVmVersionForCpuBasedMitigations'
        $hyperVOk = ($hvValue -eq '1.0' -and $hvKind -eq 'String')
    }

    return @{
        Compliant   = ($overrideOk -and $maskOk -and $hyperVOk)
        Override    = $override
        Mask        = $mask
        OverrideKind = $overrideKind
        MaskKind     = $maskKind
        OverrideOk  = $overrideOk
        MaskOk      = $maskOk
        HyperVOk    = $hyperVOk
    }
}

# --- Main ---
try {
    Ensure-LogDirectory
    Write-RemediationLog 'SpecExFix_win11.ps1 started.' 'INFO'

    if (-not (Test-IsWindows11)) {
        Write-RemediationLog 'Target is not Windows 11. No changes were made.' 'ERROR'
        exit 1
    }

    if (-not (Test-IsElevated)) {
        Write-RemediationLog 'Script is not running with administrative/SYSTEM privileges. HKLM changes will fail.' 'ERROR'
        exit 1
    }

    if (-not [Environment]::Is64BitProcess) {
        Write-RemediationLog 'Script is running in a 32-bit PowerShell process. Run it in 64-bit Windows PowerShell to avoid registry redirection.' 'ERROR'
        exit 1
    }

    $build = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).CurrentBuildNumber
    $processor = Get-ProcessorConfiguration
    $targetOverride = Get-TargetFeatureSettingsOverride -CpuVendor $processor.Vendor -SmtEnabled $processor.SmtEnabled
    $hyperVPresent = Test-HyperVInstalledEnabled

    Write-RemediationLog "Environment: Windows 11 build $build, CPU vendor '$($processor.Vendor)', physical cores $($processor.PhysicalCores), logical processors $($processor.LogicalProcessors), SMT enabled: $($processor.SmtEnabled), Hyper-V present: $hyperVPresent." 'INFO'

    $compliance = Test-MitigationCompliance -ExpectedOverride $targetOverride -ExpectHyperVKey $hyperVPresent
    if ($compliance.Compliant) {
        Write-RemediationLog 'Registry configuration is already compliant. Confirm OS updates, OEM firmware, reboot state, and active protections separately.' 'SUCCESS'
        Write-RemediationLog 'SpecExFix_win11.ps1 complete.' 'INFO'
        exit 0
    }

    Write-RemediationLog "Current state: FeatureSettingsOverride=$($compliance.Override) ($($compliance.OverrideKind)), FeatureSettingsOverrideMask=$($compliance.Mask) ($($compliance.MaskKind))." 'INFO'

    $anyFailures = $false

    if (-not (Set-VerifiedRegistryDWord -Path $MemoryManagementPath -Name 'FeatureSettingsOverride' -Value $targetOverride)) {
        $anyFailures = $true
    }
    if (-not (Set-VerifiedRegistryDWord -Path $MemoryManagementPath -Name 'FeatureSettingsOverrideMask' -Value $FeatureSettingsOverrideMask)) {
        $anyFailures = $true
    }

    if ($hyperVPresent) {
        Write-RemediationLog 'Hyper-V detected. Applying MinVmVersionForCpuBasedMitigations per KB4073119.' 'INFO'
        Write-RemediationLog 'After firmware updates, fully shut down all VMs before rebooting the host so firmware-related mitigations are exposed to guests.' 'WARNING'
        if (-not (Set-VerifiedRegistryString -Path $HyperVPath -Name 'MinVmVersionForCpuBasedMitigations' -Value '1.0')) {
            $anyFailures = $true
        }
    }
    else {
        Write-RemediationLog 'Hyper-V not detected. Skipping virtualization registry key.' 'INFO'
    }

    $postCompliance = Test-MitigationCompliance -ExpectedOverride $targetOverride -ExpectHyperVKey $hyperVPresent
    if (-not $postCompliance.Compliant) {
        Write-RemediationLog 'Post-remediation compliance check failed.' 'ERROR'
        $anyFailures = $true
    }

    if ($anyFailures) {
        Write-RemediationLog 'Remediation finished with failures. Review log and retry after confirming SYSTEM context.' 'ERROR'
        exit 1
    }

    Write-RemediationLog 'Registry remediation applied successfully. Current Windows security updates, OEM firmware/microcode, and a system reboot are required for protections to take effect.' 'SUCCESS'
    Write-RemediationLog 'After reboot, verify with: Import-Module SpeculationControl; Get-SpeculationControlSettings' 'INFO'
    Write-RemediationLog 'SpecExFix_win11.ps1 complete.' 'INFO'
    exit 0
}
catch {
    try {
        Write-RemediationLog "Unhandled error: $($_.Exception.Message)" 'ERROR'
    }
    catch {
        # Last-resort if logging itself fails
    }
    exit 1
}
