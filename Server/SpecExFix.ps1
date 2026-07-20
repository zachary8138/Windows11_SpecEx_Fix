<#
.SYNOPSIS
    Applies Microsoft-recommended speculative execution mitigations on Windows Server
    (on-premises, Hyper-V hosts, Azure Stack HCI / Azure Local, and Azure guest VMs).

.DESCRIPTION
    Remediates Tenable Nessus findings:
      - Plugin 132101: Windows Speculative Execution Configuration Check
      - Plugin 302873: Windows Speculative Execution Configuration Check - Intel BHI (CVE-2022-0001)

    Registry guidance is based on Microsoft KB4072698 (Windows Server and Azure Stack HCI).

    Mitigations applied:
      - FeatureSettingsOverride / FeatureSettingsOverrideMask per KB4072698,
        selecting the correct value for the detected SMT/Hyper-Threading state
      - Intel BHI (CVE-2022-0001) via bitwise OR of 0x800000 when an Intel CPU is detected
      - MinVmVersionForCpuBasedMitigations when the Hyper-V role/feature is present

    Deployment targets covered by this script:
      - On-premises Windows Server (member/standalone, with or without Hyper-V)
      - Hyper-V hosts (MinVmVersionForCpuBasedMitigations applied when Hyper-V is present)
      - Azure Stack HCI / Azure Local (same KB4072698 host guidance)
      - Windows Server guest VMs in Azure (same guest OS registry keys; see Azure notes below)

    Azure notes:
      - Microsoft already mitigates Azure host infrastructure between tenants.
      - Guest OS registry keys are still the correct remediation for Tenable findings
        inside the VM and for defense-in-depth / untrusted-code scenarios
        (https://learn.microsoft.com/azure/virtual-machines/mitigate-se).
      - Nested Hyper-V in Azure (limited SKUs) may also require setting the hypervisor
        scheduler type to Core; that host-scheduler step is outside this registry script.
      - A separate Azure-only script is not required for registry remediation.

    IMPORTANT PREREQUISITES:
      - Install current Windows Server security updates.
      - Install current OEM BIOS/UEFI firmware and CPU microcode on physical hosts.
      - Run in a 64-bit, elevated PowerShell 5.1+ process.
      - Reboot after remediation. Registry values alone do not prove that the
        required OS and firmware protections are installed or active.
      - On Hyper-V hosts, after firmware updates, fully shut down all VMs before
        rebooting the host so firmware-related mitigations are exposed to guests.
      - After reboot, validate with Microsoft's SpeculationControl module and
        rescan with Tenable.

    Supported processors:
      - Intel and AMD x86/x64 processors. The script fails closed if CPU vendor
        or processor topology cannot be determined.

    Exit codes:
      0 = Registry configuration is compliant or was successfully remediated
      1 = Unsupported target, prerequisite detection failure, or remediation failure

    Log: C:\ProgramData\SpecEx\SpeculativeExecutionFix_Server.log

.NOTES
    Author: zachary8138
    Requires: Windows Server (or Azure Stack HCI / Azure Local), PowerShell 5.1+, elevated context
    References:
      - https://www.tenable.com/plugins/nessus/132101
      - https://www.tenable.com/plugins/nessus/302873
      - https://support.microsoft.com/kb/4072698
      - https://learn.microsoft.com/azure/virtual-machines/mitigate-se
#>

#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# --- Configuration (Microsoft KB4072698) ---
$LogPath = 'C:\ProgramData\SpecEx\SpeculativeExecutionFix_Server.log'

# Server mitigation values for TAA, MDS, Spectre, Meltdown, MMIO, SSBD, and L1TF.
# Microsoft requires 72 when SMT/Hyper-Threading is enabled and 8264 when it is disabled.
$MitigationBaseSmtEnabled = 72      # 0x0048
$MitigationBaseSmtDisabled = 8264  # 0x2048

# Intel Branch History Injection (CVE-2022-0001) - Plugin 302873 / KB4072698
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
function Get-OsIdentity {
    try {
        $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $productName = ($cv.ProductName -as [string])
        $installationType = ($cv.InstallationType -as [string])
        $build = 0
        [void][int]::TryParse(($cv.CurrentBuildNumber -as [string]), [ref]$build)

        $isServerSku = $false
        if ($installationType -match '^(Server|Server Core)$') {
            $isServerSku = $true
        }
        elseif ($productName -match 'Windows\s+Server|Azure\s+Stack\s+HCI|Azure\s+Local') {
            $isServerSku = $true
        }

        return [pscustomobject]@{
            ProductName      = $productName
            InstallationType = $installationType
            Build            = $build
            IsServerSku      = $isServerSku
        }
    }
    catch {
        Write-RemediationLog "Windows version detection failed: $($_.Exception.Message)" 'ERROR'
        throw
    }
}

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CloudEnvironment {
    # Azure guest agent / IMDS indicate an Azure VM. Azure Stack HCI / Azure Local
    # are treated as on-prem/host SKUs via Get-OsIdentity product name.
    $result = [pscustomobject]@{
        IsAzureGuest = $false
        Evidence     = @()
    }

    try {
        if (Get-Service -Name 'WindowsAzureGuestAgent' -ErrorAction SilentlyContinue) {
            $result.IsAzureGuest = $true
            $result.Evidence += 'WindowsAzureGuestAgent service'
        }
    }
    catch {
        # ignore
    }

    if (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows Azure') {
        $result.IsAzureGuest = $true
        $result.Evidence += 'HKLM\SOFTWARE\Microsoft\Windows Azure'
    }

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if (($cs.Manufacturer -as [string]) -match 'Microsoft' -and ($cs.Model -as [string]) -match 'Virtual Machine') {
            # Hyper-V guest signal; combine with Azure evidence above when present.
            $result.Evidence += "ComputerSystem Model='$($cs.Model)'"
        }
    }
    catch {
        # ignore
    }

    return $result
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
        # logical-processor versus core count to select the KB4072698 value.
        return [pscustomobject]@{
            Vendor            = [string]$vendors[0]
            PhysicalCores     = $coreCount
            LogicalProcessors = $logicalCount
            SmtEnabled        = ($logicalCount -gt $coreCount)
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
        Write-RemediationLog "CPU vendor '$CpuVendor'. Target FeatureSettingsOverride = $target (0x$('{0:X}' -f $target)) per KB4072698 server guidance." 'INFO'
    }
    return [int]$target
}

function Test-HyperVInstalledEnabled {
    try {
        # Management service exists when the Hyper-V role is installed, even if stopped.
        if ($null -ne (Get-Service -Name 'vmms' -ErrorAction SilentlyContinue)) {
            return $true
        }

        # Windows Server / Azure Stack HCI role inventory
        if (Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $feature = Get-WindowsFeature -Name 'Hyper-V' -ErrorAction SilentlyContinue
            if ($null -ne $feature -and $feature.Installed) {
                return $true
            }
        }

        # Fallback for Server editions that expose optional features
        if (Get-Command -Name Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
            $optional = Get-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Hyper-V' -ErrorAction SilentlyContinue
            if ($null -ne $optional -and $optional.State -eq 'Enabled') {
                return $true
            }
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
        Compliant    = ($overrideOk -and $maskOk -and $hyperVOk)
        Override     = $override
        Mask         = $mask
        OverrideKind = $overrideKind
        MaskKind     = $maskKind
        OverrideOk   = $overrideOk
        MaskOk       = $maskOk
        HyperVOk     = $hyperVOk
    }
}

# --- Main ---
try {
    Ensure-LogDirectory
    Write-RemediationLog 'SpecExFix.ps1 started (Windows Server / KB4072698).' 'INFO'

    $os = Get-OsIdentity
    if (-not $os.IsServerSku) {
        Write-RemediationLog "Target is not Windows Server / Azure Stack HCI / Azure Local (ProductName='$($os.ProductName)', InstallationType='$($os.InstallationType)'). No changes were made. Use SpecExFix_win11.ps1 for Windows 11 clients." 'ERROR'
        exit 1
    }

    if (-not (Test-IsElevated)) {
        Write-RemediationLog 'Script is not running with administrative privileges. HKLM changes will fail.' 'ERROR'
        exit 1
    }

    if (-not [Environment]::Is64BitProcess) {
        Write-RemediationLog 'Script is running in a 32-bit PowerShell process. Run it in 64-bit Windows PowerShell to avoid registry redirection.' 'ERROR'
        exit 1
    }

    $processor = Get-ProcessorConfiguration
    $targetOverride = Get-TargetFeatureSettingsOverride -CpuVendor $processor.Vendor -SmtEnabled $processor.SmtEnabled
    $hyperVPresent = Test-HyperVInstalledEnabled
    $cloud = Get-CloudEnvironment

    $cloudLabel = if ($cloud.IsAzureGuest) {
        "Azure guest VM ($($cloud.Evidence -join '; '))"
    }
    else {
        'on-premises or non-Azure host/VM'
    }

    Write-RemediationLog "Environment: '$($os.ProductName)' (InstallationType='$($os.InstallationType)', build $($os.Build)), CPU vendor '$($processor.Vendor)', physical cores $($processor.PhysicalCores), logical processors $($processor.LogicalProcessors), SMT enabled: $($processor.SmtEnabled), Hyper-V present: $hyperVPresent, cloud: $cloudLabel." 'INFO'

    if ($cloud.IsAzureGuest) {
        Write-RemediationLog 'Azure guest detected. Applying the same KB4072698 guest OS registry mitigations. Azure host isolation is Microsoft-managed and is outside this script.' 'INFO'
    }

    $compliance = Test-MitigationCompliance -ExpectedOverride $targetOverride -ExpectHyperVKey $hyperVPresent
    if ($compliance.Compliant) {
        Write-RemediationLog 'Registry configuration is already compliant. Confirm OS updates, OEM firmware (physical hosts), reboot state, and active protections separately.' 'SUCCESS'
        Write-RemediationLog 'SpecExFix.ps1 complete.' 'INFO'
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
        Write-RemediationLog 'Hyper-V detected. Applying MinVmVersionForCpuBasedMitigations per KB4072698.' 'INFO'
        Write-RemediationLog 'After firmware updates on Hyper-V hosts, fully shut down all VMs before rebooting the host so firmware-related mitigations are exposed to guests.' 'WARNING'
        if ($cloud.IsAzureGuest) {
            Write-RemediationLog 'Nested Hyper-V in Azure may also require hypervisor scheduler type Core on supported SKUs; configure that separately if applicable.' 'WARNING'
        }
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
        Write-RemediationLog 'Remediation finished with failures. Review log and retry after confirming elevated 64-bit context.' 'ERROR'
        exit 1
    }

    Write-RemediationLog 'Registry remediation applied successfully. Current Windows security updates, OEM firmware/microcode (physical hosts), and a system reboot are required for protections to take effect.' 'SUCCESS'
    Write-RemediationLog 'After reboot, verify with: Import-Module SpeculationControl; Get-SpeculationControlSettings' 'INFO'
    Write-RemediationLog 'SpecExFix.ps1 complete.' 'INFO'
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
