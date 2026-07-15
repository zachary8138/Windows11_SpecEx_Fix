# Windows 11 speculative-execution remediation

`SpecExFix_win11.ps1` configures the Microsoft registry mitigations used to
remediate these Tenable findings on supported Windows 11 clients:

- Plugin 132101: Windows Speculative Execution Configuration Check
- Plugin 302873: Windows Speculative Execution Configuration Check - Intel BHI
  (CVE-2022-0001)

The script follows Microsoft KB4073119 client guidance. It detects whether
SMT/Hyper-Threading is enabled, applies the corresponding combined mitigation
value, adds the Intel BHI bit on Intel processors, and configures the Hyper-V
minimum VM version when Hyper-V is enabled.

## Important limitation

Registry configuration is only one part of remediation. A successful script
exit confirms that the expected registry values and data types were written; it
does **not** prove that the processor protections are active.

The endpoint must also have:

- Current Windows 11 security and servicing updates.
- Current BIOS/UEFI firmware and CPU microcode from the device manufacturer.
- A reboot after the registry values and updates are installed.

Microsoft notes that these mitigations can affect performance. Test them against
representative workloads before broad deployment.

## Requirements

- Windows 11 on a supported Intel or AMD x86/x64 processor.
- Windows PowerShell 5.1 or later.
- A 64-bit PowerShell process.
- Local Administrator or `SYSTEM` privileges.
- Access to write under `HKLM` and to create the log directory.
- An organizational process for deploying current Windows updates and OEM
  firmware.

The script intentionally stops with exit code `1` if it cannot identify the CPU
vendor or physical/logical processor topology. This prevents an Intel device
from being reported as remediated when the BHI setting could not be selected.

## Values applied

For `FeatureSettingsOverrideMask`, the script sets `3` (`REG_DWORD`).

For `FeatureSettingsOverride`, it selects:

- SMT/Hyper-Threading enabled, AMD: `72` (`0x48`).
- SMT/Hyper-Threading disabled, AMD: `8264` (`0x2048`).
- SMT/Hyper-Threading enabled, Intel with BHI: `8388680` (`0x800048`).
- SMT/Hyper-Threading disabled, Intel with BHI: `8396872` (`0x802048`).

These are canonical combined values for the vulnerabilities covered by the two
Tenable plugins. The script replaces the existing value instead of preserving
arbitrary bits because an existing bit can explicitly disable a protection.
Review this behavior first if the organization manages other
`FeatureSettingsOverride` options for separate processor vulnerabilities.

If Hyper-V is enabled, the script also creates:

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\MinVmVersionForCpuBasedMitigations`
as `REG_SZ` with value `1.0`.

## Run manually

1. Install all applicable Windows security updates.
2. Install the latest applicable OEM BIOS/UEFI firmware and CPU microcode.
3. Save the script locally.
4. Open **64-bit Windows PowerShell as Administrator**.
5. If required by policy, sign the script with an approved code-signing
   certificate. Do not permanently weaken the execution policy.
6. Run:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SpecExFix_win11.ps1
   ```

   `-ExecutionPolicy Bypass` affects only this process invocation. Omit it when
   application control or organizational policy requires a signed script.

7. Review the exit code and log:

   ```powershell
   $LASTEXITCODE
   Get-Content 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\SpeculativeExecutionFix.log'
   ```

8. Reboot the computer.

For a Hyper-V host, after installing firmware updates, fully shut down all
virtual machines before rebooting the host. This allows firmware-related
mitigations to be exposed to the guests when they start again.

## Deploy with Intune

For **Devices > Scripts and remediations > Platform scripts**, use:

- Run this script using the logged-on credentials: **No**
- Run script in 64-bit PowerShell host: **Yes**
- Enforce script signature check: according to organizational signing policy

Schedule or require a reboot after successful execution. Do not rescan before
the reboot.

Exit codes:

- `0`: expected registry configuration was already present or was written and
  verified. OS updates, firmware, reboot state, and active protections still
  require separate validation.
- `1`: unsupported target, detection failure, insufficient privileges, registry
  write failure, or verification failure.

## Verify after reboot

Microsoft recommends its `SpeculationControl` PowerShell module:

```powershell
Install-Module SpeculationControl -Scope AllUsers
Import-Module SpeculationControl
Get-SpeculationControlSettings
```

Install modules only from a trusted repository and under the organization's
software-management policy. Review the output for missing Windows support,
missing hardware support/microcode, or disabled protections.

Confirm the registry configuration:

```powershell
$memoryManagement = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
Get-ItemProperty -Path $memoryManagement `
  -Name FeatureSettingsOverride, FeatureSettingsOverrideMask
```

Finally, run a credentialed Tenable/Nessus scan after the reboot and confirm
that plugins 132101 and 302873 no longer report the endpoint. Plugin 302873
applies to affected Intel processors.

## Logging

The script writes to:

`C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\SpeculativeExecutionFix.log`

The log records the Windows build, CPU vendor, core and logical-processor
counts, detected SMT state, Hyper-V state, selected mitigation value, registry
writes, and any failure.

## References

- [Tenable plugin 132101](https://www.tenable.com/plugins/nessus/132101)
- [Tenable plugin 302873](https://www.tenable.com/plugins/nessus/302873)
- [Microsoft KB4073119 Windows client guidance](https://support.microsoft.com/en-us/topic/kb4073119-windows-client-guidance-for-it-pros-to-protect-against-silicon-based-microarchitectural-and-speculative-execution-side-channel-vulnerabilities-35820a8a-ae13-1299-88cc-357f104f5b11)
- [Microsoft KB4073757 general Windows guidance](https://support.microsoft.com/en-us/topic/kb4073757-protect-windows-devices-against-silicon-based-microarchitectural-and-speculative-execution-side-channel-vulnerabilities-a0b9f66c-f426-d854-fdbb-0e6beaeeee87)
