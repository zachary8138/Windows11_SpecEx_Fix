# SpecExFix — Windows Server speculative-execution remediation

`SpecExFix.ps1` configures the Microsoft registry mitigations used to remediate
these Tenable findings on supported Windows Server systems:

- [Plugin 132101](https://www.tenable.com/plugins/nessus/132101): Windows Speculative Execution Configuration Check
- [Plugin 302873](https://www.tenable.com/plugins/nessus/302873): Windows Speculative Execution Configuration Check - Intel BHI (CVE-2022-0001)

The script follows [Microsoft KB4072698](https://support.microsoft.com/kb/4072698)
(Windows Server and Azure Stack HCI guidance). It detects whether
SMT/Hyper-Threading is enabled, applies the corresponding combined mitigation
value, adds the Intel BHI bit on Intel processors, and configures the Hyper-V
minimum VM version when Hyper-V is present.

For Windows 11 workstations, use [`SpecExFix_win11.ps1`](SpecExFix_win11.ps1)
instead (KB4073119 client guidance).

## Supported targets

| Target | Supported | Notes |
| --- | --- | --- |
| On-premises Windows Server | Yes | With or without the Hyper-V role |
| Hyper-V hosts | Yes | Also sets `MinVmVersionForCpuBasedMitigations` |
| Azure Stack HCI / Azure Local | Yes | Same KB4072698 host guidance |
| Windows Server guest VMs in Azure | Yes | Same guest OS registry keys |
| Windows 11 / client SKUs | No | Exits with code `1`; use `SpecExFix_win11.ps1` |

### Azure

Microsoft already mitigates Azure **host** infrastructure between tenants.
Guest OS registry keys are still the correct remediation for Tenable findings
**inside** the VM and for defense-in-depth / untrusted-code scenarios. See
[Azure speculative-execution guidance](https://learn.microsoft.com/azure/virtual-machines/mitigate-se).

Nested Hyper-V in Azure (limited SKUs) may also require setting the hypervisor
scheduler type to **Core**. That host-scheduler step is outside this registry
script.

## Important limitation

Registry configuration is only one part of remediation. A successful script
exit confirms that the expected registry values and data types were written; it
does **not** prove that the processor protections are active.

The system must also have:

- Current Windows Server security and servicing updates.
- Current BIOS/UEFI firmware and CPU microcode from the device manufacturer
  (physical hosts).
- A reboot after the registry values and updates are installed.

Microsoft notes that these mitigations can affect performance. Test them against
representative workloads before broad deployment.

## Requirements

- Windows Server (or Azure Stack HCI / Azure Local) on a supported Intel or AMD
  x86/x64 processor.
- Windows PowerShell 5.1 or later.
- A **64-bit** PowerShell process.
- Local Administrator privileges (or equivalent elevated context).
- Access to write under `HKLM` and to create the log directory.
- An organizational process for deploying current Windows updates and OEM
  firmware on physical hosts.

The script intentionally stops with exit code `1` if it cannot identify the CPU
vendor or physical/logical processor topology. This prevents an Intel system
from being reported as remediated when the BHI setting could not be selected.

## Values applied

For `FeatureSettingsOverrideMask`, the script sets `3` (`REG_DWORD`).

For `FeatureSettingsOverride`, it selects:

| SMT / Hyper-Threading | CPU | `FeatureSettingsOverride` |
| --- | --- | --- |
| Enabled | AMD | `72` (`0x48`) |
| Disabled | AMD | `8264` (`0x2048`) |
| Enabled | Intel (with BHI) | `8388680` (`0x800048`) |
| Disabled | Intel (with BHI) | `8396872` (`0x802048`) |

These are canonical combined values for the vulnerabilities covered by the two
Tenable plugins. The script **replaces** the existing value instead of
preserving arbitrary bits, because an existing bit can explicitly disable a
protection. Review this behavior first if the organization manages other
`FeatureSettingsOverride` options for separate processor vulnerabilities.

If Hyper-V is installed, the script also creates:

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization
  MinVmVersionForCpuBasedMitigations = "1.0" (REG_SZ)
```

## Run manually

1. Install all applicable Windows Server security updates.
2. On physical hosts, install the latest applicable OEM BIOS/UEFI firmware and
   CPU microcode.
3. Copy `SpecExFix.ps1` to the server.
4. Open **64-bit Windows PowerShell as Administrator**.
5. If required by policy, sign the script with an approved code-signing
   certificate. Do not permanently weaken the execution policy.
6. Run:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SpecExFix.ps1
   ```

   `-ExecutionPolicy Bypass` affects only this process invocation. Omit it when
   application control or organizational policy requires a signed script.

7. Review the exit code and log:

   ```powershell
   $LASTEXITCODE
   Get-Content 'C:\ProgramData\SpecEx\SpeculativeExecutionFix_Server.log'
   ```

8. Reboot the server.

### Hyper-V hosts

After installing firmware updates, **fully shut down** all virtual machines
before rebooting the host. This allows firmware-related mitigations to be
exposed to the guests when they start again. A guest reboot alone is not
sufficient after host firmware changes.

## Deploy at scale

Common deployment options:

| Method | Notes |
| --- | --- |
| Group Policy startup / scheduled task | Run elevated as `SYSTEM` or a privileged service account |
| Configuration Manager / Intune | Use a 64-bit PowerShell host; reboot after success |
| Ansible / SCCM / other RMM | Invoke the script remotely with admin rights |
| Manual / break-glass | Follow the steps in **Run manually** |

Schedule or require a reboot after successful execution. Do not rescan before
the reboot.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Expected registry configuration was already present, or was written and verified. OS updates, firmware, reboot state, and active protections still require separate validation. |
| `1` | Unsupported target, detection failure, insufficient privileges, 32-bit process, registry write failure, or verification failure. |

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

# When Hyper-V is installed:
Get-ItemProperty `
  -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization' `
  -Name MinVmVersionForCpuBasedMitigations
```

Finally, run a credentialed Tenable/Nessus scan after the reboot and confirm
that plugins 132101 and 302873 no longer report the host. Plugin 302873
applies to affected Intel processors.

## Logging

The script writes to:

```text
C:\ProgramData\SpecEx\SpeculativeExecutionFix_Server.log
```

The log records the product name, installation type, build, CPU vendor, core
and logical-processor counts, detected SMT state, Hyper-V state, Azure guest
detection (when present), selected mitigation value, registry writes, and any
failure.

## Related scripts in this repository

| Script | Platform | Microsoft guidance |
| --- | --- | --- |
| `SpecExFix.ps1` | Windows Server / Azure Stack HCI / Azure Local | KB4072698 |
| `SpecExFix_win11.ps1` | Windows 11 clients | KB4073119 |
| `SpecExFix_linux.sh` | Linux workstations / servers | Distribution + kernel mitigations |

## License

This project is licensed under the
[GNU General Public License v3.0](LICENSE).

```text

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
```

When publishing on GitHub, set the repository license to **GPL-3.0** so GitHub
detects the `LICENSE` file automatically.

## Security and contribution notes

- Do not commit secrets, credentials, or environment-specific inventory.
- Prefer signed scripts in production environments that enforce code integrity.
- Open issues or pull requests with the OS build, CPU vendor, SMT state, log
  excerpt, and (when possible) `Get-SpeculationControlSettings` output after
  reboot.
- Changes that alter mitigation bitmasks should cite the corresponding
  Microsoft KB section and Tenable plugin IDs.

## References

- [Tenable plugin 132101](https://www.tenable.com/plugins/nessus/132101)
- [Tenable plugin 302873](https://www.tenable.com/plugins/nessus/302873)
- [Microsoft KB4072698 Windows Server and Azure Stack HCI guidance](https://support.microsoft.com/en-us/topic/kb4072698-windows-server-and-azure-stack-hci-guidance-to-protect-against-silicon-based-microarchitectural-and-speculative-execution-side-channel-vulnerabilities-2f965763-00e2-8f98-b632-0d96f30c8c8e)
- [Microsoft Azure speculative-execution guidance](https://learn.microsoft.com/azure/virtual-machines/mitigate-se)
- [Microsoft KB4073757 general Windows guidance](https://support.microsoft.com/en-us/topic/kb4073757-protect-windows-devices-against-silicon-based-microarchitectural-and-speculative-execution-side-channel-vulnerabilities-a0b9f66c-f426-d854-fdbb-0e6beaeeee87)
- [GNU GPL v3](https://www.gnu.org/licenses/gpl-3.0.html)
