<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_script/posh_ps_shellintel_malicious_commandlets.yml -->
title: Malicious ShellIntel PowerShell Commandlets
id: 402e1e1d-ad59-47b6-bf80-1ee44985b3a7
status: test
description: Detects Commandlet names from ShellIntel exploitation scripts.
references:
    - https://github.com/Shellntel/scripts/
author: Max Altgelt (Nextron Systems), Tobias Michalski (Nextron Systems)
date: 2021-08-09
modified: 2023-01-02
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains:
            - 'Invoke-SMBAutoBrute'
            - 'Invoke-GPOLinks'
            # - 'Out-Minidump' # Covered in 89819aa4-bbd6-46bc-88ec-c7f7fe30efa6
            - 'Invoke-Potato'
    condition: selection
falsepositives:
    - Unknown
level: high
