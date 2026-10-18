<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/registry/registry_set/registry_set_disable_windows_firewall.yml -->
title: Disable Windows Firewall by Registry
id: e78c408a-e2ea-43cd-b5ea-51975cf358c0
status: test
description: Detect set EnableFirewall to 0 to disable the Windows firewall
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1562.004/T1562.004.md
author: frack113
date: 2022-08-19
modified: 2023-08-17
tags:
    - attack.defense-impairment
    - attack.t1686.003
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith:
            - \SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\EnableFirewall
            - \SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall
        Details: DWORD (0x00000000)
    condition: selection
falsepositives:
    - Unknown
level: medium
